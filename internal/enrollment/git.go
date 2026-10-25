package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io/fs"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/relux-works/swarma-registrar/registry"
)

// Maintainer pins are canonical OpenSSH Ed25519 public keys (no options). A
// comment is ignored; neither a signature's embedded key nor author text is trust.
func parseMaintainer(text string) ([]byte, error) {
	parts := strings.Fields(text)
	if len(parts) < 2 || parts[0] != "ssh-ed25519" {
		return nil, errTrust
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return nil, errTrust
	}
	wire := sshReader{data: blob}
	algorithm := wire.string()
	key := wire.string()
	if wire.bad || len(wire.data) != 0 || string(algorithm) != "ssh-ed25519" || len(key) != ed25519.PublicKeySize {
		return nil, errTrust
	}
	return blob, nil
}

type sshReader struct {
	data []byte
	bad  bool
}

func (r *sshReader) u32() uint32 {
	if len(r.data) < 4 {
		r.bad = true
		return 0
	}
	n := binary.BigEndian.Uint32(r.data[:4])
	r.data = r.data[4:]
	return n
}
func (r *sshReader) string() []byte {
	n := r.u32()
	if r.bad || uint64(n) > uint64(len(r.data)) {
		r.bad = true
		return nil
	}
	b := r.data[:int(n)]
	r.data = r.data[int(n):]
	return b
}
func sshString(b []byte) []byte {
	out := make([]byte, 4, len(b)+4)
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

func verifySSHSig(armor, message []byte, pins []string) error {
	if !bytes.HasPrefix(armor, []byte("-----BEGIN SSH SIGNATURE-----\n")) {
		return errTrust
	}
	block, rest := pem.Decode(armor)
	if block == nil || block.Type != "SSH SIGNATURE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(block.Bytes, []byte("SSHSIG")) {
		return errTrust
	}
	r := sshReader{data: block.Bytes[6:]}
	version := r.u32()
	key := r.string()
	namespace := r.string()
	reserved := r.string()
	hashAlg := r.string()
	signature := r.string()
	if r.bad || len(r.data) != 0 || version != 1 || string(namespace) != "git" || len(reserved) != 0 {
		return errTrust
	}
	allowed := false
	for _, pin := range pins {
		blob, err := parseMaintainer(pin)
		if err == nil && bytes.Equal(key, blob) {
			allowed = true
			break
		}
	}
	if !allowed {
		return errTrust
	}
	var digest []byte
	switch string(hashAlg) {
	case "sha256":
		h := sha256.Sum256(message)
		digest = h[:]
	case "sha512":
		h := sha512.Sum512(message)
		digest = h[:]
	default:
		return errTrust
	}
	preimage := append([]byte("SSHSIG"), sshString(namespace)...)
	preimage = append(preimage, sshString(reserved)...)
	preimage = append(preimage, sshString(hashAlg)...)
	preimage = append(preimage, sshString(digest)...)
	sig := sshReader{data: signature}
	algorithm := sig.string()
	raw := sig.string()
	if sig.bad || len(sig.data) != 0 || string(algorithm) != "ssh-ed25519" || len(raw) != ed25519.SignatureSize {
		return errTrust
	}
	public := sshReader{data: key}
	public.string()
	pub := public.string()
	if !ed25519.Verify(ed25519.PublicKey(pub), preimage, raw) {
		return errTrust
	}
	return nil
}

type boundedOutput struct {
	data  bytes.Buffer
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.data.Len() {
		return 0, errTrust
	}
	return b.data.Write(p)
}

func (b *boundedOutput) Bytes() []byte { return b.data.Bytes() }

type gitVerifier struct {
	ctx           context.Context
	objectFormat  string
	dir, revision string
	pins          []string
	commit        []byte
	selected      []registry.Entry
	ready         bool
}

func newGitVerifier(ctx context.Context, dir, revision, objectFormat string, pins []string) *gitVerifier {
	return &gitVerifier{ctx: ctx, dir: dir, revision: revision, objectFormat: objectFormat, pins: append([]string(nil), pins...)}
}
func (v *gitVerifier) command(limit int, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(v.ctx, 3*time.Second)
	defer cancel()
	prefix := []string{"--no-optional-locks", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.commitGraph=false"}
	cmd := exec.CommandContext(ctx, "/usr/bin/git", append(prefix, args...)...)
	cmd.Dir = v.dir
	// No inherited environment: in particular no SSH_AUTH_SOCK, GIT_CONFIG_* or
	// object redirects. Protocol denial and disabled lazy fetch prohibit network.
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent", "LC_ALL=C", "GIT_DIR=" + v.dir, "GIT_COMMON_DIR=" + v.dir, "GIT_OBJECT_DIRECTORY=" + v.dir + "/objects", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_COUNT=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_GRAFT_FILE=/dev/null", "GIT_SHALLOW_FILE=/dev/null", "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL="}
	out := &boundedOutput{limit: limit}
	cmd.Stdout = out
	cmd.Stderr = &boundedOutput{limit: 4096}
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func (v *gitVerifier) object(kind, oid string, limit int) ([]byte, error) {
	if !validObjectID(v.objectFormat, oid) {
		return nil, errTrust
	}
	b, err := v.command(limit, "cat-file", kind, oid)
	if err != nil {
		return nil, errTrust
	}
	var h hash.Hash
	if v.objectFormat == "sha1" {
		h = sha1.New()
	} else {
		h = sha256.New()
	}
	fmt.Fprintf(h, "%s %d%c", kind, len(b), byte(0))
	h.Write(b)
	if hex.EncodeToString(h.Sum(nil)) != oid {
		return nil, errTrust
	}
	return b, nil
}

type treeEntry struct{ mode, name, oid string }

func parseTree(b []byte, oidBytes int) ([]treeEntry, error) {
	if oidBytes != 20 && oidBytes != 32 {
		return nil, errTrust
	}
	var entries []treeEntry
	seen := map[string]bool{}
	for len(b) > 0 {
		space := bytes.IndexByte(b, ' ')
		nul := bytes.IndexByte(b, 0)
		if space < 1 || nul <= space+1 || len(b) < nul+1+oidBytes {
			return nil, errTrust
		}
		mode, name := string(b[:space]), string(b[space+1:nul])
		if strings.Contains(name, "/") || name == "." || name == ".." || seen[name] {
			return nil, errTrust
		}
		seen[name] = true
		entries = append(entries, treeEntry{mode, name, hex.EncodeToString(b[nul+1 : nul+1+oidBytes])})
		b = b[nul+1+oidBytes:]
	}
	return entries, nil
}
func commitParts(raw []byte, objectFormat string) (tree string, unsigned, signature []byte, err error) {
	if objectIDBytes(objectFormat) == 0 {
		return "", nil, nil, errTrust
	}
	end := bytes.Index(raw, []byte("\n\n"))
	if end < 0 {
		return "", nil, nil, errTrust
	}
	lines := bytes.SplitAfter(raw[:end+1], []byte("\n"))
	var out bytes.Buffer
	seenSig := false
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte("tree ")) {
			if tree != "" {
				return "", nil, nil, errTrust
			}
			tree = strings.TrimSuffix(string(line[5:]), "\n")
		}
		if bytes.HasPrefix(line, []byte("parent ")) && !validObjectID(objectFormat, strings.TrimSuffix(string(line[7:]), "\n")) {
			return "", nil, nil, errTrust
		}
		signatureHeader := "gpgsig "
		if objectFormat == "sha256" {
			signatureHeader = "gpgsig-sha256 "
		}
		if bytes.HasPrefix(line, []byte("gpgsig ")) || bytes.HasPrefix(line, []byte("gpgsig-sha256 ")) {
			if !bytes.HasPrefix(line, []byte(signatureHeader)) {
				return "", nil, nil, errTrust
			}
			if seenSig {
				return "", nil, nil, errTrust
			}
			seenSig = true
			signature = append(signature, line[len(signatureHeader):]...)
			for i+1 < len(lines) && bytes.HasPrefix(lines[i+1], []byte(" ")) {
				i++
				signature = append(signature, lines[i][1:]...)
			}
			continue
		}
		out.Write(line)
	}
	out.Write(raw[end+1:])
	if !validObjectID(objectFormat, tree) {
		return "", nil, nil, errTrust
	}
	return tree, out.Bytes(), signature, nil
}
func (v *gitVerifier) entries() ([]registry.Entry, error) {
	if !validObjectID(v.objectFormat, v.revision) {
		return nil, errTrust
	}
	commit, err := v.object("commit", v.revision, 1<<20)
	if err != nil {
		return nil, err
	}
	root, _, _, err := commitParts(commit, v.objectFormat)
	if err != nil {
		return nil, err
	}
	tree, err := v.object("tree", root, 8<<20)
	if err != nil {
		return nil, err
	}
	roots, err := parseTree(tree, objectIDBytes(v.objectFormat))
	if err != nil {
		return nil, err
	}
	selected := []registry.Entry{}
	for _, entry := range roots {
		if entry.name == "enrollments" {
			if entry.mode != "40000" {
				return nil, errTrust
			}
			tree, err = v.object("tree", entry.oid, 8<<20)
			if err != nil {
				return nil, err
			}
			children, err := parseTree(tree, objectIDBytes(v.objectFormat))
			if err != nil {
				return nil, err
			}
			total := 0
			for _, child := range children {
				if !strings.HasSuffix(child.name, ".json") {
					continue
				}
				if len(selected) >= registry.MaxEntries {
					return nil, errTrust
				}
				kind := registry.Other
				if child.mode == "100644" || child.mode == "100755" {
					kind = registry.Regular
				} else if child.mode == "120000" {
					kind = registry.Symlink
				}
				var payload []byte
				if kind == registry.Regular || kind == registry.Symlink {
					payload, err = v.object("blob", child.oid, registry.MaxBytes-total+1)
					if err != nil {
						return nil, err
					}
					total += len(payload)
					if total > registry.MaxBytes {
						return nil, errTrust
					}
				}
				selected = append(selected, registry.Entry{Path: "enrollments/" + child.name, Bytes: payload, Kind: kind})
			}
		}
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Path < selected[j].Path })
	v.commit = commit
	v.selected = selected
	v.ready = true
	// Loader receives independent bytes and cannot alter the verifier's evidence.
	out := make([]registry.Entry, len(selected))
	for i, e := range selected {
		out[i] = e
		out[i].Bytes = append([]byte(nil), e.Bytes...)
	}
	return out, nil
}
func (v *gitVerifier) Verify(revision string, entries []registry.Entry) error {
	if !v.ready {
		if _, err := v.entries(); err != nil {
			return err
		}
	}
	if revision != v.revision || !reflect.DeepEqual(entries, v.selected) {
		return errTrust
	}
	_, unsigned, signature, err := commitParts(v.commit, v.objectFormat)
	if err != nil {
		return err
	}
	return verifySSHSig(signature, unsigned, v.pins)
}
func (v *gitVerifier) Descends(candidate, previous string) (bool, error) {
	if candidate != v.revision || !validObjectID(v.objectFormat, candidate) || !validObjectID(v.objectFormat, previous) {
		return false, errTrust
	}
	if candidate == previous {
		return true, nil
	}
	_, err := v.command(1024, "merge-base", "--is-ancestor", previous, candidate)
	if err == nil {
		return true, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false, nil
	}
	return false, errTrust
}

var _ registry.Verifier = (*gitVerifier)(nil)
var _ registry.Store = (*fileStore)(nil)

// Git may trust ancestor-object storage without rehashing every object. Require
// protected local storage throughout, forbid external alternates, and disable
// graft/shallow/replace metadata in the subprocess environment.
func safeRepository(ctx context.Context, files Files, dir string) error {
	if err := safeParents(files, dir, 0); err != nil {
		return err
	}
	return filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		m, err := files.Lstat(path)
		if err != nil {
			return err
		}
		if !safeMeta(m, entry.IsDir(), 0) {
			return errTrust
		}
		if !entry.IsDir() {
			if err := files.Readable(path); err != nil {
				return err
			}
		}
		if path == filepath.Join(dir, "objects", "info", "alternates") || path == filepath.Join(dir, "objects", "info", "http-alternates") {
			b, err := protectedRead(files, path, 1, 0)
			if err != nil || len(b) != 0 {
				return errTrust
			}
		}
		return nil
	})
}
