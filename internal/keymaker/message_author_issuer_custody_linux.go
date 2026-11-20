//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"golang.org/x/sys/unix"
)

const maIssuerSeedFile = "issuer-seed"
const maIssuerPinDefault = "/etc/swarma-keymaker/purpose5-pin.json"

// The fixed purpose-5 root is derived from its independent seed. No caller
// chooses a path, index, signing language or root role.
var maIssuerPath = []uint32{0x80000005, 0x80000001, 0x80000001, 0x80000001}

type maIssuerKey struct {
	mu                     sync.Mutex
	seed                   []byte
	mapped, locked, closed bool
}

func (*maIssuerKey) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[message-author issuer custody]")
}
func (*maIssuerKey) MarshalJSON() ([]byte, error) { return nil, errMessageAuthorKey }
func (*maIssuerKey) MarshalText() ([]byte, error) { return nil, errMessageAuthorKey }
func (k *maIssuerKey) close() error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	e := eraseMALiveMemory(k.seed, k.mapped, k.locked)
	k.seed = nil
	k.mapped = false
	k.locked = false
	k.closed = true
	return e
}
func newMAIssuerKey(seed []byte) (*maIssuerKey, Code) {
	if len(seed) != 32 {
		return nil, "custody_unavailable"
	}
	page, e := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if e != nil {
		return nil, "custody_unavailable"
	}
	if unix.Madvise(page, unix.MADV_DONTDUMP) != nil {
		_ = eraseMALiveMemory(page, true, false)
		return nil, "custody_unavailable"
	}
	locked := syscall.Mlock(page) == nil
	copy(page, seed)
	return &maIssuerKey{seed: page[:32], mapped: true, locked: locked}, ""
}
func (k *maIssuerKey) privateHeld() (ed25519.PrivateKey, Code) {
	if k.closed || !k.mapped || len(k.seed) != 32 {
		return nil, "custody_unavailable"
	}
	node := deriveNode(k.seed, maIssuerPath)
	defer erase(node)
	return ed25519.NewKeyFromSeed(node[:32]), ""
}
func (k *maIssuerKey) public() (string, Code) {
	if k == nil {
		return "", "custody_unavailable"
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	p, c := k.privateHeld()
	if c != "" {
		return "", c
	}
	defer erase(p)
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(p[32:]), ""
}
func (k *maIssuerKey) attest(body map[string]any) ([]byte, Code) {
	if k == nil {
		return nil, "custody_unavailable"
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	p, c := k.privateHeld()
	if c != "" {
		return nil, c
	}
	defer erase(p)
	issuer := "ed25519:" + base64.RawURLEncoding.EncodeToString(p[32:])
	// A fixed internal profile, not a generic Ed25519 preimage capability.
	sub, ok := body["subject"].(map[string]any)
	if !ok {
		return nil, "binding_conflict"
	}
	key, ok := sub["key_id"].(string)
	if !ok {
		return nil, "binding_conflict"
	}
	from, ok := body["iat"].(string)
	if !ok {
		return nil, "binding_conflict"
	}
	until, ok := body["exp"].(string)
	if !ok {
		return nil, "binding_conflict"
	}
	var b messageBinding
	bindingRaw, e := canonical(body["binding"])
	if e != nil || StrictJSON(bytes.NewReader(bindingRaw), &b) != nil || body["issuer"] != issuer {
		return nil, "binding_conflict"
	}
	if len(b.Path) < 4 || b.Path[:4] != "m/9'" {
		return nil, "binding_conflict"
	}
	cert := &maIssuerCertificate{Key: key, From: from, Until: until}
	if len(key) < len("bip340:") || record.ValidateKey(key) != nil || key[:len("bip340:")] != "bip340:" {
		return nil, "binding_conflict"
	}
	expected := map[string]any{"type": "attestation/1", "issuer": issuer, "subject": map[string]any{"algorithm": "BIP-340", "key_id": key, "public_bytes": key[len("bip340:"):]}, "key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"}, "iat": from, "exp": until, "binding": map[string]any{"uid": int64(b.UID), "generation": b.Generation, "registration_number": int64(b.Number), "master_epoch": b.Epoch, "owner": b.Owner, "path": b.Path}}
	want, _ := canonical(expected)
	got, _ := canonical(body)
	start, e1 := time.Parse(time.RFC3339, from)
	end, e2 := time.Parse(time.RFC3339, until)
	if !bytes.Equal(want, got) || e1 != nil || e2 != nil || messageStamp(start) != from || messageStamp(end) != until || !end.After(start) || end.Sub(start) > 86400*time.Second {
		return nil, "binding_conflict"
	}
	pre, e := record.SigningPreimage("attestation/1", issuer, "author", body)
	if e != nil {
		return nil, "binding_conflict"
	}
	t, e := record.ContentID("attestation/1", body)
	if e != nil {
		return nil, "binding_conflict"
	}
	raw, e := record.Canonical(map[string]any{"version": "swarm-envelope/2", "body": body, "id": t, "signatures": []any{map[string]any{"key": issuer, "role": "author", "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(p, pre))}}})
	if e != nil {
		return nil, "binding_conflict"
	}
	cert.T, cert.A = t, raw
	if len(b.Path) < 4 || b.Path[:4] != "m/9'" {
		return nil, "binding_conflict"
	}
	binding := Binding{UID: b.UID, Generation: b.Generation, Number: b.Number, Epoch: b.Epoch, Owner: b.Owner, Path: "m/1'" + b.Path[len("m/9'"):], Status: "active"}
	if len(b.Path) < 4 || b.Path[:4] != "m/9'" || !maIssuerEnvelope(cert, binding) {
		return nil, "binding_conflict"
	}
	return raw, ""
}

type maIssuerPin struct {
	Format  string `json:"format"`
	Issuer  string `json:"issuer_key"`
	Profile string `json:"profile"`
}

func (k *maIssuerKey) pin() ([]byte, Code) {
	p, c := k.public()
	if c != "" {
		return nil, c
	}
	raw, e := canonical(maIssuerPin{"keymaker-purpose5-pin/1", p, "attestation/1"})
	if e != nil {
		return nil, "custody_unavailable"
	}
	return append(raw, '\n'), ""
}

// Parsing is separately testable without manufacturing root-owned fixture files.
func maIssuerCheckPin(raw []byte, key string) Code {
	if len(raw) > 4096 || len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return "message_author_issuer_pin_invalid"
	}
	if _, e := objectMembers(raw, []string{"format", "issuer_key", "profile"}); e != nil {
		return "message_author_issuer_pin_invalid"
	}
	var pin maIssuerPin
	if StrictJSON(bytes.NewReader(raw), &pin) != nil || pin.Format != "keymaker-purpose5-pin/1" || pin.Profile != "attestation/1" || !strings.HasPrefix(pin.Issuer, "ed25519:") || record.ValidateKey(pin.Issuer) != nil {
		return "message_author_issuer_pin_invalid"
	}
	canonical, _ := canonical(pin)
	if !bytes.Equal(append(canonical, '\n'), raw) {
		return "message_author_issuer_pin_invalid"
	}
	if pin.Issuer != key {
		return "message_author_issuer_pin_mismatch"
	}
	return ""
}
func maIssuerStartupPin(path string, k *maIssuerKey) (bool, Code) {
	return maIssuerStartupPinOwner(path, k, 0)
}

// Production fixes owner=root. The fixture owner parameter exercises the same
// descriptor walk and modes without privilege or root-owned test files.
func maIssuerStartupPinOwner(path string, k *maIssuerKey, owner uint32) (bool, Code) {
	if path == "" {
		path = maIssuerPinDefault
	}
	if !cleanAbsolute(path) {
		return false, "message_author_issuer_pin_invalid"
	}
	fd, e := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return false, "message_author_issuer_pin_invalid"
	}
	dir := os.NewFile(uintptr(fd), "pin parent")
	defer func() { dir.Close() }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for n, part := range parts {
		var st syscall.Stat_t
		if syscall.Fstat(int(dir.Fd()), &st) != nil || !protectedAncestor(st, owner) || !j7NoACL(int(dir.Fd()), true) {
			return false, "message_author_issuer_pin_invalid"
		}
		if n == len(parts)-1 {
			file, e := syscall.Openat(int(dir.Fd()), part, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
			if e == syscall.ENOENT {
				return false, ""
			}
			if e != nil {
				return false, "message_author_issuer_pin_invalid"
			}
			f := os.NewFile(uintptr(file), "issuer pin")
			defer f.Close()
			if syscall.Fstat(file, &st) != nil || st.Mode != syscall.S_IFREG|0644 || st.Uid != owner || st.Nlink != 1 || !j7NoACL(file, false) {
				return false, "message_author_issuer_pin_invalid"
			}
			raw, e := io.ReadAll(io.LimitReader(f, 4097))
			if e != nil {
				return false, "message_author_issuer_pin_invalid"
			}
			pub, c := k.public()
			if c != "" {
				return false, c
			}
			c = maIssuerCheckPin(raw, pub)
			return c == "", c
		}
		next, e := syscall.Openat(int(dir.Fd()), part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if e == syscall.ENOENT {
			return false, ""
		}
		if e != nil {
			return false, "message_author_issuer_pin_invalid"
		}
		dir.Close()
		dir = os.NewFile(uintptr(next), "pin parent")
	}
	return false, "message_author_issuer_pin_invalid"
}
func loadMAIssuerKey(dir *os.File, uid uint32) (*maIssuerKey, Code) {
	fd, e := syscall.Openat(int(dir.Fd()), maIssuerSeedFile, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, "custody_unavailable"
	}
	f := os.NewFile(uintptr(fd), "issuer custody")
	defer f.Close()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode != syscall.S_IFREG|0600 || st.Uid != uid || st.Nlink != 1 || !j7NoACL(fd, false) {
		return nil, "custody_unavailable"
	}
	seed, e := io.ReadAll(io.LimitReader(f, 33))
	defer erase(seed)
	if e != nil {
		return nil, "custody_unavailable"
	}
	return newMAIssuerKey(seed)
}
func (s *Store) initMAIssuerSeed(ctx context.Context, p Principal, entropy io.Reader) Code {
	if !s.mu.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	defer s.mu.Unlock()
	if s.failed || s.maLive == nil || s.maLive.Fenced {
		return "message_author_unqualified"
	}
	// O_EXCL is the authoritative no-replacement check. A failed/partial file is
	// retained evidence, never silently removed or treated as virgin custody.
	var st unix.Stat_t
	if e := unix.Fstatat(int(s.dir.Fd()), maIssuerSeedFile, &st, unix.AT_SYMLINK_NOFOLLOW); e != unix.ENOENT {
		return "custody_unavailable"
	}
	if c := s.maLiveAudit(ctx, p, "", "message_author_issuer_seed_init", nil); c != "" {
		return c
	}
	fd, e := syscall.Openat(int(s.dir.Fd()), maIssuerSeedFile, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return "custody_unavailable"
	}
	f := os.NewFile(uintptr(fd), "issuer custody")
	defer f.Close()
	var seed [32]byte
	defer erase(seed[:])
	if entropy == nil {
		entropy = rand.Reader
	}
	if _, e = io.ReadFull(entropy, seed[:]); e != nil {
		return "entropy_unavailable"
	}
	if _, e = f.Write(seed[:]); e != nil || f.Sync() != nil || s.dir.Sync() != nil {
		return "custody_unavailable"
	}
	return ""
}
