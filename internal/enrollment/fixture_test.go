package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/envelope"
	"github.com/relux-works/swarma-registrar/registry"
)

const testGeneration = "00000000000000000000000000000001"
const testName = "sample_core_worker"
const testAudience = "carrier.example.invalid"

var testNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

// This fixture substitutes ownership and can inject explicit read denials. All
// content, Git objects, SSH signatures, writes and registrar validation are real.
type fixtureFiles struct {
	base          string
	override      map[string]Metadata
	denyRead      map[string]error
	approvalClock approvalSource
}

func (f fixtureFiles) approvalSource() approvalSource {
	if f.approvalClock != nil {
		return f.approvalClock
	}
	return &fixedApprovalSource{instant: approvalInstant{bootID: "test-boot", utc: testNow.UnixNano(), boot: int64(time.Hour), trusted: true, authorityUntil: testNow.Add(time.Hour)}}
}

func (f fixtureFiles) Lstat(path string) (Metadata, error) {
	m, err := (LinuxFiles{}).Lstat(path)
	if err != nil {
		return m, err
	}
	m.UID = 0
	if path != f.base && !strings.HasPrefix(path, f.base+"/") {
		m.Mode = fs.ModeDir | 0755
	}
	if other, ok := f.override[path]; ok {
		return other, nil
	}
	return m, nil
}
func (f fixtureFiles) Readable(path string) error {
	if err := f.denyRead[path]; err != nil {
		return err
	}
	return (LinuxFiles{}).Readable(path)
}

func (f fixtureFiles) Read(path string, limit int64) ([]byte, Metadata, error) {
	b, m, err := (LinuxFiles{}).Read(path, limit)
	m.UID = 0
	if other, ok := f.override[path]; ok {
		m = other
	}
	return b, m, err
}

type fixture struct {
	t                                   *testing.T
	base, repo, key, public, configPath string
	config                              PinConfig
	files                               fixtureFiles
}

func private(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
}
func public(seed byte) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(private(seed).Public().(ed25519.PublicKey))
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWithFormat(t, "sha1")
}
func newFixtureWithFormat(t *testing.T, objectFormat string) *fixture {
	t.Helper()
	base := t.TempDir()
	if err := os.Chmod(base, 0700); err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, base: base, repo: filepath.Join(base, "registry.git"), key: filepath.Join(base, "test-signing-key"), configPath: filepath.Join(base, "pins.json")}
	f.files = fixtureFiles{base: base, override: map[string]Metadata{}}
	f.run("/usr/bin/ssh-keygen", nil, "-q", "-t", "ed25519", "-N", "", "-f", f.key)
	pub, err := os.ReadFile(f.key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	f.public = strings.TrimSpace(string(pub))
	f.run("/usr/bin/git", nil, "init", "--bare", "--quiet", "--object-format="+objectFormat, f.repo)
	if err := os.Chmod(f.repo, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "state")
	if err = os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	f.config = PinConfig{ObjectFormat: objectFormat, Maintainers: []string{f.public}, Publisher: public(1), Audience: testAudience, Registry: f.repo, StateDir: state, Stations: map[string]bool{"sample": true}, Generations: map[string]string{"30001": testGeneration}}
	return f
}
func (f *fixture) run(program string, input []byte, args ...string) []byte {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + f.base, "XDG_CONFIG_HOME=" + f.base, "LC_ALL=C", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_COUNT=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL="}
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		f.t.Fatalf("fixture command %s: %v (%s)", filepath.Base(program), err, stderr.String())
	}
	return stdout.Bytes()
}
func (f *fixture) git(input []byte, args ...string) []byte {
	prefix := []string{"--git-dir=" + f.repo, "-c", "core.hooksPath=/dev/null", "-c", "user.name=Fixture Signer", "-c", "user.email=fixture@example.invalid", "-c", "gpg.format=ssh", "-c", "gpg.ssh.program=/usr/bin/ssh-keygen", "-c", "user.signingkey=" + f.key}
	return f.run("/usr/bin/git", input, append(prefix, args...)...)
}
func (f *fixture) writeConfig() {
	f.t.Helper()
	if err := filepath.WalkDir(f.repo, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := fs.FileMode(0600)
		if d.IsDir() {
			mode = 0700
		}
		return os.Chmod(path, mode)
	}); err != nil {
		f.t.Fatal(err)
	}
	b, err := json.Marshal(f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	if err = os.WriteFile(f.configPath, b, 0600); err != nil {
		f.t.Fatal(err)
	}
}

// Initial fixture state uses the same explicit operator publisher as the CLI.
// This convenience is never used by the empty-state refusal regressions.
func (f *fixture) authority() *Authority {
	f.writeConfig()
	return f.reconciledAuthority()
}

func (f *fixture) reconciledAuthority() *Authority {
	high, err := bootstrapFixture(context.Background(), f.configPath, f.files, diskOps{})
	if err != nil {
		return New(f.configPath, f.files, nil)
	}
	return New(f.configPath, f.files, exactReconciler{high})
}

func (f *fixture) operatorBootstrap(ops durableOps) (*registry.HighWater, error) {
	f.writeConfig()
	return bootstrapFixture(context.Background(), f.configPath, f.files, ops)
}

func bootstrapFixture(ctx context.Context, path string, files Files, ops durableOps) (*registry.HighWater, error) {
	c, policy, err := loadConfig(path, files)
	if err != nil {
		return nil, err
	}
	if err = safeRepository(ctx, files, c.Registry); err != nil {
		return nil, err
	}
	v := newGitVerifier(ctx, c.Registry, c.Revision, c.ObjectFormat, c.Maintainers)
	entries, err := v.entries()
	if err != nil {
		return nil, err
	}
	s := newFileStore(ctx, c.StateDir, files, c.ObjectFormat)
	s.ops = ops
	_, high, err := (registry.Loader{ObjectFormat: c.ObjectFormat, Policy: policy, Verifier: v, Store: initialPublisher{s}}).Load(registry.Input{Revision: c.Revision, Entries: entries, FirstUse: true})
	return high, err
}

// The conformance harness explicitly supplies initial operator publication;
// service Store.Commit itself never accepts an empty retained state.
type conformanceStore struct{ *fileStore }

func (s conformanceStore) Commit(previous *registry.HighWater, next registry.HighWater) error {
	if previous == nil {
		return (initialPublisher{s.fileStore}).Commit(nil, next)
	}
	return s.fileStore.Commit(previous, next)
}
func baseBody() map[string]any {
	return map[string]any{
		"type": "enrollment/1", "host": "sample", "seq": int64(1), "state": "active",
		"keys":    []any{map[string]any{"key": public(2), "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}},
		"names":   map[string]any{"prefix": "sample_", "explicit": []any{}},
		"uid_map": []any{map[string]any{"uid": int64(30001), "names": []any{testName}}},
	}
}
func signedRecord(t *testing.T, body map[string]any, seed byte) []byte {
	t.Helper()
	preimage, id, err := envelope.SigningInput(envelope.Enrollment, body)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ccj.Marshal(map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(private(seed), preimage))}, ccj.EnrollmentMalformed)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func (f *fixture) commit(entries []registry.Entry, parent string, signed bool) string {
	f.t.Helper()
	var treeInput bytes.Buffer
	blobs := map[string]string{}
	emptyTree := strings.TrimSpace(string(f.git(nil, "mktree")))
	for _, e := range entries {
		name := strings.TrimPrefix(e.Path, "enrollments/")
		mode, kind := "100644", "blob"
		if e.Kind == registry.Symlink {
			mode = "120000"
		}
		if e.Kind == registry.Other {
			mode, kind = "040000", "tree"
		}
		oid := emptyTree
		if kind == "blob" {
			var ok bool
			oid, ok = blobs[string(e.Bytes)]
			if !ok {
				oid = strings.TrimSpace(string(f.git(e.Bytes, "hash-object", "-w", "--stdin")))
				blobs[string(e.Bytes)] = oid
			}
		}
		fmt.Fprintf(&treeInput, "%s %s %s\t%s\n", mode, kind, oid, name)
	}
	enrollTree := strings.TrimSpace(string(f.git(treeInput.Bytes(), "mktree")))
	root := strings.TrimSpace(string(f.git([]byte("040000 tree "+enrollTree+"\tenrollments\n"), "mktree")))
	args := []string{"commit-tree", root, "-m", "Fixture registry"}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	if signed {
		args = append(args, "-S")
	}
	return strings.TrimSpace(string(f.git(nil, args...)))
}
func (f *fixture) valid() []registry.Entry {
	return []registry.Entry{{Path: "enrollments/1.json", Bytes: signedRecord(f.t, baseBody(), 1), Kind: registry.Regular}}
}
func authorize(a *Authority) (EnrolledKey, Code) {
	return a.Authorize(context.Background(), 30001, testGeneration, public(2), testName, testAudience, testNow, testNow)
}
func expectCode(t *testing.T, want, got Code) {
	t.Helper()
	if got != want {
		t.Fatalf("code = %q, want %q", got, want)
	}
}
