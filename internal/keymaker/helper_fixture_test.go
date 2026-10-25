package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/enrollment"
	"github.com/relux-works/swarma-registrar/ccj"
	enrolled "github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/envelope"
	"github.com/relux-works/swarma-registrar/registry"
)

const helperName = "sample_core_worker"
const helperAudience = "carrier.example.invalid"
const helperPath = "m/2'/1'/1'/1'"

var helperNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

type helperClock struct {
	mu      sync.Mutex
	at      time.Time
	healthy bool
}

func (c *helperClock) Sample(context.Context) (timeconf.Sample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return timeconf.Sample{Now: c.at, Trusted: c.healthy, Fresh: c.healthy, AuthorityUntil: c.at.Add(5 * time.Minute), Boot: "fixture-boot"}, nil
}
func (c *helperClock) set(at time.Time, healthy bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at, c.healthy = at, healthy
}

// Only metadata ownership is substituted. All file bytes, Git objects, signed
// commits, signed enrollment and Authority.Reload/Authorize paths remain real.
type helperFiles struct{ base string }

func (f helperFiles) Lstat(p string) (enrollment.Metadata, error) {
	m, e := (enrollment.LinuxFiles{}).Lstat(p)
	if e != nil {
		return m, e
	}
	if !strings.HasPrefix(p, f.base+"/") && p != f.base {
		m.Mode = fs.ModeDir | 0755
	}
	if p != filepath.Join(f.base, "state") && !strings.HasPrefix(p, filepath.Join(f.base, "state")+"/") {
		m.UID = 0
	}
	return m, nil
}
func (f helperFiles) Read(p string, l int64) ([]byte, enrollment.Metadata, error) {
	b, m, e := (enrollment.LinuxFiles{}).Read(p, l)
	if !strings.HasPrefix(p, filepath.Join(f.base, "state")+"/") {
		m.UID = 0
	}
	return b, m, e
}
func (f helperFiles) Readable(p string) error { return (enrollment.LinuxFiles{}).Readable(p) }

type helperPublication struct {
	revision string
	entries  []registry.Entry
	high     *registry.HighWater
}

func (p *helperPublication) Verify(r string, e []registry.Entry) error {
	if r != p.revision || !reflect.DeepEqual(e, p.entries) {
		return errors.New("unapproved fixture")
	}
	return nil
}
func (p *helperPublication) Descends(a, b string) (bool, error) { return a == b, nil }
func (p *helperPublication) Commit(old *registry.HighWater, next registry.HighWater) error {
	if old != nil {
		return errors.New("fixture first use only")
	}
	p.high = next.Clone()
	return nil
}
func (p *helperPublication) Check(_ context.Context, h *registry.HighWater) error {
	if !reflect.DeepEqual(h, p.high) {
		return errors.New("unreconciled fixture")
	}
	return nil
}

type helperTrust struct {
	authority *enrollment.Authority
	config    string
	clock     *helperClock
	helper    *RegistrationHelper
}

func newHelperTrust(t *testing.T, f *nativeFixture, body map[string]any, admitted map[string]string, verified bool) *helperTrust {
	t.Helper()
	base := t.TempDir()
	os.Chmod(base, 0700)
	run := func(program string, in []byte, args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, program, args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + base, "XDG_CONFIG_HOME=" + base, "LC_ALL=C", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_COUNT=0", "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL="}
		cmd.Stdin = bytes.NewReader(in)
		var out, errout bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errout
		if e := cmd.Run(); e != nil {
			t.Fatalf("fixture %s: %v %s", filepath.Base(program), e, errout.String())
		}
		return out.Bytes()
	}
	key := filepath.Join(base, "fixture-key")
	run("/usr/bin/ssh-keygen", nil, "-q", "-t", "ed25519", "-N", "", "-f", key)
	pin, e := os.ReadFile(key + ".pub")
	if e != nil {
		t.Fatal(e)
	}
	repo := filepath.Join(base, "registry.git")
	run("/usr/bin/git", nil, "init", "--bare", "--quiet", repo)
	git := func(in []byte, args ...string) string {
		prefix := []string{"--git-dir=" + repo, "-c", "core.hooksPath=/dev/null", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "gpg.format=ssh", "-c", "gpg.ssh.program=/usr/bin/ssh-keygen", "-c", "user.signingkey=" + key}
		return strings.TrimSpace(string(run("/usr/bin/git", in, append(prefix, args...)...)))
	}
	publisher := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{43}, 32))
	publisherPublic := "ed25519:" + base64.RawURLEncoding.EncodeToString(publisher[32:])
	pre, id, e := envelope.SigningInput(envelope.Enrollment, body)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := ccj.Marshal(map[string]any{"body": body, "id": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(publisher, pre))}, ccj.EnrollmentMalformed)
	if e != nil {
		t.Fatal(e)
	}
	blob := git(raw, "hash-object", "-w", "--stdin")
	tree := git([]byte("100644 blob "+blob+"\t1.json\n"), "mktree")
	root := git([]byte("040000 tree "+tree+"\tenrollments\n"), "mktree")
	revision := git(nil, "commit-tree", root, "-S", "-m", "Fixture enrollment")
	if err := filepath.WalkDir(repo, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		mode := fs.FileMode(0600)
		if d.IsDir() {
			mode = 0700
		}
		return os.Chmod(p, mode)
	}); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "state")
	os.Mkdir(state, 0700)
	config := enrollment.PinConfig{ObjectFormat: "sha1", Maintainers: []string{strings.TrimSpace(string(pin))}, Revision: revision, Publisher: publisherPublic, Audience: helperAudience, Registry: repo, StateDir: state, Stations: map[string]bool{"sample": true}, Generations: admitted}
	path := filepath.Join(base, "pins.json")
	write := func(p string, b []byte) {
		t.Helper()
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	cfg, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	write(path, cfg)
	publication := &helperPublication{revision: revision, entries: []registry.Entry{{Path: "enrollments/1.json", Bytes: raw, Kind: registry.Regular}}}
	policy, e := enrolled.NewPolicy(helperAudience, publisherPublic, config.Stations)
	if e != nil {
		t.Fatal(e)
	}
	_, high, loadErr := (registry.Loader{Policy: policy, Verifier: publication, Store: publication}).Load(registry.Input{Revision: revision, Entries: publication.entries, FirstUse: true})
	if loadErr != nil && verified {
		t.Fatal(loadErr)
	}
	// Invalid schema fixtures retain an independently shaped baseline state; Reload
	// must reject their real signed candidate rather than admit an invented snapshot.
	if high == nil {
		high = &registry.HighWater{Revision: revision, Hosts: map[string]registry.HostWater{}, KeyOwners: map[string]string{}, NameOwners: map[string]string{}}
		publication.high = high.Clone()
	}
	disk, e := json.Marshal(map[string]any{"version": 1, "high_water": high})
	if e != nil {
		t.Fatal(e)
	}
	write(filepath.Join(state, "high-water.json"), disk)
	write(filepath.Join(state, "accepted"), []byte("accepted/1\n"))
	write(filepath.Join(state, "high-water.lock"), nil)
	files := helperFiles{base}
	authority := enrollment.New(path, files, publication)
	if !verified && loadErr == nil {
		write(path, []byte("{}"))
	}
	code := authority.Reload(context.Background())
	if verified && code != "" {
		t.Fatal("valid enrollment reload", code)
	}
	if !verified && code != "enrollment_unverified" {
		t.Fatal("invalid enrollment not fenced", code)
	}
	clock := &helperClock{at: helperNow, healthy: true}
	h, e := NewRegistrationHelper(f.master, helperPath, authority, clock, rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return &helperTrust{authority: authority, config: path, clock: clock, helper: h}
}
func helperBody(t *testing.T, f *nativeFixture, uid uint32) map[string]any {
	t.Helper()
	pub, c := f.master.withPurpose(helperPath, "host-registration", func(k ed25519.PrivateKey) []byte { return append([]byte(nil), k[32:]...) })
	if c != "" {
		t.Fatal(c)
	}
	return map[string]any{"type": "enrollment/1", "host": "sample", "seq": int64(1), "state": "active", "keys": []any{map[string]any{"key": "ed25519:" + base64.RawURLEncoding.EncodeToString(pub), "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}}, "names": map[string]any{"prefix": "sample_", "explicit": []any{}}, "uid_map": []any{map[string]any{"uid": int64(uid), "names": []any{helperName}}}}
}
func helperSetup(t *testing.T) (*nativeFixture, *helperTrust) {
	t.Helper()
	b := nativeOwnBinding()
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
	trust := newHelperTrust(t, f, helperBody(t, f, b.UID), map[string]string{strconv.FormatUint(uint64(b.UID), 10): nativeToken}, true)
	f.native.Config.Helper = trust.helper
	f.config.Helper = trust.helper
	return f, trust
}
