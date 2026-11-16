//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/control"
	wire "github.com/relux-works/swarma-keymaker/j7lifecycle"
	"github.com/relux-works/swarma-keymaker/staticgate"
	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

// j7ServiceTrace records the order of startup seams and any ordering violation
// a seam observes while it runs.
type j7ServiceTrace struct {
	mu         sync.Mutex
	events     []string
	violations []string
}

func (r *j7ServiceTrace) add(event string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}
func (r *j7ServiceTrace) violate(what string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.violations = append(r.violations, what)
}
func (r *j7ServiceTrace) count(event string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e == event {
			n++
		}
	}
	return n
}
func (r *j7ServiceTrace) snapshot() ([]string, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.events...), append([]string{}, r.violations...)
}
func (r *j7ServiceTrace) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events, r.violations = nil, nil
}

type j7ServiceStatus struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *j7ServiceStatus) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *j7ServiceStatus) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// j7ServiceGate is the fixture static gate: it records its input and returns
// a configured verdict. It stands in for the verifier unit, not for a signed
// statement; no test here qualifies the real gate.
type j7ServiceGate struct {
	mu     sync.Mutex
	trace  *j7ServiceTrace
	key    string
	code   Code
	inputs []j7StaticGateInput
}

func (g *j7ServiceGate) verify(_ context.Context, in j7StaticGateInput) (j7StaticGateResult, Code) {
	g.trace.add("gate")
	g.mu.Lock()
	defer g.mu.Unlock()
	g.inputs = append(g.inputs, in)
	return j7StaticGateResult{RequestKey: g.key, check: func(time.Time, staticgate.Class) Code { return "" }}, g.code
}

type j7ServiceFixture struct {
	sf          *j7StateFixture
	uid         uint32
	root        string
	statePath   string
	policyDir   string
	keyFile     string
	socketDir   string
	headFile    string
	cfg         Config
	static      []byte
	deps        j7ServiceDeps
	gen         *fakeGenerations
	gate        *j7ServiceGate
	trace       *j7ServiceTrace
	public      string
	contract    j7Contract
	contractRaw []byte
	unhealthy   bool
}

type j7ServiceOptions struct {
	schema   int
	launcher *Principal
	prepare  func(*testing.T, *j7StateFixture)
}

func j7ServiceHead(t *testing.T, path string, head j7Expectation) {
	t.Helper()
	raw := fmt.Sprintf("{\"expected_version\":%d,\"expected_digest\":\"%s\"}\n", head.Version, head.Digest)
	if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
}

// The fixture is one service account's complete host layout in private
// scratch: schema-5 Store with an active station binding, published policy,
// initialized seed, head file, socket directory and closed role configuration.
// The launcher, input and station accounts exist only as generation rows.
func j7ServiceSetup(t *testing.T, o j7ServiceOptions) *j7ServiceFixture {
	t.Helper()
	sf := j7StateSetup(t)
	root := filepath.Dir(sf.path)
	f := &j7ServiceFixture{sf: sf, uid: sf.uid, root: root, statePath: sf.path, policyDir: filepath.Join(root, "policy"), keyFile: filepath.Join(root, "key", "request.seed"), socketDir: filepath.Join(root, "run"), headFile: filepath.Join(root, "head.json"), trace: &j7ServiceTrace{}}
	instance := strings.Repeat("1", 32)
	for dir, mode := range map[string]os.FileMode{filepath.Dir(f.keyFile): 0700, f.socketDir: 0755} {
		if os.Mkdir(dir, mode) != nil || os.Chmod(dir, mode) != nil {
			t.Fatal("fixture directory")
		}
	}
	if e := InitializeJ7Seed(f.keyFile, f.uid, j7RequestRole, instance); e != nil {
		t.Fatal(e)
	}
	k, e := loadJ7Key(f.keyFile, f.uid, j7RequestRole, instance, sf.binding.Epoch, sf.binding.RegistryRevision)
	if e != nil {
		t.Fatal(e)
	}
	public, e := k.request(sf.store, sf.binding, nil)
	k.close()
	if e != nil {
		t.Fatal(e)
	}
	f.public = hex.EncodeToString(public)
	if o.schema == 0 {
		o.schema = j7SigningSchema
	}
	if o.schema >= j7SigningSchema {
		if c := sf.store.migrateJ7Signing(t.Context(), j7Head(t, sf.store)); c != "" {
			t.Fatal("signing migration", c)
		}
	}
	if o.schema == j7DelegationSchema {
		if c := sf.store.migrateJ7Delegation(t.Context(), j7Head(t, sf.store)); c != "" {
			t.Fatal("delegation migration", c)
		}
	}
	f.contract = j7Contract{Profile: "swarma-trust-contract/1", Network: "regtest", Landlord: "id/test-owner", Agent: "id/test-executor", Grantee: f.public, Actions: []string{"instruct"}, Repos: []string{}, NotBefore: 1, NotAfter: 2000000000}
	f.contractRaw, _ = j7Compact(f.contract)
	table := sf.table(1)
	table.Rows[0].Use = []string{}
	triple := j7ConsentTriple(f.contractRaw)
	triple.AndUse = true
	table.Rows[0].Consent = []j7ConsentPermission{triple}
	sf.publish(t, table)
	if o.prepare != nil {
		o.prepare(t, sf)
	}
	j7ServiceHead(t, f.headFile, j7Head(t, sf.store))
	// The stopped operator is done: release every descriptor and the lock.
	if e := sf.store.Close(); e != nil {
		t.Fatal(e)
	}
	sf.store = nil
	sf.policy.close()
	sf.lock.Close()
	sf.dir.Close()

	launcher := Principal{UID: f.uid + 1, Generation: "launcher-generation"}
	if o.launcher != nil {
		launcher = *o.launcher
	}
	f.gen = newGenerations(f.uid, nativeToken)
	for _, p := range []Principal{launcher, {sf.binding.UID, sf.binding.Generation}, {f.uid + 200, "input-a"}} {
		f.gen.entries[p.UID] = Generation{UID: p.UID, Generation: p.Generation, State: "active", Revision: "fixture", Provenance: "fixture-only", Verified: true}
	}
	raw := fmt.Sprintf(`{"service_role":"j7-request","j7_key_file":%q,"instance_id":%q,"service_uid":%d,"service_gid":%d,"master_epoch":%q,"registry_revision":%q,`+
		`"j7_policy":{"path":%q,"holder_uid":%d,"schema":"keymaker-j7-policy/1","instance":%q,"identity_registration_number":%d,"launcher_principal":{"uid":%d,"generation":%q}},`+
		`"j7_state":{"path":%q,"minimum_reader_schema":5,"head_file":%q},`+
		`"generation_journal":{"path":%q,"initial_floor":{"seq":0,"hash":%q}},`+
		`"socket":{"dir":%q,"group":%d},`+
		`"static_gate":{"approver_key_file":%q,"statement_file":%q,"signature_file":%q,"digest_file":%q}}`,
		f.keyFile, instance, f.uid, os.Getgid(), sf.binding.Epoch, sf.binding.RegistryRevision,
		filepath.Join(f.policyDir, "table.json"), f.uid, instance, sf.binding.Number, launcher.UID, launcher.Generation,
		f.statePath, f.headFile,
		filepath.Join(root, "generations"), gj.ZeroHash,
		f.socketDir, os.Getgid(),
		filepath.Join(root, "gate", "approver.pub"), filepath.Join(root, "gate", "statement.json"), filepath.Join(root, "gate", "statement.sig"), filepath.Join(root, "gate", "statement.sha256"))
	cfg, e := ParseConfig(strings.NewReader(raw))
	if e != nil {
		t.Fatal("fixture configuration", e)
	}
	f.cfg, f.static = cfg, []byte(raw)
	f.gate = &j7ServiceGate{trace: f.trace, key: f.public}
	f.deps.clock = func(*timeconf.Policy) (*timeconf.Provider, error) {
		f.trace.add("clock")
		p, _, collector := fixtureTimeProvider(t, helperNow)
		if f.unhealthy {
			collector.e.Tracking.Leap = "Not synchronised"
		}
		return p, nil
	}
	f.deps.gate = f.gate
	// Scratch below a shared temporary root cannot satisfy the production
	// ancestor walk; that walk keeps its own negative in TestJ7ServiceAncestors.
	f.deps.ancestors = func(string, uint32) error { f.trace.add("ancestors"); return nil }
	// The production head reader needs a root-owned file; the fixture reads a
	// holder-owned one through the same strict decoder.
	f.deps.head = func(path string) (j7Expectation, error) {
		f.trace.add("head")
		b, e := os.ReadFile(path)
		if e != nil {
			return j7Expectation{}, e
		}
		return decodeJ7Head(b)
	}
	f.deps.generation = func(*Store, generationJournalConfig) GenerationSource {
		f.trace.add("generation")
		return f.gen
	}
	// The fixture policy opens the protected directory inode directly with the
	// exact holder/mode/ACL rule and the same pins; it skips only the ancestry.
	f.deps.policy = func(path string, uid uint32, s *Store, instance string, identity uint64) (*j7Policy, error) {
		f.trace.add("policy")
		if s == nil || s.j7 == nil || s.j7.Instance != instance || s.j7.Identity != identity {
			return nil, failure("J7 policy pins unavailable")
		}
		dir, e := OpenDirectory(filepath.Dir(path), uid, 0700)
		if e != nil {
			return nil, e
		}
		if !j7NoACL(int(dir.Fd()), true) {
			dir.Close()
			return nil, failure("unsafe policy ancestry")
		}
		return &j7Policy{dir: dir, name: filepath.Base(path), uid: uid, instance: instance, identity: identity, store: s}, nil
	}
	f.deps.loadKey = func(path string, uid uint32, role, instance, epoch, registry string) (*j7Key, error) {
		f.trace.add("key")
		if dir, e := OpenDirectory(f.statePath, uid, 0700); e == nil {
			if lock, e := LockState(dir, uid); e == nil {
				lock.Close()
				f.trace.violate("key loaded before the state lock")
			}
			dir.Close()
		}
		return loadJ7Key(path, uid, role, instance, epoch, registry)
	}
	f.deps.listen = func(dir *os.File, gid uint32) (*net.UnixListener, uint64, uint64, error) {
		if f.trace.count("key") != 1 {
			f.trace.violate("listener published before the key was loaded")
		}
		listener, inode, device, err := createControlSocket(dir, gid)
		if err == nil {
			f.trace.add("listen")
		}
		return listener, inode, device, err
	}
	return f
}

func (f *j7ServiceFixture) socketPath() string { return filepath.Join(f.socketDir, "control.sock") }

// The retained directory still names the real filesystem socket; the short
// descriptor path avoids Linux sun_path limits for long protected test roots.
func j7ServiceSocketAddress(t *testing.T, f *j7ServiceFixture) string {
	t.Helper()
	dir, err := os.Open(f.socketDir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	return fmt.Sprintf("/proc/self/fd/%d/control.sock", dir.Fd())
}

// Claim: the reader accepts only the operator's exact two-member, ordered,
// canonical integer/lowercase-digest object and one LF. Every lexical refusal
// returns a zero expectation beside the exact accepted export bytes.
func TestJ7ServiceHeadCanonical(t *testing.T) {
	good := []byte("{\"expected_version\":7,\"expected_digest\":\"" + strings.Repeat("a", 64) + "\"}\n")
	bad := map[string][]byte{
		"missing-lf":     bytes.TrimSuffix(good, []byte("\n")),
		"extra-lf":       append(append([]byte{}, good...), '\n'),
		"space":          bytes.Replace(good, []byte(":"), []byte(": "), 1),
		"bom":            append([]byte{0xef, 0xbb, 0xbf}, good...),
		"reordered":      []byte("{\"expected_digest\":\"" + strings.Repeat("a", 64) + "\",\"expected_version\":7}\n"),
		"uppercase":      bytes.Replace(good, []byte(strings.Repeat("a", 64)), []byte(strings.Repeat("A", 64)), 1),
		"duplicate":      bytes.Replace(good, []byte("{\"expected_version\":7"), []byte("{\"expected_version\":7,\"expected_version\":7"), 1),
		"missing":        []byte("{\"expected_version\":7}\n"),
		"extra":          bytes.Replace(good, []byte("}\n"), []byte(",\"extra\":1}\n"), 1),
		"zero":           bytes.Replace(good, []byte(":7,"), []byte(":0,"), 1),
		"fraction":       bytes.Replace(good, []byte(":7,"), []byte(":1.0,"), 1),
		"exponent":       bytes.Replace(good, []byte(":7,"), []byte(":1e0,"), 1),
		"leading-zero":   bytes.Replace(good, []byte(":7,"), []byte(":01,"), 1),
		"unsafe-integer": bytes.Replace(good, []byte(":7,"), []byte(":9007199254740992,"), 1),
		"trailing":       append(append([]byte{}, good...), '{', '}'),
	}
	for name, raw := range bad {
		t.Run(name, func(t *testing.T) {
			if pin, e := decodeJ7Head(raw); e == nil || pin != (j7Expectation{}) {
				t.Fatal("noncanonical head accepted", pin, e)
			}
			if pin, e := decodeJ7Head(good); e != nil || pin.Version != 7 || pin.Digest != strings.Repeat("a", 64) {
				t.Fatal("canonical head refused", pin, e)
			}
		})
	}
}

type j7ServiceRun struct {
	cancel context.CancelFunc
	done   chan error
	status *j7ServiceStatus
}

const j7ServiceReadyPrefix = "j7-request control ready; memory_locked="

// start runs the service until its readiness line; entry selects the full
// entry or the post-cross-field entry used by the single-UID launcher fixture.
func (f *j7ServiceFixture) start(t *testing.T, entry func(context.Context, Config, []byte, *j7ServiceStatus, j7ServiceDeps) error) *j7ServiceRun {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &j7ServiceRun{cancel: cancel, done: make(chan error, 1), status: &j7ServiceStatus{}}
	go func() { r.done <- entry(ctx, f.cfg, f.static, r.status, f.deps) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
		}
	})
	until := time.Now().Add(10 * time.Second)
	for time.Now().Before(until) {
		if strings.HasSuffix(r.status.String(), "\n") {
			return r
		}
		select {
		case e := <-r.done:
			r.done <- e
			_, violations := f.trace.snapshot()
			t.Fatalf("service did not become ready: %v violations=%v", e, violations)
		case <-time.After(2 * time.Millisecond):
		}
	}
	t.Fatal("service readiness timeout")
	return nil
}
func (r *j7ServiceRun) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	select {
	case e := <-r.done:
		r.done <- e
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("service did not stop")
		return nil
	}
}

func j7ServiceFull(ctx context.Context, cfg Config, static []byte, status *j7ServiceStatus, d j7ServiceDeps) error {
	return serveJ7Request(ctx, cfg, static, status, d)
}
func j7ServiceInner(ctx context.Context, cfg Config, static []byte, status *j7ServiceStatus, d j7ServiceDeps) error {
	return startJ7Request(ctx, cfg, static, status, d)
}

// serves is the positive control: the complete fixture loads the key exactly
// once, then publishes control.sock 0660 with the exact owner and group, then
// prints exactly one readiness line; cancellation unlinks the socket.
func (f *j7ServiceFixture) serves(t *testing.T) {
	t.Helper()
	f.trace.reset()
	r := f.start(t, j7ServiceFull)
	st, e := os.Lstat(f.socketPath())
	if e != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0660 || st.Sys().(*syscall.Stat_t).Uid != f.uid || st.Sys().(*syscall.Stat_t).Gid != f.cfg.J7Socket.Group {
		t.Fatal("control socket not published 0660 with the exact owner and group", e)
	}
	events, violations := f.trace.snapshot()
	if len(violations) != 0 || f.trace.count("key") != 1 || f.trace.count("listen") != 1 {
		t.Fatal("positive control order", events, violations)
	}
	if e := r.stop(t); e != nil {
		t.Fatal("positive control stop", e)
	}
	status := r.status.String()
	if strings.Count(status, "\n") != 1 || !strings.HasPrefix(status, j7ServiceReadyPrefix) {
		t.Fatalf("positive control readiness %q", status)
	}
	if _, e := os.Lstat(f.socketPath()); !os.IsNotExist(e) {
		t.Fatal("own socket survived shutdown")
	}
}

type j7ServiceRefusal struct {
	// keyGate permits the loader seam: the refusal is the key step itself.
	keyGate bool
	// incident permits the one audited generation-fence incident record.
	incident bool
	// seams lists seams that must not have run at all.
	absent []string
}

// refuses asserts the exact refusal and the absence of effects: no readiness
// line, no socket-directory change, no listener seam, an unchanged state tree
// (snapshot, audit journal, anchors) and head file, and no key-loader call.
func (f *j7ServiceFixture) refuses(t *testing.T, want string, o j7ServiceRefusal) {
	t.Helper()
	f.trace.reset()
	state := map[string]string{}
	if _, e := os.Stat(f.statePath); e == nil {
		state = recoveryFiles(t, f.statePath)
	}
	sockets := j7ServiceListing(t, f.socketDir)
	head, _ := os.ReadFile(f.headFile)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	status := &j7ServiceStatus{}
	e := serveJ7Request(ctx, f.cfg, f.static, status, f.deps)
	if e == nil || e.Error() != want {
		t.Fatalf("refusal %v, want %s", e, want)
	}
	events, violations := f.trace.snapshot()
	if status.String() != "" {
		t.Fatalf("refusal printed a readiness line %q", status.String())
	}
	if f.trace.count("listen") != 0 || !reflect.DeepEqual(sockets, j7ServiceListing(t, f.socketDir)) {
		t.Fatal("refusal reached the listener or changed the socket directory", events)
	}
	if !o.keyGate && f.trace.count("key") != 0 {
		t.Fatal("refusal called the key loader", events)
	}
	if len(violations) != 0 {
		t.Fatal("refusal order", violations)
	}
	for _, seam := range o.absent {
		if f.trace.count(seam) != 0 {
			t.Fatal("refusal reached a later step", seam, events)
		}
	}
	if _, e := os.Stat(f.statePath); e == nil {
		after := recoveryFiles(t, f.statePath)
		if !o.incident && !reflect.DeepEqual(state, after) {
			t.Fatal("refusal changed state or appended audit")
		}
		if o.incident {
			if len(state) != len(after) {
				t.Fatal("fence created or removed state files")
			}
			changed := 0
			for path, old := range state {
				now, ok := after[path]
				if !ok {
					t.Fatal("fence removed state evidence")
				}
				if now == old {
					continue
				}
				delta := strings.TrimPrefix(now, old)
				if !strings.Contains(path, "/audit/") || !strings.HasPrefix(now, old) || strings.Count(delta, "\n") != 1 || strings.Count(delta, `"operation":"generation_fence"`) != 1 || !strings.Contains(delta, `"refusal_code":"generation_source_fenced"`) {
					t.Fatal("fence changed more than its one incident", path)
				}
				changed++
			}
			if changed != 1 {
				t.Fatal("missing or repeated fence incident", changed)
			}
		}
	}
	if now, _ := os.ReadFile(f.headFile); !bytes.Equal(head, now) {
		t.Fatal("refusal changed the head file")
	}
}

func j7ServiceListing(t *testing.T, dir string) []string {
	t.Helper()
	entries, e := os.ReadDir(dir)
	if e != nil {
		return []string{"unreadable"}
	}
	out := []string{}
	for _, entry := range entries {
		info, e := entry.Info()
		if e != nil {
			t.Fatal(e)
		}
		out = append(out, fmt.Sprintf("%s %s %d", entry.Name(), info.Mode(), info.Sys().(*syscall.Stat_t).Ino))
	}
	return out
}

type j7ServiceCase struct {
	name    string
	want    string
	refusal j7ServiceRefusal
	// damage breaks exactly one precondition and returns its repair.
	damage func(*testing.T, *j7ServiceFixture) func()
}

// Each case first proves the refusal and its absent effects, then repairs the
// one damaged precondition and proves the same fixture serves.
func j7ServiceCases(t *testing.T, cases []j7ServiceCase) {
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := j7ServiceSetup(t, j7ServiceOptions{})
			repair := c.damage(t, f)
			f.refuses(t, c.want, c.refusal)
			repair()
			f.serves(t)
		})
	}
}

func j7ServiceChmod(path string, damaged, repaired os.FileMode) func(*testing.T, *j7ServiceFixture) func() {
	return func(t *testing.T, f *j7ServiceFixture) func() {
		target := strings.NewReplacer("{state}", f.statePath, "{policy}", f.policyDir, "{key}", filepath.Dir(f.keyFile), "{seed}", f.keyFile, "{run}", f.socketDir, "{table}", filepath.Join(f.policyDir, "table.json"), "{root}", f.root).Replace(path)
		if e := os.Chmod(target, damaged); e != nil {
			t.Fatal(e)
		}
		return func() {
			if e := os.Chmod(target, repaired); e != nil {
				t.Fatal(e)
			}
		}
	}
}

// Claim: the delegation role refuses operation_unsupported and unknown or null
// roles refuse at parse, all before any path access; the request role instead
// proceeds to its next gate (trusted time, then the required static gate).
func TestJ7ServiceRoleDispatch(t *testing.T) {
	d := t.TempDir()
	delegation := strings.Replace(j7Config(j7DelegationRole), "/fixture/root", filepath.Join(d, "absent", "root"), 1)
	cfg, e := ParseConfig(strings.NewReader(delegation))
	if e != nil {
		t.Fatal(e)
	}
	var status bytes.Buffer
	if e := serveValidatedConfig(context.Background(), cfg, &status, nil); e != Code("operation_unsupported") {
		t.Fatal("delegation role", e)
	}
	trace := &j7ServiceTrace{}
	deps := productionJ7ServiceDeps()
	deps.clock = func(*timeconf.Policy) (*timeconf.Provider, error) {
		trace.add("clock")
		return nil, timeconf.ErrUnavailable
	}
	if e := serveJ7Request(context.Background(), cfg, []byte(delegation), &status, deps); e != Code("operation_unsupported") || trace.count("clock") != 0 {
		t.Fatal("delegation role reached the request service", e)
	}
	for _, bad := range []string{strings.Replace(delegation, `"delegation"`, `"unknown"`, 1), strings.Replace(delegation, `"delegation"`, `null`, 1), strings.Replace(delegation, `"delegation"`, `""`, 1)} {
		if _, e := ParseConfig(strings.NewReader(bad)); e == nil || e.Error() != "keymaker: invalid configuration" {
			t.Fatal("unknown or null role", e)
		}
	}
	if entries, e := os.ReadDir(d); e != nil || len(entries) != 0 || status.Len() != 0 {
		t.Fatal("refused role touched paths or printed readiness")
	}
	// Positive control: the complete request role passes role dispatch and its
	// cross-field and identity steps; production then stops at untrusted time,
	// and with trusted time at the required static gate.
	f := j7ServiceSetup(t, j7ServiceOptions{})
	if e := serveValidatedConfig(context.Background(), f.cfg, &status, nil); e != Code("clock_untrusted") || status.Len() != 0 {
		t.Fatal("request role next gate", e)
	}
	f.deps.gate = nil
	f.refuses(t, "static_gate_unavailable", j7ServiceRefusal{absent: []string{"gate", "ancestors", "head"}})
	if f.trace.count("clock") != 1 {
		t.Fatal("request role did not reach trusted time")
	}
	f.deps.gate = f.gate
	f.serves(t)
}

// Claim: the request role's new members are closed (unknown, missing, null,
// relative, duplicate or mistyped values refuse), inline head pins are refused
// for the request role, and neither the delegation role nor the legacy schema
// accepts the new members; the complete role configuration parses.
func TestJ7ServiceConfigMembers(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	good := string(f.static)
	example, e := os.ReadFile("../../packaging/config.example.json")
	if e != nil {
		t.Fatal(e)
	}
	_, policy, ok := strings.Cut(string(example), `"time_policy": `)
	if !ok {
		t.Fatal("example time policy")
	}
	policy = strings.TrimSuffix(strings.TrimSpace(policy), "}")
	withTime := strings.TrimSuffix(good, "}") + `,"time_policy":` + policy + `}`
	replace := func(old, new string) string {
		if strings.Count(good, old) != 1 {
			t.Fatal("fixture member not unique", old)
		}
		return strings.Replace(good, old, new, 1)
	}
	gid := fmt.Sprint(os.Getgid())
	bad := map[string]string{
		"socket-unknown-member":      replace(`"group":`+gid+`}`, `"group":`+gid+`,"mode":432}`),
		"socket-missing-group":       replace(`,"group":`+gid+`}`, `}`),
		"socket-relative-dir":        replace(`"socket":{"dir":"`, `"socket":{"dir":"relative`),
		"socket-null":                strings.Replace(good, `"socket":{`, `"socket":null,"x":{`, 1),
		"socket-group-string":        replace(`"group":`+gid+`}`, `"group":"`+gid+`"}`),
		"socket-group-negative":      replace(`"group":`+gid+`}`, `"group":-1}`),
		"gate-missing-digest":        replace(`,"digest_file":"`+filepath.Join(f.root, "gate", "statement.sha256")+`"`, ``),
		"gate-unknown-member":        replace(`"static_gate":{`, `"static_gate":{"binary_sha256":"00",`),
		"gate-relative":              replace(`"statement_file":"`, `"statement_file":"x`),
		"gate-duplicate-file":        replace(filepath.Join(f.root, "gate", "statement.sig"), filepath.Join(f.root, "gate", "statement.json")),
		"gate-null":                  replace(`"static_gate":{`, `"static_gate":null,"y":{`),
		"state-inline-version":       replace(`"head_file":"`+f.headFile+`"`, `"expected_version":1,"expected_digest":"`+strings.Repeat("a", 64)+`"`),
		"state-inline-beside-head":   replace(`"head_file":"`, `"expected_version":1,"head_file":"`),
		"state-missing-head":         replace(`,"head_file":"`+f.headFile+`"`, ``),
		"state-relative-head":        replace(`"head_file":"`, `"head_file":"x`),
		"state-floor-6":              replace(`"minimum_reader_schema":5`, `"minimum_reader_schema":6`),
		"journal-unknown-member":     replace(`"initial_floor":{"seq":0,`, `"initial_floor":{"seq":0,"extra":1,`),
		"journal-relative":           replace(`"generation_journal":{"path":"`, `"generation_journal":{"path":"x`),
		"journal-bad-floor":          replace(`"seq":0,`, `"seq":-1,`),
		"time-low-backward":          strings.Replace(withTime, `"backward_tolerance_ns": 1000000000`, `"backward_tolerance_ns": 999999999`, 1),
		"time-null":                  strings.TrimSuffix(good, "}") + `,"time_policy":null}`,
		"legacy-member-in-role":      replace(`"socket":{`, `"socket_dir":"/fixture/run","socket":{`),
		"node-member":                replace(`"socket":{`, `"node":{"rpc":"/fixture"},"socket":{`),
		"delegation-with-socket":     replace(`"service_role":"j7-request"`, `"service_role":"delegation"`),
		"legacy-with-static-gate":    strings.Replace(string(example), `"socket_dir"`, `"static_gate":{"approver_key_file":"/a","statement_file":"/b","signature_file":"/c","digest_file":"/d"},"socket_dir"`, 1),
		"legacy-with-role-socket":    strings.Replace(string(example), `"socket_dir"`, `"socket":{"dir":"/a","group":1},"socket_dir"`, 1),
		"delegation-with-head-file":  strings.TrimSuffix(j7Config(j7DelegationRole), "}") + `,"j7_state":{"path":"/protected/state","minimum_reader_schema":5,"head_file":"/protected/head.json"}}`,
		"delegation-with-time":       strings.TrimSuffix(j7Config(j7DelegationRole), "}") + `,"time_policy":` + policy + `}`,
		"request-duplicate-socket":   strings.TrimSuffix(good, "}") + `,"socket":{"dir":"/a","group":1}}`,
		"request-trailing-data":      good + `{}`,
		"gate-file-is-root":          replace(`"approver_key_file":"`+filepath.Join(f.root, "gate", "approver.pub")+`"`, `"approver_key_file":"/"`),
		"socket-dir-unclean":         replace(`"socket":{"dir":"`+f.socketDir+`"`, `"socket":{"dir":"`+f.socketDir+`/../run"`),
		"state-head-number":          replace(`"head_file":"`+f.headFile+`"`, `"head_file":7`),
		"journal-missing-floor":      replace(`,"initial_floor":{"seq":0,"hash":"`+gj.ZeroHash+`"}`, ``),
		"gate-string-not-object":     strings.Replace(good, `"static_gate":{`, `"static_gate":"x","z":{`, 1),
		"policy-holder-not-service":  replace(`"holder_uid":`+fmt.Sprint(f.uid), `"holder_uid":`+fmt.Sprint(f.uid+7)),
		"request-inline-digest-only": replace(`"head_file":"`+f.headFile+`"`, `"head_file":"`+f.headFile+`","expected_digest":"`+strings.Repeat("a", 64)+`"`),
	}
	for name, raw := range bad {
		t.Run(name, func(t *testing.T) {
			if raw == good {
				t.Fatal("damage not applied")
			}
			if _, e := ParseConfig(strings.NewReader(raw)); e == nil {
				t.Fatal("closed configuration admitted the damaged member")
			}
		})
	}
	// Positive controls: the complete role parses with and without the inline
	// time policy; the frozen delegation shape and the legacy example still do.
	for name, raw := range map[string]string{"request": good, "request-with-time": withTime, "legacy-example": string(example), "delegation-inline-pins": strings.TrimSuffix(j7Config(j7DelegationRole), "}") + `,"j7_state":{"path":"/protected/state","minimum_reader_schema":5,"expected_version":1,"expected_digest":"` + strings.Repeat("a", 64) + `"}}`} {
		cfg, e := ParseConfig(strings.NewReader(raw))
		if e != nil {
			t.Fatal("valid configuration refused", name, e)
		}
		if name == "request-with-time" && (cfg.TimePolicy == nil || cfg.J7Socket == nil || cfg.StaticGate == nil || cfg.GenerationJournal == nil || cfg.J7State.HeadFile != f.headFile) {
			t.Fatal("request members not decoded")
		}
	}
}

// Claim: a configuration file below a parent that is not root-owned refuses
// "unsafe configuration parent" with no effects; the same bytes, parsed and
// handed to the service entry, serve. The root-owned positive is PENDING on a
// privileged multi-UID window; it is not exercised here.
func TestJ7ServiceProtectedConfigStartup(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	path := filepath.Join(f.root, "config.json")
	if e := os.WriteFile(path, f.static, 0600); e != nil {
		t.Fatal(e)
	}
	state := recoveryFiles(t, f.statePath)
	var status bytes.Buffer
	if e := serveConfigured(context.Background(), path, &status, nil); e == nil || e.Error() != "keymaker: unsafe configuration parent" {
		t.Fatal("foreign-owned configuration parent", e)
	}
	if status.Len() != 0 || len(j7ServiceListing(t, f.socketDir)) != 0 || !reflect.DeepEqual(state, recoveryFiles(t, f.statePath)) {
		t.Fatal("refused configuration had effects")
	}
	cfg, e := ParseConfig(bytes.NewReader(f.static))
	if e != nil || !reflect.DeepEqual(cfg, f.cfg) {
		t.Fatal("same bytes parse to the served configuration", e)
	}
	f.serves(t)
}

// Claim: a missing required stanza, a reader floor other than 5, a launcher
// UID equal to the service UID and overlapping or service-writable locations
// each refuse by name before the clock, the gate or any path is touched.
func TestJ7ServiceCrossFieldStartup(t *testing.T) {
	early := j7ServiceRefusal{absent: []string{"clock", "gate", "ancestors", "head", "generation", "policy"}}
	member := func(want string, damage func(*Config)) j7ServiceCase {
		return j7ServiceCase{want: want, refusal: early, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			saved := f.cfg
			policy, state, socket, gate := *f.cfg.J7Policy, *f.cfg.J7State, *f.cfg.J7Socket, *f.cfg.StaticGate
			f.cfg.J7Policy, f.cfg.J7State, f.cfg.J7Socket, f.cfg.StaticGate = &policy, &state, &socket, &gate
			damage(&f.cfg)
			return func() { f.cfg = saved }
		}}
	}
	cases := map[string]j7ServiceCase{
		"socket-group-unavailable": member("j7_socket_group_unavailable", func(c *Config) {
			for gid := uint32(100000); ; gid++ {
				if !j7SocketGroupAvailable(gid) {
					c.J7Socket.Group = gid
					break
				}
			}
		}),
		"missing-policy":        member("j7_configuration_incomplete", func(c *Config) { c.J7Policy = nil }),
		"missing-state":         member("j7_configuration_incomplete", func(c *Config) { c.J7State = nil }),
		"missing-head-file":     member("j7_configuration_incomplete", func(c *Config) { c.J7State.HeadFile = "" }),
		"missing-socket":        member("j7_configuration_incomplete", func(c *Config) { c.J7Socket = nil }),
		"missing-static-gate":   member("j7_configuration_incomplete", func(c *Config) { c.StaticGate = nil }),
		"missing-generation":    member("generation_source_unavailable", func(c *Config) { c.GenerationJournal = nil }),
		"reader-floor-4":        member("j7_signing_floor_required", func(c *Config) { c.J7State.Minimum = 4 }),
		"launcher-is-service":   member("j7_configuration_conflict", func(c *Config) { c.J7Policy.Launcher.UID = c.ServiceUID }),
		"state-equals-key-dir":  member("j7_configuration_conflict", func(c *Config) { c.J7State.Path = filepath.Dir(c.J7KeyFile) }),
		"socket-inside-state":   member("j7_configuration_conflict", func(c *Config) { c.J7Socket.Dir = filepath.Join(c.J7State.Path, "run") }),
		"policy-above-socket":   member("j7_configuration_conflict", func(c *Config) { c.J7Policy.Path = filepath.Join(filepath.Dir(c.J7Socket.Dir), "table.json") }),
		"key-inside-policy":     member("j7_configuration_conflict", func(c *Config) { c.J7KeyFile = filepath.Join(filepath.Dir(c.J7Policy.Path), "seed", "request.seed") }),
		"head-inside-state":     member("j7_configuration_conflict", func(c *Config) { c.J7State.HeadFile = filepath.Join(c.J7State.Path, "head.json") }),
		"gate-file-inside-key":  member("j7_configuration_conflict", func(c *Config) { c.StaticGate.StatementFile = filepath.Join(filepath.Dir(c.J7KeyFile), "g.json") }),
		"gate-file-inside-sock": member("j7_configuration_conflict", func(c *Config) { c.StaticGate.DigestFile = filepath.Join(c.J7Socket.Dir, "digest") }),
	}
	var list []j7ServiceCase
	for name, c := range cases {
		c.name = name
		list = append(list, c)
	}
	j7ServiceCases(t, list)
}

// Claim: the deliberately incomplete historical role fixture refuses with the
// named cross-field code through the validated-config entry, and the direct
// legacy clock entry stays closed for every non-legacy role.
func TestJ7ServiceIncompleteStartup(t *testing.T) {
	cfg, e := ParseConfig(strings.NewReader(j7Config(j7RequestRole)))
	if e != nil {
		t.Fatal(e)
	}
	var status bytes.Buffer
	if e := serveValidatedConfig(context.Background(), cfg, &status, nil); e != Code("j7_configuration_incomplete") || status.Len() != 0 {
		t.Fatal("incomplete request role", e)
	}
	f := j7ServiceSetup(t, j7ServiceOptions{})
	// Positive control beside both negatives: the complete fixture serves.
	if e := serveWithClock(context.Background(), f.cfg, &status, nil, nil); e != Code("operation_unsupported") || status.Len() != 0 {
		t.Fatal("legacy clock entry admitted the request role", e)
	}
	f.serves(t)
}

// Claim: missing or untrusted time refuses clock_untrusted before the static
// gate and before any path; the gate never sees a host-clock value. With
// trusted time the gate runs once with the trusted sample and the digest of
// the static bytes, and a missing, failing or keyless gate refuses by name.
func TestJ7ServiceTrustedTimeBeforeGateStartup(t *testing.T) {
	early := j7ServiceRefusal{absent: []string{"gate", "ancestors", "head", "generation", "policy"}}
	late := j7ServiceRefusal{absent: []string{"ancestors", "head", "generation", "policy"}}
	j7ServiceCases(t, []j7ServiceCase{
		{name: "unhealthy-clock", want: "clock_untrusted", refusal: early, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			f.unhealthy = true
			return func() { f.unhealthy = false }
		}},
		{name: "missing-time-policy", want: "clock_untrusted", refusal: early, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			saved := f.deps.clock
			f.deps.clock = productionJ7ServiceDeps().clock
			return func() { f.deps.clock = saved }
		}},
		{name: "no-clock-source", want: "clock_untrusted", refusal: early, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			saved := f.deps.clock
			f.deps.clock = nil
			return func() { f.deps.clock = saved }
		}},
		{name: "gate-not-wired", want: "static_gate_unavailable", refusal: early, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			f.deps.gate = nil
			return func() { f.deps.gate = f.gate }
		}},
		{name: "no-static-bytes", want: "static_gate_unavailable", refusal: early, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			saved := f.static
			f.static = nil
			return func() { f.static = saved }
		}},
		{name: "gate-refuses", want: "STATIC_GATE_FIXTURE_REFUSAL", refusal: late, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			f.gate.code = "STATIC_GATE_FIXTURE_REFUSAL"
			return func() { f.gate.code = "" }
		}},
		{name: "gate-without-key", want: "static_gate_unavailable", refusal: late, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			f.gate.key = ""
			return func() { f.gate.key = f.public }
		}},
	})
	f := j7ServiceSetup(t, j7ServiceOptions{})
	f.serves(t)
	events, _ := f.trace.snapshot()
	if len(events) < 2 || events[0] != "clock" || events[1] != "gate" || f.trace.count("gate") != 1 {
		t.Fatal("trusted time must precede the single gate call", events)
	}
	in := f.gate.inputs[len(f.gate.inputs)-1]
	sum := j7Hash(f.static)
	if !in.Now.Equal(helperNow) || in.Lower.After(in.Now) || in.Upper.Before(in.Now) || in.ConfigSHA256 != sum || in.ServiceUID != f.uid || in.Files != *f.cfg.StaticGate {
		t.Fatal("gate input is not the trusted sample and static digest", in)
	}
}

// Claim: the production ancestor walk refuses a group-writable ancestor of a
// service directory before any state is opened; with the walk satisfied the
// same fixture serves.
func TestJ7ServiceAncestorsStartup(t *testing.T) {
	j7ServiceCases(t, []j7ServiceCase{{name: "group-writable-root", want: "keymaker: unsafe configured ancestor", refusal: j7ServiceRefusal{absent: []string{"head", "generation", "policy"}}, damage: func(t *testing.T, f *j7ServiceFixture) func() {
		saved := f.deps.ancestors
		f.deps.ancestors = safeAncestors
		if e := os.Chmod(f.root, 0770); e != nil {
			t.Fatal(e)
		}
		return func() {
			f.deps.ancestors = saved
			if e := os.Chmod(f.root, 0700); e != nil {
				t.Fatal(e)
			}
		}
	}}})
}

// Claim: an unsafe state directory, a pending binding intent, a second
// instance, a missing, malformed, unprotected or mismatched head pin each
// refuse before the generation source, policy, key or listener are touched.
func TestJ7ServiceStateGateStartup(t *testing.T) {
	gate := j7ServiceRefusal{absent: []string{"generation", "policy"}}
	head := func(raw func(*j7ServiceFixture, []byte) []byte) func(*testing.T, *j7ServiceFixture) func() {
		return func(t *testing.T, f *j7ServiceFixture) func() {
			saved, e := os.ReadFile(f.headFile)
			if e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(f.headFile, raw(f, append([]byte(nil), saved...)), 0600); e != nil {
				t.Fatal(e)
			}
			return func() {
				if e := os.WriteFile(f.headFile, saved, 0600); e != nil {
					t.Fatal(e)
				}
			}
		}
	}
	j7ServiceCases(t, []j7ServiceCase{
		{name: "state-mode-0750", want: "keymaker: unsafe directory ownership or mode", refusal: gate, damage: j7ServiceChmod("{state}", 0750, 0700)},
		{name: "state-missing", want: "keymaker: unsafe directory", refusal: gate, damage: func(t *testing.T, f *j7ServiceFixture) func() {
			moved := f.statePath + ".moved"
			if e := os.Rename(f.statePath, moved); e != nil {
				t.Fatal(e)
			}
			return func() {
				if e := os.Rename(moved, f.statePath); e != nil {
					t.Fatal(e)
				}
			}
		}},
		{name: "pending-binding-intent", want: "keymaker: unresolved binding intent", refusal: gate, damage: func(t *testing.T, f *j7ServiceFixture) func() {
			next := filepath.Join(f.statePath, "bindings.next")
			if e := os.WriteFile(next, []byte("{}"), 0600); e != nil {
				t.Fatal(e)
			}
			return func() {
				if e := os.Remove(next); e != nil {
					t.Fatal(e)
				}
			}
		}},
		{name: "second-instance", want: "keymaker: state already locked", refusal: gate, damage: func(t *testing.T, f *j7ServiceFixture) func() {
			dir, e := OpenDirectory(f.statePath, f.uid, 0700)
			if e != nil {
				t.Fatal(e)
			}
			lock, e := LockState(dir, f.uid)
			if e != nil {
				t.Fatal(e)
			}
			return func() { lock.Close(); dir.Close() }
		}},
		{name: "head-version-ahead", want: "keymaker: J7 expected head mismatch", refusal: gate, damage: head(func(f *j7ServiceFixture, saved []byte) []byte {
			pin, _ := decodeJ7Head(saved)
			return []byte(fmt.Sprintf("{\"expected_version\":%d,\"expected_digest\":\"%s\"}\n", pin.Version+1, pin.Digest))
		})},
		{name: "head-digest-differs", want: "keymaker: J7 expected head mismatch", refusal: gate, damage: head(func(f *j7ServiceFixture, saved []byte) []byte {
			pin, _ := decodeJ7Head(saved)
			return []byte(fmt.Sprintf("{\"expected_version\":%d,\"expected_digest\":\"%s\"}\n", pin.Version, strings.Repeat("a", 64)))
		})},
		{name: "head-empty", want: "j7_head_pin_unavailable", refusal: gate, damage: head(func(*j7ServiceFixture, []byte) []byte { return nil })},
		{name: "head-zero-version", want: "j7_head_pin_unavailable", refusal: gate, damage: head(func(*j7ServiceFixture, []byte) []byte {
			return []byte(`{"expected_version":0,"expected_digest":"` + strings.Repeat("a", 64) + `"}`)
		})},
		{name: "head-extra-member", want: "j7_head_pin_unavailable", refusal: gate, damage: head(func(_ *j7ServiceFixture, saved []byte) []byte {
			return append(bytes.TrimSuffix(saved, []byte("}\n")), []byte(",\"reset\":true}\n")...)
		})},
		{name: "head-missing", want: "j7_head_pin_unavailable", refusal: gate, damage: func(t *testing.T, f *j7ServiceFixture) func() {
			moved := f.headFile + ".moved"
			state := f.cfg.J7State.Path
			f.cfg.J7State.Path = filepath.Join(f.root, "absent-state")
			if e := os.Rename(f.headFile, moved); e != nil {
				t.Fatal(e)
			}
			return func() {
				if e := os.Rename(moved, f.headFile); e != nil {
					t.Fatal(e)
				}
				f.cfg.J7State.Path = state
			}
		}},
		// The production reader accepts only a root-owned head below root-owned
		// ancestors: the holder-owned scratch file refuses. Its root-owned
		// positive is PENDING with the root-owned configuration.
		{name: "head-not-root-owned", want: "j7_head_pin_unavailable", refusal: gate, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			saved := f.deps.head
			f.deps.head = protectedJ7Head
			return func() { f.deps.head = saved }
		}},
	})
}

// Claim: reader floor 5 opens only a schema-5 Store: a schema-4 or schema-6
// Store refuses "message schema floor mismatch" with no effects, beside the
// schema-5 fixture that serves. Startup never migrates.
func TestJ7ServiceSchemaFloorStartup(t *testing.T) {
	for _, schema := range []int{j7Schema, j7DelegationSchema} {
		t.Run(fmt.Sprint("schema-", schema), func(t *testing.T) {
			f := j7ServiceSetup(t, j7ServiceOptions{schema: schema})
			f.refuses(t, "keymaker: message schema floor mismatch", j7ServiceRefusal{absent: []string{"generation", "policy"}})
		})
	}
	j7ServiceSetup(t, j7ServiceOptions{}).serves(t)
}

// Claim: a Store whose instance, identity, epoch or registry pins differ from
// the configuration, or whose station binding is not active, refuses before
// the generation source, policy and key; the matching active binding serves.
func TestJ7ServiceIdentityGateStartup(t *testing.T) {
	gate := j7ServiceRefusal{absent: []string{"generation", "policy"}}
	member := func(want string, damage func(*Config)) j7ServiceCase {
		return j7ServiceCase{want: want, refusal: gate, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			saved := f.cfg
			policy := *f.cfg.J7Policy
			f.cfg.J7Policy = &policy
			damage(&f.cfg)
			return func() { f.cfg = saved }
		}}
	}
	cases := map[string]j7ServiceCase{
		"identity-not-in-store": member("j7_state_identity_mismatch", func(c *Config) { c.J7Policy.Identity++ }),
		"instance-differs": member("j7_state_identity_mismatch", func(c *Config) {
			c.InstanceID = strings.Repeat("2", 32)
			c.J7Policy.Instance = c.InstanceID
		}),
		"epoch-differs":    member("j7_state_identity_mismatch", func(c *Config) { c.Epoch = "other-epoch" }),
		"registry-differs": member("j7_state_identity_mismatch", func(c *Config) { c.RegistryRevision = "other-revision" }),
	}
	var list []j7ServiceCase
	for name, c := range cases {
		c.name = name
		list = append(list, c)
	}
	j7ServiceCases(t, list)
	t.Run("binding-not-active", func(t *testing.T) {
		f := j7ServiceSetup(t, j7ServiceOptions{prepare: func(t *testing.T, sf *j7StateFixture) {
			sf.store.mu.Lock()
			defer sf.store.mu.Unlock()
			for i := range sf.store.records {
				sf.store.records[i].Status = "revoked"
			}
			if c := sf.store.commitJ7(t.Context()); c != "" {
				t.Fatal("fixture revocation", c)
			}
		}})
		f.refuses(t, "binding_not_found", gate)
	})
}

// Claim: an unavailable generation source, an inactive or replaced launcher
// and an inactive station each refuse before the policy, key and listener; a
// fenced journal source refuses generation_source_fenced. Active rows serve.
func TestJ7ServiceGenerationGateStartup(t *testing.T) {
	gate := j7ServiceRefusal{absent: []string{"policy"}}
	row := func(want string, damage func(f *j7ServiceFixture)) j7ServiceCase {
		return j7ServiceCase{want: want, refusal: gate, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			f.gen.mu.Lock()
			saved := map[uint32]Generation{}
			for uid, g := range f.gen.entries {
				saved[uid] = g
			}
			f.gen.mu.Unlock()
			damage(f)
			return func() {
				f.gen.mu.Lock()
				f.gen.entries, f.gen.unavailable = saved, false
				f.gen.mu.Unlock()
			}
		}}
	}
	cases := map[string]j7ServiceCase{
		"source-unavailable": row("generation_source_unavailable", func(f *j7ServiceFixture) {
			f.gen.mu.Lock()
			f.gen.unavailable = true
			f.gen.mu.Unlock()
		}),
		"launcher-inactive": row("generation_inactive", func(f *j7ServiceFixture) {
			f.gen.set(f.cfg.J7Policy.Launcher.UID, "retiring", f.cfg.J7Policy.Launcher.Generation)
		}),
		"launcher-replaced": row("generation_mismatch", func(f *j7ServiceFixture) { f.gen.set(f.cfg.J7Policy.Launcher.UID, "active", "next-launcher") }),
		"launcher-unknown": row("generation_source_unavailable", func(f *j7ServiceFixture) {
			f.gen.mu.Lock()
			delete(f.gen.entries, f.cfg.J7Policy.Launcher.UID)
			f.gen.mu.Unlock()
		}),
		"station-inactive": row("generation_inactive", func(f *j7ServiceFixture) { f.gen.set(f.sf.binding.UID, "removed", f.sf.binding.Generation) }),
		"no-source": {want: "generation_source_unavailable", refusal: gate, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			saved := f.deps.generation
			f.deps.generation = func(*Store, generationJournalConfig) GenerationSource { return nil }
			return func() { f.deps.generation = saved }
		}},
	}
	var list []j7ServiceCase
	for name, c := range cases {
		c.name = name
		list = append(list, c)
	}
	j7ServiceCases(t, list)
	// The production journal source finds a Store with records and no carried
	// anchor: it fences and appends its one incident record, which is the only
	// permitted effect. No key, listener or readiness follows. The fence is
	// durable by design, so this case has its control in the cases above.
	t.Run("anchor-missing-with-records", func(t *testing.T) {
		f := j7ServiceSetup(t, j7ServiceOptions{})
		f.deps.generation = productionJ7ServiceDeps().generation
		f.refuses(t, "generation_source_fenced", j7ServiceRefusal{absent: []string{"policy"}, incident: true})
	})
}

// Claim: an unsafe policy directory and a missing or unprotected policy table
// refuse readiness before the key is loaded; the protected table serves, and
// an existing table is not required to carry rows.
func TestJ7ServicePolicyGateStartup(t *testing.T) {
	j7ServiceCases(t, []j7ServiceCase{
		{name: "policy-dir-group-writable", want: "keymaker: unsafe directory ownership or mode", damage: j7ServiceChmod("{policy}", 0770, 0700)},
		{name: "policy-table-group-readable", want: "j7_policy_unavailable", damage: j7ServiceChmod("{table}", 0640, 0600)},
		{name: "policy-table-missing", want: "j7_policy_unavailable", damage: func(t *testing.T, f *j7ServiceFixture) func() {
			table := filepath.Join(f.policyDir, "table.json")
			moved := filepath.Join(f.root, "table.moved")
			if e := os.Rename(table, moved); e != nil {
				t.Fatal(e)
			}
			return func() {
				if e := os.Rename(moved, table); e != nil {
					t.Fatal(e)
				}
			}
		}},
		{name: "policy-table-symlink", want: "j7_policy_unavailable", damage: func(t *testing.T, f *j7ServiceFixture) func() {
			table := filepath.Join(f.policyDir, "table.json")
			moved := filepath.Join(f.root, "table.moved")
			if os.Rename(table, moved) != nil || os.Symlink(moved, table) != nil {
				t.Fatal("fixture symlink")
			}
			return func() {
				if os.Remove(table) != nil || os.Rename(moved, table) != nil {
					t.Fatal("fixture repair")
				}
			}
		}},
	})
}

// Claim: a missing or unsafe seed, an unsafe key directory and a derived
// public key that differs from the gate's expected key each refuse before the
// listener and readiness; the matching key serves.
func TestJ7ServiceKeyGateStartup(t *testing.T) {
	gate := j7ServiceRefusal{keyGate: true}
	j7ServiceCases(t, []j7ServiceCase{
		{name: "seed-missing", want: "key custody unavailable", refusal: gate, damage: func(t *testing.T, f *j7ServiceFixture) func() {
			moved := filepath.Join(f.root, "seed.moved")
			if e := os.Rename(f.keyFile, moved); e != nil {
				t.Fatal(e)
			}
			return func() {
				if e := os.Rename(moved, f.keyFile); e != nil {
					t.Fatal(e)
				}
			}
		}},
		{name: "seed-group-readable", want: "key custody unavailable", refusal: gate, damage: j7ServiceChmod("{seed}", 0640, 0600)},
		{name: "key-dir-mode-0750", want: "key custody unavailable", refusal: gate, damage: j7ServiceChmod("{key}", 0750, 0700)},
		{name: "seed-hard-linked", want: "key custody unavailable", refusal: gate, damage: func(t *testing.T, f *j7ServiceFixture) func() {
			link := filepath.Join(f.root, "seed.link")
			if e := os.Link(f.keyFile, link); e != nil {
				t.Fatal(e)
			}
			return func() {
				if e := os.Remove(link); e != nil {
					t.Fatal(e)
				}
			}
		}},
		{name: "gate-expects-other-key", want: "j7_request_key_mismatch", refusal: gate, damage: func(_ *testing.T, f *j7ServiceFixture) func() {
			f.gate.key = strings.Repeat("ab", 32)
			return func() { f.gate.key = f.public }
		}},
	})
}

// Claim: an existing control.sock (file, symlink or socket), a leftover
// staging directory, a socket directory with the wrong mode and a held
// directory lock each refuse without unlinking or changing any entry and
// without a readiness line; a fresh directory serves.
func TestJ7ServiceSocketGateStartup(t *testing.T) {
	gate := j7ServiceRefusal{keyGate: true}
	entry := func(create func(t *testing.T, path string), name string) func(*testing.T, *j7ServiceFixture) func() {
		return func(t *testing.T, f *j7ServiceFixture) func() {
			path := filepath.Join(f.socketDir, name)
			create(t, path)
			return func() {
				if e := os.Remove(path); e != nil {
					t.Fatal("refusal removed or replaced the existing entry", e)
				}
			}
		}
	}
	j7ServiceCases(t, []j7ServiceCase{
		{name: "existing-file", want: "keymaker: control socket already exists", refusal: gate, damage: entry(func(t *testing.T, path string) {
			if e := os.WriteFile(path, []byte("evidence"), 0600); e != nil {
				t.Fatal(e)
			}
		}, "control.sock")},
		{name: "existing-symlink", want: "keymaker: control socket already exists", refusal: gate, damage: entry(func(t *testing.T, path string) {
			if e := os.Symlink("/nonexistent/target", path); e != nil {
				t.Fatal(e)
			}
		}, "control.sock")},
		{name: "existing-socket", want: "keymaker: control socket already exists", refusal: gate, damage: entry(func(t *testing.T, path string) {
			dir, e := os.Open(filepath.Dir(path))
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			l, e := net.ListenUnix("unix", &net.UnixAddr{Name: fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), filepath.Base(path)), Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			l.SetUnlinkOnClose(false)
			l.Close()
		}, "control.sock")},
		{name: "leftover-staging", want: "keymaker: control staging unavailable", refusal: gate, damage: entry(func(t *testing.T, path string) {
			if e := os.Mkdir(path, 0700); e != nil {
				t.Fatal(e)
			}
		}, "control.stage")},
		{name: "socket-dir-mode-0775", want: "keymaker: unsafe directory ownership or mode", refusal: gate, damage: j7ServiceChmod("{run}", 0775, 0755)},
		{name: "socket-dir-locked", want: "keymaker: socket directory already locked", refusal: gate, damage: func(t *testing.T, f *j7ServiceFixture) func() {
			dir, e := os.Open(f.socketDir)
			if e != nil || syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
				t.Fatal("fixture lock", e)
			}
			return func() { dir.Close() }
		}},
	})
}

// Claim: the complete fixture runs its steps in the ruled order: trusted
// time, static gate, ancestors, protected head, state lock, generation, policy,
// key last, then the listener, then one readiness line. The key loader runs
// only while the state lock is held and the listener only after the key.
func TestJ7ServiceStartupOrder(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	r := f.start(t, j7ServiceFull)
	events, violations := f.trace.snapshot()
	if e := r.stop(t); e != nil {
		t.Fatal(e)
	}
	if len(violations) != 0 {
		t.Fatal("startup order violated:", violations)
	}
	want := []string{"clock", "gate", "ancestors", "ancestors", "ancestors", "ancestors", "head", "generation", "policy", "key", "listen"}
	if !reflect.DeepEqual(events, want) {
		t.Fatal("startup order", events)
	}
	// Negative beside it: with the state lock held elsewhere nothing after the
	// lock runs, in particular neither the key loader nor the listener.
	dir, e := OpenDirectory(f.statePath, f.uid, 0700)
	if e != nil {
		t.Fatal(e)
	}
	lock, e := LockState(dir, f.uid)
	if e != nil {
		t.Fatal(e)
	}
	f.refuses(t, "keymaker: state already locked", j7ServiceRefusal{absent: []string{"generation", "policy"}})
	lock.Close()
	dir.Close()
	f.serves(t)
}

func j7ServiceDial(t *testing.T, f *j7ServiceFixture) *net.UnixConn {
	t.Helper()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: j7ServiceSocketAddress(t, f), Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

// Claim: on the full entry a peer that is not the configured launcher is
// refused role_not_permitted on hello and that refusal is audited; no request
// is retained. The launcher positive is TestJ7ServiceLauncherWire; a launcher
// under its own distinct UID through the full entry is PENDING.
func TestJ7ServiceNonLauncherPeer(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	r := f.start(t, j7ServiceFull)
	before := recoveryFiles(t, f.statePath)
	c := j7ServiceDial(t, f)
	nativeSend(t, c, nativeHello(1))
	nativeResponse(t, nativeReceive(t, c), nativeID(1), "role_not_permitted")
	if e := r.stop(t); e != nil {
		t.Fatal(e)
	}
	after := recoveryFiles(t, f.statePath)
	snapshot := filepath.Join(f.statePath, "bindings.json")
	audited := false
	for path, body := range after {
		if strings.Contains(path, "/audit/") && body != before[path] && strings.Contains(body, "role_not_permitted") {
			audited = true
		}
	}
	if !audited || after[snapshot] != before[snapshot] {
		t.Fatal("non-launcher refusal must be audited and retain nothing", audited)
	}
	// The refusal advanced no head: the same pin restarts the service.
	f.serves(t)
}

// Claim: the composed service serves exactly the first-run methods to the
// launcher on the real published socket: hello, bind, j7_pubkey (the gate's
// key) and consent_v3 succeed; legacy methods refuse operation_unsupported;
// enrollment refuses delegation_evidence_unavailable and an unenrolled
// envelope is refused, because no node is wired. Every commit advances the
// head, so a restart with the old pin refuses until the operator re-exports.
// This single-UID fixture enters after the cross-field step, which forbids a
// launcher equal to the service UID; the distinct-UID launcher is PENDING.
func TestJ7ServiceLauncherWire(t *testing.T) {
	uid := uint32(os.Getuid())
	f := j7ServiceSetup(t, j7ServiceOptions{launcher: &Principal{UID: uid, Generation: nativeToken}})
	if c := j7ServiceCrossField(f.cfg); c != "j7_configuration_conflict" {
		t.Fatal("full entry must refuse the single-UID launcher", c)
	}
	r := f.start(t, j7ServiceInner)
	c := j7ServiceDial(t, f)
	lifecycleHello(t, c, 1)
	j7Call(t, c, 2, "pubkey", control.Object{}, "operation_unsupported")
	j7Call(t, c, 3, "j7_pubkey", control.Object{}, "run_identity_unavailable")
	origin := f.sf.origin
	args := j7BindArguments{Identity: f.sf.binding.Number, Origin: &origin, Input: Principal{uid + 200, "input-a"}}
	bound := lifecycleCall(t, c, wire.Request{ID: nativeID(4), Method: wire.BindMethod, TimeoutMS: 2000, Bind: &wire.BindParams{IdentityRegistrationNumber: args.Identity, InputPrincipal: wire.Principal{UID: args.Input.UID, Generation: args.Input.Generation}, Origin: &wire.Origin{Kind: origin.Kind, EventID: origin.Event, GrantID: origin.Grant, TipHash: origin.Tip, Mode: origin.Mode}}}, "")
	if bound.Run == nil || !messageID(bound.Run.RunID) {
		t.Fatal("bound run", bound)
	}
	if pub := j7Call(t, c, 5, "j7_pubkey", control.Object{}, ""); pub["public_key"] != f.public {
		t.Fatal("served public key differs from the gate key")
	}
	consent := j7ResultEvent(t, j7Call(t, c, 6, "j7_sign", j7TypedParams(t, "consent_v3", j7ConsentInput{Contract: j7Encode64(f.contractRaw)}), ""))
	if consent.Kind != 8181 {
		t.Fatal("consent event", consent.Kind)
	}
	// This builder's detached fixture only constructs a signed grant. Its
	// synthetic node/evidence are never installed into the running service.
	sign := &j7SignFixture{f: &j7StateFixture{store: &Store{}}, a: &j7RequestCustody{}, contract: f.contract, raw: f.contractRaw, public: f.public}
	grant, _, evidence := j7IssueFixture(t, sign, consent)
	j7Call(t, c, 7, "j7_enroll", j7GrantParams(t, sign, grant, evidence), "delegation_evidence_unavailable")
	j7Call(t, c, 8, "j7_sign", j7EnvelopeParams(t, sign, grant, evidence), "GRANT_NOT_FOR_RUN")
	j7Call(t, c, 9, "j7_sign", j7TypedParams(t, "delegation_request_v3", j7ConsentInput{Contract: j7Encode64(f.contractRaw)}), "operation_unsupported")
	lifecycleCall(t, c, lifecycleEnd(10, bound.Run.RunID), "")
	if e := r.stop(t); e != nil {
		t.Fatal(e)
	}
	// The service never rewrote its own pin: restart needs the operator.
	f.trace.reset()
	status := &j7ServiceStatus{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if e := startJ7Request(ctx, f.cfg, f.static, status, f.deps); e == nil || e.Error() != "keymaker: J7 expected head mismatch" || status.String() != "" || f.trace.count("key") != 0 || f.trace.count("listen") != 0 {
		t.Fatal("restart with the stale head pin", e)
	}
	dir, e := OpenDirectory(f.statePath, uid, 0700)
	if e != nil {
		t.Fatal(e)
	}
	disk, e := loadStoreMessage(dir, uid, j7SigningSchema, false)
	dir.Close()
	if e != nil {
		t.Fatal(e)
	}
	j7ServiceHead(t, f.headFile, j7Head(t, disk))
	r = f.start(t, j7ServiceInner)
	if e := r.stop(t); e != nil {
		t.Fatal("restart after the operator re-exported the head", e)
	}
}

// j7ServiceStub is a wire adapter whose audit can be failed on demand.
type j7ServiceStub struct {
	mu          sync.Mutex
	broken      bool
	refused     int
	afterRefuse func()
}

func (*j7ServiceStub) RunLifecycleOnly()  {}
func (*j7ServiceStub) RunRequestSigning() {}
func (*j7ServiceStub) Scope(ctx context.Context, _ net.Conn) (context.Context, func()) {
	return ctx, func() {}
}
func (*j7ServiceStub) BoundChannel(context.Context, net.Conn, control.Peer) bool { return false }
func (*j7ServiceStub) Identify(context.Context, net.Conn) (control.Peer, control.Code) {
	return control.Peer{UID: 1, Generation: "fixture"}, ""
}
func (*j7ServiceStub) Enter(context.Context, net.Conn) (func(), control.Code) { return func() {}, "" }
func (s *j7ServiceStub) Refuse(_ context.Context, _ net.Conn, _ *control.Peer, _ control.Request, _ []byte, refusal control.Code) control.Code {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refused++
	if s.afterRefuse != nil {
		s.afterRefuse()
	}
	if s.broken {
		return "audit_unavailable"
	}
	return refusal
}
func (*j7ServiceStub) Admit(context.Context, control.Peer, control.Request) control.Code {
	return "role_not_permitted"
}
func (*j7ServiceStub) Handle(context.Context, control.Peer, control.Request) (control.Object, control.Code) {
	return nil, control.OperationUnsupported
}
func (*j7ServiceStub) WithActive(context.Context, control.Peer, control.Request, control.Object, func(context.Context) control.Code) control.Code {
	return "role_not_permitted"
}

// Claim: an audit failure or a failed Store latches fatal: admission closes
// before the failing call returns, serve returns the cause and later calls are
// refused without reaching the adapter. A healthy refusal beside it keeps
// serving, and cancellation alone returns nil.
func TestJ7ServiceFailureLatch(t *testing.T) {
	for _, kind := range []string{"audit-refusal", "store-failed", "idle-store-failed", "idle-audit-failed", "healthy"} {
		t.Run(kind, func(t *testing.T) {
			f := j7ServiceSetup(t, j7ServiceOptions{})
			stub := &j7ServiceStub{broken: kind == "audit-refusal"}
			var health Code
			var healthMu sync.Mutex
			latch := newJ7Latch()
			h := &j7ServiceHandler{inner: stub, latch: latch, health: func() Code {
				healthMu.Lock()
				defer healthMu.Unlock()
				return health
			}}
			if kind == "store-failed" {
				stub.afterRefuse = func() { healthMu.Lock(); health = "j7_state_fenced"; healthMu.Unlock() }
			}
			wire, e := control.New(h, h, h, h, h)
			if e != nil {
				t.Fatal(e)
			}
			socket, e := openJ7Socket(f.socketDir, f.uid, uint32(os.Getgid()), createControlSocket)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- socket.serve(ctx, wire, latch, h.health) }()
			var c *net.UnixConn
			if !strings.HasPrefix(kind, "idle-") {
				c = j7ServiceDial(t, f)
				nativeSend(t, c, nativeHello(1))
			}
			if strings.HasPrefix(kind, "idle-") {
				healthMu.Lock()
				health = "j7_state_fenced"
				if kind == "idle-audit-failed" {
					health = "audit_unavailable"
				}
				healthMu.Unlock()
			}
			if kind == "healthy" {
				nativeResponse(t, nativeReceive(t, c), nativeID(1), "role_not_permitted")
				second := j7ServiceDial(t, f)
				nativeSend(t, second, nativeHello(2))
				nativeResponse(t, nativeReceive(t, second), nativeID(2), "role_not_permitted")
				select {
				case e := <-done:
					t.Fatal("healthy refusal stopped the service", e)
				default:
				}
				cancel()
				if e := <-done; e != nil {
					t.Fatal("cancellation", e)
				}
			} else {
				want := Code("audit_unavailable")
				if kind == "store-failed" || kind == "idle-store-failed" {
					want = "j7_state_fenced"
				}
				select {
				case e := <-done:
					if e != want {
						t.Fatal("latch cause", e)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("failure did not latch the listener closed")
				}
				if _, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: j7ServiceSocketAddress(t, f), Net: "unix"}); e == nil {
					t.Fatal("latched service still accepts")
				}
				before := stub.refused
				if _, code := h.Identify(context.Background(), nil); Code(code) != want {
					t.Fatal("latched identify", code)
				}
				if code := h.Refuse(context.Background(), nil, nil, control.Request{}, nil, "busy"); Code(code) != want || stub.refused != before {
					t.Fatal("latched refusal reached the adapter", code)
				}
			}
			socket.remove()
			if _, e := os.Lstat(f.socketPath()); !os.IsNotExist(e) {
				t.Fatal("own socket not unlinked")
			}
			// Control: after the latched or cancelled listener is removed, the
			// complete service starts on the same directory.
			f.serves(t)
		})
	}
}

// Claim: shutdown unlinks control.sock only while it is still the inode this
// process published: a replaced entry survives shutdown and then refuses the
// next start, which succeeds once the foreign entry is gone. The unreplaced
// control beside it is unlinked and restarts.
func TestJ7ServiceShutdownInodeMatch(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	r := f.start(t, j7ServiceFull)
	moved := filepath.Join(f.root, "own.sock")
	if e := os.Rename(f.socketPath(), moved); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(f.socketPath(), []byte("foreign"), 0600); e != nil {
		t.Fatal(e)
	}
	foreign := j7ServiceListing(t, f.socketDir)
	if e := r.stop(t); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(foreign, j7ServiceListing(t, f.socketDir)) {
		t.Fatal("shutdown unlinked or changed a foreign entry")
	}
	f.refuses(t, "keymaker: control socket already exists", j7ServiceRefusal{keyGate: true})
	if e := os.Remove(f.socketPath()); e != nil {
		t.Fatal(e)
	}
	f.serves(t)
	f.serves(t)
}

// Claim: the socket admits at most 8 connections per peer UID: the ninth is
// closed at accept without a reply, and closing one admitted connection lets
// the next one in.
func TestJ7ServiceAcceptBounds(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	r := f.start(t, j7ServiceFull)
	var held []*net.UnixConn
	for i := 0; i < 8; i++ {
		c := j7ServiceDial(t, f)
		nativeSend(t, c, nativeHello(i+1))
		nativeResponse(t, nativeReceive(t, c), nativeID(i+1), "role_not_permitted")
		held = append(held, c)
	}
	ninth := j7ServiceDial(t, f)
	ninth.SetDeadline(time.Now().Add(3 * time.Second))
	var one [1]byte
	if n, e := ninth.Read(one[:]); n != 0 || e != io.EOF {
		t.Fatal("ninth connection of one UID was served")
	}
	held[0].Close()
	until := time.Now().Add(3 * time.Second)
	for {
		c := j7ServiceDial(t, f)
		nativeSend(t, c, nativeHello(20))
		c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if body, code := ReadFrame(c); code == "" && body != nil {
			break
		}
		c.Close()
		if time.Now().After(until) {
			t.Fatal("released slot was not admitted")
		}
	}
	if e := r.stop(t); e != nil {
		t.Fatal(e)
	}
}

// Claim: policy directory access ACLs are refused even if their mask adds no
// permissions; removing only that ACL restores the same positive service.
func TestJ7ServicePolicyACLStartup(t *testing.T) {
	j7ServiceCases(t, []j7ServiceCase{{name: "directory-acl", want: "keymaker: unsafe policy ancestry", damage: func(t *testing.T, f *j7ServiceFixture) func() {
		acl := []byte{2, 0, 0, 0, 1, 0, 7, 0, 255, 255, 255, 255, 2, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 255, 255, 255, 255, 16, 0, 0, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255}
		if e := unix.Setxattr(f.policyDir, "system.posix_acl_access", acl, 0); e != nil {
			t.Fatal("ACL fixture unavailable", e)
		}
		return func() {
			if e := unix.Removexattr(f.policyDir, "system.posix_acl_access"); e != nil {
				t.Fatal(e)
			}
		}
	}}})
}

// Claim: a present valid empty policy is readiness, not signing authority.
// The existing missing-table negative is paired with this empty-table control.
func TestJ7ServiceEmptyPolicyStartup(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{prepare: func(t *testing.T, sf *j7StateFixture) {
		table := sf.table(2)
		table.Rows = []j7PolicyRow{}
		sf.publish(t, table)
	}})
	f.serves(t)
}

type j7FailedStatus struct{}

func (j7FailedStatus) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// Claim: failure to publish status does not leave a running listener, change
// state/head, or append audit; the same candidate with a working writer serves.
func TestJ7ServiceReadinessWriteFailure(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	before := recoveryFiles(t, f.statePath)
	head, _ := os.ReadFile(f.headFile)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if e := serveJ7Request(ctx, f.cfg, f.static, j7FailedStatus{}, f.deps); e == nil || e.Error() != "keymaker: readiness status unavailable" {
		t.Fatal("readiness write failure", e)
	}
	if _, e := os.Lstat(f.socketPath()); !os.IsNotExist(e) {
		t.Fatal("unreported listener retained")
	}
	after, _ := os.ReadFile(f.headFile)
	if !reflect.DeepEqual(before, recoveryFiles(t, f.statePath)) || !bytes.Equal(head, after) {
		t.Fatal("readiness failure changed state")
	}
	f.serves(t)
}

// Claim: both global and per-UID admission thresholds refuse at their exact
// bounds and reopen below them. Synthetic map entries test arithmetic only;
// TestJ7ServiceAcceptBounds separately exercises real accept/close behavior.
func TestJ7ServiceAdmissionCapacity(t *testing.T) {
	s := &j7Socket{connections: map[*net.UnixConn]uint32{}, counts: map[uint32]int{}}
	for i := 0; i < 127; i++ {
		s.connections[new(net.UnixConn)] = uint32(i)
	}
	if s.atCapacity(500) {
		t.Fatal("global limit refused below bound")
	}
	final := new(net.UnixConn)
	s.connections[final] = 127
	if !s.atCapacity(500) {
		t.Fatal("global limit admitted at bound")
	}
	delete(s.connections, final)
	if s.atCapacity(500) {
		t.Fatal("global slot did not reopen")
	}
	s.counts[500] = 8
	if !s.atCapacity(500) {
		t.Fatal("UID limit admitted at bound")
	}
	s.counts[500] = 7
	if s.atCapacity(500) {
		t.Fatal("UID slot did not reopen")
	}
}

// Claim: actual Store/journal failure flags close an idle composed service,
// without requiring a new request. Healthy idle readiness and a clean restart
// beside each fault establish that the latch is not unconditional.
func TestJ7ServiceIdleStoreHealth(t *testing.T) {
	for _, kind := range []string{"store", "audit"} {
		t.Run(kind, func(t *testing.T) {
			f := j7ServiceSetup(t, j7ServiceOptions{})
			opened := make(chan *Store, 1)
			gen := f.deps.generation
			f.deps.generation = func(s *Store, c generationJournalConfig) GenerationSource { opened <- s; return gen(s, c) }
			r := f.start(t, j7ServiceFull)
			store := <-opened
			if code := j7StoreHealth(store); code != "" {
				t.Fatal("healthy store refused", code)
			}
			want := Code("j7_state_fenced")
			if kind == "audit" {
				want = "audit_unavailable"
				store.journal.mu.Lock()
				store.journal.failed = true
				store.journal.mu.Unlock()
			} else {
				store.mu.Lock()
				store.failed = true
				store.mu.Unlock()
			}
			select {
			case e := <-r.done:
				r.done <- e
				if e != want {
					t.Fatal("idle failure cause", e)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("idle Store failure did not stop service")
			}
			if _, e := os.Lstat(f.socketPath()); !os.IsNotExist(e) {
				t.Fatal("failed idle socket retained")
			}
			f.deps.generation = gen
			f.serves(t)
		})
	}
}

// Claim: a socket-creation fault that changes mode after the constructor's
// checks is rejected by the service's final owner/group/mode check; the owned
// inode is removed, state/head stay unchanged and a healthy constructor serves.
func TestJ7ServiceSocketPostCreationCheck(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	before := recoveryFiles(t, f.statePath)
	head, _ := os.ReadFile(f.headFile)
	good := f.deps.listen
	f.deps.listen = func(dir *os.File, gid uint32) (*net.UnixListener, uint64, uint64, error) {
		l, i, d, e := good(dir, gid)
		if e != nil {
			return l, i, d, e
		}
		if e := os.Chmod(fmt.Sprintf("/proc/self/fd/%d/control.sock", dir.Fd()), 0600); e != nil {
			t.Fatal(e)
		}
		return l, i, d, nil
	}
	var status bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if e := serveJ7Request(ctx, f.cfg, f.static, &status, f.deps); e == nil || e.Error() != "keymaker: unsafe control socket" {
		t.Fatal("unsafe created socket admitted", e)
	}
	if status.Len() != 0 {
		t.Fatal("unsafe created socket printed readiness")
	}
	if _, e := os.Lstat(f.socketPath()); !os.IsNotExist(e) {
		t.Fatal("unsafe owned socket retained")
	}
	after, _ := os.ReadFile(f.headFile)
	if !bytes.Equal(head, after) || !reflect.DeepEqual(before, recoveryFiles(t, f.statePath)) {
		t.Fatal("socket refusal changed custody")
	}
	f.deps.listen = good
	f.serves(t)
}

// Claim: an otherwise valid schema-5 history with an uncertain signing handoff
// refuses the composed entry without key/listener/readiness or durable changes.
// The uncertainty marker is planted in an isolated complete request history;
// the adjacent complete service is the positive control, not a repair path.
func TestJ7ServiceUnknownHandoffStartup(t *testing.T) {
	uid := uint32(os.Getuid())
	f := j7ServiceSetup(t, j7ServiceOptions{launcher: &Principal{uid, nativeToken}})
	opened := make(chan *Store, 1)
	gen := f.deps.generation
	f.deps.generation = func(s *Store, c generationJournalConfig) GenerationSource { opened <- s; return gen(s, c) }
	r := f.start(t, j7ServiceInner)
	store := <-opened
	c := j7ServiceDial(t, f)
	nativeNegotiate(t, c, 1)
	origin := f.sf.origin
	j7Call(t, c, 2, "j7_run_bind", j7Params(t, j7BindArguments{Identity: f.sf.binding.Number, Origin: &origin, Input: Principal{uid + 200, "input-a"}}), "")
	j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", j7TypedParams(t, "consent_v3", j7ConsentInput{Contract: j7Encode64(f.contractRaw)}), ""))
	store.mu.Lock()
	if len(store.j7Signing.Records) != 1 {
		store.mu.Unlock()
		t.Fatal("signing history absent")
	}
	store.j7Signing.Records[0].Release = "handoff_unknown"
	code := store.commitJ7(t.Context())
	store.mu.Unlock()
	if code != "" {
		t.Fatal("uncertain fixture commit", code)
	}
	if e := r.stop(t); e != nil {
		t.Fatal(e)
	}
	j7ServiceHead(t, f.headFile, j7Head(t, store))
	f.cfg.J7Policy.Launcher = Principal{uid + 1, "launcher-generation"}
	f.deps.generation = gen
	f.refuses(t, "keymaker: unknown signing handoff", j7ServiceRefusal{absent: []string{"generation", "policy"}})
	j7ServiceSetup(t, j7ServiceOptions{}).serves(t)
}

// Claim: the shipped request-role example decodes through the actual closed
// schema with every required service member and floor 5. It remains an inert
// provisioning template; parsing establishes no installed UID or authority.
func TestJ7ServicePackagingConfiguration(t *testing.T) {
	raw, e := os.ReadFile("../../packaging/j7-request.example.json")
	if e != nil {
		t.Fatal(e)
	}
	cfg, e := ParseConfig(bytes.NewReader(raw))
	if e != nil {
		t.Fatal("shipped request example", e)
	}
	if cfg.ServiceRole != j7RequestRole || cfg.TimePolicy == nil || j7ServiceCrossField(cfg) != "" || cfg.J7State.Minimum != 5 {
		t.Fatal("shipped service contract incomplete")
	}
	// Negative beside it: an inline moving head cannot reappear in the template.
	bad := bytes.Replace(raw, []byte(`"head_file":`), []byte(`"expected_version":1,"head_file":`), 1)
	if bytes.Equal(raw, bad) {
		t.Fatal("template plant not applied")
	}
	if _, e := ParseConfig(bytes.NewReader(bad)); e == nil {
		t.Fatal("shipped example admitted inline moving head")
	}
}
