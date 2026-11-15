//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type j7StateFixture struct {
	store   *Store
	dir     *os.File
	path    string
	policy  *j7Policy
	binding Binding
	origin  j7Origin
	uid     uint32
	lock    *os.File
}

func j7Head(t *testing.T, s *Store) j7Expectation {
	t.Helper()
	d, e := s.contentDigest(s.version)
	if e != nil {
		t.Fatal(e)
	}
	return j7Expectation{s.version, d}
}

// This fixture supplies a real protected directory inode directly. It does not
// attest production pathname ancestry: the full path constructor remains strict
// and its positive needs separately authorized protected scratch provisioning.
func j7FixturePolicy(t *testing.T, path string, uid uint32, s *Store) *j7Policy {
	t.Helper()
	dir, e := OpenDirectory(filepath.Dir(path), uid, 0700)
	if e != nil {
		t.Fatal(e)
	}
	if !j7NoACL(int(dir.Fd()), true) {
		dir.Close()
		t.Fatal("fixture directory ACL")
	}
	return &j7Policy{dir: dir, name: filepath.Base(path), uid: uid, instance: s.j7.Instance, identity: s.j7.Identity, store: s}
}
func j7StateSetup(t *testing.T) *j7StateFixture {
	t.Helper()
	uid := uint32(os.Getuid())
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("fixture chmod")
	}
	path := filepath.Join(root, "state")
	if os.Mkdir(path, 0700) != nil {
		t.Fatal("fixture state")
	}
	dir, e := OpenDirectory(path, uid, 0700)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { dir.Close() })
	lock, e := LockState(dir, uid)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { lock.Close() })
	s, e := fixtureOpenStore(dir, uid)
	if e != nil {
		t.Fatal(e)
	}
	b := fixtureBinding(uid + 100)
	b, c := s.Register(fixtureOperator, fixtureOperator, b)
	if c != "" {
		t.Fatal(c)
	}
	if c := s.migrateJ7(t.Context(), j7Head(t, s), strings.Repeat("1", 32), b.Number); c != "" {
		t.Fatal("migrate", c)
	}
	policyPath := filepath.Join(root, "policy")
	if os.Mkdir(policyPath, 0700) != nil {
		t.Fatal("fixture policy")
	}
	p := j7FixturePolicy(t, filepath.Join(policyPath, "table.json"), uid, s)
	t.Logf("owned fixture root=%s state=%s policy=%s", root, path, policyPath)
	f := &j7StateFixture{store: s, dir: dir, path: path, policy: p, binding: b, origin: j7Origin{Kind: "admission", Event: strings.Repeat("a", 64), Grant: strings.Repeat("b", 64), Tip: strings.Repeat("c", 64), Mode: "enforcing"}, uid: uid, lock: lock}
	t.Cleanup(func() {
		p.close()
		if f.store != nil {
			f.store.Close()
		}
	})
	return f
}
func (f *j7StateFixture) table(version uint64) *j7PolicyTable {
	return &j7PolicyTable{Format: "keymaker-j7-policy/1", Instance: strings.Repeat("1", 32), Identity: f.binding.Number, Version: version, Rows: []j7PolicyRow{{Origin: f.origin.key(), Use: []string{strings.Repeat("d", 64)}, Delegate: []string{strings.Repeat("e", 64)}, Consent: []j7ConsentPermission{{strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64), true}}, Deny: []string{}}}}
}
func j7PolicyRaw(t *testing.T, p *j7PolicyTable) []byte {
	t.Helper()
	b, e := canonical(p)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func (f *j7StateFixture) publish(t *testing.T, p *j7PolicyTable) []byte {
	t.Helper()
	b := j7PolicyRaw(t, p)
	if c := f.policy.publish(t.Context(), b); c != "" {
		t.Fatal("publish", c)
	}
	return b
}
func (f *j7StateFixture) reopen(t *testing.T) {
	t.Helper()
	head := j7Head(t, f.store)
	if e := f.store.Close(); e != nil {
		t.Fatal(e)
	}
	f.store = nil
	s, e := openJ7Store(f.dir, f.uid, fixtureAuditClock{}, head)
	if e != nil {
		t.Fatal("restart", e)
	}
	f.store = s
	f.policy.store = s
}

// Exact operator bytes are idempotent. Rollback/equivocation/missing/corrupt or
// foreign rows are empty across restart, never cached or replaced by owner rows.
func TestJ7PolicyRollbackAfterRestart(t *testing.T) {
	f := j7StateSetup(t)
	p := f.table(1)
	old := f.publish(t, p)
	p.Version = 2
	current := f.publish(t, p)
	f.reopen(t)
	grant := strings.Repeat("d", 64)
	check := func(want Code) {
		t.Helper()
		if c := f.policy.permission(t.Context(), f.origin, "use", []string{grant}, nil); c != want {
			t.Fatalf("policy verdict %s, want %s", c, want)
		}
	}
	check("")
	head := f.store.j7.Version
	for _, raw := range [][]byte{old, append(append([]byte{}, current...), ' '), []byte("{}"), nil} {
		name := filepath.Join(f.policy.dir.Name(), f.policy.name)
		if raw == nil {
			if os.Remove(name) != nil {
				t.Fatal("fixture remove")
			}
		} else if os.WriteFile(name, raw, 0600) != nil {
			t.Fatal("fixture replace")
		}
		check("GRANT_NOT_FOR_RUN")
		if f.store.j7.Version != head {
			t.Fatal("policy floor fell")
		}
		if os.WriteFile(name, current, 0600) != nil {
			t.Fatal("restore fixture")
		}
		check("")
	}
	f.reopen(t)
	check("")
	owner := f.origin
	owner.Kind = "owner_command"
	owner.Command = strings.Repeat("7", 64)
	owner.Event = ""
	owner.Grant = ""
	owner.Tip = ""
	owner.Mode = ""
	if c := f.policy.permission(t.Context(), owner, "use", []string{grant}, nil); c != "GRANT_NOT_FOR_RUN" {
		t.Fatal("owner fallback", c)
	}
	if c := f.policy.permission(t.Context(), owner, "consent", nil, &p.Rows[0].Consent[0]); c != "CONSENT_NOT_FOR_RUN" {
		t.Fatal("consent owner fallback", c)
	}
}

// Explicit removal/deny persists; later explicit use alone lifts it. Absence of
// an enrolled grant from an unchanged list and consent removal do not withdraw
// it. These transition fixtures create no signed consent or enrolled authority.
func TestJ7PolicyWithdrawalContinuity(t *testing.T) {
	f := j7StateSetup(t)
	p := f.table(1)
	f.publish(t, p)
	grant := p.Rows[0].Use[0]
	p.Version = 2
	p.Rows[0].Use = []string{}
	f.publish(t, p)
	f.reopen(t)
	if len(f.store.j7.Denials) != 1 || f.store.j7.Denials[0].Grant != grant {
		t.Fatal("withdrawal denial lost")
	}
	p.Version = 3
	p.Rows[0].Consent = []j7ConsentPermission{}
	f.publish(t, p)
	if len(f.store.j7.Denials) != 1 {
		t.Fatal("consent removal erased denial")
	}
	p.Version = 4
	p.Rows[0].Use = []string{grant}
	f.publish(t, p)
	if len(f.store.j7.Denials) != 0 || f.policy.permission(t.Context(), f.origin, "use", []string{grant}, nil) != "" {
		t.Fatal("new operator use did not lift denial")
	}
	p.Version = 5
	p.Rows[0].Use = []string{}
	p.Rows[0].Deny = []string{strings.Repeat("f", 64)}
	f.publish(t, p)
	if len(f.store.j7.Denials) != 2 {
		t.Fatal("explicit enrolled-grant deny absent")
	}
	old := f.table(6)
	next := f.table(7)
	next.Rows[0].Consent = []j7ConsentPermission{}
	if got := reconcileJ7Denials(old, next, nil); len(got) != 0 {
		t.Fatal("unchanged-list absence/consent removal invented withdrawal")
	}
	next.Rows[0].Use = nil
	next.Rows[0].Deny = []string{grant}
	next.Version = 8
	if validateJ7Policy(next, next.Instance, next.Identity) == nil {
		t.Fatal("null array admitted")
	}
	next.Rows[0].Use = []string{grant}
	if validateJ7Policy(next, next.Instance, next.Identity) == nil {
		t.Fatal("use/deny conflict admitted")
	}
}

// Every closed policy type is required; null/missing/unknown/duplicate members,
// unsafe or noncanonical numbers and duplicate/conflicting permissions refuse.
// Valid independent admission and owner-command rows remain distinct controls.
func TestJ7PolicySchema(t *testing.T) {
	f := j7StateSetup(t)
	p := f.table(j7SafeInteger)
	raw := j7PolicyRaw(t, p)
	owner := p.Rows[0]
	owner.Origin = j7OriginKey{Kind: "owner_command"}
	p.Rows = append(p.Rows, owner)
	positive := j7PolicyRaw(t, p)
	if _, e := decodeJ7Policy(positive, p.Instance, p.Identity); e != nil {
		t.Fatal("distinct valid rows", e)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"version":9007199254740991`), []byte(`"version":9007199254740992`), 1),
		bytes.Replace(raw, []byte(`"version":9007199254740991`), []byte(`"version":1e0`), 1),
		bytes.Replace(raw, []byte(`"version":9007199254740991`), []byte(`"version":-0`), 1),
		bytes.Replace(raw, []byte(`"version":9007199254740991`), []byte(`"version":0`), 1),
		bytes.Replace(raw, []byte(`"version":9007199254740991`), []byte(`"version":1,"version":2`), 1),
		bytes.Replace(raw, []byte(`"and_use":true`), []byte(`"and_use":null`), 1),
		bytes.Replace(raw, []byte(`"and_use":true,`), nil, 1),
		bytes.Replace(raw, []byte(`"rows":`), []byte(`"Rows":`), 1),
		bytes.Replace(raw, []byte(`"deny":[]`), []byte(`"deny":[],"unknown":true`), 1),
	} {
		if _, e := decodeJ7Policy(bad, p.Instance, p.Identity); e == nil {
			t.Fatal("malformed policy accepted", string(bad))
		}
	}
	for _, change := range []func(*j7PolicyTable){func(p *j7PolicyTable) { p.Instance = strings.Repeat("2", 32) }, func(p *j7PolicyTable) { p.Identity++ }, func(p *j7PolicyTable) { p.Rows = append(p.Rows, p.Rows[0]) }, func(p *j7PolicyTable) { p.Rows[0].Use = append(p.Rows[0].Use, p.Rows[0].Use[0]) }, func(p *j7PolicyTable) { p.Rows[0].Deny = append(p.Rows[0].Deny, p.Rows[0].Use[0]) }, func(p *j7PolicyTable) { p.Rows[0].Consent = append(p.Rows[0].Consent, p.Rows[0].Consent[0]) }} {
		p := f.table(1)
		change(p)
		if _, e := decodeJ7Policy(j7PolicyRaw(t, p), f.store.j7.Instance, f.binding.Number); e == nil {
			t.Fatal("invalid policy semantic accepted")
		}
	}
}

// Byte, row and aggregate permission bounds have inclusive and one-over
// controls. Row/permission validation is isolated from the independent byte
// cap where large valid arrays cannot fit the complete file simultaneously.
func TestJ7PolicyCapacity(t *testing.T) {
	f := j7StateSetup(t)
	p := f.table(1)
	raw := j7PolicyRaw(t, p)
	raw = append(raw, bytes.Repeat([]byte{' '}, j7PolicyBytes-len(raw))...)
	if _, e := decodeJ7Policy(raw, p.Instance, p.Identity); e != nil {
		t.Fatal("inclusive byte limit", e)
	}
	if _, e := decodeJ7Policy(append(raw, ' '), p.Instance, p.Identity); e == nil {
		t.Fatal("byte overflow")
	}
	p.Rows = []j7PolicyRow{}
	for i := 0; i < j7PolicyRows; i++ {
		row := f.table(1).Rows[0]
		row.Origin.Event = fmt.Sprintf("%064x", i)
		p.Rows = append(p.Rows, row)
	}
	if e := validateJ7Policy(p, p.Instance, p.Identity); e != nil {
		t.Fatal("inclusive rows", e)
	}
	p.Rows = append(p.Rows, f.table(1).Rows[0])
	if validateJ7Policy(p, p.Instance, p.Identity) == nil {
		t.Fatal("row overflow")
	}
	p = f.table(1)
	row := &p.Rows[0]
	row.Use = []string{}
	row.Delegate = []string{}
	row.Consent = []j7ConsentPermission{}
	for i := 0; i < j7PolicyPermissions; i++ {
		row.Use = append(row.Use, fmt.Sprintf("%064x", i))
	}
	if e := validateJ7Policy(p, p.Instance, p.Identity); e != nil {
		t.Fatal("inclusive permissions", e)
	}
	row.Use = append(row.Use, strings.Repeat("f", 64))
	if validateJ7Policy(p, p.Instance, p.Identity) == nil {
		t.Fatal("permission overflow")
	}
}

// Unsafe files and directories are unreadable, beside restored holder-owned
// positives. The ACL control uses real xattrs in this private fixture only.
func TestJ7PolicyProtection(t *testing.T) {
	f := j7StateSetup(t)
	raw := f.publish(t, f.table(1))
	path := filepath.Join(f.policy.dir.Name(), f.policy.name)
	good := func() {
		t.Helper()
		b, e := f.policy.read()
		if e != nil || !bytes.Equal(b, raw) {
			t.Fatal("protected positive", e)
		}
	}
	good()
	for _, mode := range []os.FileMode{0644, 0400} {
		if os.Chmod(path, mode) != nil {
			t.Fatal("chmod")
		}
		if _, e := f.policy.read(); e == nil {
			t.Fatal("mode accepted")
		}
		os.Chmod(path, 0600)
		good()
	}
	link := path + ".link"
	if os.Link(path, link) != nil {
		t.Fatal("link")
	}
	if _, e := f.policy.read(); e == nil {
		t.Fatal("hardlink accepted")
	}
	os.Remove(link)
	good()
	if os.Remove(path) != nil || os.Symlink("missing", path) != nil {
		t.Fatal("symlink fixture")
	}
	if _, e := f.policy.read(); e == nil {
		t.Fatal("symlink accepted")
	}
	os.Remove(path)
	os.WriteFile(path, raw, 0600)
	good()
	// A valid extended access ACL with an extra named user is rejected even when
	// its mask grants no additional permission; no ACL authority is inferred.
	acl := []byte{2, 0, 0, 0, 1, 0, 6, 0, 255, 255, 255, 255, 2, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 255, 255, 255, 255, 16, 0, 0, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255}
	if e := unix.Setxattr(path, "system.posix_acl_access", acl, 0); e != nil {
		t.Fatal("ACL fixture unavailable", e)
	}
	if _, e := f.policy.read(); e == nil {
		t.Fatal("ACL accepted")
	}
	if unix.Removexattr(path, "system.posix_acl_access") != nil {
		t.Fatal("ACL removal")
	}
	good()
	bad := filepath.Join(t.TempDir(), "unsafe")
	os.Mkdir(bad, 0777)
	os.Chmod(bad, 0777)
	child := filepath.Join(bad, "child")
	if os.Mkdir(child, 0700) != nil {
		t.Fatal("fixture unsafe ancestor")
	}
	if d, e := j7PolicyDirectory(child, f.uid); e == nil {
		d.Close()
		t.Fatal("writable ancestry accepted")
	}
	if d, e := j7PolicyDirectory(f.policy.dir.Name(), f.uid+1); e == nil {
		d.Close()
		t.Fatal("wrong holder accepted")
	}
}

// Two independently opened policy descriptors share the kernel directory lock.
// A canceled reader cannot consume later permissions; a waiting publication
// proceeds after release and makes withdrawal durable before later checks.
func TestJ7PolicyPublicationOrdering(t *testing.T) {
	f := j7StateSetup(t)
	f.publish(t, f.table(1))
	other := j7FixturePolicy(t, filepath.Join(f.policy.dir.Name(), f.policy.name), f.uid, f.store)
	defer other.close()
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan Code, 1)
	go func() {
		done <- f.policy.withTable(context.Background(), func(*j7PolicyTable) Code { close(entered); <-release; return "" })
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if c := other.withTable(ctx, func(*j7PolicyTable) Code { t.Error("canceled read entered"); return "" }); c != "request_deadline_exceeded" {
		t.Fatal("publication gate cancellation", c)
	}
	p := f.table(2)
	p.Rows[0].Use = []string{}
	raw := j7PolicyRaw(t, p)
	published := make(chan Code, 1)
	go func() { published <- other.publish(context.Background(), raw) }()
	select {
	case c := <-published:
		t.Fatal("publication bypassed shared fence", c)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if c := <-done; c != "" {
		t.Fatal(c)
	}
	if c := <-published; c != "" {
		t.Fatal(c)
	}
	if c := f.policy.permission(t.Context(), f.origin, "use", []string{strings.Repeat("d", 64)}, nil); c != "GRANT_NOT_FOR_RUN" {
		t.Fatal("withdrawal not visible", c)
	}
	if !reflect.DeepEqual(f.store.j7.Policy, p) {
		t.Fatal("different publication committed")
	}
}

// Public local fixtures separate admission/owner rows and retain concrete
// unreadable counterexamples; schema validity alone supplies no run authority.
func TestJ7PolicyPublicFixtures(t *testing.T) {
	var vectors struct {
		Format   string `json:"format"`
		Instance string `json:"instance"`
		Identity uint64 `json:"identity_registration_number"`
		Positive []struct {
			ID     string          `json:"id"`
			Policy json.RawMessage `json:"policy"`
		} `json:"positive"`
		Negative []struct {
			ID       string          `json:"id"`
			Policy   json.RawMessage `json:"policy"`
			Expected string          `json:"expected"`
		} `json:"negative"`
		Note string `json:"note"`
	}
	raw, e := os.ReadFile("../../vectors/j7/policy.json")
	if e != nil || StrictJSON(bytes.NewReader(raw), &vectors) != nil || vectors.Format != "keymaker-j7-policy-vectors/1" || len(vectors.Positive) != 1 || len(vectors.Negative) != 6 {
		t.Fatal("policy vector identity", e)
	}
	for _, v := range vectors.Positive {
		if p, e := decodeJ7Policy(v.Policy, vectors.Instance, vectors.Identity); e != nil || len(p.Rows) != 2 || p.Rows[0].Origin == p.Rows[1].Origin {
			t.Fatal("public positive", v.ID, e)
		}
	}
	for _, v := range vectors.Negative {
		if _, e := decodeJ7Policy(v.Policy, vectors.Instance, vectors.Identity); e == nil || v.Expected != "unreadable" {
			t.Fatal("public negative", v.ID, e)
		}
	}
}

// Exercise the actual production pathname constructor under explicitly supplied
// protected TMPDIR, then paired unsafe ancestor/symlink/ACL controls. This proves
// pathname/file protection for this holder fixture, not a second UID or broker.
func TestJ7PolicyProtectedPath(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	t.Logf("full-path fixture root=%s", root)
	f := j7StateSetup(t)
	path := filepath.Join(root, "table.json")
	p, e := newJ7Policy(path, f.uid, f.store, f.store.j7.Instance, f.binding.Number)
	if e != nil {
		t.Fatal("protected TMPDIR ancestry required for full-path positive", e)
	}
	defer p.close()
	raw := j7PolicyRaw(t, f.table(1))
	if c := p.publish(t.Context(), raw); c != "" {
		t.Fatal("full-path holder positive", c)
	}
	if c := p.permission(t.Context(), f.origin, "use", []string{strings.Repeat("d", 64)}, nil); c != "" {
		t.Fatal("full-path read positive", c)
	}
	parent := filepath.Join(root, "unsafe")
	if os.Mkdir(parent, 0700) != nil || os.Mkdir(filepath.Join(parent, "leaf"), 0700) != nil {
		t.Fatal("ancestor fixture")
	}
	if os.Chmod(parent, 0777) != nil {
		t.Fatal("unsafe mode")
	}
	if q, e := j7PolicyDirectory(filepath.Join(parent, "leaf"), f.uid); e == nil {
		q.Close()
		t.Fatal("writable ancestor accepted")
	}
	if os.Chmod(parent, 0700) != nil {
		t.Fatal("restore fixture")
	}
	if q, e := j7PolicyDirectory(filepath.Join(parent, "leaf"), f.uid); e != nil {
		t.Fatal("restored ancestor positive", e)
	} else {
		q.Close()
	}
	link := filepath.Join(root, "link")
	if os.Symlink(parent, link) != nil {
		t.Fatal("symlink")
	}
	if q, e := j7PolicyDirectory(filepath.Join(link, "leaf"), f.uid); e == nil {
		q.Close()
		t.Fatal("symlink ancestor accepted")
	}
	acl := []byte{2, 0, 0, 0, 1, 0, 7, 0, 255, 255, 255, 255, 2, 0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 255, 255, 255, 255, 16, 0, 0, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255}
	if e := unix.Setxattr(parent, "system.posix_acl_access", acl, 0); e != nil {
		t.Fatal("ancestor ACL fixture", e)
	}
	if q, e := j7PolicyDirectory(filepath.Join(parent, "leaf"), f.uid); e == nil {
		q.Close()
		t.Fatal("ACL ancestor accepted")
	}
	if unix.Removexattr(parent, "system.posix_acl_access") != nil {
		t.Fatal("restore ACL")
	}
}

// Distinct admission/owner rows cannot borrow each other's permissions. Every
// ID in a path is checked and consent requires its exact triple. Origins here
// are internal fixtures; actual caller-to-origin authority is the run tests.
func TestJ7PolicyOriginPermissions(t *testing.T) {
	f := j7StateSetup(t)
	table := f.table(1)
	owner := table.Rows[0]
	owner.Origin = j7OriginKey{Kind: "owner_command"}
	owner.Use = []string{strings.Repeat("f", 64)}
	owner.Delegate = []string{}
	owner.Consent = []j7ConsentPermission{}
	table.Rows = append(table.Rows, owner)
	f.publish(t, table)
	foreign := strings.Repeat("f", 64)
	own := strings.Repeat("d", 64)
	if c := f.policy.permission(t.Context(), f.origin, "use", []string{foreign}, nil); c != "GRANT_NOT_FOR_RUN" {
		t.Fatal("foreign origin grant admitted", c)
	}
	if c := f.policy.permission(t.Context(), f.origin, "use", []string{own}, nil); c != "" {
		t.Fatal("own origin positive refused", c)
	}
	for _, ids := range [][]string{{own, foreign}, {foreign, own}} {
		if c := f.policy.permission(t.Context(), f.origin, "use", ids, nil); c != "GRANT_NOT_FOR_RUN" {
			t.Fatal("partial path permission admitted", c)
		}
	}
	command := j7Origin{Kind: "owner_command", Command: strings.Repeat("7", 64)}
	if c := f.policy.permission(t.Context(), command, "use", []string{foreign}, nil); c != "" {
		t.Fatal("owner positive refused", c)
	}
	if c := f.policy.permission(t.Context(), command, "use", []string{own}, nil); c != "GRANT_NOT_FOR_RUN" {
		t.Fatal("owner borrowed admission row", c)
	}
	missing := f.origin
	missing.Event = strings.Repeat("8", 64)
	if c := f.policy.permission(t.Context(), missing, "use", []string{foreign}, nil); c != "GRANT_NOT_FOR_RUN" {
		t.Fatal("missing row used owner fallback", c)
	}
	if c := f.policy.permission(t.Context(), f.origin, "delegate", []string{strings.Repeat("e", 64)}, nil); c != "" {
		t.Fatal("delegate positive", c)
	}
	if c := f.policy.permission(t.Context(), f.origin, "delegate", []string{foreign}, nil); c != "GRANT_NOT_FOR_RUN" {
		t.Fatal("foreign parent admitted", c)
	}
	consent := table.Rows[0].Consent[0]
	if c := f.policy.permission(t.Context(), f.origin, "consent", nil, &consent); c != "" {
		t.Fatal("consent positive", c)
	}
	consent.Privacy = strings.Repeat("9", 64)
	if c := f.policy.permission(t.Context(), f.origin, "consent", nil, &consent); c != "CONSENT_NOT_FOR_RUN" {
		t.Fatal("wrong consent triple admitted", c)
	}
}
