//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Missing J7 evidence never authorizes initialization. Old/default and message
// readers reject the new snapshot before changing any state or audit bytes.
// An independent exact head, not a service-writable local floor, admits restart.
func TestJ7RecoveryReaderAndExpectedHead(t *testing.T) {
	f := j7StateSetup(t)
	f.publish(t, f.table(1))
	head := j7Head(t, f.store)
	f.store.Close()
	f.store = nil
	before := recoveryFiles(t, f.path)
	for _, floor := range []int{0, 2} {
		s, _, _, e := openCustodyStateMessage(f.dir, f.uid, fixtureAuditClock{}, floor, false)
		if e == nil {
			if s != nil {
				s.Close()
			}
			t.Fatal("older reader admitted J7")
		}
		if !reflect.DeepEqual(before, recoveryFiles(t, f.path)) {
			t.Fatal("old reader mutated authoritative state")
		}
	}
	wrong := head
	wrong.Version--
	if s, e := openJ7Store(f.dir, f.uid, fixtureAuditClock{}, wrong); e == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("wrong independent head admitted")
	}
	if !reflect.DeepEqual(before, recoveryFiles(t, f.path)) {
		t.Fatal("expected-head refusal mutated state")
	}
	s, e := openJ7Store(f.dir, f.uid, fixtureAuditClock{}, head)
	if e != nil {
		t.Fatal("exact head positive", e)
	}
	f.store = s
	f.policy.store = s
	empty := t.TempDir()
	os.Chmod(empty, 0700)
	dir, e := OpenDirectory(empty, f.uid, 0700)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	if s, e := openJ7Store(dir, f.uid, fixtureAuditClock{}, head); e == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("empty directory became J7 bootstrap")
	}
	entries, e := os.ReadDir(empty)
	if e != nil || len(entries) != 0 {
		t.Fatal("missing J7 bootstrap wrote artifacts", e)
	}
}

// A coordinated rollback is rejected relative to an independently retained
// later head. Accepting an intentionally supplied old expectation is explicitly
// outside local detection, not advertised as restore protection.
func TestJ7RecoveryRollbackAndLoss(t *testing.T) {
	for _, mode := range []string{"matched-rollback", "snapshot-only", "lost-snapshot", "lost-floor", "lost-journal"} {
		t.Run(mode, func(t *testing.T) {
			f := j7StateSetup(t)
			f.publish(t, f.table(1))
			old := recoveryFiles(t, f.path)
			p := f.table(2)
			p.Rows[0].Use = []string{}
			f.publish(t, p)
			expected := j7Head(t, f.store)
			f.store.Close()
			f.store = nil
			snapshot := filepath.Join(f.path, "bindings.json")
			switch mode {
			case "matched-rollback":
				for path, value := range old {
					if os.WriteFile(path, []byte(value), 0600) != nil {
						t.Fatal("restore fixture")
					}
				}
			case "snapshot-only":
				os.WriteFile(snapshot, []byte(old[snapshot]), 0600)
			case "lost-snapshot":
				os.Remove(snapshot)
			case "lost-floor":
				raw, e := os.ReadFile(snapshot)
				if e != nil {
					t.Fatal(e)
				}
				var obj map[string]any
				if json.Unmarshal(raw, &obj) != nil {
					t.Fatal("fixture JSON")
				}
				delete(obj, "j7")
				raw, _ = json.Marshal(obj)
				os.WriteFile(snapshot, raw, 0600)
			case "lost-journal":
				os.Remove(filepath.Join(f.path, "audit", auditName(1)))
			}
			before := recoveryFiles(t, f.path)
			s, e := openJ7Store(f.dir, f.uid, fixtureAuditClock{}, expected)
			if e == nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("lost/rolled-back J7 state admitted")
			}
			if !reflect.DeepEqual(before, recoveryFiles(t, f.path)) {
				t.Fatal("rejected restore rewrote evidence")
			}
		})
	}
}

// Every journal/snapshot boundary fences the current instance; startup either
// finds the old exact pair before any journal effect or the complete new pair
// after durable installation. Intermediate pairs refuse without repair.
func TestJ7RecoveryCommitBoundaries(t *testing.T) {
	for _, point := range []string{"prepare", "before-journal", "after-journal", "snapshot-write", "snapshot-sync", "snapshot-rename", "snapshot-directory-sync"} {
		t.Run(point, func(t *testing.T) {
			f := j7StateSetup(t)
			f.publish(t, f.table(1))
			old := j7Head(t, f.store)
			f.store.j7Fault = func(p string) Code {
				if p == point {
					return "j7_state_fenced"
				}
				return ""
			}
			f.store.mu.Lock()
			f.store.j7 = cloneJ7(f.store.j7)
			f.store.j7.Denials = append(f.store.j7.Denials, j7Denial{f.origin.key(), strings.Repeat("e", 64), 1})
			code := f.store.commitJ7(t.Context())
			commit := f.store.journal.binding
			f.store.mu.Unlock()
			if code != "j7_state_fenced" || !f.store.failed {
				t.Fatal("injected failure not fenced", point, code)
			}
			f.store.Close()
			f.store = nil
			expect := old
			shouldOpen := point == "prepare" || point == "before-journal"
			if point == "snapshot-rename" || point == "snapshot-directory-sync" {
				expect = j7Expectation{commit.Version, commit.Digest}
				shouldOpen = true
			}
			before := recoveryFiles(t, f.path)
			s, e := openJ7Store(f.dir, f.uid, fixtureAuditClock{}, expect)
			if !shouldOpen {
				if e == nil {
					if s != nil {
						s.Close()
					}
					t.Fatal("interrupted commit admitted")
				}
				if !reflect.DeepEqual(before, recoveryFiles(t, f.path)) {
					t.Fatal("interrupted evidence repaired")
				}
			} else {
				if e != nil {
					t.Fatal("complete surviving pair refused", e)
				}
				f.store = s
				f.policy.store = s
			}
		})
	}
}

// A policy publication's prepared floor is never usable before its file and
// completion commit. Every actual file write/sync/rename interruption retains a
// pending/fenced state, including cases where the new file itself survived.
func TestJ7RecoveryPolicyPublicationBoundaries(t *testing.T) {
	for _, point := range []string{"policy-prepared", "policy-write", "policy-sync", "policy-rename", "policy-directory-sync"} {
		t.Run(point, func(t *testing.T) {
			f := j7StateSetup(t)
			f.publish(t, f.table(1))
			p := f.table(2)
			p.Rows[0].Use = []string{}
			f.store.j7Fault = func(p string) Code {
				if p == point {
					return "j7_state_fenced"
				}
				return ""
			}
			if code := f.policy.publish(t.Context(), j7PolicyRaw(t, p)); code != "j7_state_fenced" {
				t.Fatal("publication interruption accepted", code)
			}
			if code := f.policy.permission(t.Context(), f.origin, "use", []string{strings.Repeat("d", 64)}, nil); code != "j7_state_fenced" {
				t.Fatal("partial publication usable", code)
			}
			commit := f.store.journal.binding
			expected := j7Expectation{commit.Version, commit.Digest}
			f.store.Close()
			f.store = nil
			before := recoveryFiles(t, f.path)
			s, e := openJ7Store(f.dir, f.uid, fixtureAuditClock{}, expected)
			if e == nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("pending publication admitted after restart")
			}
			if !reflect.DeepEqual(before, recoveryFiles(t, f.path)) {
				t.Fatal("pending publication evidence changed")
			}
		})
	}
}

// Schema4 retains native IDs, bindings, message certificates and their immutable
// artifacts through ordinary mutation, snapshot preview and replay. This tests
// existing message snapshot work, not publication/activation of message keys.
func TestJ7RecoveryMessageCoexistence(t *testing.T) {
	f := messageStateSetup(t)
	s := f.store
	id, c := f.service.issue(t.Context(), f.binding)
	if c != "" {
		t.Fatal("prior message fixture", c)
	}
	cert := s.messages.Certificates[0]
	tx := s.messages.Transactions[0]
	beforeNative := append([]retainedRequest{}, s.requests...)
	if c := s.migrateJ7(t.Context(), j7Head(t, s), strings.Repeat("1", 32), f.binding.Number); c != "" {
		t.Fatal("message/J7 migrate", c)
	}
	policyDir := t.TempDir()
	if os.Chmod(policyDir, 0700) != nil {
		t.Fatal("policy fixture")
	}
	policy := j7FixturePolicy(t, filepath.Join(policyDir, "table.json"), uint32(os.Getuid()), s)
	defer policy.close()
	table := &j7PolicyTable{Format: "keymaker-j7-policy/1", Instance: s.j7.Instance, Identity: f.binding.Number, Version: 1, Rows: []j7PolicyRow{{Origin: j7OriginKey{Kind: "owner_command"}, Use: []string{}, Delegate: []string{}, Consent: []j7ConsentPermission{}, Deny: []string{strings.Repeat("d", 64)}}}}
	if c := policy.publish(t.Context(), j7PolicyRaw(t, table)); c != "" {
		t.Fatal("coexisting policy", c)
	}

	if s.schema != j7Schema || s.messageTx(id) == nil || s.messages.Certificates[0] != cert || !reflect.DeepEqual(s.messages.Transactions[0], tx) {
		t.Fatal("migration lost message state")
	}
	s.mu.Lock()
	preview := s.messagePreview()
	if preview.j7 != s.j7 {
		t.Fatal("preview lost participant")
	}
	s.mu.Unlock()
	next := fixtureBinding(f.binding.UID + 1)
	next.Path = "m/1'/1'/1'/2'"
	if _, c := s.Register(fixtureOperator, fixtureOperator, next); c != "" {
		t.Fatal("ordinary binding commit", c)
	}
	entry := retainedRequest{Caller: fixtureOperator, ID: strings.Repeat("a", 32), Method: "hello", Arguments: "{}", Status: "committed", Result: []byte(`{"version":1}`)}
	s.mu.Lock()
	s.appendRequest(entry)
	c = s.persistContext(t.Context())
	s.mu.Unlock()
	if c != "" {
		t.Fatal("retained request commit", c)
	}
	candidate, _, code := s.messageRecoverySnapshot(s.journal.binding, id)
	if code != "" || candidate == nil || !reflect.DeepEqual(candidate.j7, s.j7) {
		t.Fatal("message recovery clone lost J7", code)
	}

	expected := j7Head(t, s)
	if s.Close() != nil {
		t.Fatal("close")
	}
	f.store = nil
	s, e := openJ7Store(f.dir, uint32(os.Getuid()), fixtureAuditClock{}, expected)
	if e != nil {
		t.Fatal("message/J7 reopen", e)
	}
	defer s.Close()
	if s.j7 == nil || s.messages.Certificates[0] != cert || !reflect.DeepEqual(s.messages.Transactions[0], tx) || len(s.requests) != len(beforeNative)+1 || !bytes.Equal(s.requests[len(s.requests)-1].Result, entry.Result) {
		t.Fatal("snapshot/replay lost a participant")
	}
	if e := s.validateMessages(); e != nil {
		t.Fatal("message artifacts changed", e)
	}
}

// Migration requires the exact paired operator expectation and a real existing
// identity. Invalid expectations cannot append a commit or reset any state.
func TestJ7RecoveryMigrationAuthority(t *testing.T) {
	f := j7StateSetup(t)
	before := recoveryFiles(t, f.path)
	old := j7Head(t, f.store)
	if c := f.store.migrateJ7(context.Background(), old, strings.Repeat("2", 32), f.binding.Number); c != "j7_state_fenced" {
		t.Fatal("established J7 reinitialized", c)
	}
	if !reflect.DeepEqual(before, recoveryFiles(t, f.path)) {
		t.Fatal("repeat migration changed files")
	}
}

// A real unavailable audit descriptor refuses publication before any table
// replacement. No cached permission can survive the resulting Store fence.
func TestJ7RecoveryAuditFailure(t *testing.T) {
	f := j7StateSetup(t)
	old := f.publish(t, f.table(1))
	path := filepath.Join(f.policy.dir.Name(), f.policy.name)
	if e := f.store.journal.file.Close(); e != nil {
		t.Fatal(e)
	}
	if c := f.policy.publish(t.Context(), j7PolicyRaw(t, f.table(2))); c != "audit_unavailable" {
		t.Fatal("audit failure disguised", c)
	}
	current, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(old, current) {
		t.Fatal("audit failure published policy", e)
	}
	if c := f.policy.permission(t.Context(), f.origin, "use", []string{strings.Repeat("d", 64)}, nil); c != "j7_state_fenced" {
		t.Fatal("audit-failed store used cached authority", c)
	}
}

// A subprocess exits after actual staged policy fsync. Its prepared floor and
// unknown intent survive; a fresh reader refuses without publishing/erasing it.
// This is process-crash evidence, not a host power-loss qualification.
func TestJ7RecoveryAbruptPublication(t *testing.T) {
	if path := os.Getenv("KEYMAKER_J7_CRASH_STATE"); path != "" {
		uid := uint32(os.Getuid())
		dir, e := OpenDirectory(path, uid, 0700)
		if e != nil {
			t.Fatal(e)
		}
		defer dir.Close()
		lock, e := LockState(dir, uid)
		if e != nil {
			t.Fatal(e)
		}
		defer lock.Close()
		version, e := strconv.ParseUint(os.Getenv("KEYMAKER_J7_CRASH_VERSION"), 10, 64)
		if e != nil {
			t.Fatal(e)
		}
		s, e := openJ7Store(dir, uid, fixtureAuditClock{}, j7Expectation{version, os.Getenv("KEYMAKER_J7_CRASH_DIGEST")})
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		policy := j7FixturePolicy(t, os.Getenv("KEYMAKER_J7_CRASH_POLICY"), uid, s)
		defer policy.close()
		next := *s.j7.Policy
		next.Version++
		next.Rows = append([]j7PolicyRow{}, next.Rows...)
		next.Rows[0].Use = []string{}
		s.j7Fault = func(point string) Code {
			if point == "policy-sync" {
				os.Exit(73)
			}
			return ""
		}
		code := policy.publish(t.Context(), j7PolicyRaw(t, &next))
		t.Fatal("crash point not reached", code)
	}
	f := j7StateSetup(t)
	old := f.publish(t, f.table(1))
	expected := j7Head(t, f.store)
	f.store.Close()
	f.store = nil
	if e := f.lock.Close(); e != nil {
		t.Fatal(e)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, exe, "-test.run=^TestJ7RecoveryAbruptPublication$", "-test.timeout=8s")
	command.Env = []string{"KEYMAKER_J7_CRASH_STATE=" + f.path, "KEYMAKER_J7_CRASH_VERSION=" + strconv.FormatUint(expected.Version, 10), "KEYMAKER_J7_CRASH_DIGEST=" + expected.Digest, "KEYMAKER_J7_CRASH_POLICY=" + filepath.Join(f.policy.dir.Name(), f.policy.name), "HOME=" + os.Getenv("HOME"), "TMPDIR=" + os.Getenv("TMPDIR")}
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	if e := command.Start(); e != nil {
		t.Fatal(e)
	}
	t.Logf("started publication crash pid=%d", command.Process.Pid)
	e = command.Wait()
	status, ok := e.(*exec.ExitError)
	if !ok || status.ExitCode() != 73 {
		t.Fatalf("intended crash absent: %v %s", e, output.String())
	}
	t.Logf("reaped publication crash pid=%d exit=73", command.Process.Pid)
	current, e := os.ReadFile(filepath.Join(f.policy.dir.Name(), f.policy.name))
	if e != nil || !bytes.Equal(current, old) {
		t.Fatal("crash published partial policy", e)
	}
	stage, e := os.ReadFile(filepath.Join(f.policy.dir.Name(), "."+f.policy.name+".next"))
	if e != nil || len(stage) == 0 {
		t.Fatal("unknown intent absent", e)
	}
	before := recoveryFiles(t, f.path)
	s, e := openJ7Store(f.dir, f.uid, fixtureAuditClock{}, expected)
	if e == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("crash resurrected old authority")
	}
	if !reflect.DeepEqual(before, recoveryFiles(t, f.path)) {
		t.Fatal("crash recovery changed state")
	}
	after, e := os.ReadFile(filepath.Join(f.policy.dir.Name(), "."+f.policy.name+".next"))
	if e != nil || !bytes.Equal(stage, after) {
		t.Fatal("crash intent erased")
	}
}

// The public state fixture decodes only as a supported participant. Its hash
// references are not journal proof; negative fixtures cannot become an empty
// authority or borrow the reserved schema3 reader.
func TestJ7RecoveryPublicFixtures(t *testing.T) {
	var vectors struct {
		Format   string `json:"format"`
		Note     string `json:"note"`
		Positive []struct {
			ID       string          `json:"id"`
			Snapshot json.RawMessage `json:"snapshot"`
		} `json:"positive"`
		Negative []struct {
			ID       string          `json:"id"`
			Snapshot json.RawMessage `json:"snapshot"`
			Expected string          `json:"expected"`
		} `json:"negative"`
	}
	raw, e := os.ReadFile("../../vectors/j7/state.json")
	if e != nil || StrictJSON(bytes.NewReader(raw), &vectors) != nil || vectors.Format != "keymaker-j7-state-vectors/1" || len(vectors.Positive) != 1 || len(vectors.Negative) != 7 {
		t.Fatal("state vector identity", e)
	}
	check := func(raw []byte) error {
		var d bindingDisk
		if e := StrictJSON(bytes.NewReader(raw), &d); e != nil {
			return e
		}
		s := NewStore()
		s.schema, s.j7, s.messages = d.SchemaVersion, d.J7, d.Messages
		s.records, s.requests, s.next = d.Records, d.Requests, d.Next
		return s.validateJ7()
	}
	for _, v := range vectors.Positive {
		if e := check(v.Snapshot); e != nil {
			t.Fatal("public state positive", v.ID, e)
		}
	}
	for _, v := range vectors.Negative {
		if e := check(v.Snapshot); e == nil || v.Expected != "fenced" {
			t.Fatal("public state negative", v.ID, e)
		}
	}
}

// A valid full retained-ID fixture is actually journal/snapshot committed, and
// one more entry refuses without an effect. This is Store capacity/persistence
// evidence; no race-instrumented maximum-size native latency is claimed.
func TestJ7RecoveryRetainedCapacity(t *testing.T) {
	f := j7StateSetup(t)
	s := f.store
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.requests) < maxRetainedRequests {
		n := len(s.requests)
		s.appendRequest(retainedRequest{Caller: fixtureOperator, ID: fmt.Sprintf("%032x", 10000+n), Method: "hello", Arguments: "{}", Status: "committed", Result: []byte(`{"version":1}`)})
	}
	s.requestIndex = map[requestKey]int{}
	if e := s.validateRequests(); e != nil {
		t.Fatal("dense retained fixture invalid", e)
	}
	if !s.fitsState(s.records, s.next, s.requests) {
		t.Fatal("inclusive retained count rejected")
	}
	if c := s.commitJ7(t.Context()); c != "" {
		t.Fatal("dense retained state not durable", c)
	}
	before := recoveryFiles(t, f.path)
	commit := s.journal.binding
	extra := retainedRequest{Caller: fixtureOperator, ID: strings.Repeat("f", 32), Method: "hello", Arguments: "{}", Status: "committed", Result: []byte(`{"version":1}`)}
	prospective := append(append([]retainedRequest{}, s.requests...), extra)
	if s.fitsState(s.records, s.next, prospective) {
		t.Fatal("retained count overflow accepted")
	}
	if s.journal.binding != commit || !reflect.DeepEqual(before, recoveryFiles(t, f.path)) {
		t.Fatal("retained preflight wrote state")
	}
}
