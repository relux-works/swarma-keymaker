//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

func j7DelegationRestart(t *testing.T, f *j7SignFixture) {
	t.Helper()
	f.f.store.mu.Lock()
	healthy := !f.f.store.failed && !f.f.store.j7UnknownHandoff()
	f.f.store.mu.Unlock()
	if !healthy {
		t.Fatal("release not durably complete before stopped restart")
	}
	f.stop()
	<-f.done
	f.f.store.mu.Lock()
	head := j7Head(t, f.f.store)
	f.f.store.mu.Unlock()
	f.f.store.Close()
	f.f.store = nil
	s, e := openJ7DelegationStore(f.f.dir, f.f.uid, fixtureAuditClock{}, head)
	if e != nil {
		t.Fatal("schema6 exact restart", e)
	}
	f.f.store = s
	f.f.policy.store = s
	l, e := newJ7Lifecycle(s, f.f.policy, f.gen, f.a.launcher)
	if e != nil {
		t.Fatal(e)
	}
	a, e := newJ7RequestCustody(l, f.a.key, f.a.clock, f.a.evidence)
	if e != nil {
		t.Fatal(e)
	}
	f.a = a
	j7DelegationServe(t, f, nil)
}

// Stopped migration preserves complete retained5 participant bytes and requires
// the independent head. Default/2/4/5 readers refuse6 without writes; exact6
// restarts. An unchanged actual40b9 reader is additionally exercised privately.
func TestJ7DelegationMigrationAndOldReader(t *testing.T) {
	f := j7SigningSetup(t)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	j7Call(t, c, 3, "j7_sign", f.consent(t), "")
	j7DelegationWaitReleased(t, f, 3)
	f.stop()
	<-f.done
	head := j7Head(t, f.f.store)
	bad := head
	bad.Digest = strings.Repeat("f", 64)
	before := recoveryFiles(t, f.f.path)
	if code := f.f.store.migrateJ7Delegation(t.Context(), bad); code != "j7_state_fenced" {
		t.Fatal("wrong migration head", code)
	}
	if !reflect.DeepEqual(before, recoveryFiles(t, f.f.path)) {
		t.Fatal("rejected migration changed authority")
	}
	participants, _ := canonical(struct {
		J7       *j7Inventory
		Signing  *j7SigningInventory
		Requests []retainedRequest
		Bindings []Binding
	}{f.f.store.j7, f.f.store.j7Signing, f.f.store.requests, f.f.store.records})
	if e := f.f.store.validateJ7(); e != nil {
		t.Fatal("pre-migration participant validation", e)
	}
	if !f.f.store.j7HeadMatches(head) || f.f.store.failed {
		t.Fatal("pre-migration exact pair unavailable", f.f.store.failed)
	}
	if code := f.f.store.migrateJ7Delegation(t.Context(), head); code != "" {
		t.Fatal("migration positive", code)
	}
	after, _ := canonical(struct {
		J7       *j7Inventory
		Signing  *j7SigningInventory
		Requests []retainedRequest
		Bindings []Binding
	}{f.f.store.j7, f.f.store.j7Signing, f.f.store.requests, f.f.store.records})
	if !bytes.Equal(participants, after) || f.f.store.schema != 6 || j7StateSchema(3) {
		t.Fatal("migration lost participants or aliased PC2")
	}
	head = j7Head(t, f.f.store)
	f.f.store.Close()
	f.f.store = nil
	before = recoveryFiles(t, f.f.path)
	for _, floor := range []int{0, 2, 4, 5} {
		s, _, _, e := openCustodyStateMessage(f.f.dir, f.f.uid, fixtureAuditClock{}, floor, false)
		if e == nil {
			if s != nil {
				s.Close()
			}
			t.Fatalf("old floor%d admitted6", floor)
		}
		if !reflect.DeepEqual(before, recoveryFiles(t, f.f.path)) {
			t.Fatal("old reader wrote authority", floor)
		}
	}
	if s, e := openJ7DelegationStore(f.f.dir, f.f.uid, fixtureAuditClock{}, bad); e == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("wrong independent6head accepted")
	}
	if !reflect.DeepEqual(before, recoveryFiles(t, f.f.path)) {
		t.Fatal("wrong6head changed authority")
	}
	s, e := openJ7DelegationStore(f.f.dir, f.f.uid, fixtureAuditClock{}, head)
	if e != nil {
		t.Fatal("6positive", e)
	}
	f.f.store = s
	f.f.policy.store = s
	// The historical parser remains5 even in a6 process; the trusted Store selects
	// the new entrypoint, never a caller-provided floor or an operation alias.
	if _, code := j7ParseRequest(control.Request{Method: "j7_sign", Params: j7TypedParams(t, "delegation_request_v3", control.Object{})}); code != "operation_unsupported" {
		t.Fatal("historical parser widened", code)
	}
	empty := t.TempDir()
	os.Chmod(empty, 0700)
	dir, e := OpenDirectory(empty, f.f.uid, 0700)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	if s, e := openJ7DelegationStore(dir, f.f.uid, fixtureAuditClock{}, head); e == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("schema6 bootstrapped missing evidence")
	}
	entries, e := os.ReadDir(empty)
	if e != nil || len(entries) != 0 {
		t.Fatal("missing-evidence opener wrote files", e)
	}
}

// Real socket retry after stopped exact-head restart needs a fresh launcher
// rebind. It preserves the retained nonce/time/signature and current Delegate.
func TestJ7DelegationRestartRetry(t *testing.T) {
	f, c, _, _, p := j7DelegationReady(t)
	result := j7Call(t, c, 4, "j7_sign", p, "")
	f.f.store.mu.Lock()
	run := f.f.store.j7SigningRecord(f.a.launcher, nativeID(4)).Run
	f.f.store.mu.Unlock()
	j7DelegationRestart(t, f)
	next := f.dial(t, 10)
	j7Call(t, next, 11, "j7_sign", p, "run_identity_unavailable")
	j7Call(t, next, 12, "j7_run_rebind", control.Object{"run_id": run}, "")
	if got := j7Call(t, next, 4, "j7_sign", p, ""); !reflect.DeepEqual(got, result) {
		t.Fatal("restart changed signed result")
	}
}

// Every exercised journal/snapshot boundary fences uncertainty. A missing or
// partially paired store cannot be reopened by lowering the reader floor or
// guessing a head. This models process/file faults, not power-loss qualification.
func TestJ7DelegationCrashAndSocketFence(t *testing.T) {
	for _, point := range []string{"prepare", "before-journal", "after-journal", "snapshot-write", "snapshot-sync", "snapshot-rename", "snapshot-directory-sync", "signing-prepared", "signing-handoff-unknown", "signing-after-write"} {
		t.Run(point, func(t *testing.T) {
			f, c, _, _, p := j7DelegationReady(t)
			old := j7Head(t, f.f.store)
			var applied atomic.Bool
			f.f.store.mu.Lock()
			f.f.store.j7Fault = func(at string) Code {
				if at == point {
					applied.Store(true)
					return "j7_state_fenced"
				}
				return ""
			}
			f.f.store.mu.Unlock()
			nativeSend(t, c, nativeRequest(4, "j7_sign", p))
			if point == "signing-after-write" {
				j7ResultEvent(t, nativeResponse(t, nativeReceive(t, c), nativeID(4), ""))
			} else {
				nativeResponse(t, nativeReceive(t, c), nativeID(4), "j7_state_fenced")
			}
			f.stop()
			<-f.done
			if !applied.Load() {
				t.Fatal("fault not applied")
			}
			f.f.store.mu.Lock()
			failed := f.f.store.failed
			f.f.store.mu.Unlock()
			if !failed {
				t.Fatal("uncertain store remained usable")
			}
			f.f.store.Close()
			f.f.store = nil
			before := recoveryFiles(t, f.f.path)
			reopened, e := openJ7DelegationStore(f.f.dir, f.f.uid, fixtureAuditClock{}, old)
			if point == "prepare" || point == "before-journal" {
				if e != nil {
					t.Fatal("intact old pair refused before durable effects", e)
				}
				if reopened.j7SigningRecord(f.a.launcher, nativeID(4)) != nil {
					t.Fatal("uncommitted request survived")
				}
				reopened.Close()
			} else if e == nil {
				reopened.Close()
				t.Fatal("uncertain newer pair accepted old head")
			}
			if !reflect.DeepEqual(before, recoveryFiles(t, f.f.path)) {
				t.Fatal("refused recovery rewrote evidence")
			}
		})
	}
}

// A zero/partial actual callback write leaves durable handoff_unknown and no
// complete response. Final commit loss after a full write also fences reopen.
func TestJ7DelegationPartialWrite(t *testing.T) {
	for _, limit := range []int{0, 17} {
		t.Run(fmt.Sprint(limit), func(t *testing.T) {
			f, c, _, _, p := j7DelegationReady(t)
			f.stop()
			<-f.done
			var written atomic.Int64
			wire, e := control.New(f.a, f.a, f.a, f.a, f.a)
			if e != nil {
				t.Fatal(e)
			}
			address := fmt.Sprintf("@j7-delegation-partial-%d-%d", os.Getpid(), j7SocketCounter.Add(1))
			listener, e := net.Listen("unix", address)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() {
				done <- wire.Serve(ctx, j7FaultListener{Listener: listener, limit: limit, written: &written})
				close(done)
			}()
			f.socket, f.stop, f.done = address, cancel, done
			t.Cleanup(func() { cancel(); listener.Close(); <-done })
			// Hello and rebind occupy writes1/2, so the existing fault listener's write3
			// is the actual delegation response, not setup failure.
			f.f.store.mu.Lock()
			run := f.f.store.j7.Runs[0].ID
			f.f.store.mu.Unlock()
			c = f.dial(t, 10)
			j7Call(t, c, 11, "j7_run_rebind", control.Object{"run_id": run}, "")
			nativeSend(t, c, nativeRequest(4, "j7_sign", p))
			raw, e := io.ReadAll(io.LimitReader(c, 65537))
			if e != nil || len(raw) != limit || written.Load() != int64(limit) {
				t.Fatal("intended partial write not applied", e, len(raw), written.Load())
			}
			if len(raw) >= 4 && int(binary.BigEndian.Uint32(raw[:4])) <= len(raw)-4 {
				t.Fatal("partial write exposed complete result")
			}
			f.stop()
			<-f.done
			f.f.store.mu.Lock()
			rec := f.f.store.j7SigningRecord(f.a.launcher, nativeID(4))
			state := rec.Release
			head := j7Head(t, f.f.store)
			f.f.store.mu.Unlock()
			if state != "handoff_unknown" {
				t.Fatal("unknown missing", state)
			}
			f.f.store.Close()
			f.f.store = nil
			before := recoveryFiles(t, f.f.path)
			if s, e := openJ7DelegationStore(f.f.dir, f.f.uid, fixtureAuditClock{}, head); e == nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("unknown release became usable")
			}
			if !reflect.DeepEqual(before, recoveryFiles(t, f.f.path)) {
				t.Fatal("unknown reopen changed evidence")
			}
		})
	}
}

// Existing base2 messages, native/binding history, J7 policy/denials and signed5
// bytes survive5->6 and exact restart; schema3 is not routed into this format.
func TestJ7DelegationMessageCoexistence(t *testing.T) {
	f := messageStateSetup(t)
	s := f.store
	id, code := f.service.issue(t.Context(), f.binding)
	if code != "" {
		t.Fatal(code)
	}
	if code = s.migrateJ7(t.Context(), j7Head(t, s), strings.Repeat("1", 32), f.binding.Number); code != "" {
		t.Fatal(code)
	}
	if code = s.migrateJ7Signing(t.Context(), j7Head(t, s)); code != "" {
		t.Fatal(code)
	}
	body := func(s *Store) []byte {
		b, e := canonical(struct {
			M *messageInventory
			Q []retainedRequest
			B []Binding
			J *j7Inventory
			S *j7SigningInventory
		}{s.messages, s.requests, s.records, s.j7, s.j7Signing})
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	before := body(s)
	if code = s.migrateJ7Delegation(t.Context(), j7Head(t, s)); code != "" {
		t.Fatal(code)
	}
	if !bytes.Equal(before, body(s)) || s.j7.BaseSchema != 2 {
		t.Fatal("message/native/J7 participant loss")
	}
	if e := s.validateMessages(); e != nil {
		t.Fatal(e)
	}
	candidate, _, code := s.messageRecoverySnapshot(s.journal.binding, id)
	if code != "" || candidate == nil || !reflect.DeepEqual(candidate.j7Signing, s.j7Signing) || candidate.schema != 6 {
		t.Fatal("message recovery lost6", code)
	}
	head := j7Head(t, s)
	s.Close()
	f.store = nil
	reopened, e := openJ7DelegationStore(f.dir, uint32(os.Getuid()), fixtureAuditClock{}, head)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if !bytes.Equal(before, body(reopened)) {
		t.Fatal("restart lost participants")
	}
}

func j7DelegationWaitReleased(t *testing.T, f *j7SignFixture, id int) {
	t.Helper()
	f.f.store.mu.Lock()
	defer f.f.store.mu.Unlock()
	record := f.f.store.j7SigningRecord(f.a.launcher, nativeID(id))
	if f.f.store.failed || record == nil || record.Release != "released" {
		t.Fatal("successful socket write was not durably released")
	}
}

// Validation binds schema6 retained output to the exact operation, grant,
// consent role and local profile. These in-memory corruptions are not a claim
// that a complete old journal/snapshot rollback can be detected without a head.
func TestJ7DelegationRetainedAssociations(t *testing.T) {
	f, c, _, _, p := j7DelegationReady(t)
	j7Call(t, c, 20, "j7_sign", p, "")
	j7DelegationWaitReleased(t, f, 20)
	s := f.f.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.validateJ7Signing(); e != nil {
		t.Fatal("uncorrupted control", e)
	}
	original := cloneJ7Signing(s.j7Signing)
	index := -1
	for i, r := range original.Records {
		if r.ID == nativeID(20) {
			index = i
		}
	}
	if index < 0 {
		t.Fatal("missing retained request")
	}
	for _, mode := range []string{"operation", "grant", "consent", "event", "release"} {
		s.j7Signing = cloneJ7Signing(original)
		r := &s.j7Signing.Records[index]
		switch mode {
		case "operation":
			r.Operation = "envelope_v3"
		case "grant":
			r.Grants[0] = strings.Repeat("f", 64)
		case "consent":
			r.Consent.AndUse = true
		case "event":
			r.EventID = strings.Repeat("f", 64)
		case "release":
			r.Release = "caller_released"
		}
		if e := s.validateJ7Signing(); e == nil {
			t.Fatal("retained association admitted", mode)
		}
	}
	s.j7Signing = original
	if e := s.validateJ7Signing(); e != nil {
		t.Fatal("restored control", e)
	}
}
