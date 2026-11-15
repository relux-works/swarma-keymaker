//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/relux-works/swarma-keymaker/internal/control"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func j7RestartSigning(t *testing.T, f *j7SignFixture) {
	t.Helper()
	f.stop()
	<-f.done
	f.f.store.mu.Lock()
	expected := j7Head(t, f.f.store)
	f.f.store.mu.Unlock()
	f.f.store.Close()
	f.f.store = nil
	s, e := openJ7SigningStore(f.f.dir, f.f.uid, fixtureAuditClock{}, expected)
	if e != nil {
		t.Fatal("current signing reader restart", e)
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
	wire, e := control.New(a, a, a, a, a)
	if e != nil {
		t.Fatal(e)
	}
	address := fmt.Sprintf("@j7-signing-restart-%d-%d", os.Getpid(), j7SocketCounter.Add(1))
	listener, e := net.Listen("unix", address)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- wire.Serve(ctx, listener); close(done) }()
	f.socket, f.stop, f.done = address, cancel, done
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("restart server did not stop")
		}
	})
}

type j7FaultListener struct {
	net.Listener
	limit   int
	written *atomic.Int64
}
type j7FaultConn struct {
	*net.UnixConn
	limit   int
	writes  int
	written *atomic.Int64
}

func (l j7FaultListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return c, e
	}
	return &j7FaultConn{UnixConn: c.(*net.UnixConn), limit: l.limit, written: l.written}, nil
}
func (c *j7FaultConn) Write(b []byte) (int, error) {
	c.writes++
	if c.writes == 3 && c.limit >= 0 {
		if c.limit == 0 {
			return 0, io.ErrClosedPipe
		}
		limit := c.limit
		if limit > len(b) {
			limit = len(b)
		}
		n, e := c.UnixConn.Write(b[:limit])
		c.written.Store(int64(n))
		if e != nil {
			return n, e
		}
		return n, io.ErrUnexpectedEOF
	}
	return c.UnixConn.Write(b)
}

// Zero/partial actual Unix writes leave durable unknown, never released or
// enrollment-ready. The old readers and exact-head current reader refuse
// unknown continuity without changing files; an intact write/restart is positive.
func TestJ7SigningHandoffRecovery(t *testing.T) {
	for _, mode := range []struct {
		name  string
		limit int
	}{{"intact", -1}, {"zero-write", 0}, {"partial-write", 17}} {
		t.Run(mode.name, func(t *testing.T) {
			var written atomic.Int64
			f := j7SigningSetupOptions(t, nil, func(l net.Listener) net.Listener {
				return j7FaultListener{Listener: l, limit: mode.limit, written: &written}
			})
			c := f.dial(t, 1)
			f.bind(t, c, 2, f.f.origin, f.f.uid+200)
			nativeSend(t, c, nativeRequest(3, "j7_sign", f.consent(t)))
			if mode.limit < 0 {
				j7ResultEvent(t, nativeResponse(t, nativeReceive(t, c), nativeID(3), ""))
			} else {
				raw, e := io.ReadAll(io.LimitReader(c, 65537))
				if e != nil {
					t.Fatal("transport setup", e)
				}
				if len(raw) != mode.limit || written.Load() != int64(mode.limit) {
					t.Fatal("intended write control not exercised", len(raw), written.Load())
				}
				if len(raw) >= 4 && int(binary.BigEndian.Uint32(raw[:4])) <= len(raw)-4 {
					t.Fatal("partial write exposed complete result")
				}
			}

			if mode.limit < 0 {
				f.f.store.mu.Lock()
				valid := !f.f.store.failed && f.f.store.j7SigningRecord(f.a.launcher, nativeID(3)).Release == "released"
				f.f.store.mu.Unlock()
				if !valid {
					t.Fatal("intact final durability failed")
				}
			}
			f.stop()
			<-f.done
			f.f.store.mu.Lock()
			rec := f.f.store.j7SigningRecord(f.a.launcher, nativeID(3))
			state := rec.Release
			count := len(f.f.store.j7Signing.Enrollments)
			f.f.store.mu.Unlock()
			want := "handoff_unknown"
			if mode.limit < 0 {
				want = "released"
			}
			if state != want || count != 0 {
				t.Fatal("handoff continuity verdict", state, count)
			}
			expected := j7Head(t, f.f.store)
			f.f.store.Close()
			f.f.store = nil
			before := recoveryFiles(t, f.f.path)
			for _, floor := range []int{0, 2, j7Schema} {
				s, _, _, e := openCustodyStateMessage(f.f.dir, f.f.uid, fixtureAuditClock{}, floor, false)
				if e == nil {
					if s != nil {
						s.Close()
					}
					t.Fatal("old reader accepted signing state")
				}
				if !reflect.DeepEqual(before, recoveryFiles(t, f.f.path)) {
					t.Fatal("old reader changed signing state")
				}
			}
			wrong := expected
			wrong.Digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			if s, e := openJ7SigningStore(f.f.dir, f.f.uid, fixtureAuditClock{}, wrong); e == nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("wrong independent signing head accepted")
			}
			s, e := openJ7SigningStore(f.f.dir, f.f.uid, fixtureAuditClock{}, expected)
			if mode.limit < 0 {
				if e != nil {
					t.Fatal("exact current-reader positive", e)
				}
				f.f.store = s
				f.f.policy.store = s
			} else {
				if e == nil {
					if s != nil {
						s.Close()
					}
					t.Fatal("unknown handoff became releasable state")
				}
				if !reflect.DeepEqual(before, recoveryFiles(t, f.f.path)) {
					t.Fatal("unknown recovery rewrote evidence")
				}
			}
		})
	}
}

// Explicit schema4->5 migration requires the exact independently retained head;
// an unrelated expected digest cannot mutate either participant or audit bytes.
func TestJ7SigningMigrationAuthority(t *testing.T) {
	f := j7StateSetup(t)
	f.publish(t, f.table(1))
	head := j7Head(t, f.store)
	bad := head
	bad.Digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	before := recoveryFiles(t, f.path)
	if c := f.store.migrateJ7Signing(t.Context(), bad); c != "j7_state_fenced" {
		t.Fatal("wrong signing migration head accepted", c)
	}
	if !reflect.DeepEqual(before, recoveryFiles(t, f.path)) {
		t.Fatal("refused signing migration changed evidence")
	}
	if c := f.store.migrateJ7Signing(t.Context(), head); c != "" {
		t.Fatal("exact migration positive", c)
	}
	if f.store.schema != j7SigningSchema || f.store.j7Signing == nil || len(f.store.j7Signing.Records) != 0 || len(f.store.j7Signing.Enrollments) != 0 {
		t.Fatal("explicit participant missing")
	}
}

// All actual snapshot/journal phases of a new prepared signature are exercised.
// Startup accepts only a surviving complete exact pair; an interrupted pair is
// preserved and refused. This is process/file fault evidence, not power loss.
func TestJ7SigningCommitBoundaries(t *testing.T) {
	for _, point := range []string{"prepare", "before-journal", "after-journal", "snapshot-write", "snapshot-sync", "snapshot-rename", "snapshot-directory-sync", "signing-prepared", "signing-handoff-unknown", "signing-after-write"} {
		t.Run(point, func(t *testing.T) {
			f := j7SigningSetup(t)
			c := f.dial(t, 1)
			f.bind(t, c, 2, f.f.origin, f.f.uid+200)
			f.f.store.mu.Lock()
			old := j7Head(t, f.f.store)
			f.f.store.j7Fault = func(p string) Code {
				if p == point {
					return "j7_state_fenced"
				}
				return ""
			}
			f.f.store.mu.Unlock()
			nativeSend(t, c, nativeRequest(3, "j7_sign", f.consent(t)))
			if point == "signing-after-write" {
				j7ResultEvent(t, nativeResponse(t, nativeReceive(t, c), nativeID(3), ""))
			} else {
				nativeResponse(t, nativeReceive(t, c), nativeID(3), "j7_state_fenced")
			}
			f.stop()
			<-f.done
			f.f.store.mu.Lock()
			failed := f.f.store.failed
			commit := f.f.store.journal.binding
			f.f.store.mu.Unlock()
			if !failed {
				t.Fatal("failed signing commit remained usable")
			}
			f.f.store.Close()
			f.f.store = nil
			expected := j7Expectation{commit.Version, commit.Digest}
			shouldOpen := point == "prepare" || point == "before-journal" || point == "snapshot-rename" || point == "snapshot-directory-sync" || point == "signing-prepared"
			if point == "prepare" || point == "before-journal" {
				expected = old
			}
			before := recoveryFiles(t, f.f.path)
			s, e := openJ7SigningStore(f.f.dir, f.f.uid, fixtureAuditClock{}, expected)
			if shouldOpen {
				if e != nil {
					t.Fatal("complete prepared pair refused", e)
				}
				f.f.store = s
				f.f.policy.store = s
				if len(s.j7Signing.Enrollments) != 0 {
					t.Fatal("interrupted signature enrolled")
				}
			} else {
				if e == nil {
					if s != nil {
						s.Close()
					}
					t.Fatal("uncertain signature pair admitted")
				}
				if !reflect.DeepEqual(before, recoveryFiles(t, f.f.path)) {
					t.Fatal("uncertain evidence rewritten")
				}
			}
		})
	}
}

// A lost/corrupt signing participant, snapshot or audit cannot silently become
// an empty signing history. An intact exact-head restart is the positive control.
func TestJ7SigningRecoveryLoss(t *testing.T) {
	for _, mode := range []string{"intact", "lost-snapshot", "lost-journal", "missing-participant", "null-participant", "missing-records", "altered-result"} {
		t.Run(mode, func(t *testing.T) {
			f := j7SigningSetup(t)
			c := f.dial(t, 1)
			f.bind(t, c, 2, f.f.origin, f.f.uid+200)
			j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
			// Client read completion precedes the post-write durability commit.
			f.f.store.mu.Lock()
			released := f.f.store.j7SigningRecord(f.a.launcher, nativeID(3)).Release == "released" && !f.f.store.failed
			f.f.store.mu.Unlock()
			if !released {
				t.Fatal("intact release commit did not complete")
			}
			f.stop()
			<-f.done
			expected := j7Head(t, f.f.store)
			f.f.store.Close()
			f.f.store = nil
			path := filepath.Join(f.f.path, "bindings.json")
			switch mode {
			case "lost-snapshot":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
			case "lost-journal":
				if e := os.Remove(filepath.Join(f.f.path, "audit", auditName(1))); e != nil {
					t.Fatal(e)
				}
			case "missing-participant", "null-participant", "missing-records", "altered-result":
				raw, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				var obj map[string]json.RawMessage
				if e = json.Unmarshal(raw, &obj); e != nil {
					t.Fatal(e)
				}
				if mode == "missing-participant" {
					delete(obj, "j7_signing")
				}
				if mode == "null-participant" {
					obj["j7_signing"] = json.RawMessage("null")
				}
				if mode == "missing-records" {
					var inv map[string]json.RawMessage
					json.Unmarshal(obj["j7_signing"], &inv)
					delete(inv, "records")
					obj["j7_signing"], _ = json.Marshal(inv)
				}
				if mode == "altered-result" {
					obj["j7_signing"] = json.RawMessage(strings.Replace(string(obj["j7_signing"]), `"released"`, `"prepared"`, 1))
				}
				raw, e = json.Marshal(obj)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(path, raw, 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := recoveryFiles(t, f.f.path)
			s, e := openJ7SigningStore(f.f.dir, f.f.uid, fixtureAuditClock{}, expected)
			if mode == "intact" {
				if e != nil {
					t.Fatal("intact recovery", e)
				}
				f.f.store = s
				f.f.policy.store = s
				return
			}
			if e == nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("lost signing evidence admitted")
			}
			if !reflect.DeepEqual(before, recoveryFiles(t, f.f.path)) {
				t.Fatal("lost signing evidence rewritten")
			}
		})
	}
}

// Schema5 preserves prior message/native/binding/J7 bytes and artifacts through
// its explicit migration, preview, message recovery clone and exact-head restart.
func TestJ7SigningMessageCoexistence(t *testing.T) {
	f := messageStateSetup(t)
	s := f.store
	id, c := f.service.issue(t.Context(), f.binding)
	if c != "" {
		t.Fatal(c)
	}
	if c = s.migrateJ7(t.Context(), j7Head(t, s), strings.Repeat("1", 32), f.binding.Number); c != "" {
		t.Fatal(c)
	}
	before, _ := canonical(struct {
		Messages *messageInventory
		Requests []retainedRequest
		Records  []Binding
		J7       *j7Inventory
	}{s.messages, s.requests, s.records, s.j7})
	files := recoveryFiles(t, f.path)
	if c = s.migrateJ7Signing(t.Context(), j7Head(t, s)); c != "" {
		t.Fatal(c)
	}
	preserved := func(s *Store) {
		t.Helper()
		after, _ := canonical(struct {
			Messages *messageInventory
			Requests []retainedRequest
			Records  []Binding
			J7       *j7Inventory
		}{s.messages, s.requests, s.records, s.j7})
		if !bytes.Equal(before, after) || s.j7Signing == nil {
			t.Fatal("schema5 lost existing participants")
		}
		for path, raw := range files {
			if strings.Contains(path, "/message-tx/") && recoveryFiles(t, f.path)[path] != raw {
				t.Fatal("prior artifact changed")
			}
		}
		if e := s.validateMessages(); e != nil {
			t.Fatal(e)
		}
	}
	preserved(s)
	s.mu.Lock()
	preview := s.messagePreview()
	s.mu.Unlock()
	if preview.j7Signing != s.j7Signing {
		t.Fatal("preview dropped signing participant")
	}
	candidate, _, code := s.messageRecoverySnapshot(s.journal.binding, id)
	if code != "" || candidate == nil || !reflect.DeepEqual(candidate.j7Signing, s.j7Signing) {
		t.Fatal("message recovery dropped signing participant", code)
	}
	expected := j7Head(t, s)
	s.Close()
	f.store = nil
	reopened, e := openJ7SigningStore(f.dir, uint32(os.Getuid()), fixtureAuditClock{}, expected)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	preserved(reopened)
}

// The real inclusive retained-ID bound includes the schema5 participant and is
// committed. One more candidate refuses preflight without state effects. This
// is Store capacity evidence, NOT maximum-density native-deadline qualification.
func TestJ7SigningCapacityPreflight(t *testing.T) {
	f := j7SigningSetup(t)
	f.stop()
	<-f.done
	s := f.f.store
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.requests) < maxRetainedRequests {
		n := len(s.requests)
		s.appendRequest(retainedRequest{Caller: fixtureOperator, ID: fmt.Sprintf("%032x", 10000+n), Method: "hello", Arguments: "{}", Status: "committed", Result: []byte(`{"version":1}`)})
	}
	if !s.fitsState(s.records, s.next, s.requests) {
		t.Fatal("inclusive positive capacity")
	}
	if code := s.commitJ7(t.Context()); code != "" {
		t.Fatal("full retained positive", code)
	}
	before := recoveryFiles(t, f.f.path)
	commit := s.journal.binding
	extra := retainedRequest{Caller: fixtureOperator, ID: strings.Repeat("f", 32), Method: "hello", Arguments: "{}", Status: "committed", Result: []byte(`{"version":1}`)}
	if s.fitsState(s.records, s.next, append(append([]retainedRequest{}, s.requests...), extra)) {
		t.Fatal("schema5 retained capacity overflow accepted")
	}
	if len(s.j7Signing.Records) != 0 || len(s.requests) != maxRetainedRequests || s.failed || s.journal.binding != commit || !reflect.DeepEqual(before, recoveryFiles(t, f.f.path)) {
		t.Fatal("capacity preflight changed state")
	}
}

// A full actual response write followed by refusal from the FINAL commit
// itself remains unknown/fenced on restart, not released enrollment evidence.
// The injected pre-journal failure is process-level, not a power-loss model.
func TestJ7SigningPostWriteCommitFailure(t *testing.T) {
	f := j7SigningSetup(t)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	commits := 0
	f.f.store.mu.Lock()
	f.f.store.j7Fault = func(p string) Code {
		if p == "prepare" {
			commits++
		}
		if commits == 3 && p == "before-journal" {
			return "j7_state_fenced"
		}
		return ""
	}
	f.f.store.mu.Unlock()
	j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
	f.f.store.mu.Lock()
	unknown := f.f.store.j7SigningRecord(f.a.launcher, nativeID(3)).Release == "handoff_unknown" && f.f.store.failed && commits == 3
	expected := j7Head(t, f.f.store)
	f.f.store.mu.Unlock()
	if !unknown {
		t.Fatal("final commit failure did not retain unknown fence")
	}
	f.stop()
	<-f.done
	f.f.store.Close()
	f.f.store = nil
	before := recoveryFiles(t, f.f.path)
	s, e := openJ7SigningStore(f.f.dir, f.f.uid, fixtureAuditClock{}, expected)
	if e == nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("failed final commit became released")
	}
	if !reflect.DeepEqual(before, recoveryFiles(t, f.f.path)) {
		t.Fatal("failed final commit evidence rewritten")
	}
}
