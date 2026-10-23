package keymaker

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

// Changed canonical arguments/methods cannot reuse a committed effect ID, even
// across restart. Exact retries (including a timeout change) return the same
// original result without issuing another number or binding transition.
func TestNativeDurableRetries(t *testing.T) {
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
	nativeTarget(f)
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	request := nativeRegisterRequest(2)
	nativeSend(t, c, request)
	first := nativeResponse(t, nativeReceive(t, c), nativeID(2), "")
	for _, change := range []string{"arguments", "method"} {
		t.Run(change, func(t *testing.T) {
			clone := nativeRegisterRequest(2)
			if change == "arguments" {
				clone["params"].(control.Object)["owner"] = "different-owner"
			} else {
				clone = nativeRequest(2, "revoke", control.Object{"registration_number": int64(1), "mode": "operator", "operator_record": nil})
			}
			before := nativeSnapshot(t, f)
			nativeSend(t, c, clone)
			nativeResponse(t, nativeReceive(t, c), nativeID(2), "request_conflict")
			if !bytes.Equal(before, nativeSnapshot(t, f)) {
				t.Fatal("conflicting ID changed state")
			}
		})
	}
	request["timeout_ms"] = int64(1000)
	nativeSend(t, c, request)
	if got := nativeResponse(t, nativeReceive(t, c), nativeID(2), ""); !reflect.DeepEqual(first, got) {
		t.Fatal("retry changed result")
	}
	f.restart(t, nil)
	fresh := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, fresh, 3)
	nativeSend(t, fresh, request)
	if got := nativeResponse(t, nativeReceive(t, fresh), nativeID(2), ""); !reflect.DeepEqual(first, got) {
		t.Fatal("restart lost retained result")
	}
	if rows := f.store.Snapshot(); len(rows) != 1 || rows[0].Number != 1 || f.store.next != 2 {
		t.Fatal("retry repeated binding effect")
	}
	// The same ID is fresh in another authoritative generation, only on a new
	// connection; the previously negotiated connection cannot adopt it.
	f.generation.set(uint32(os.Getuid()), "active", "replacement")
	next := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, next, 1)
}

// Concurrent same-ID requests serialize at the transaction, rather than using
// per-peer mutable context to guess which connection owns an admitted ID.
func TestNativeConcurrentRetry(t *testing.T) {
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
	nativeTarget(f)
	f.start()
	a, b := nativeDial(t, f.server.ControlPath), nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, a, 10)
	nativeNegotiate(t, b, 11)
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan control.Object, 2)
	for _, c := range []*net.UnixConn{a, b} {
		wg.Go(func() {
			var result control.Object
			defer func() { results <- result }()
			<-start
			nativeSend(t, c, nativeRegisterRequest(2))
			result = nativeResponse(t, nativeReceive(t, c), nativeID(2), "")
		})
	}
	close(start)
	wg.Wait()
	one, two := <-results, <-results
	if !reflect.DeepEqual(one, two) {
		t.Fatal("concurrent retry results diverged")
	}
	if rows := f.store.Snapshot(); len(rows) != 1 || f.store.next != 2 {
		t.Fatal("concurrent retry duplicated effect")
	}
}

type nativeSyncCut struct {
	file  *os.File
	calls int
	cut   int
	after func()
	fail  bool
}

func (w *nativeSyncCut) Write(b []byte) (int, error) { return w.file.Write(b) }
func (w *nativeSyncCut) Sync() error {
	if err := w.file.Sync(); err != nil {
		return err
	}
	w.calls++
	if w.calls == w.cut {
		if w.after != nil {
			w.after()
		}
		if w.fail {
			return errors.New("injected durable native cut")
		}
	}
	return nil
}

// An intent-only crash fences before reporting the target absent; a result
// journal ahead of the snapshot also fences. A completed effect with a closed
// response retains its original result for same-ID recovery after restart.
func TestNativeTransactionCrash(t *testing.T) {
	for _, cut := range []string{"intent-only", "result-journal-only", "result-before-response", "intact"} {
		t.Run(cut, func(t *testing.T) {
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
			nativeTarget(f)
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			if cut != "intact" {
				syncNumber := 2
				if cut != "intent-only" {
					syncNumber = 3
				}
				writer := &nativeSyncCut{file: f.store.journal.file, cut: syncNumber, fail: cut == "result-journal-only"}
				if cut != "result-journal-only" {
					writer.after = f.cancel
				}
				f.store.journal.mu.Lock()
				f.store.journal.writer = writer
				f.store.journal.mu.Unlock()
			}
			nativeSend(t, c, nativeRegisterRequest(2))
			if cut == "intact" {
				nativeResponse(t, nativeReceive(t, c), nativeID(2), "")
			} else {
				body, code := ReadFrame(c)
				if code != "" {
					t.Fatal("crash did not close native connection", code)
				}
				if body != nil {
					obj, err := control.Decode(body)
					if err != nil {
						t.Fatal(err)
					}
					nativeResponse(t, obj, nativeID(2), "audit_unavailable")
				}
			}
			f.stop(t)
			f.store.Close()
			before := nativeSnapshot(t, f)
			recovered, err := OpenStore(f.state, uint32(os.Getuid()))
			if cut == "intent-only" || cut == "result-journal-only" {
				want := "keymaker: unresolved native mutation intent"
				if cut == "result-journal-only" {
					want = "keymaker: binding journal recovery mismatch"
				}
				if err == nil || recovered != nil || err.Error() != want {
					if recovered != nil {
						recovered.Close()
					}
					t.Fatal("wrong native crash recovery", err, want)
				}
				if !bytes.Equal(before, nativeSnapshot(t, f)) {
					t.Fatal("crash recovery changed retained state")
				}
				var disk bindingDisk
				if err := json.Unmarshal(before, &disk); err != nil {
					t.Fatal(err)
				}
				if len(disk.Records) != 0 || len(disk.Requests) != 2 || disk.Requests[1].Status != "pending" {
					t.Fatal("intent did not fence the original transaction")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			recovered.Close()
			f.restart(t, nil)
			fresh := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, fresh, 3)
			nativeSend(t, fresh, nativeRegisterRequest(2))
			result := nativeResponse(t, nativeReceive(t, fresh), nativeID(2), "")
			if result["registration_number"] != int64(1) || len(f.store.Snapshot()) != 1 {
				t.Fatal("lost committed native result")
			}
		})
	}
}

// Ephemeral cleanup needs original registrar authority and the exact retired
// target generation; active or replaced targets cannot acquire a tombstone.
func TestNativeEphemeralRetirement(t *testing.T) {
	for _, state := range []string{"active", "replacement", "retiring"} {
		t.Run(state, func(t *testing.T) {
			b := fixtureBinding(30001)
			b.Generation = nativeToken
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
			if state == "replacement" {
				f.generation.set(b.UID, "retiring", "replacement")
			} else {
				f.generation.set(b.UID, state, b.Generation)
			}
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			before := nativeSnapshot(t, f)
			nativeSend(t, c, nativeRequest(2, "revoke", control.Object{"registration_number": int64(1), "mode": "ephemeral", "operator_record": nil}))
			want := Code("")
			if state == "active" {
				want = "generation_inactive"
			}
			if state == "replacement" {
				want = "generation_mismatch"
			}
			nativeResponse(t, nativeReceive(t, c), nativeID(2), want)
			if want != "" && !bytes.Equal(before, nativeSnapshot(t, f)) {
				t.Fatal("invalid cleanup changed state")
			}
			if want == "" && f.store.Snapshot()[0].Status != "revoked" {
				t.Fatal("retired cleanup missing tombstone")
			}
		})
	}
}

// A count bound prevents unbounded ID churn; the normal combined-state fixture
// fits. This is a preflight primitive check, not a 256 MiB allocation/load test.
func TestNativeResultCapacity(t *testing.T) {
	s := NewStore()
	if s.fitsState(nil, 1, make([]retainedRequest, maxRetainedRequests+1)) {
		t.Fatal("unbounded result count admitted")
	}
	if !s.fitsState(s.records, s.next, s.requests) {
		t.Fatal("empty state capacity control refused")
	}
}

// Complete canonical signed evidence participates in deduplication. Encoding
// retained arguments as a string preserves the wire depth budget when nested
// in the protected snapshot; it is decoded/validated on startup, never audited.
func TestNativeCanonicalRetainedArguments(t *testing.T) {
	b := fixtureBinding(30001)
	b.Generation = nativeToken
	b.Lifetime = "persistent"
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, fixtureAct{}, &b)
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	evidence := control.Object{"leaf": "fixture"}
	for i := 0; i < 12; i++ {
		evidence = control.Object{"nested": evidence}
	}
	request := nativeRequest(2, "revoke", control.Object{"registration_number": int64(1), "mode": "operator", "operator_record": evidence})
	nativeSend(t, c, request)
	original := nativeResponse(t, nativeReceive(t, c), nativeID(2), "")
	changed := nativeRequest(2, "revoke", control.Object{"registration_number": int64(1), "mode": "operator", "operator_record": control.Object{"changed": "fixture"}})
	before := nativeSnapshot(t, f)
	nativeSend(t, c, changed)
	nativeResponse(t, nativeReceive(t, c), nativeID(2), "request_conflict")
	if !bytes.Equal(before, nativeSnapshot(t, f)) {
		t.Fatal("changed signed evidence altered result")
	}
	f.restart(t, fixtureAct{})
	fresh := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, fresh, 3)
	nativeSend(t, fresh, request)
	got := nativeResponse(t, nativeReceive(t, fresh), nativeID(2), "")
	if !reflect.DeepEqual(got, original) {
		t.Fatal("canonical evidence replay lost result")
	}
}

// Rotating the configured operator does not transfer the original registrar's
// ephemeral-cleanup authority. Matching current operator/registrar beside the
// same retired target can create the tombstone; neither case needs an act.
func TestNativeOriginalRegistrar(t *testing.T) {
	for _, original := range []bool{false, true} {
		name := "different-registrar"
		if original {
			name = "original-registrar"
		}
		t.Run(name, func(t *testing.T) {
			operator := Principal{uint32(os.Getuid()), nativeToken}
			registrar := operator
			if !original {
				registrar.Generation = "prior-operator-generation"
			}
			b := fixtureBinding(30001)
			b.Generation = nativeToken
			f := nativeBase(t, registrar, nil, &b)
			// Trusted config rotation in the fixture changes intake authority,
			// not the registrar recorded by the earlier durable registration.
			f.config.Operator = operator
			f.native.Config.Operator = operator
			f.generation.set(b.UID, "removed", nativeToken)
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			before := nativeSnapshot(t, f)
			nativeSend(t, c, nativeRequest(2, "revoke", control.Object{"registration_number": int64(1), "mode": "ephemeral", "operator_record": nil}))
			want := Code("")
			if !original {
				want = "role_not_permitted"
			}
			nativeResponse(t, nativeReceive(t, c), nativeID(2), want)
			if !original && !bytes.Equal(before, nativeSnapshot(t, f)) {
				t.Fatal("operator rotation transferred cleanup authority")
			}
			if original && f.store.Snapshot()[0].Status != "revoked" {
				t.Fatal("original registrar cleanup refused")
			}
		})
	}
}
