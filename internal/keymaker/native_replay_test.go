package keymaker

import (
	"bytes"
	"context"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

type nativePauseEffect struct {
	delayedGenerationWatch
	calls   atomic.Int32
	entered chan struct{}
	resume  <-chan struct{}
}

func (g *nativePauseEffect) WithEvidence(ctx context.Context, cs []GenerationCondition, fn func() Code) Code {
	if len(cs) > 1 && g.calls.Add(1) == 1 {
		close(g.entered)
		select {
		case <-g.resume:
		case <-ctx.Done():
			return "request_deadline_exceeded"
		}
	}
	return g.delayedGenerationWatch.WithEvidence(ctx, cs, fn)
}

// A request paused after its first dedup check races a second connection's
// commit. Exact retry must recover that result after target retirement; a new
// ID against the same still-active target must refuse binding_conflict. Changed
// arguments still conflict; an ended caller still refuses. These socket fixtures
// use injected generation evidence, not live user-manager qualification.
func TestNativeConcurrentTargetReplay(t *testing.T) {
	for _, mode := range []string{"same-id", "same-id-retired", "same-id-reused", "different-id", "changed-arguments", "retired-caller"} {
		t.Run(mode, func(t *testing.T) {
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
			nativeTarget(f)
			resume := make(chan struct{})
			var resumed atomic.Bool
			unblock := func() {
				if resumed.CompareAndSwap(false, true) {
					close(resume)
				}
			}
			defer unblock()
			g := &nativePauseEffect{delayedGenerationWatch: delayedGenerationWatch{f.generation}, entered: make(chan struct{}), resume: resume}
			f.engine.Generations = g
			f.start()
			a, b := nativeDial(t, f.server.ControlPath), nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, a, 10)
			nativeNegotiate(t, b, 11)
			nativeSend(t, a, nativeRegisterRequest(2))
			select {
			case <-g.entered:
			case <-time.After(time.Second):
				t.Fatal("first attempt did not pause at effect barrier")
			}
			winnerID := 2
			if mode == "different-id" {
				winnerID = 3
			}
			winnerRequest := nativeRegisterRequest(winnerID)
			if mode == "changed-arguments" {
				winnerRequest["params"].(control.Object)["owner"] = "different-owner"
			}
			nativeSend(t, b, winnerRequest)
			winner := nativeResponse(t, nativeReceive(t, b), nativeID(winnerID), "")
			if mode == "same-id-retired" {
				f.generation.set(30001, "retiring", nativeToken)
			}
			if mode == "same-id-reused" {
				f.generation.set(30001, "active", "replacement")
			}
			if mode == "retired-caller" {
				f.generation.set(uint32(os.Getuid()), "retiring", nativeToken)
			}
			before := nativeSnapshot(t, f)
			unblock()
			got := nativeReceive(t, a)
			if mode == "different-id" {
				nativeResponse(t, got, nativeID(2), "binding_conflict")
			} else if mode == "changed-arguments" {
				nativeResponse(t, got, nativeID(2), "request_conflict")
			} else if mode == "retired-caller" {
				nativeResponse(t, got, nativeID(2), "generation_inactive")
			} else {
				if _, bad := got["error"]; bad {
					t.Fatalf("REGRESSION: concurrent exact retry refused after committed result became available: %v", got)
				}
				if result := nativeResponse(t, got, nativeID(2), ""); !reflect.DeepEqual(result, winner) {
					t.Fatal("concurrent retry result changed")
				}
			}
			if !bytes.Equal(before, nativeSnapshot(t, f)) {
				t.Fatal("concurrent retry changed committed binding/result state")
			}
			if len(f.store.Snapshot()) != 1 || f.store.next != 2 {
				t.Fatal("concurrent target acquired multiple effects")
			}
		})
	}
}

// A non-retained register must apply the observed target verdict before any
// durable intent, number allocation or result. The active target is the paired
// positive control; missing evidence is not interchangeable with retirement.
func TestNativeFreshTargetEvidence(t *testing.T) {
	for _, mode := range []string{"active", "retired", "reused", "missing", "unverified", "verdict-not-recorded"} {
		t.Run(mode, func(t *testing.T) {
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
			nativeTarget(f)
			want := Code("")
			switch mode {
			case "retired":
				f.generation.set(30001, "retiring", nativeToken)
				want = "generation_inactive"
			case "reused":
				f.generation.set(30001, "active", "replacement")
				want = "generation_mismatch"
			case "missing", "unverified":
				f.generation.mu.Lock()
				if mode == "missing" {
					delete(f.generation.entries, 30001)
				} else {
					g := f.generation.entries[30001]
					g.Verified = false
					f.generation.entries[30001] = g
				}
				f.generation.mu.Unlock()
				want = "generation_source_unavailable"
			case "verdict-not-recorded":
				f.engine.Generations = nativeUnrecordedVerdict{f.generation}
				want = "generation_source_unavailable"
			}
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			before := nativeSnapshot(t, f)
			nativeSend(t, c, nativeRegisterRequest(2))
			nativeResponse(t, nativeReceive(t, c), nativeID(2), want)
			if want != "" {
				if !bytes.Equal(before, nativeSnapshot(t, f)) || len(f.store.Snapshot()) != 0 || f.store.next != 1 {
					t.Fatal("refused fresh target changed binding/result state")
				}
			} else if len(f.store.Snapshot()) != 1 || f.store.next != 2 {
				t.Fatal("active target did not commit exactly one effect")
			}
		})
	}
}

// Model a source that enforces ordinary predicates but does not implement the
// deferred-verdict contract. Its silence must never default to authorization.
type nativeUnrecordedVerdict struct{ *fakeGenerations }

func (g nativeUnrecordedVerdict) WithEvidence(ctx context.Context, cs []GenerationCondition, fn func() Code) Code {
	cs = append([]GenerationCondition(nil), cs...)
	for i := range cs {
		cs[i].Verdict = nil
	}
	return g.fakeGenerations.WithEvidence(ctx, cs, fn)
}

// Pause after the first caller-only replay lookup has released both locks, so
// a second connection can commit before the first prepares its revoke plan.
type nativePauseReplay struct {
	delayedGenerationWatch
	armed   atomic.Bool
	entered chan struct{}
	resume  <-chan struct{}
}

func (g *nativePauseReplay) WithActive(ctx context.Context, uid uint32, token string, fn func() Code) Code {
	c := g.delayedGenerationWatch.WithActive(ctx, uid, token, fn)
	if g.armed.CompareAndSwap(true, false) {
		close(g.entered)
		select {
		case <-g.resume:
		case <-ctx.Done():
			return "request_deadline_exceeded"
		}
	}
	return c
}

// A concurrently committed revoke also outranks a now-stale fresh plan refusal.
// A distinct ID still sees identity_revoked, while changed arguments on the
// winning ID still conflict. Every case preserves the winner's exact tombstone.
func TestNativeConcurrentRevokeReplay(t *testing.T) {
	for _, mode := range []string{"same-id", "different-id", "changed-arguments"} {
		t.Run(mode, func(t *testing.T) {
			b := nativeOwnBinding()
			b.UID = 30001
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, fixtureAct{}, &b)
			resume := make(chan struct{})
			var resumed atomic.Bool
			unblock := func() {
				if resumed.CompareAndSwap(false, true) {
					close(resume)
				}
			}
			defer unblock()
			g := &nativePauseReplay{delayedGenerationWatch: delayedGenerationWatch{f.generation}, entered: make(chan struct{}), resume: resume}
			f.engine.Generations = g
			f.start()
			a, winnerConn := nativeDial(t, f.server.ControlPath), nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, a, 10)
			nativeNegotiate(t, winnerConn, 11)
			request := func(id int, act string) control.Object {
				return nativeRequest(id, "revoke", control.Object{"registration_number": int64(1), "mode": "operator", "operator_record": control.Object{"fixture": act}})
			}
			g.armed.Store(true)
			nativeSend(t, a, request(2, "original"))
			select {
			case <-g.entered:
			case <-time.After(time.Second):
				t.Fatal("revoke did not pause after replay lookup")
			}
			winnerID, act := 2, "original"
			if mode == "different-id" {
				winnerID = 3
			} else if mode == "changed-arguments" {
				act = "different"
			}
			nativeSend(t, winnerConn, request(winnerID, act))
			winner := nativeResponse(t, nativeReceive(t, winnerConn), nativeID(winnerID), "")
			before := nativeSnapshot(t, f)
			unblock()
			want := Code("")
			if mode == "different-id" {
				want = "identity_revoked"
			} else if mode == "changed-arguments" {
				want = "request_conflict"
			}
			got := nativeResponse(t, nativeReceive(t, a), nativeID(2), want)
			if want == "" && !reflect.DeepEqual(got, winner) {
				t.Fatal("concurrent revoke lost retained result")
			}
			rows := f.store.Snapshot()
			if !bytes.Equal(before, nativeSnapshot(t, f)) || len(rows) != 1 || rows[0].Status != "revoked" || f.store.next != 2 {
				t.Fatal("concurrent revoke changed the committed tombstone or result")
			}
		})
	}
}
