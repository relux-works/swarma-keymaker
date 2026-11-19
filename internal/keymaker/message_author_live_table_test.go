package keymaker

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/messageauthor"
)

// Each retained event uses the same complete immutable identity but a distinct
// durable starting state. Forbidden callbacks, state changes and invocations
// are asserted separately from the adjacent valid admission/replay controls.
func TestMALiveRetainedEventTable(t *testing.T) {
	for _, status := range []string{"intent", "result", "handoff_unknown", "released", "dead"} {
		for _, event := range []string{"retry", "old-t", "conflict", "loss"} {
			t.Run(status+"/"+event, func(t *testing.T) {
				f := newMALiveFixture(t)
				s := f.h.store
				if status == "intent" {
					s.maLive.Attempts = []maLiveAttempt{maLiveIntent(f)}
				} else {
					f.control(t)
					s.maLive.Attempts[0].Status = status
				}
				if c := s.persistMALive(t.Context(), 0); c != "" {
					t.Fatal(c)
				}
				count := f.calls.Load()
				r := f.request()
				want := Code("")
				wantStatus := status
				switch event {
				case "retry":
					if status == "dead" {
						want = "message_author_unqualified"
					} else {
						wantStatus = "released"
						if status == "intent" {
							count++
						}
					}
				case "old-t":
					f.source.tuple.T = "sha256:" + strings.Repeat("b", 64)
					want = "signer_identity_mismatch"
					wantStatus = "dead"
				case "conflict":
					r.Method = messageauthor.IdentityMethod
					r.Preimage = nil
					want = "request_conflict"
				case "loss":
					f.h.key.epoch = "replacement"
					want = "message_author_unqualified"
					wantStatus = "dead"
				}
				if want != "" {
					f.refusal(t, r, want, count)
				} else {
					out, c := f.call(t.Context(), r)
					if c != "" || out.Signature == nil || f.calls.Load() != count {
						t.Fatal("table retry changed effect", c, f.calls.Load(), count)
					}
				}
				if s.maLive.Attempts[0].Status != wantStatus || len(s.maLive.Attempts) != 1 {
					t.Fatal("retained event table state", status, event, s.maLive.Attempts[0].Status, wantStatus)
				}
				if c := f.restart(t); c != "" {
					t.Fatal("event table durability", c)
				}
				if f.calls.Load() != count || f.h.store.maLive.Attempts[0].Status != wantStatus {
					t.Fatal("event table recovery re-signed/changed state")
				}
				t.Logf("table state=%s event=%s invocation_count=%d", status, event, count)
				newMALiveFixture(t).control(t)
			})
		}
	}
}

// A running invoking marker owns Store/current/custody and its single flight.
// An equal caller waits until its deadline without a second crypto effect; after
// the owner completes, a fresh retry returns its identical retained result.
func TestMALiveRunningInvokeWait(t *testing.T) {
	f := newMALiveFixture(t)
	inside, release := make(chan struct{}), make(chan struct{})
	original := f.h.invoke
	f.h.invoke = func(s *Store, b Binding, p *messageAuthorPlan, before func() Code) ([]byte, Code) {
		return original(s, b, p, func() Code {
			c := before()
			if c == "" {
				close(inside)
				<-release
			}
			return c
		})
	}
	result := make(chan Code, 1)
	go func() { _, c := f.call(t.Context(), f.request()); result <- c }()
	select {
	case <-inside:
	case <-time.After(3 * time.Second):
		t.Fatal("invoking not reached")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	out, c := f.call(ctx, f.request())
	cancel()
	if c != "request_deadline_exceeded" || out.Signature != nil || f.calls.Load() != 0 {
		close(release)
		<-result
		t.Fatal("running duplicate crossed invocation boundary", c)
	}
	close(release)
	if c := <-result; c != "" {
		t.Fatal(c)
	}
	f.control(t)
	t.Log("running invoking duplicate timed out while waiting; owner and retry invocation_count=1")
}
