package keymaker

import (
	"context"
	"testing"
	"time"
)

type boundedGeneration struct {
	*fakeGenerations
	expired bool
}

func (g boundedGeneration) WithActive(ctx context.Context, uid uint32, token string, commit func(context.Context) Code) Code {
	return g.fakeGenerations.WithActive(ctx, uid, token, func(ctx context.Context) Code {
		deadline := time.Now().Add(40 * time.Millisecond)
		if g.expired {
			deadline = time.Now().Add(-time.Second)
		}
		bounded, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		return commit(bounded)
	})
}

// A post-callback check cannot recall bytes. The bounded context must reach the
// audit wait and the actual handoff before either begins. This uses an audit
// gate, not a claim that an already-started filesystem sync can be cancelled.
func TestGenerationDeadlineAgentAudit(t *testing.T) {
	for _, mode := range []string{"active", "expired", "audit-wait"} {
		t.Run(mode, func(t *testing.T) {
			e, g, _, a, s := fixtureEngine(t)
			e.Generations = boundedGeneration{g, mode == "expired"}
			unlock := make(chan struct{})
			unlocked := make(chan struct{})
			if mode == "audit-wait" {
				a.mu.Lock()
				go func() { <-unlock; a.mu.Unlock(); close(unlocked) }()
				// This unlock bounds a broken implementation too; such an implementation
				// must fail assertions instead of hanging the shared host.
				timer := time.AfterFunc(120*time.Millisecond, func() { close(unlock) })
				defer timer.Stop()
			}
			emitted := false
			started := time.Now()
			c := e.Handle(context.Background(), s, []byte{11}, func(ctx context.Context, _ []byte) error {
				emitted = true
				d, ok := ctx.Deadline()
				if !ok || time.Until(d) > 50*time.Millisecond {
					t.Error("handoff lost window deadline")
				}
				return nil
			})
			if mode == "active" {
				if c != "" || !emitted {
					t.Fatal(c, emitted)
				}
				return
			}
			if c != "request_deadline_exceeded" || emitted {
				t.Fatal("expired window released", c, emitted)
			}
			if mode == "audit-wait" {
				<-unlocked
				// A separate refusal audit may follow; there must be no success audit.
				for _, r := range a.records {
					if r.Result == "success" {
						t.Fatal("late success audit")
					}
				}
				if time.Since(started) > 500*time.Millisecond {
					t.Fatal("bounded wait overran")
				}
			}
		})
	}
}
