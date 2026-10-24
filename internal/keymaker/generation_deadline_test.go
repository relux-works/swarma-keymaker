package keymaker

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

type boundedGeneration struct {
	*fakeGenerations
	expired  bool
	before   func()
	duration time.Duration
}

func (g boundedGeneration) WithActive(ctx context.Context, uid uint32, token string, commit func(context.Context) Code) Code {
	return g.fakeGenerations.WithActive(ctx, uid, token, func(ctx context.Context) Code {
		duration := g.duration
		if duration == 0 {
			duration = 40 * time.Millisecond
		}
		deadline := time.Now().Add(duration)
		if g.expired {
			deadline = time.Now().Add(-time.Second)
		}
		bounded, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		if g.before != nil {
			g.before()
		}
		return commit(bounded)
	})
}

// A post-callback check cannot recall bytes. The bounded context must reach the
// audit wait and the actual handoff before either begins. This uses an audit
// gate, not a claim that an already-started filesystem sync can be cancelled.
func TestGenerationDeadlineAgentAudit(t *testing.T) {
	for _, mode := range []string{"active", "expired", "audit-wait", "store-wait"} {
		t.Run(mode, func(t *testing.T) {
			e, g, _, a, s := fixtureEngine(t)
			boundedSource := boundedGeneration{fakeGenerations: g, expired: mode == "expired"}
			e.Generations = boundedSource
			unlock := make(chan struct{})
			unlocked := make(chan struct{})
			if mode == "audit-wait" || mode == "store-wait" {
				var once sync.Once
				release := func() { once.Do(func() { close(unlock) }) }
				if mode == "audit-wait" {
					a.mu.Lock()
					go func() { <-unlock; a.mu.Unlock(); close(unlocked) }()
				} else {
					boundedSource.before = func() {
						e.Store.mu.Lock()
						go func() { <-unlock; e.Store.mu.Unlock(); close(unlocked) }()
					}
					e.Generations = boundedSource
				}
				// This unlock bounds a broken implementation too; such an implementation
				// must fail assertions instead of hanging the shared host.
				timer := time.AfterFunc(120*time.Millisecond, release)
				defer func() { timer.Stop(); release(); <-unlocked }()
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
			if mode == "store-wait" && time.Since(started) > 100*time.Millisecond {
				t.Fatal("store wait ignored source deadline")
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

// The native coordinator passes the window budget to its success-audit wait and
// release callback. Retained-result persistence may already have committed; this
// test promises no late success audit or handoff, not cancellation of that commit.
func TestGenerationDeadlineNativeAudit(t *testing.T) {
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
	a := &memoryAudit{}
	f.engine.Audit = a
	f.engine.Generations = boundedGeneration{fakeGenerations: f.generation, duration: 250 * time.Millisecond}
	peer := control.Peer{UID: uint32(os.Getuid()), Generation: nativeToken}
	req := control.Request{ID: nativeID(1), Method: "hello"}
	conn := &nativeConnection{requestID: req.ID}
	ctx := context.WithValue(context.Background(), nativeConnectionKey{}, conn)
	a.mu.Lock()
	var once sync.Once
	unlock := func() { once.Do(func() { a.mu.Unlock() }) }
	timer := time.AfterFunc(time.Second, unlock)
	defer func() { timer.Stop(); unlock() }()
	called := false
	start := time.Now()
	c := f.native.WithActive(ctx, peer, req, control.Object{"version": int64(1)}, func(context.Context) control.Code { called = true; return "" })
	elapsed := time.Since(start)
	if c != control.DeadlineExceeded || called || elapsed > 700*time.Millisecond {
		t.Fatal("native audit ignored window", c, called, elapsed)
	}
	unlock()
	if len(a.records) != 0 || f.engine.closed.Load() {
		t.Fatal("late audit or healthy engine fenced", len(a.records))
	}
	req.ID = nativeID(2)
	conn.requestID = req.ID
	c = f.native.WithActive(ctx, peer, req, control.Object{"version": int64(1)}, func(ctx context.Context) control.Code {
		called = true
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 250*time.Millisecond {
			t.Error("native handoff lost bounded context")
		}
		return ""
	})
	if c != "" || !called || len(a.records) != 1 || a.records[0].Result != "success" {
		t.Fatal("native active control", c, called, len(a.records))
	}
}
