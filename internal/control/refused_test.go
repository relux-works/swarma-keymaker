package control

import (
	"context"
	"net"
	"testing"
	"time"
)

type refusedObserver struct {
	observerFixture
	limit Code
}

func (o *refusedObserver) Enter(ctx context.Context, c net.Conn) (func(), Code) {
	done, _ := o.observerFixture.Enter(ctx, c)
	return done, o.limit
}

func refusedClient(t *testing.T, s *Server, ctx context.Context, code Code) (net.Conn, <-chan struct{}) {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeConnRefused(ctx, a, Peer{UID: 1001}, code)
	}()
	b.SetDeadline(time.Now().Add(time.Second))
	t.Cleanup(func() {
		b.Close()
		a.Close()
		<-done
	})
	return b, done
}

// Generation refusals still charge shared work and durable refusal audit. Audit
// failure overrides the original code; budget failures never enter execution.
// A normal hello on the same wire object is the positive authority control.
func TestRefusedConnectionObservers(t *testing.T) {
	for _, mode := range []string{"healthy", "busy", "rate_limited", "audit-failed"} {
		t.Run(mode, func(t *testing.T) {
			s := testServer(t, nil, nil, nil)
			o := &refusedObserver{}
			want := Code("generation_inactive")
			if mode == "busy" || mode == "rate_limited" {
				o.limit, want = Code(mode), Code(mode)
			} else if mode == "audit-failed" {
				o.fail, want = true, "audit_unavailable"
			}
			s.observer = o
			c, done := refusedClient(t, s, context.Background(), "generation_inactive")
			send(t, c, hello(1, 1))
			id := any(requestID(1))
			if o.limit != "" {
				id = nil
			}
			wantError(t, receive(t, c), id, want)
			closed(t, c)
			<-done
			if o.entered.Load() != 1 || o.released.Load() != 1 || o.refused.Load() != 1 {
				t.Fatal("refused observer admission/audit/slot not paired")
			}
			s.observer = testObserver{}
			fresh, _ := client(t, s, nil)
			negotiate(t, fresh)
		})
	}
}

// The parent's remaining admission budget bounds the refused connection rather
// than granting it a new frame budget. Neither a silent reader nor an invalid
// refusal code reaches workload/audit; the valid refusal is the nearby control.
func TestRefusedConnectionBounds(t *testing.T) {
	s := testServer(t, nil, nil, nil)
	o := &observerFixture{}
	s.observer = o
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	c, done := refusedClient(t, s, ctx, "generation_inactive")
	closed(t, c)
	<-done
	invalid, stopped := refusedClient(t, s, context.Background(), "peer_identity_unavailable")
	closed(t, invalid)
	<-stopped
	if o.entered.Load() != 0 || o.refused.Load() != 0 {
		t.Fatal("unread or unauthenticated connection reached audit")
	}
	valid, finished := refusedClient(t, s, context.Background(), "generation_mismatch")
	send(t, valid, hello(1, 1))
	wantError(t, receive(t, valid), requestID(1), "generation_mismatch")
	closed(t, valid)
	<-finished
}
