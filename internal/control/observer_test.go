package control

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type observerFixture struct {
	fail                       bool
	entered, released, refused atomic.Int32
}

func (o *observerFixture) Enter(context.Context, net.Conn) (func(), Code) {
	o.entered.Add(1)
	return func() { o.released.Add(1) }, ""
}
func (o *observerFixture) Refuse(_ context.Context, _ net.Conn, p *Peer, r Request, body []byte, c Code) Code {
	o.refused.Add(1)
	if o.fail {
		return "audit_unavailable"
	}
	return c
}

// Early framing refusals call the observer before any error response, and its
// failure overrides that response and closes. The healthy reporter preserves
// the exact framing error; an independent hello then negotiates successfully.
func TestRefusalObserver(t *testing.T) {
	for _, fail := range []bool{true, false} {
		t.Run(map[bool]string{true: "unavailable", false: "healthy"}[fail], func(t *testing.T) {
			s := testServer(t, nil, nil, nil)
			o := &observerFixture{fail: fail}
			s.observer = o
			c, done := client(t, s, nil)
			if _, err := c.Write([]byte{0, 0, 0, 0}); err != nil {
				t.Fatal(err)
			}
			want := FrameMalformed
			if fail {
				want = "audit_unavailable"
			}
			wantError(t, receive(t, c), nil, want)
			closed(t, c)
			<-done
			if o.entered.Load() != 1 || o.released.Load() != 1 || o.refused.Load() != 1 {
				t.Fatal("observer not paired with request")
			}
			fresh, _ := client(t, s, nil)
			negotiate(t, fresh)
		})
	}
}

type requestHandler func(context.Context, Peer, Request) (Object, Code)

func (f requestHandler) Handle(c context.Context, p Peer, r Request) (Object, Code) {
	return f(c, p, r)
}

// The coordinator receives the exact admitted effect ID rather than recovering
// it from shared per-peer state, which would be ambiguous across connections.
func TestHandlerReceivesRequestID(t *testing.T) {
	s := testServer(t, nil, nil, nil)
	s.handler = requestHandler(func(_ context.Context, _ Peer, r Request) (Object, Code) {
		if r.ID != requestID(2) || r.Method != "pubkey" || len(r.Params) != 0 {
			t.Fatal("handler lost admitted envelope")
		}
		return Object{}, ""
	})
	c, _ := client(t, s, nil)
	negotiate(t, c)
	send(t, c, operation(2, "pubkey", Object{}, 2000))
	wantSuccess(t, receive(t, c), requestID(2))
	if _, err := New(s.handler, s.peers, s.ids, s.fence, nil); err == nil {
		t.Fatal("missing observer admitted")
	}
}

type boundedObserver struct {
	observerFixture
	bounded atomic.Int32
}

func (o *boundedObserver) Enter(ctx context.Context, _ net.Conn) (func(), Code) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > frameBudget {
		return nil, "busy"
	}
	o.bounded.Add(1)
	return func() {}, ""
}

// Shared-work admission receives a bounded context for hello and methods even
// when the daemon parent has no deadline; a healthy observer permits both.
func TestObserverAdmissionDeadline(t *testing.T) {
	s := testServer(t, nil, nil, nil)
	o := &boundedObserver{}
	s.observer = o
	c, _ := client(t, s, nil)
	negotiate(t, c)
	send(t, c, operation(2, "pubkey", Object{}, 2000))
	wantSuccess(t, receive(t, c), requestID(2))
	if o.bounded.Load() != 2 {
		t.Fatal("observer admission escaped deadline")
	}
}
