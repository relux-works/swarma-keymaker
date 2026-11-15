//go:build linux

package keymaker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	wire "github.com/relux-works/swarma-keymaker/j7lifecycle"
)

func lifecycleIdleSetup(t *testing.T, kind string) *j7RunFixture {
	t.Helper()
	if kind == "lifecycle" {
		return j7RunSetup(t)
	}
	s := j7SigningSetup(t)
	return &j7RunFixture{f: s.f, life: s.a.j7Lifecycle, gen: s.gen, socket: s.socket}
}
func lifecycleIdleEnd(t *testing.T, c *net.UnixConn, id string) {
	t.Helper()
	q := lifecycleEnd(10, id)
	frame, e := wire.EncodeRequestFrame(q)
	if e != nil {
		t.Fatal(e)
	}
	if e := c.SetDeadline(time.Now().Add(5 * time.Second)); e != nil {
		t.Fatal(e)
	}
	for len(frame) > 0 {
		n, e := c.Write(frame)
		if e != nil || n == 0 {
			t.Fatalf("bound idle channel lost while sending normal end: %v", e)
		}
		frame = frame[n:]
	}
	b, e := lifecycleRead(c)
	if e != nil {
		t.Fatalf("bound idle channel lost before normal end response: %v", e)
	}
	r, e := wire.DecodeResponseFrame(q, b)
	if e != nil || r.Refusal != nil || r.Run == nil || r.Run.RunID != id || r.Run.State != "ended" {
		t.Fatalf("bound idle channel lost or failed normal end: %v %+v", e, r)
	}
}

// Actual lifecycle and embedded request channels survive no-byte waiting well
// past2s, then acknowledge a normal end. Local caller deadlines are refreshed;
// fixture generations do not establish distinct-UID or installed qualification.
func TestJ7LifecycleBoundIdle(t *testing.T) {
	for _, kind := range []string{"lifecycle", "request-adapter"} {
		t.Run(kind, func(t *testing.T) {
			f := lifecycleIdleSetup(t, kind)
			c := lifecycleConnect(t, f.socket)
			lifecycleHello(t, c, 1)
			q := lifecycleBind(f, 2)
			bound := lifecycleCall(t, c, q, "")
			lifecycleCall(t, c, q, "") // another completed frame must not leave a stale read deadline
			time.Sleep(3200 * time.Millisecond)
			lifecycleIdleEnd(t, c, bound.Run.RunID)
		})
	}
}

type lifecycleIdleListener struct {
	net.Listener
	accepted chan *lifecycleIdleConn
}
type lifecycleIdleConn struct {
	*net.UnixConn
	reads chan time.Time
	done  chan struct{}
	once  sync.Once
}

func (l *lifecycleIdleListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	x := &lifecycleIdleConn{UnixConn: c.(*net.UnixConn), reads: make(chan time.Time, 64), done: make(chan struct{})}
	l.accepted <- x
	return x, nil
}
func (c *lifecycleIdleConn) SetReadDeadline(d time.Time) error {
	if e := c.UnixConn.SetReadDeadline(d); e != nil {
		return e
	}
	c.reads <- d
	return nil
}
func (c *lifecycleIdleConn) Close() error {
	e := c.UnixConn.Close()
	c.once.Do(func() { close(c.done) })
	return e
}
func lifecycleIdleObserved(t *testing.T, f *j7RunFixture) (*lifecycleIdleListener, string) {
	t.Helper()
	f.stop(t)
	l, e := newJ7Lifecycle(f.f.store, f.f.policy, f.gen, f.life.launcher)
	if e != nil {
		t.Fatal(e)
	}
	f.life = l
	server, e := control.New(l, l, l, l, l)
	if e != nil {
		t.Fatal(e)
	}
	address := fmt.Sprintf("@lifecycle-idle-%d-%d", os.Getpid(), j7SocketCounter.Add(1))
	listener, e := net.Listen("unix", address)
	if e != nil {
		t.Fatal(e)
	}
	observed := &lifecycleIdleListener{Listener: listener, accepted: make(chan *lifecycleIdleConn, 8)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, observed) }()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("idle fixture server did not stop")
		}
	})
	return observed, address
}
func lifecycleIdleDeadline(t *testing.T, c *lifecycleIdleConn, zero bool) time.Time {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for {
		select {
		case d := <-c.reads:
			if d.IsZero() == zero {
				return d
			}
		case <-timer.C:
			t.Fatal("expected server read deadline was not observed")
		}
	}
}
func lifecycleDeadlineReply(t *testing.T, c *net.UnixConn) {
	t.Helper()
	if e := c.SetReadDeadline(time.Now().Add(8 * time.Second)); e != nil {
		t.Fatal(e)
	}
	raw, e := lifecycleRead(c)
	if e != nil {
		t.Fatal("expected remote deadline refusal, not local read failure", e)
	}
	// An idle framing refusal has no outstanding RPC. Inspect its canonical
	// closed envelope directly; do not invent expected request context from it.
	object, e := control.Decode(raw[4:])
	refusal, ok := object["error"].(control.Object)
	if e != nil || len(object) != 2 || object["request_id"] != nil || !ok || len(refusal) != 2 || refusal["code"] != "request_deadline_exceeded" || refusal["retryable"] != true {
		t.Fatal("wrong remote started-frame/idle refusal", e, object)
	}
	var b [1]byte
	n, e := c.Read(b[:])
	if n != 0 || !errors.Is(e, io.EOF) {
		t.Fatal("deadline refusal did not end with clean EOF", n, e)
	}
}

// Recording deadline calls on an actual Unix FD separates the single2s frame
// budget from later refusal audit/write budgets. Header/body completion cannot
// reset it; the eventual intended refusal is required, not any client timeout.
func TestJ7LifecyclePartialFrameDeadline(t *testing.T) {
	for _, part := range []string{"header", "body"} {
		t.Run(part, func(t *testing.T) {
			f := j7RunSetup(t)
			observed, address := lifecycleIdleObserved(t, f)
			c := lifecycleConnect(t, address)
			accepted := <-observed.accepted
			lifecycleHello(t, c, 1)
			bound := lifecycleCall(t, c, lifecycleBind(f, 2), "")
			lifecycleIdleDeadline(t, accepted, true)
			time.Sleep(3200 * time.Millisecond)
			q := lifecycleEnd(3, bound.Run.RunID)
			frame, e := wire.EncodeRequestFrame(q)
			if e != nil {
				t.Fatal(e)
			}
			if e := c.SetDeadline(time.Now().Add(8 * time.Second)); e != nil {
				t.Fatal(e)
			}
			started := time.Now()
			lifecycleWrite(t, c, frame[:1])
			d := lifecycleIdleDeadline(t, accepted, false)
			if d.Before(started.Add(1700*time.Millisecond)) || d.After(time.Now().Add(2200*time.Millisecond)) {
				t.Fatal("started frame did not receive one2s budget", d.Sub(started))
			}
			if part == "body" {
				time.Sleep(100 * time.Millisecond)
				lifecycleWrite(t, c, frame[1:5])
				select {
				case <-accepted.reads:
					t.Fatal("frame deadline reset after partial header/body")
				case <-time.After(150 * time.Millisecond):
				}
			}
			lifecycleDeadlineReply(t, c)
			if time.Since(started) < 1700*time.Millisecond {
				t.Fatal("remote deadline was not a started-frame budget")
			}
			f.waitDisconnected(t, bound.Run.RunID)
			f.f.store.mu.Lock()
			state := f.life.run(bound.Run.RunID).State
			count := len(f.f.store.j7.Runs)
			f.f.store.mu.Unlock()
			if state != "live" || count != 1 {
				t.Fatal("partial frame ended/duplicated retained run")
			}
		})
	}
}

// Negotiation, a failed bind and a successful administrative end cannot confer
// bound status. Actual legacy sockets retain the same finite idle behavior.
func TestJ7LifecycleUnboundIdle(t *testing.T) {
	for _, kind := range []string{"prehello", "hello", "failed-bind", "administrative-end", "legacy"} {
		t.Run(kind, func(t *testing.T) {
			var c *net.UnixConn
			if kind == "legacy" {
				own := nativeOwnBinding()
				f := nativeBase(t, Principal{own.UID, nativeToken}, nil, &own)
				f.start()
				c = lifecycleConnect(t, f.server.ControlPath)
				lifecycleHello(t, c, 1)
			} else {
				f := j7RunSetup(t)
				observed, address := lifecycleIdleObserved(t, f)
				if kind == "administrative-end" {
					a := lifecycleConnect(t, address)
					<-observed.accepted
					lifecycleHello(t, a, 1)
					bound := lifecycleCall(t, a, lifecycleBind(f, 2), "")
					c = lifecycleConnect(t, address)
					accepted := <-observed.accepted
					lifecycleFiniteDeadline(t, accepted)
					lifecycleHello(t, c, 3)
					lifecycleFiniteDeadline(t, accepted)
					q := lifecycleEnd(4, bound.Run.RunID)
					lifecycleCall(t, c, q, "")
					lifecycleFiniteDeadline(t, accepted)
				} else {
					c = lifecycleConnect(t, address)
					accepted := <-observed.accepted
					lifecycleFiniteDeadline(t, accepted)
					if kind != "prehello" {
						lifecycleHello(t, c, 1)
						lifecycleFiniteDeadline(t, accepted)
					}
					if kind == "failed-bind" {
						q := lifecycleBind(f, 2)
						q.Bind.IdentityRegistrationNumber++
						lifecycleCall(t, c, q, "request_malformed")
						lifecycleFiniteDeadline(t, accepted)
					}
				}
			}
			lifecycleDeadlineReply(t, c)
		})
	}
}

func lifecycleFiniteDeadline(t *testing.T, c *lifecycleIdleConn) {
	t.Helper()
	select {
	case d := <-c.reads:
		if d.IsZero() {
			t.Fatal("unbound channel received indefinite read deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("unbound deadline was not observed")
	}
}

// EOF removes only the volatile association; current retained history remains
// available for a permitted end. This is socket closure, not UID-helper or
// process-incarnation qualification.
func TestJ7LifecycleEOFIdleRetention(t *testing.T) {
	f := j7RunSetup(t)
	observed, address := lifecycleIdleObserved(t, f)
	c := lifecycleConnect(t, address)
	accepted := <-observed.accepted
	lifecycleHello(t, c, 1)
	bound := lifecycleCall(t, c, lifecycleBind(f, 2), "")
	lifecycleIdleDeadline(t, accepted, true)
	before := j7RunWitnessOf(t, f)
	c.Close()
	f.waitDisconnected(t, bound.Run.RunID)
	if j7RunWitnessOf(t, f) != before {
		t.Fatal("EOF changed durable run history")
	}
	f.f.store.mu.Lock()
	state := f.life.run(bound.Run.RunID).State
	f.f.store.mu.Unlock()
	if state != "live" {
		t.Fatal("EOF ended retained run")
	}
	fresh := lifecycleConnect(t, address)
	lifecycleHello(t, fresh, 3)
	lifecycleCall(t, fresh, lifecycleEnd(4, bound.Run.RunID), "")
}

// Existing holder rebind establishes a new actual scope, which then survives
// idle. This preserves the holder method; v1 launcher policy still never rebinds.
func TestJ7LifecycleRebindIdle(t *testing.T) {
	f := j7RunSetup(t)
	c := lifecycleConnect(t, f.socket)
	lifecycleHello(t, c, 1)
	bound := lifecycleCall(t, c, lifecycleBind(f, 2), "")
	c.Close()
	f.waitDisconnected(t, bound.Run.RunID)
	fresh := lifecycleConnect(t, f.socket)
	lifecycleHello(t, fresh, 3)
	q := wire.Request{ID: nativeID(4), Method: wire.RebindMethod, TimeoutMS: 2000, RunID: bound.Run.RunID}
	lifecycleCall(t, fresh, q, "")
	time.Sleep(3200 * time.Millisecond)
	lifecycleIdleEnd(t, fresh, bound.Run.RunID)
}

// Only one actual channel per live run receives the exemption. A competing
// socket is refused without changing durable history or the original mapping.
// The obsolete case removes only a volatile map entry under the Store lock;
// that negative-only instrument is not a legitimate holder transition or a
// fabricated bound positive. Its next read must regain the finite deadline.
func TestJ7LifecycleSingleIdleChannel(t *testing.T) {
	for _, kind := range []string{"competing", "obsolete-map"} {
		t.Run(kind, func(t *testing.T) {
			f := j7RunSetup(t)
			observed, address := lifecycleIdleObserved(t, f)
			original := lifecycleConnect(t, address)
			originalFD := <-observed.accepted
			lifecycleHello(t, original, 1)
			bound := lifecycleCall(t, original, lifecycleBind(f, 2), "")
			lifecycleIdleDeadline(t, originalFD, true)
			_, originalChannel := j7ActualChannel(t, f, bound.Run.RunID)
			other := lifecycleConnect(t, address)
			otherFD := <-observed.accepted
			lifecycleFiniteDeadline(t, otherFD)
			lifecycleHello(t, other, 3)
			lifecycleFiniteDeadline(t, otherFD)
			var rejected *net.UnixConn
			var rejectedFD *lifecycleIdleConn
			var rejectedChannel *j7Channel
			var control *net.UnixConn
			controlID := bound.Run.RunID
			if kind == "competing" {
				before := j7RunWitnessOf(t, f)
				q := wire.Request{ID: nativeID(4), Method: wire.RebindMethod, TimeoutMS: 2000, RunID: bound.Run.RunID}
				lifecycleCall(t, other, q, "run_identity_unavailable")
				lifecycleFiniteDeadline(t, otherFD)
				if j7RunWitnessOf(t, f) != before {
					t.Fatal("competing channel changed durable history")
				}
				rejected, rejectedFD, control = other, otherFD, original
			} else {
				q := lifecycleBind(f, 4)
				q.Bind.InputPrincipal = wire.Principal{UID: f.f.uid + 201, Generation: "input-b"}
				second := lifecycleCall(t, other, q, "")
				lifecycleIdleDeadline(t, otherFD, true)
				_, secondChannel := j7ActualChannel(t, f, second.Run.RunID)
				before := j7RunWitnessOf(t, f)
				f.f.store.mu.Lock()
				delete(f.life.channels, second.Run.RunID)
				f.f.store.mu.Unlock()
				// Complete the currently waiting frame without invoking a run
				// mutation; the following iteration must re-prove association.
				lifecycleCall(t, other, wire.Request{ID: nativeID(5), Method: wire.HelloMethod, Versions: []int64{1}}, "hello_already_negotiated")
				select {
				case d := <-otherFD.reads: // first-byte started-frame budget
					if d.IsZero() {
						t.Fatal("started frame received indefinite deadline")
					}
				case <-time.After(time.Second):
					t.Fatal("started-frame deadline missing")
				}
				select {
				case d := <-otherFD.reads:
					if d.IsZero() {
						t.Fatal("obsolete channel received indefinite read deadline")
					}
				case <-time.After(time.Second):
					t.Fatal("obsolete channel deadline missing")
				}
				if j7RunWitnessOf(t, f) != before {
					t.Fatal("obsolete map probe changed durable history")
				}
				rejected, rejectedFD, rejectedChannel, control = other, otherFD, secondChannel, original
			}
			before := j7RunWitnessOf(t, f)
			lifecycleDeadlineReply(t, rejected)
			select {
			case <-rejectedFD.done:
			case <-time.After(time.Second):
				t.Fatal("rejected idle socket was not closed")
			}
			f.f.store.mu.Lock()
			stillOriginal := f.life.channels[controlID] == originalChannel && len(f.life.channels) == 1
			obsoleteActive := rejectedChannel != nil && rejectedChannel.active()
			f.f.store.mu.Unlock()
			if !stillOriginal || obsoleteActive || j7RunWitnessOf(t, f) != before {
				t.Fatal("idle cleanup duplicated association or changed durable history")
			}
			// The genuine original association outlives the rejected channel's
			// finite read/cleanup and remains capable of normal exact end.
			lifecycleIdleEnd(t, control, controlID)
		})
	}
}

// Withdrawal and parent cancellation interrupt a real no-byte idle wait. No
// successful bytes or local timeout may substitute for the required EOF.
func TestJ7LifecycleIdleWithdrawal(t *testing.T) {
	for _, kind := range []string{"launcher", "input", "station", "binding", "server-cancel"} {
		t.Run(kind, func(t *testing.T) {
			f := j7RunSetup(t)
			c := lifecycleConnect(t, f.socket)
			lifecycleHello(t, c, 1)
			bound := lifecycleCall(t, c, lifecycleBind(f, 2), "")
			switch kind {
			case "launcher":
				f.gen.set(f.life.launcher.UID, "retiring", f.life.launcher.Generation)
			case "input":
				f.gen.set(f.args().Input.UID, "retiring", f.args().Input.Generation)
			case "station":
				f.gen.set(f.f.binding.UID, "retiring", f.f.binding.Generation)
			case "binding":
				if code := f.f.store.Unbind(fixtureOperator, fixtureOperator, f.f.binding.UID, f.f.binding.Generation); code != "" {
					t.Fatal(code)
				}
			case "server-cancel":
				f.cancel()
			}
			if e := c.SetReadDeadline(time.Now().Add(time.Second)); e != nil {
				t.Fatal(e)
			}
			var b [1]byte
			n, e := c.Read(b[:])
			if n != 0 || !errors.Is(e, io.EOF) {
				t.Fatal("withdrawal failed to close idle connection with EOF", n, e)
			}
			f.waitDisconnected(t, bound.Run.RunID)
			f.f.store.mu.Lock()
			state := f.life.run(bound.Run.RunID).State
			f.f.store.mu.Unlock()
			if state != "live" {
				t.Fatal("withdrawal erased/ended retained history")
			}
		})
	}
}

// A true proof uses a capability from an actual accepted socket. Fixture-only
// metadata counterexamples cannot gain an exemption through hello/row/label
// alone; probing itself performs no durable mutation or result release.
func TestJ7LifecycleIdleProof(t *testing.T) {
	for _, kind := range []string{"absent-scope", "foreign-connection", "foreign-peer", "canceled-probe", "canceled-channel", "failed-store", "pending", "missing-inventory", "no-map", "never-bound", "no-run", "ended", "foreign-launcher", "changed-binding"} {
		t.Run(kind, func(t *testing.T) {
			f := j7RunSetup(t)
			c := lifecycleConnect(t, f.socket)
			lifecycleHello(t, c, 1)
			bound := lifecycleCall(t, c, lifecycleBind(f, 2), "")
			ctx, ch := j7ActualChannel(t, f, bound.Run.RunID)
			peer := control.Peer{UID: f.life.launcher.UID, Generation: f.life.launcher.Generation}
			conn := ch.conn
			if !f.life.BoundChannel(ctx, conn, peer) {
				t.Fatal("actual bound proof control refused")
			}
			before := j7RunWitnessOf(t, f)
			undo := func() {}
			switch kind {
			case "absent-scope":
				ctx = context.Background()
			case "foreign-connection":
				conn = c
			case "foreign-peer":
				peer.UID++
			case "canceled-probe":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "canceled-channel":
				ch.cancel()
			default:
				f.f.store.mu.Lock()
				s := f.f.store
				row := f.life.run(ch.run)
				switch kind {
				case "failed-store":
					s.failed = true
					undo = func() { s.failed = false }
				case "pending":
					s.j7.Pending = true
					undo = func() { s.j7.Pending = false }
				case "missing-inventory":
					saved := s.j7
					s.j7 = nil
					undo = func() { s.j7 = saved }
				case "no-map":
					delete(f.life.channels, ch.run)
					undo = func() { f.life.channels[ch.run] = ch }
				case "never-bound":
					ch.ever = false
					undo = func() { ch.ever = true }
				case "no-run":
					saved := ch.run
					ch.run = ""
					undo = func() { ch.run = saved }
				case "ended":
					row.State = "ended"
					undo = func() { row.State = "live" }
				case "foreign-launcher":
					saved := row.Launcher
					row.Launcher.UID++
					undo = func() { row.Launcher = saved }
				case "changed-binding":
					saved := row.Binding
					row.Binding.Epoch += "-different"
					undo = func() { row.Binding = saved }
				}
				f.f.store.mu.Unlock()
			}
			if f.life.BoundChannel(ctx, conn, peer) {
				t.Fatal("false bound proof accepted", kind)
			}
			f.f.store.mu.Lock()
			undo()
			f.f.store.mu.Unlock()
			if j7RunWitnessOf(t, f) != before {
				t.Fatal("metadata proof mutated durable state")
			}
		})
	}
}
