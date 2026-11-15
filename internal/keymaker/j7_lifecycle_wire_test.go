//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	wire "github.com/relux-works/swarma-keymaker/j7lifecycle"
)

// These helpers are test-only socket I/O, not a launcher client. The accepted
// Unix FD/kernel opener is real; generations describe fixtures, not host users.
func lifecycleWrite(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	for len(b) > 0 {
		n, e := c.Write(b)
		if e != nil || n == 0 {
			t.Fatal("fixture write", e)
		}
		b = b[n:]
	}
}
func lifecycleRead(c net.Conn) ([]byte, error) {
	var h [4]byte
	if _, e := io.ReadFull(c, h[:]); e != nil {
		return nil, e
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > wire.MaxFrame {
		return nil, fmt.Errorf("unexpected response frame size %d", n)
	}
	b := make([]byte, 4+int(n))
	copy(b, h[:])
	_, e := io.ReadFull(c, b[4:])
	return b, e
}
func lifecycleCall(t *testing.T, c net.Conn, q wire.Request, want Code) wire.Response {
	t.Helper()
	b, e := wire.EncodeRequestFrame(q)
	if e != nil {
		t.Fatal(e)
	}
	lifecycleWrite(t, c, b)
	f, e := lifecycleRead(c)
	if e != nil {
		t.Fatal("fixture response read", e)
	}
	r, e := wire.DecodeResponseFrame(q, f)
	if e != nil {
		t.Fatal("public response decode", e)
	}
	if want == "" {
		if r.Refusal != nil || r.ID != q.ID {
			t.Fatalf("unexpected wire refusal %+v", r)
		}
	} else if r.Refusal == nil || r.Refusal.Code != string(want) || r.Run != nil {
		t.Fatalf("wire refusal %+v want %s", r, want)
	}
	return r
}
func lifecycleConnect(t *testing.T, address string) *net.UnixConn {
	t.Helper()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: address, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	if e := c.SetDeadline(time.Now().Add(4 * time.Second)); e != nil {
		t.Fatal(e)
	}
	return c
}
func lifecycleHello(t *testing.T, c net.Conn, id int) {
	t.Helper()
	r := lifecycleCall(t, c, wire.Request{ID: nativeID(id), Method: wire.HelloMethod, Versions: []int64{1}}, "")
	if r.Version == nil || *r.Version != 1 {
		t.Fatal("hello version missing")
	}
}
func lifecycleBind(f *j7RunFixture, id int) wire.Request {
	a := f.args()
	o := a.Origin
	return wire.Request{ID: nativeID(id), Method: wire.BindMethod, TimeoutMS: 2000, Bind: &wire.BindParams{IdentityRegistrationNumber: a.Identity, InputPrincipal: wire.Principal{UID: a.Input.UID, Generation: a.Input.Generation}, Origin: &wire.Origin{Kind: o.Kind, EventID: o.Event, GrantID: o.Grant, TipHash: o.Tip, Mode: o.Mode, CommandID: o.Command}}}
}
func lifecycleEnd(id int, run string) wire.Request {
	return wire.Request{ID: nativeID(id), Method: wire.EndMethod, TimeoutMS: 2000, RunID: run}
}

// Public literal schemas interoperate with the existing lifecycle and embedded
// request-custody compositions, without a new factory or production startup.
// Synthetic generation/key fixtures do not qualify custody or distinct-UID input.
func TestJ7LifecycleWireCompatibility(t *testing.T) {
	for _, kind := range []string{"lifecycle", "request-adapter"} {
		t.Run(kind, func(t *testing.T) {
			var f *j7RunFixture
			if kind == "lifecycle" {
				f = j7RunSetup(t)
			} else {
				s := j7SigningSetup(t)
				f = &j7RunFixture{f: s.f, life: s.a.j7Lifecycle, gen: s.gen, socket: s.socket}
			}
			parent := lifecycleConnect(t, f.socket)
			lifecycleHello(t, parent, 1)
			q := lifecycleBind(f, 2)
			r := lifecycleCall(t, parent, q, "")
			if r.Run == nil || r.Run.State != "live" || !messageID(r.Run.RunID) {
				t.Fatal("bound result")
			}
			if retry := lifecycleCall(t, parent, q, ""); !reflect.DeepEqual(r, retry) {
				t.Fatal("original-channel exact retry changed result")
			}
			child := lifecycleConnect(t, f.socket)
			lifecycleHello(t, child, 3)
			childQ := lifecycleBind(f, 4)
			childQ.Bind.Origin = nil
			childQ.Bind.ParentRun = r.Run.RunID
			childQ.Bind.InputPrincipal = wire.Principal{UID: f.f.uid + 201, Generation: "input-b"}
			cr := lifecycleCall(t, child, childQ, "")
			f.f.store.mu.Lock()
			origin := f.life.run(cr.Run.RunID).Origin
			f.f.store.mu.Unlock()
			if origin != f.f.origin {
				t.Fatal("wire child changed immutable origin")
			}
			ack := lifecycleCall(t, child, lifecycleEnd(5, cr.Run.RunID), "")
			if ack.Run.State != "ended" {
				t.Fatal("child end result")
			}
			admin := lifecycleConnect(t, f.socket)
			lifecycleHello(t, admin, 6)
			end := lifecycleEnd(7, r.Run.RunID)
			ended := lifecycleCall(t, admin, end, "")
			fresh := lifecycleConnect(t, f.socket)
			lifecycleHello(t, fresh, 8)
			before := j7RunWitnessOf(t, f)
			if got := lifecycleCall(t, fresh, end, ""); !reflect.DeepEqual(got, ended) {
				t.Fatal("fresh exact end acknowledgement changed")
			}
			if j7RunWitnessOf(t, f) != before {
				t.Fatal("exact end retry changed retained state")
			}
		})
	}
}

// Wrong authority and reused/foreign channels reject with the intended code
// and no retained-body/snapshot/commit mutation (refusal audit is permitted).
func TestJ7LifecycleWireAuthority(t *testing.T) {
	for _, kind := range []string{"role", "launcher-generation", "input-generation", "inactive-input", "same-launcher-uid", "station-uid", "registration"} {
		t.Run(kind, func(t *testing.T) {
			f := j7RunSetup(t)
			q := lifecycleBind(f, 2)
			want := Code("role_not_permitted")
			if kind == "role" {
				f.life.launcher.UID++
			}
			if kind == "launcher-generation" {
				f.life.launcher.Generation = "other"
			}
			c := lifecycleConnect(t, f.socket)
			if kind == "role" || kind == "launcher-generation" {
				before := j7RunWitnessOf(t, f)
				lifecycleCall(t, c, wire.Request{ID: nativeID(1), Method: wire.HelloMethod, Versions: []int64{1}}, want)
				if j7RunWitnessOf(t, f) != before {
					t.Fatal("wrong launcher hello changed state")
				}
				return
			}
			lifecycleHello(t, c, 1)
			switch kind {
			case "input-generation":
				q.Bind.InputPrincipal.Generation = "other"
				want = "generation_mismatch"
			case "inactive-input":
				f.gen.set(q.Bind.InputPrincipal.UID, "retiring", q.Bind.InputPrincipal.Generation)
				want = "generation_inactive"
			case "same-launcher-uid":
				q.Bind.InputPrincipal = wire.Principal{UID: f.life.launcher.UID, Generation: f.life.launcher.Generation}
				want = "request_malformed"
			case "station-uid":
				q.Bind.InputPrincipal = wire.Principal{UID: f.f.binding.UID, Generation: f.f.binding.Generation}
				want = "run_identity_unavailable"
			case "registration":
				q.Bind.IdentityRegistrationNumber++
				want = "request_malformed"
			}
			before := j7RunWitnessOf(t, f)
			lifecycleCall(t, c, q, want)
			if j7RunWitnessOf(t, f) != before {
				t.Fatal("refused wire authority changed state")
			}
		})
	}
	f := j7RunSetup(t)
	a := lifecycleConnect(t, f.socket)
	lifecycleHello(t, a, 1)
	q := lifecycleBind(f, 2)
	r := lifecycleCall(t, a, q, "")
	b := lifecycleConnect(t, f.socket)
	lifecycleHello(t, b, 3)
	before := j7RunWitnessOf(t, f)
	lifecycleCall(t, b, q, "run_identity_unavailable")
	if j7RunWitnessOf(t, f) != before {
		t.Fatal("foreign retry changed retained state")
	}
	changed := lifecycleBind(f, 2)
	changed.Bind.InputPrincipal = wire.Principal{UID: f.f.uid + 201, Generation: "input-b"}
	lifecycleCall(t, a, changed, "request_conflict")
	changed.ID = nativeID(4)
	lifecycleCall(t, a, changed, "run_identity_unavailable")
	if j7RunWitnessOf(t, f) != before {
		t.Fatal("reused channel changed retained state")
	}
	a.Close()
	f.waitDisconnected(t, r.Run.RunID)
	// The existing holder method remains; v1 launcher policy does not call it.
	rebind := wire.Request{ID: nativeID(5), Method: wire.RebindMethod, TimeoutMS: 2000, RunID: r.Run.RunID}
	lifecycleCall(t, b, rebind, "")
	f.gen.set(q.Bind.InputPrincipal.UID, "retiring", q.Bind.InputPrincipal.Generation)
	f.waitDisconnected(t, r.Run.RunID)
	cleanup := lifecycleConnect(t, f.socket)
	lifecycleHello(t, cleanup, 6)
	lifecycleCall(t, cleanup, lifecycleEnd(7, r.Run.RunID), "")
}

type lifecycleFaultListener struct {
	net.Listener
	accepted chan *lifecycleFaultConn
	arm      *atomic.Bool
	target   int
	prefix   int
}
type lifecycleFaultConn struct {
	*net.UnixConn
	arm                    *atomic.Bool
	target, prefix, writes int
	done                   chan struct{}
	closed                 sync.Once
}

func (l *lifecycleFaultListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	f := &lifecycleFaultConn{UnixConn: c.(*net.UnixConn), arm: l.arm, target: l.target, prefix: l.prefix, done: make(chan struct{})}
	l.accepted <- f
	return f, nil
}
func (c *lifecycleFaultConn) Write(b []byte) (int, error) {
	c.writes++
	if c.writes == c.target && c.arm.CompareAndSwap(true, false) {
		n := c.prefix
		if n > len(b) {
			n = len(b)
		}
		if n == 0 {
			return 0, io.ErrClosedPipe
		}
		written, e := c.UnixConn.Write(b[:n])
		if e != nil {
			return written, e
		}
		return written, io.ErrUnexpectedEOF
	}
	return c.UnixConn.Write(b)
}
func (c *lifecycleFaultConn) Close() error {
	e := c.UnixConn.Close()
	c.closed.Do(func() { close(c.done) })
	return e
}
func lifecycleFaultServer(t *testing.T, f *j7RunFixture, target, prefix int) (*lifecycleFaultListener, string) {
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
	address := fmt.Sprintf("@lifecycle-wire-%d-%d", os.Getpid(), j7SocketCounter.Add(1))
	listener, e := net.Listen("unix", address)
	if e != nil {
		t.Fatal(e)
	}
	wrap := &lifecycleFaultListener{Listener: listener, accepted: make(chan *lifecycleFaultConn, 8), arm: &atomic.Bool{}, target: target, prefix: prefix}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, wrap) }()
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("fault server did not stop")
		}
	})
	return wrap, address
}
func lifecycleClosed(t *testing.T, c *lifecycleFaultConn) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		t.Fatal("actual connection did not close")
	}
}
func lifecycleLostRead(t *testing.T, c net.Conn) {
	t.Helper()
	_, e := lifecycleRead(c)
	if !errors.Is(e, io.EOF) && !errors.Is(e, io.ErrUnexpectedEOF) && !errors.Is(e, net.ErrClosed) {
		t.Fatal("ack loss was not EOF/partial EOF", e)
	}
}

// Complete but discarded bind replies can be recovered only on the original
// live channel. Zero/partial actual writes commit one run, lose the channel and
// refuse bind-result adoption on a fresh channel. No launcher input is emulated.
func TestJ7LifecycleBindAckLoss(t *testing.T) {
	f := j7RunSetup(t)
	a := lifecycleConnect(t, f.socket)
	lifecycleHello(t, a, 1)
	q := lifecycleBind(f, 2)
	frame, e := wire.EncodeRequestFrame(q)
	if e != nil {
		t.Fatal(e)
	}
	lifecycleWrite(t, a, frame)
	if _, e := lifecycleRead(a); e != nil {
		t.Fatal(e)
	} // application discarded complete response
	recovered := lifecycleCall(t, a, q, "")
	if recovered.Run == nil || len(f.f.store.j7.Runs) != 1 {
		t.Fatal("original retry lost/duplicated bind")
	}
	for _, prefix := range []int{0, 2, 7} {
		t.Run(fmt.Sprint(prefix), func(t *testing.T) {
			f := j7RunSetup(t)
			wrap, address := lifecycleFaultServer(t, f, 2, prefix)
			wrap.arm.Store(true)
			c := lifecycleConnect(t, address)
			accepted := <-wrap.accepted
			lifecycleHello(t, c, 1)
			q := lifecycleBind(f, 2)
			b, e := wire.EncodeRequestFrame(q)
			if e != nil {
				t.Fatal(e)
			}
			lifecycleWrite(t, c, b)
			lifecycleLostRead(t, c)
			lifecycleClosed(t, accepted)
			f.f.store.mu.Lock()
			count := len(f.f.store.j7.Runs)
			channels := len(f.life.channels)
			state := ""
			if count == 1 {
				state = f.f.store.j7.Runs[0].State
			}
			f.f.store.mu.Unlock()
			if count != 1 || channels != 0 || state != "live" {
				t.Fatal("lost bind did not retain exactly one disconnected run")
			}
			fresh := lifecycleConnect(t, address)
			lifecycleHello(t, fresh, 3)
			before := j7RunWitnessOf(t, f)
			lifecycleCall(t, fresh, q, "run_identity_unavailable")
			if j7RunWitnessOf(t, f) != before {
				t.Fatal("lost bind adopted/mutated on new channel")
			}
		})
	}
}

// Before a complete frame no bind can commit. A journal/snapshot interruption
// instead fences uncertain history; neither path can emit successful authority.
func TestJ7LifecycleCommitLoss(t *testing.T) {
	t.Run("incomplete-frame", func(t *testing.T) {
		f := j7RunSetup(t)
		wrap, address := lifecycleFaultServer(t, f, 0, 0)
		c := lifecycleConnect(t, address)
		accepted := <-wrap.accepted
		lifecycleHello(t, c, 1)
		before := j7RunWitnessOf(t, f)
		frame, e := wire.EncodeRequestFrame(lifecycleBind(f, 2))
		if e != nil {
			t.Fatal(e)
		}
		lifecycleWrite(t, c, frame[:6])
		c.Close()
		lifecycleClosed(t, accepted)
		if j7RunWitnessOf(t, f) != before || len(f.f.store.j7.Runs) != 0 {
			t.Fatal("incomplete frame committed bind")
		}
	})
	for _, point := range []string{"before-journal", "after-journal"} {
		t.Run(point, func(t *testing.T) {
			f := j7RunSetup(t)
			c := lifecycleConnect(t, f.socket)
			lifecycleHello(t, c, 1)
			f.f.store.j7Fault = func(p string) Code {
				if p == point {
					return "j7_state_fenced"
				}
				return ""
			}
			lifecycleCall(t, c, lifecycleBind(f, 2), "j7_state_fenced")
			f.f.store.mu.Lock()
			failed := f.f.store.failed
			channels := len(f.life.channels)
			f.f.store.mu.Unlock()
			if !failed || channels != 0 {
				t.Fatal("uncertain commit did not fence without channel")
			}
		})
	}
}

// A lost durable end acknowledgement is recovered exactly on a permitted fresh
// launcher connection. EOF and input retirement do not revive or erase history.
func TestJ7LifecycleEndAckLoss(t *testing.T) {
	for _, prefix := range []int{0, 2, 7} {
		t.Run(fmt.Sprint(prefix), func(t *testing.T) {
			f := j7RunSetup(t)
			wrap, address := lifecycleFaultServer(t, f, 3, prefix)
			c := lifecycleConnect(t, address)
			accepted := <-wrap.accepted
			lifecycleHello(t, c, 1)
			bound := lifecycleCall(t, c, lifecycleBind(f, 2), "")
			q := lifecycleEnd(3, bound.Run.RunID)
			wrap.arm.Store(true)
			b, e := wire.EncodeRequestFrame(q)
			if e != nil {
				t.Fatal(e)
			}
			lifecycleWrite(t, c, b)
			lifecycleLostRead(t, c)
			lifecycleClosed(t, accepted)
			f.f.store.mu.Lock()
			ended := f.life.run(q.RunID).State
			channels := len(f.life.channels)
			f.f.store.mu.Unlock()
			if ended != "ended" || channels != 0 {
				t.Fatal("end loss lost durable retirement")
			}
			f.gen.set(f.args().Input.UID, "retiring", f.args().Input.Generation)
			fresh := lifecycleConnect(t, address)
			lifecycleHello(t, fresh, 4)
			before := j7RunWitnessOf(t, f)
			got := lifecycleCall(t, fresh, q, "")
			if got.Run == nil || got.Run.RunID != q.RunID || got.Run.State != "ended" {
				t.Fatal("fresh end recovery mismatch")
			}
			if j7RunWitnessOf(t, f) != before {
				t.Fatal("fresh exact end retry rewrote history")
			}
			// Changing the same ID's target remains request_conflict, never another end.
			changed := q
			changed.RunID = strings.Repeat("f", 32)
			lifecycleCall(t, fresh, changed, "request_conflict")
			if j7RunWitnessOf(t, f) != before {
				t.Fatal("changed end body mutated history")
			}
		})
	}
}

// Server method schemas remain independently closed when an extra field is
// deliberately sent around the public encoder. Expected refusal, not any error.
func TestJ7LifecycleWireMalformed(t *testing.T) {
	f := j7RunSetup(t)
	c := lifecycleConnect(t, f.socket)
	lifecycleHello(t, c, 1)
	q := lifecycleBind(f, 2)
	raw, e := wire.EncodeRequestFrame(q)
	if e != nil {
		t.Fatal(e)
	}
	body := bytes.Replace(raw[4:], []byte(`"origin":`), []byte(`"nonce":"not-authority","origin":`), 1)
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	before := j7RunWitnessOf(t, f)
	lifecycleWrite(t, c, frame)
	got, e := lifecycleRead(c)
	if e != nil {
		t.Fatal(e)
	}
	r, e := wire.DecodeResponseFrame(q, got)
	if e != nil || r.Refusal == nil || r.Refusal.Code != "request_malformed" || r.Run != nil {
		t.Fatal("extra argument did not specifically refuse", e, r)
	}
	if j7RunWitnessOf(t, f) != before {
		t.Fatal("malformed bind changed state")
	}
}
