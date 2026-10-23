package control

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Same-tuple work continues; either component changing refuses and closes before
// ID admission or execution. A fresh connection can negotiate the new tuple.
func TestConnectionGenerationPinned(t *testing.T) {
	for _, changed := range []Peer{{1001, "generation-b"}, {1002, "generation-a"}} {
		t.Run(changed.Generation+"-"+requestID(int(changed.UID)), func(t *testing.T) {
			var current atomic.Value
			current.Store(Peer{1001, "generation-a"})
			var admissions, calls atomic.Int32
			s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) {
				calls.Add(1)
				return Object{}, ""
			}), peerFunc(func(context.Context, net.Conn) (Peer, Code) {
				return current.Load().(Peer), ""
			}), idsFunc(func(context.Context, Peer, Request) Code { admissions.Add(1); return "" }))
			c, _ := client(t, s, nil)
			negotiate(t, c)
			send(t, c, operation(2, "pubkey", Object{}, 2000))
			wantSuccess(t, receive(t, c), requestID(2))
			current.Store(changed)
			send(t, c, operation(3, "pubkey", Object{}, 2000))
			wantError(t, receive(t, c), requestID(3), "generation_mismatch")
			closed(t, c)
			if admissions.Load() != 2 || calls.Load() != 1 {
				t.Fatal("changed tuple reached admission or handler")
			}
			fresh, _ := client(t, s, nil)
			send(t, fresh, hello(4, 1))
			wantSuccess(t, receive(t, fresh), requestID(4))
			send(t, fresh, operation(5, "pubkey", Object{}, 2000))
			wantSuccess(t, receive(t, fresh), requestID(5))
			if admissions.Load() != 4 || calls.Load() != 2 {
				t.Fatal("new-tuple control failed")
			}
		})
	}
}

// This authority is a test fixture: its one mutex serializes authoritative
// retirement with the entire release callback, matching the core barrier seam.
type lifetimeAuthority struct {
	mu     sync.Mutex
	peer   Peer
	active bool
}

func newLifetimeAuthority() *lifetimeAuthority {
	return &lifetimeAuthority{peer: Peer{1001, "generation-a"}, active: true}
}

func (a *lifetimeAuthority) Identify(context.Context, net.Conn) (Peer, Code) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.active {
		return Peer{}, "generation_inactive"
	}
	return a.peer, ""
}

func (a *lifetimeAuthority) WithActive(ctx context.Context, peer Peer, _ Request, _ Object, release func() Code) Code {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil {
		return DeadlineExceeded
	}
	if !a.active {
		return "generation_inactive"
	}
	if peer != a.peer {
		return "generation_mismatch"
	}
	return release()
}

func (a *lifetimeAuthority) retire() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.active = false
}

type beforeWriteConn struct {
	net.Conn
	armed  *atomic.Bool
	before func()
}

func (c beforeWriteConn) SetWriteDeadline(d time.Time) error {
	if c.armed.CompareAndSwap(true, false) {
		c.before()
	}
	return c.Conn.SetWriteDeadline(d)
}

// Retirement after successful lookup/handler preparation but before the actual
// write suppresses success, emits only the typed refusal, then closes. The same
// hello/method paths succeed through that barrier when authority stays active.
func TestReleaseFenceRetirementWins(t *testing.T) {
	for _, method := range []string{"hello", "pubkey", "register", "revoke", "sign_registration"} {
		for _, retire := range []bool{false, true} {
			name := method + "/active"
			if retire {
				name = method + "/retired"
			}
			t.Run(name, func(t *testing.T) {
				a := newLifetimeAuthority()
				var armed atomic.Bool
				var calls atomic.Int32
				armed.Store(method == "hello" && retire)
				s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) {
					calls.Add(1)
					armed.Store(retire)
					return Object{"sensitive": "result"}, ""
				}), a, nil, a)
				c, _ := client(t, s, func(n net.Conn) net.Conn { return beforeWriteConn{n, &armed, a.retire} })
				id := 1
				if method == "hello" {
					send(t, c, hello(id, 1))
				} else {
					negotiate(t, c)
					id = 2
					send(t, c, operation(id, method, Object{}, 2000))
				}
				if retire {
					wantError(t, receive(t, c), requestID(id), "generation_inactive")
					closed(t, c)
				} else {
					wantSuccess(t, receive(t, c), requestID(id))
				}
				wantCalls := int32(1)
				if method == "hello" {
					wantCalls = 0
				}
				if calls.Load() != wantCalls {
					t.Fatal("unexpected handler dispatch")
				}
			})
		}
	}
}

type blockingWriteConn struct {
	net.Conn
	armed   *atomic.Bool
	entered chan struct{}
	allow   <-chan struct{}
}

func (c blockingWriteConn) Write(p []byte) (int, error) {
	if c.armed.CompareAndSwap(true, false) {
		close(c.entered)
		<-c.allow
	}
	return c.Conn.Write(p)
}

// A write already inside the barrier completes before retirement can commit.
// Retirement cannot recall that response, but the next request refuses and
// closes without further dispatch. Both hello and operation use this ordering.
func TestReleaseFenceReleaseWins(t *testing.T) {
	for _, method := range []string{"hello", "pubkey", "register", "revoke", "sign_registration"} {
		t.Run(method, func(t *testing.T) {
			a := newLifetimeAuthority()
			var armed atomic.Bool
			armed.Store(method == "hello")
			var calls atomic.Int32
			s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) {
				calls.Add(1)
				armed.Store(true)
				return Object{"released": true}, ""
			}), a, nil, a)
			entered, allow := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(allow) }) }
			c, _ := client(t, s, func(n net.Conn) net.Conn { return blockingWriteConn{n, &armed, entered, allow} })
			defer unblock()
			id := 1
			if method == "hello" {
				send(t, c, hello(id, 1))
			} else {
				negotiate(t, c)
				id = 2
				send(t, c, operation(id, method, Object{}, 2000))
			}
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("write did not enter barrier")
			}
			attempt, retired := make(chan struct{}), make(chan struct{})
			go func() { close(attempt); a.retire(); close(retired) }()
			<-attempt
			select {
			case <-retired:
				t.Fatal("retirement overtook an in-progress release")
			case <-time.After(30 * time.Millisecond):
			}
			unblock()
			wantSuccess(t, receive(t, c), requestID(id))
			select {
			case <-retired:
			case <-time.After(time.Second):
				t.Fatal("retirement did not commit after release")
			}
			send(t, c, operation(3, "pubkey", Object{}, 2000))
			wantError(t, receive(t, c), requestID(3), "generation_inactive")
			closed(t, c)
			wantCalls := int32(1)
			if method == "hello" {
				wantCalls = 0
			}
			if calls.Load() != wantCalls {
				t.Fatal("retired next request reached handler")
			}
		})
	}
}

type partialWriteConn struct {
	net.Conn
	armed *atomic.Bool
}

func (c partialWriteConn) Write(p []byte) (int, error) {
	if c.armed.CompareAndSwap(true, false) {
		n, err := c.Conn.Write(p[:7])
		if err != nil {
			return n, err
		}
		return n, errors.New("injected partial write")
	}
	return c.Conn.Write(p)
}

// A partially emitted success is never followed by a competing error frame;
// the client observes exactly its prefix and EOF, not a repair or retry.
func TestReleaseFencePartialWriteCloses(t *testing.T) {
	var armed atomic.Bool
	result := Object{"ok": true}
	s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) {
		armed.Store(true)
		return result, ""
	}), nil, nil)
	c, _ := client(t, s, func(n net.Conn) net.Conn { return partialWriteConn{n, &armed} })
	negotiate(t, c)
	send(t, c, operation(2, "pubkey", Object{}, 2000))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := marshalFrame(Object{"request_id": requestID(2), "result": result})
	if err != nil || string(got) != string(frame[:7]) {
		t.Fatalf("unexpected bytes after partial release: %q error=%v", got, err)
	}
}
