package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type handlerFunc func(context.Context, Peer, string, Object) (Object, Code)

func (f handlerFunc) Handle(c context.Context, p Peer, r Request) (Object, Code) {
	return f(c, p, r.Method, r.Params)
}

type peerFunc func(context.Context, net.Conn) (Peer, Code)

func (f peerFunc) Identify(c context.Context, n net.Conn) (Peer, Code) { return f(c, n) }

type idsFunc func(context.Context, Peer, Request) Code

func (f idsFunc) Admit(c context.Context, p Peer, r Request) Code { return f(c, p, r) }

type fenceFunc func(context.Context, Peer, Request, Object, func(context.Context) Code) Code

func (f fenceFunc) WithActive(c context.Context, p Peer, r Request, o Object, release func(context.Context) Code) Code {
	return f(c, p, r, o, release)
}

func testServer(t *testing.T, handler Handler, peers PeerSource, ids RequestIDs, fences ...ReleaseFence) *Server {
	t.Helper()
	if handler == nil {
		handler = handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) { return Object{"ok": true}, "" })
	}
	if peers == nil {
		peers = peerFunc(func(context.Context, net.Conn) (Peer, Code) { return Peer{UID: 1001, Generation: "generation-a"}, "" })
	}
	if ids == nil {
		var mu sync.Mutex
		seen := map[string]bool{}
		ids = idsFunc(func(_ context.Context, p Peer, r Request) Code {
			mu.Lock()
			defer mu.Unlock()
			key := fmt.Sprintf("%d/%s/%s", p.UID, p.Generation, r.ID)
			if seen[key] {
				return RequestConflict
			}
			seen[key] = true
			return ""
		})
	}
	// Fixed-active fixture only; real adapters must serialize with retirement.
	var fence ReleaseFence = fenceFunc(func(ctx context.Context, _ Peer, _ Request, _ Object, release func(context.Context) Code) Code {
		return release(ctx)
	})
	if len(fences) == 1 {
		fence = fences[0]
	} else if len(fences) > 1 {
		t.Fatal("multiple test fences")
	}
	s, err := New(handler, peers, ids, fence, testObserver{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Keep socket names short even when the caller's temporary root is long.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ctrl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return filepath.Join(dir, "c.sock")
}

func client(t *testing.T, s *Server, wrap func(net.Conn) net.Conn) (*net.UnixConn, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("unix", socketPath(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		listener.Close()
		if wrap != nil {
			conn = wrap(conn)
		}
		s.ServeConn(ctx, conn)
	}()
	c, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		cancel()
		listener.Close()
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(4 * time.Second))
	t.Cleanup(func() {
		cancel()
		c.Close()
		listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("connection did not stop")
		}
	})
	return c, done
}
func requestID(n int) string { return fmt.Sprintf("%032x", n) }
func hello(n int, versions ...int64) Object {
	list := make([]any, len(versions))
	for i, v := range versions {
		list[i] = v
	}
	return Object{"method": "hello", "request_id": requestID(n), "versions": list}
}
func operation(n int, method string, params Object, timeout int64) Object {
	return Object{"method": method, "params": params, "request_id": requestID(n), "timeout_ms": timeout}
}
func send(t *testing.T, c net.Conn, obj Object) {
	t.Helper()
	if err := writeFrame(c, obj); err != nil {
		t.Fatal(err)
	}
}
func receive(t *testing.T, c net.Conn) Object {
	t.Helper()
	b, code := readFrame(c)
	if code != "" || b == nil {
		t.Fatalf("response missing: %s %q", code, b)
	}
	obj, err := Decode(b)
	if err != nil {
		t.Fatalf("noncanonical response: %q: %v", b, err)
	}
	return obj
}
func wantError(t *testing.T, obj Object, id any, code Code) {
	t.Helper()
	if !members(obj, "error", "request_id") || obj["request_id"] != id {
		t.Fatalf("response shape/id: %#v", obj)
	}
	e, ok := obj["error"].(Object)
	if !ok || !members(e, "code", "retryable") || e["code"] != string(code) || e["retryable"] != retryable(code) {
		t.Fatalf("error fields: %#v", obj)
	}
}
func wantSuccess(t *testing.T, obj Object, id string) {
	t.Helper()
	if !members(obj, "request_id", "result") || obj["request_id"] != id {
		t.Fatalf("success shape/id: %#v", obj)
	}
	if _, ok := obj["result"].(Object); !ok {
		t.Fatalf("result not an object: %#v", obj)
	}
}
func closed(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	n, err := c.Read(one[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("wanted EOF with no extra reply: n=%d err=%v", n, err)
	}
}
func negotiate(t *testing.T, c net.Conn) {
	t.Helper()
	send(t, c, hello(1, 1))
	r := receive(t, c)
	wantSuccess(t, r, requestID(1))
	if r["result"].(Object)["version"] != int64(1) {
		t.Fatal(r)
	}
}

// Every native vector is exercised as exact frame bytes over a Unix socket;
// refusal/control pairs check ID, response shape, close policy and no dispatch.
func TestNativeVectors(t *testing.T) {
	var fixtures struct {
		Negative []struct {
			ID    string `json:"id"`
			Input struct {
				FrameHex string `json:"frame_hex"`
			} `json:"input"`
			Code     Code   `json:"expected_code"`
			Positive string `json:"positive_control"`
		} `json:"negative"`
		Positive []struct {
			ID    string `json:"id"`
			Input struct {
				FrameHex string `json:"frame_hex"`
			} `json:"input"`
			Verdict string `json:"expected_verdict"`
		} `json:"positive"`
	}
	data, err := os.ReadFile("../../vectors/refusals.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	controls := map[string]string{}
	for _, p := range fixtures.Positive {
		controls[p.ID] = p.Input.FrameHex
	}
	count := 0
	for _, v := range fixtures.Negative {
		if !strings.HasPrefix(v.ID, "native-") {
			continue
		}
		count++
		t.Run(v.ID, func(t *testing.T) {
			var calls atomic.Int32
			s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) { calls.Add(1); return Object{}, "" }), nil, nil)
			c, _ := client(t, s, nil)
			frame, err := hex.DecodeString(v.Input.FrameHex)
			if err != nil {
				t.Fatal(err)
			}
			if err = writeAll(c, frame); err != nil {
				t.Fatal(err)
			}
			if v.ID == "native-truncated" {
				if err = c.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			var id any
			if v.ID == "native-unknown-version" || v.ID == "native-claimed-uid" {
				id = requestID(1)
			}
			wantError(t, receive(t, c), id, v.Code)
			if v.ID == "native-claimed-uid" {
				// Schema refusal keeps negotiation available; it does not consume the ID.
				negotiate(t, c)
				c.CloseWrite()
			}
			closed(t, c)
			if calls.Load() != 0 {
				t.Fatalf("refusal invoked handler %d times", calls.Load())
			}
		})
		t.Run(v.Positive, func(t *testing.T) {
			var calls atomic.Int32
			s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) { calls.Add(1); return Object{}, "" }), nil, nil)
			c, _ := client(t, s, nil)
			h, ok := controls[v.Positive]
			if !ok {
				t.Fatal("missing vector control")
			}
			b, err := hex.DecodeString(h)
			if err != nil {
				t.Fatal(err)
			}
			if err = writeAll(c, b); err != nil {
				t.Fatal(err)
			}
			r := receive(t, c)
			wantSuccess(t, r, requestID(1))
			if r["result"].(Object)["version"] != int64(1) {
				t.Fatal(r)
			}
			c.CloseWrite()
			closed(t, c)
			if calls.Load() != 0 {
				t.Fatal("hello dispatched to handler")
			}
		})
	}
	if count != 11 {
		t.Fatalf("native coverage changed: %d", count)
	}
}

// A repeated hello refuses without dispatch or state reset; ordinary work after
// that refusal still uses the successfully negotiated version.
func TestSecondHello(t *testing.T) {
	var calls atomic.Int32
	s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) { calls.Add(1); return Object{}, "" }), nil, nil)
	c, _ := client(t, s, nil)
	negotiate(t, c)
	send(t, c, hello(2, 1))
	wantError(t, receive(t, c), requestID(2), HelloAlreadyNegotiated)
	if calls.Load() != 0 {
		t.Fatal("second hello dispatched")
	}
	send(t, c, operation(3, "pubkey", Object{}, 2000))
	wantSuccess(t, receive(t, c), requestID(3))
	if calls.Load() != 1 {
		t.Fatal("valid operation not dispatched once")
	}
}

// Missing negotiation and forbidden/unknown methods refuse; only the four
// intended control methods are dispatched, with their original params and peer.
func TestNegotiationAndMethodAllowlist(t *testing.T) {
	var got []string
	s := testServer(t, handlerFunc(func(_ context.Context, p Peer, m string, params Object) (Object, Code) {
		if p.UID != 1001 || p.Generation != "generation-a" {
			t.Error("untrusted peer")
		}
		got = append(got, m)
		return Object{}, ""
	}), nil, nil)
	c, done := client(t, s, nil)
	send(t, c, operation(2, "pubkey", Object{}, 2000))
	wantError(t, receive(t, c), requestID(2), HelloRequired)
	send(t, c, hello(1, 7, 1, 2))
	wantSuccess(t, receive(t, c), requestID(1))
	for i, m := range []string{"sign", "decrypt", "unknown"} {
		send(t, c, operation(i+3, m, Object{"bytes": "not-signable"}, 2000))
		wantError(t, receive(t, c), requestID(i+3), OperationUnsupported)
	}
	if len(got) != 0 {
		t.Fatal("forbidden operation dispatched")
	}
	for i, m := range []string{"pubkey", "register", "revoke", "sign_registration"} {
		send(t, c, operation(i+6, m, Object{}, 2000))
		wantSuccess(t, receive(t, c), requestID(i+6))
	}
	c.CloseWrite()
	closed(t, c)
	<-done
	if strings.Join(got, ",") != "pubkey,register,revoke,sign_registration" {
		t.Fatal(got)
	}
}

// Hello requires a unique nonempty positive safe-integer version list and exact
// envelope schema. Rejected hellos do not negotiate or consume a valid ID.
func TestHelloSchema(t *testing.T) {
	cases := []Object{
		hello(1), hello(1, 1, 1), hello(1, 0), hello(1, -1),
		{"method": "hello", "request_id": requestID(1), "versions": "1"},
		{"method": "hello", "request_id": requestID(1), "versions": []any{true}},
		{"method": "hello", "request_id": requestID(1)},
		{"method": "hello", "request_id": requestID(1), "uid": int64(1001), "versions": []any{int64(1)}},
	}
	for i, bad := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			s := testServer(t, nil, nil, nil)
			c, _ := client(t, s, nil)
			send(t, c, bad)
			wantError(t, receive(t, c), requestID(1), RequestMalformed)
			negotiate(t, c)
		})
	}
}

// Post-hello schema failures echo only a valid parsed ID, never call Handler,
// and preserve a usable connection for the nearest valid envelope.
func TestRequestEnvelope(t *testing.T) {
	tests := []struct {
		name   string
		change func(Object)
		id     any
	}{
		{"extra-member", func(o Object) { o["uid"] = int64(999) }, requestID(2)},
		{"missing-method", func(o Object) { delete(o, "method") }, requestID(2)},
		{"method-type", func(o Object) { o["method"] = int64(2) }, requestID(2)},
		{"missing-params", func(o Object) { delete(o, "params") }, requestID(2)},
		{"null-params", func(o Object) { o["params"] = nil }, requestID(2)},
		{"array-params", func(o Object) { o["params"] = []any{} }, requestID(2)},
		{"missing-timeout", func(o Object) { delete(o, "timeout_ms") }, requestID(2)},
		{"timeout-zero", func(o Object) { o["timeout_ms"] = int64(0) }, requestID(2)},
		{"timeout-large", func(o Object) { o["timeout_ms"] = int64(2001) }, requestID(2)},
		{"timeout-string", func(o Object) { o["timeout_ms"] = "1" }, requestID(2)},
		{"missing-id", func(o Object) { delete(o, "request_id") }, nil},
		{"uppercase-id", func(o Object) { o["request_id"] = strings.Repeat("A", 32) }, nil},
		{"short-id", func(o Object) { o["request_id"] = "a" }, nil},
		{"long-id", func(o Object) { o["request_id"] = strings.Repeat("a", 33) }, nil},
		{"id-type", func(o Object) { o["request_id"] = int64(2) }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) { calls.Add(1); return Object{}, "" }), nil, nil)
			c, _ := client(t, s, nil)
			negotiate(t, c)
			o := operation(2, "pubkey", Object{}, 2000)
			tt.change(o)
			send(t, c, o)
			wantError(t, receive(t, c), tt.id, RequestMalformed)
			if calls.Load() != 0 {
				t.Fatal("malformed envelope dispatched")
			}
			send(t, c, operation(2, "pubkey", Object{}, 2000))
			wantSuccess(t, receive(t, c), requestID(2))
			if calls.Load() != 1 {
				t.Fatal("control not dispatched exactly once")
			}
		})
	}
}

// The current peer/generation source is called for hello and again per request;
// retirement or unavailable evidence prevents both ID admission and execution.
func TestPeerRevalidation(t *testing.T) {
	for _, refusal := range []Code{"peer_identity_unavailable", "generation_inactive", "generation_mismatch", "generation_source_unavailable"} {
		t.Run(string(refusal), func(t *testing.T) {
			var peerCalls, admitted, handled atomic.Int32
			peers := peerFunc(func(context.Context, net.Conn) (Peer, Code) {
				if peerCalls.Add(1) == 2 {
					return Peer{}, refusal
				}
				return Peer{1001, "current"}, ""
			})
			s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) { handled.Add(1); return Object{}, "" }), peers, idsFunc(func(context.Context, Peer, Request) Code { admitted.Add(1); return "" }))
			c, _ := client(t, s, nil)
			negotiate(t, c)
			send(t, c, operation(2, "pubkey", Object{}, 2000))
			wantError(t, receive(t, c), requestID(2), refusal)
			if admitted.Load() != 1 || handled.Load() != 0 {
				t.Fatal("failed authority reached ID/handler")
			}
			closed(t, c)
			// Recovery requires a new negotiated connection, even if the source
			// resumes returning active evidence on its next lookup.
			fresh, _ := client(t, s, nil)
			send(t, fresh, hello(3, 1))
			wantSuccess(t, receive(t, fresh), requestID(3))
			send(t, fresh, operation(4, "pubkey", Object{}, 2000))
			wantSuccess(t, receive(t, fresh), requestID(4))
			if admitted.Load() != 3 || handled.Load() != 1 {
				t.Fatal("fresh-connection control did not pass")
			}
		})
	}
}

// Empty generation evidence cannot silently create an authenticated peer.
func TestMissingGeneration(t *testing.T) {
	peers := peerFunc(func(context.Context, net.Conn) (Peer, Code) { return Peer{UID: 1001}, "" })
	s := testServer(t, nil, peers, idsFunc(func(context.Context, Peer, Request) Code { t.Error("missing authority admitted"); return "" }))
	c, _ := client(t, s, nil)
	send(t, c, hello(1, 1))
	wantError(t, receive(t, c), requestID(1), "generation_source_unavailable")
}

// ID conflicts from the injected generation-scoped gate prevent dispatch;
// fresh IDs still execute. The gate sees the resolved peer and complete params.
func TestRequestIDAdmission(t *testing.T) {
	var calls atomic.Int32
	s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) { calls.Add(1); return Object{}, "" }), nil, nil)
	c, _ := client(t, s, nil)
	negotiate(t, c)
	send(t, c, operation(2, "pubkey", Object{}, 2000))
	wantSuccess(t, receive(t, c), requestID(2))
	send(t, c, operation(2, "pubkey", Object{}, 2000))
	wantError(t, receive(t, c), requestID(2), RequestConflict)
	if calls.Load() != 1 {
		t.Fatal("duplicate ID executed")
	}
	send(t, c, operation(3, "pubkey", Object{}, 2000))
	wantSuccess(t, receive(t, c), requestID(3))
	if calls.Load() != 2 {
		t.Fatal("fresh ID failed")
	}
}

// Typed errors expose only the fixed code and six permitted retryable classes;
// neither a handler's result-on-error nor its arbitrary diagnostic can escape.
func TestResponseRefusals(t *testing.T) {
	codes := []Code{"rate_limited", "busy", "generation_source_unavailable", "enrollment_unavailable", "audit_unavailable", DeadlineExceeded, RequestConflict, "identity_revoked", "role_not_permitted", "enrollment_unverified", "enrollment_unsupported", "generation_source_fenced"}
	for _, code := range codes {
		t.Run(string(code), func(t *testing.T) {
			s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) {
				return Object{"payload": "must-not-escape"}, code
			}), nil, nil)
			c, _ := client(t, s, nil)
			negotiate(t, c)
			send(t, c, operation(2, "pubkey", Object{}, 2000))
			r := receive(t, c)
			wantError(t, r, requestID(2), code)
			b, _ := Marshal(r)
			if strings.Contains(string(b), "must-not-escape") {
				t.Fatal("payload leaked")
			}
		})
	}
	for _, kind := range []string{"diagnostic", "invalid-result", "nil-result"} {
		t.Run(kind, func(t *testing.T) {
			s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) {
				switch kind {
				case "diagnostic":
					return nil, "arbitrary-private-diagnostic"
				case "invalid-result":
					return Object{"a": 1.5}, ""
				default:
					return nil, ""
				}
			}), nil, nil)
			c, _ := client(t, s, nil)
			negotiate(t, c)
			send(t, c, operation(2, "pubkey", Object{}, 2000))
			closed(t, c)
		})
	}
}

type narrowReadConn struct {
	net.Conn
	limit time.Duration
}

func (c narrowReadConn) SetReadDeadline(d time.Time) error {
	short := time.Now().Add(c.limit)
	if short.Before(d) {
		d = short
	}
	return c.Conn.SetReadDeadline(d)
}

// Actual socket header/body timeouts use the deadline code, null ID and close;
// complete hello frames through the same narrowed deadline remain valid.
func TestSocketReadDeadlines(t *testing.T) {
	for _, prefix := range [][]byte{{0}, packet([]byte(`{}`))[:5]} {
		t.Run(fmt.Sprintf("prefix-%d", len(prefix)), func(t *testing.T) {
			s := testServer(t, nil, nil, nil)
			wrap := func(c net.Conn) net.Conn { return narrowReadConn{c, 100 * time.Millisecond} }
			c, _ := client(t, s, wrap)
			if err := writeAll(c, prefix); err != nil {
				t.Fatal(err)
			}
			wantError(t, receive(t, c), nil, DeadlineExceeded)
			closed(t, c)
			c2, _ := client(t, s, wrap)
			negotiate(t, c2)
		})
	}
}

// Operation timing starts at completed frame receipt, not its header; a handler
// returning success after its deadline yields only the typed timeout response.
func TestOperationDeadline(t *testing.T) {
	var calls atomic.Int32
	s := testServer(t, handlerFunc(func(ctx context.Context, _ Peer, _ string, _ Object) (Object, Code) {
		d, ok := ctx.Deadline()
		if !ok || time.Until(d) <= 0 || time.Until(d) > 25*time.Millisecond {
			t.Error("wrong operation deadline")
		}
		if calls.Add(1) == 1 {
			<-ctx.Done()
			return Object{"late-success": true}, ""
		}
		return Object{}, ""
	}), nil, nil)
	c, _ := client(t, s, nil)
	negotiate(t, c)
	b, err := Marshal(operation(2, "pubkey", Object{}, 20))
	if err != nil {
		t.Fatal(err)
	}
	p := packet(b)
	if err = writeAll(c, p[:len(p)-1]); err != nil {
		t.Fatal(err)
	}
	time.Sleep(35 * time.Millisecond)
	if err = writeAll(c, p[len(p)-1:]); err != nil {
		t.Fatal(err)
	}
	wantError(t, receive(t, c), requestID(2), DeadlineExceeded)
	send(t, c, operation(3, "pubkey", Object{}, 20))
	wantSuccess(t, receive(t, c), requestID(3))
}

type countReadsConn struct {
	net.Conn
	reads *atomic.Int32
}

func (c countReadsConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	return c.Conn.Read(p)
}

// Queued bytes cause neither another server Read nor a second Handler call
// while the first operation is in flight; both requests succeed in order later.
func TestSequentialDispatch(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	var calls, reads atomic.Int32
	s := testServer(t, handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return Object{}, ""
	}), nil, nil)
	c, _ := client(t, s, func(n net.Conn) net.Conn { return countReadsConn{n, &reads} })
	defer unblock()
	negotiate(t, c)
	send(t, c, operation(2, "pubkey", Object{}, 2000))
	<-started
	before := reads.Load()
	send(t, c, operation(3, "pubkey", Object{}, 2000))
	// Bounded scheduling window, rather than the socket read deadline.
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != 1 || reads.Load() != before {
		t.Fatalf("read-ahead or concurrent dispatch: calls=%d reads=%d before=%d", calls.Load(), reads.Load(), before)
	}
	unblock()
	wantSuccess(t, receive(t, c), requestID(2))
	wantSuccess(t, receive(t, c), requestID(3))
}

// Closing/cancelling while a handler is in flight cannot release its late
// result; the connection exits after the cooperative handler observes cancel.
func TestCancellationNoLateResponse(t *testing.T) {
	started := make(chan struct{})
	returned := make(chan struct{})
	s := testServer(t, handlerFunc(func(ctx context.Context, _ Peer, _ string, _ Object) (Object, Code) {
		close(started)
		<-ctx.Done()
		close(returned)
		return Object{"late": true}, ""
	}), nil, nil)
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.ServeConn(ctx, serverConn) }()
	t.Cleanup(func() { cancel(); clientConn.Close() })
	negotiate(t, clientConn)
	send(t, clientConn, operation(2, "pubkey", Object{}, 2000))
	<-started
	cancel()
	closed(t, clientConn)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("handler not cancelled")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection not stopped")
	}
}

// The listener loop handles independent Unix connections, and cancellation
// closes the listener plus idle clients without unsolicited protocol replies.
func TestUnixListenerCancellation(t *testing.T) {
	s := testServer(t, nil, nil, nil)
	l, err := net.Listen("unix", socketPath(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	c1, err := net.Dial("unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := net.Dial("unix", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	negotiate(t, c1)
	send(t, c2, hello(2, 1))
	wantSuccess(t, receive(t, c2), requestID(2))
	cancel()
	closed(t, c1)
	closed(t, c2)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("listener did not stop")
	}
}

// A missing dependency fails construction rather than enabling a permissive
// handler, peer source, uniqueness tracker or release fence; valid injection works.
func TestRequiredDependencies(t *testing.T) {
	h := handlerFunc(func(context.Context, Peer, string, Object) (Object, Code) { return Object{}, "" })
	p := peerFunc(func(context.Context, net.Conn) (Peer, Code) { return Peer{1001, "g"}, "" })
	ids := idsFunc(func(context.Context, Peer, Request) Code { return "" })
	fence := fenceFunc(func(ctx context.Context, _ Peer, _ Request, _ Object, release func(context.Context) Code) Code {
		return release(ctx)
	})
	for _, deps := range []struct {
		h Handler
		p PeerSource
		i RequestIDs
		f ReleaseFence
	}{{nil, p, ids, fence}, {h, nil, ids, fence}, {h, p, nil, fence}, {h, p, ids, nil}} {
		if _, err := New(deps.h, deps.p, deps.i, deps.f, testObserver{}); err == nil {
			t.Fatal("missing dependency accepted")
		}
	}
	if _, err := New(h, p, ids, fence, testObserver{}); err != nil {
		t.Fatal(err)
	}
}

// A shared injected ID gate receives authenticated generation and canonical
// arguments across connections; conflicts never dispatch, and exact effect
// retries can reach a Handler which owns durable result recovery.
func TestSharedRequestIDContract(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]string{}
	var peerCalls, handlerCalls atomic.Int32
	var generation atomic.Value
	generation.Store("generation-a")
	peers := peerFunc(func(context.Context, net.Conn) (Peer, Code) {
		peerCalls.Add(1)
		return Peer{1001, generation.Load().(string)}, ""
	})
	ids := idsFunc(func(_ context.Context, p Peer, r Request) Code {
		b, err := Marshal(r.Params)
		if err != nil {
			t.Error(err)
			return RequestMalformed
		}
		key := fmt.Sprintf("%d/%s/%s", p.UID, p.Generation, r.ID)
		arguments := r.Method + string(b)
		mu.Lock()
		defer mu.Unlock()
		if previous, ok := seen[key]; ok && previous != arguments {
			return RequestConflict
		}
		seen[key] = arguments
		return ""
	})
	s := testServer(t, handlerFunc(func(_ context.Context, p Peer, m string, params Object) (Object, Code) {
		handlerCalls.Add(1)
		if m != "register" || params["example"] != int64(1) {
			t.Error("method/params changed")
		}
		return Object{"retained": true}, ""
	}), peers, ids)
	c1, _ := client(t, s, nil)
	negotiate(t, c1)
	send(t, c1, operation(2, "register", Object{"example": int64(1)}, 2000))
	wantSuccess(t, receive(t, c1), requestID(2))
	c2, _ := client(t, s, nil)
	send(t, c2, hello(3, 1))
	wantSuccess(t, receive(t, c2), requestID(3))
	send(t, c2, operation(2, "register", Object{"example": int64(2)}, 2000))
	wantError(t, receive(t, c2), requestID(2), RequestConflict)
	send(t, c2, operation(2, "revoke", Object{"example": int64(1)}, 2000))
	wantError(t, receive(t, c2), requestID(2), RequestConflict)
	if handlerCalls.Load() != 1 {
		t.Fatal("conflict reached handler")
	}
	send(t, c2, operation(2, "register", Object{"example": int64(1)}, 1000))
	wantSuccess(t, receive(t, c2), requestID(2))
	if handlerCalls.Load() != 2 {
		t.Fatal("exact retry was not delegated")
	}
	generation.Store("generation-b")
	send(t, c2, operation(2, "register", Object{"example": int64(1)}, 2000))
	wantError(t, receive(t, c2), requestID(2), "generation_mismatch")
	closed(t, c2)
	mu.Lock()
	_, adopted := seen["1001/generation-b/"+requestID(2)]
	mu.Unlock()
	if adopted || handlerCalls.Load() != 2 {
		t.Fatal("old connection adopted new generation")
	}
	// The ID's generation scope changes only on a new negotiated connection.
	c3, _ := client(t, s, nil)
	send(t, c3, hello(4, 1))
	wantSuccess(t, receive(t, c3), requestID(4))
	send(t, c3, operation(2, "register", Object{"example": int64(1)}, 2000))
	wantSuccess(t, receive(t, c3), requestID(2))
	mu.Lock()
	_, ok := seen["1001/generation-b/"+requestID(2)]
	mu.Unlock()
	if !ok || peerCalls.Load() != 9 || handlerCalls.Load() != 3 {
		t.Fatalf("gate did not see current peer: generation=%v source calls=%d", ok, peerCalls.Load())
	}
}

type deadlineRecordConn struct {
	net.Conn
	deadlines chan time.Time
}

func (c deadlineRecordConn) SetReadDeadline(d time.Time) error {
	c.deadlines <- d
	return c.Conn.SetReadDeadline(d)
}

// Pre-hello refusals cannot extend the two-second hello window; after successful
// negotiation the next frame receives its separate two-second read budget.
func TestHelloWindowNotExtended(t *testing.T) {
	deadlines := make(chan time.Time, 8)
	s := testServer(t, nil, nil, nil)
	c, _ := client(t, s, func(n net.Conn) net.Conn { return deadlineRecordConn{n, deadlines} })
	initial := <-deadlines
	if remaining := time.Until(initial); remaining <= 0 || remaining > 2*time.Second {
		t.Fatal("unbounded hello deadline")
	}
	send(t, c, operation(2, "pubkey", Object{}, 2000))
	wantError(t, receive(t, c), requestID(2), HelloRequired)
	if next := <-deadlines; !next.Equal(initial) {
		t.Fatal("hello refusal reset deadline")
	}
	negotiate(t, c)
	if next := <-deadlines; !next.After(initial) {
		t.Fatal("next frame did not get a fresh read window")
	}
}

// A parent deadline closes an in-flight hello without releasing a late
// dependency result or sending a reply after the connection lifetime ends.
func TestHelloParentDeadlineCloses(t *testing.T) {
	s := testServer(t, nil, peerFunc(func(ctx context.Context, _ net.Conn) (Peer, Code) {
		<-ctx.Done()
		return Peer{}, "generation_source_unavailable"
	}), nil)
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	// An earlier parent cancellation closes without a protocol reply, since the
	// listener/connection lifetime has ended. It must not become truncated EOF.
	done := make(chan struct{})
	go func() { defer close(done); s.ServeConn(ctx, serverConn) }()
	defer clientConn.Close()
	send(t, clientConn, hello(1, 1))
	closed(t, clientConn)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled hello did not stop")
	}
}

// Only the six specified transient refusals are retryable; every stable code in
// this package is a fixed identifier and may be sent without a diagnostic field.
func TestRetryableAllowlist(t *testing.T) {
	transient := map[Code]bool{"rate_limited": true, "busy": true, "generation_source_unavailable": true, "enrollment_unavailable": true, "audit_unavailable": true, DeadlineExceeded: true}
	codes := []Code{FrameTooLarge, FrameTruncated, FrameMalformed, CCJNoncanonical, RequestMalformed, RequestConflict, DeadlineExceeded, VersionUnsupported, HelloRequired, HelloAlreadyNegotiated, OperationUnsupported,
		"peer_identity_unavailable", "peer_binding_mismatch", "binding_conflict", "generation_source_unavailable", "generation_inactive", "generation_mismatch", "binding_not_found", "role_not_permitted", "identity_revoked", "persistent_revoke_requires_operator", "operator_record_unavailable", "operator_record_invalid", "path_not_hardened", "path_invalid", "purpose_unknown", "name_invalid", "name_unknown", "name_registry_invalid", "index_exhausted", "sign_data_not_sshsig", "sshsig_malformed", "namespace_not_permitted", "sign_key_mismatch", "sign_flags_unsupported", "agent_message_unsupported", "request_expired", "enrollment_unavailable", "enrollment_unverified", "enrollment_unsupported", "host_revoked", "uid_map_required", "uid_not_permitted", "name_not_permitted", "audience_mismatch", "key_not_enrolled", "key_not_valid_now", "entropy_unavailable", "clock_untrusted", "rate_limited", "busy", "state_capacity_exceeded", "audit_unavailable"}
	for _, code := range codes {
		if !validCode(code) || retryable(code) != transient[code] {
			t.Fatalf("code %s: valid=%v retryable=%v", code, validCode(code), retryable(code))
		}
	}
	if validCode("not-a-code") {
		t.Fatal("arbitrary diagnostic accepted")
	}
}

// The actual two-second handshake budget bounds a cooperative peer lookup;
// expiry sends exactly one ID-echoed timeout and closes without ID admission.
func TestHelloOwnDeadline(t *testing.T) {
	var admissions atomic.Int32
	s := testServer(t, nil, peerFunc(func(ctx context.Context, _ net.Conn) (Peer, Code) {
		<-ctx.Done()
		return Peer{}, "generation_source_unavailable"
	}), idsFunc(func(context.Context, Peer, Request) Code { admissions.Add(1); return "" }))
	c, _ := client(t, s, nil)
	send(t, c, hello(1, 1))
	wantError(t, receive(t, c), requestID(1), DeadlineExceeded)
	closed(t, c)
	if admissions.Load() != 0 {
		t.Fatal("expired hello reached ID admission")
	}
}

// Wire tests use a fixed available observer; core tests qualify durable audit.
type testObserver struct{}

func (testObserver) Enter(context.Context, net.Conn) (func(), Code) { return func() {}, "" }
func (testObserver) Refuse(_ context.Context, _ net.Conn, _ *Peer, _ Request, _ []byte, c Code) Code {
	return c
}

// A socket owner's accepted tuple applies to the first hello, before ID
// admission or release. Both UID and generation replacements refuse and close;
// unchanged authority negotiates and still enters the mandatory write fence.
func TestAcceptedTupleBeforeHello(t *testing.T) {
	accepted := Peer{UID: 1001, Generation: "generation-a"}
	for _, which := range []string{"intact", "uid", "generation", "missing"} {
		t.Run(which, func(t *testing.T) {
			current, pin := accepted, accepted
			switch which {
			case "uid":
				current.UID++
			case "generation":
				current.Generation = "generation-b"
			case "missing":
				pin.Generation = ""
			}
			var admitted, released atomic.Int32
			s := testServer(t, nil, peerFunc(func(context.Context, net.Conn) (Peer, Code) { return current, "" }), idsFunc(func(context.Context, Peer, Request) Code { admitted.Add(1); return "" }), fenceFunc(func(ctx context.Context, _ Peer, _ Request, _ Object, write func(context.Context) Code) Code {
				released.Add(1)
				return write(ctx)
			}))
			server, client := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			defer client.Close()
			done := make(chan struct{})
			go func() { defer close(done); s.ServeConnAccepted(ctx, server, pin) }()
			if which == "missing" {
				closed(t, client)
			} else {
				send(t, client, hello(1, 1))
				if which == "intact" {
					wantSuccess(t, receive(t, client), requestID(1))
					client.Close()
				} else {
					wantError(t, receive(t, client), requestID(1), "generation_mismatch")
					closed(t, client)
				}
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("accepted connection did not close")
			}
			want := int32(0)
			if which == "intact" {
				want = 1
			}
			if admitted.Load() != want || released.Load() != want {
				t.Fatal("changed accepted tuple entered admission or release")
			}
		})
	}
}
