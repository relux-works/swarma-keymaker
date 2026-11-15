//go:build linux

package keymaker

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

var j7SocketCounter atomic.Uint64

type j7RunFixture struct {
	f       *j7StateFixture
	life    *j7Lifecycle
	gen     *fakeGenerations
	socket  string
	cancel  context.CancelFunc
	done    chan error
	stopped bool
}

func j7RunSetup(t *testing.T) *j7RunFixture {
	t.Helper()
	f := j7StateSetup(t)
	f.publish(t, f.table(1))
	launcher := Principal{f.uid, nativeToken}
	g := newGenerations(f.uid, nativeToken)
	for _, p := range []Principal{{f.binding.UID, f.binding.Generation}, {f.uid + 200, "input-a"}, {f.uid + 201, "input-b"}, {f.uid + 202, "input-c"}} {
		g.entries[p.UID] = Generation{UID: p.UID, Generation: p.Generation, State: "active", Revision: "fixture", Provenance: "fixture-only", Verified: true}
	}
	l, e := newJ7Lifecycle(f.store, f.policy, g, launcher)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := control.New(l, l, l, l, l)
	if e != nil {
		t.Fatal(e)
	}
	// An abstract socket avoids filesystem path-length/permission claims. The
	// accepted connection and SO_PEERCRED are real, not an injected peer source.
	address := fmt.Sprintf("@j7-fixture-%d-%d", os.Getpid(), j7SocketCounter.Add(1))
	listener, e := net.Listen("unix", address)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- wire.Serve(ctx, listener) }()
	rf := &j7RunFixture{f: f, life: l, gen: g, socket: address, cancel: cancel, done: done}
	t.Cleanup(func() { rf.stop(t); listener.Close() })
	return rf
}
func (f *j7RunFixture) stop(t *testing.T) {
	t.Helper()
	if f.stopped {
		return
	}
	f.stopped = true
	f.cancel()
	select {
	case <-f.done:
	case <-time.After(3 * time.Second):
		t.Error("lifecycle server did not stop")
	}
}
func (f *j7RunFixture) dial(t *testing.T, id int) *net.UnixConn {
	t.Helper()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: f.socket, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	nativeNegotiate(t, c, id)
	return c
}
func j7Params(t *testing.T, value any) control.Object {
	t.Helper()
	raw, e := canonical(value)
	if e != nil {
		t.Fatal(e)
	}
	obj, e := control.Decode(raw)
	if e != nil {
		t.Fatal(e)
	}
	return obj
}
func (f *j7RunFixture) args() j7BindArguments {
	return j7BindArguments{Identity: f.f.binding.Number, Origin: &f.f.origin, Input: Principal{f.f.uid + 200, "input-a"}}
}
func j7Call(t *testing.T, c *net.UnixConn, id int, method string, params control.Object, want Code) control.Object {
	t.Helper()
	nativeSend(t, c, nativeRequest(id, method, params))
	return nativeResponse(t, nativeReceive(t, c), nativeID(id), want)
}
func (f *j7RunFixture) waitDisconnected(t *testing.T, id string) {
	t.Helper()
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		f.f.store.mu.Lock()
		gone := f.life.channels[id] == nil
		f.f.store.mu.Unlock()
		if gone {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("connection binding survived EOF")
}

// Real kernel launcher connections bind once. Another connection/reused input,
// wrong native route, forged owner label and copied run handles cannot adopt it.
// Generation fixtures describe input accounts only, not actual broker isolation.
func TestJ7RunChannelIsolation(t *testing.T) {
	f := j7RunSetup(t)
	a := f.dial(t, 1)
	args := f.args()
	result := j7Call(t, a, 2, "j7_run_bind", j7Params(t, args), "")
	id := result["run_id"].(string)
	if !messageID(id) {
		t.Fatal("nonopaque run identity")
	}
	retry := j7Call(t, a, 2, "j7_run_bind", j7Params(t, args), "")
	if !reflect.DeepEqual(result, retry) {
		t.Fatal("same-connection retry changed result")
	}
	b := f.dial(t, 3)
	before := len(f.f.store.j7.Runs)
	j7Call(t, b, 2, "j7_run_bind", j7Params(t, args), "run_identity_unavailable")
	j7Call(t, b, 4, "j7_run_rebind", control.Object{"run_id": id}, "run_identity_unavailable")
	j7Call(t, b, 5, "j7_run_bind", j7Params(t, args), "run_identity_unavailable")
	altered := args
	altered.Origin = &j7Origin{Kind: "owner"}
	altered.Input = Principal{f.f.uid + 201, "input-b"}
	j7Call(t, b, 6, "j7_run_bind", j7Params(t, altered), "request_malformed")
	j7Call(t, b, 7, "j7_sign", control.Object{}, "operation_unsupported")
	j7Call(t, b, 70, "j7_pubkey", control.Object{}, "operation_unsupported")
	j7Call(t, b, 71, "j7_enroll", control.Object{}, "operation_unsupported")
	if len(f.f.store.j7.Runs) != before {
		t.Fatal("refused channel changed runs")
	}
	altered = args
	altered.Input = Principal{f.f.uid + 201, "input-b"}
	j7Call(t, a, 8, "j7_run_bind", j7Params(t, altered), "run_identity_unavailable")
	// This privileged endpoint returns administrative run IDs only. An agent has
	// no signing/lookup route and cannot select any run from these returned bytes.
	if c := f.f.store.validateJ7(); c != nil {
		t.Fatal(c)
	}
}

// Spawn inherits the exact retained origin; rebind accepts only the retained ID
// and never a new origin. Disconnect drops the mapping, end is durable/idempotent
// and neither a retry nor a fresh channel can revive the ended run.
func TestJ7RunOriginAndRebind(t *testing.T) {
	f := j7RunSetup(t)
	a := f.dial(t, 1)
	parent := j7Call(t, a, 2, "j7_run_bind", j7Params(t, f.args()), "")["run_id"].(string)
	b := f.dial(t, 3)
	args := f.args()
	args.Origin = nil
	args.Parent = parent
	args.Input = Principal{f.f.uid + 201, "input-b"}
	child := j7Call(t, b, 4, "j7_run_bind", j7Params(t, args), "")["run_id"].(string)
	f.f.store.mu.Lock()
	origin := f.life.run(child).Origin
	f.f.store.mu.Unlock()
	if origin != f.f.origin {
		t.Fatal("spawn changed origin")
	}
	a.Close()
	f.waitDisconnected(t, parent)
	c := f.dial(t, 5)
	j7Call(t, c, 6, "j7_run_rebind", control.Object{"run_id": parent, "origin": "owner"}, "request_malformed")
	j7Call(t, c, 7, "j7_run_rebind", control.Object{"run_id": parent}, "")
	d := f.dial(t, 8)
	j7Call(t, d, 9, "j7_run_end", control.Object{"run_id": parent}, "")
	j7Call(t, d, 9, "j7_run_end", control.Object{"run_id": parent}, "")
	e := f.dial(t, 10)
	j7Call(t, e, 11, "j7_run_rebind", control.Object{"run_id": parent}, "run_identity_unavailable")
	j7Call(t, e, 12, "j7_run_bind", j7Params(t, j7BindArguments{Identity: f.f.binding.Number, Parent: parent, Input: Principal{f.f.uid + 202, "input-c"}}), "run_identity_unavailable")
	f.f.store.mu.Lock()
	if f.life.run(parent).State != "ended" {
		t.Fatal("ended state not retained")
	}
	f.f.store.mu.Unlock()
}

// The real peer UID is compared with the configured launcher, and active
// generation evidence is rechecked. Kernel identity never comes from params.
func TestJ7RunWrongPeerAndGeneration(t *testing.T) {
	for _, mode := range []string{"wrong-role", "wrong-generation", "inactive-input", "same-uid", "wrong-input-generation"} {
		t.Run(mode, func(t *testing.T) {
			f := j7RunSetup(t)
			c := f.dial(t, 1)
			args := f.args()
			want := Code("role_not_permitted")
			switch mode {
			case "wrong-role":
				f.life.launcher.UID++
			case "wrong-generation":
				f.life.launcher.Generation = "other"
			case "inactive-input":
				f.gen.set(args.Input.UID, "retiring", args.Input.Generation)
				want = "generation_inactive"
			case "same-uid":
				args.Input = f.life.launcher
				want = "request_malformed"
			case "wrong-input-generation":
				args.Input.Generation = "other"
				want = "generation_mismatch"
			}
			before := len(f.f.store.j7.Runs)
			j7Call(t, c, 2, "j7_run_bind", j7Params(t, args), want)
			if len(f.f.store.j7.Runs) != before {
				t.Fatal("bad caller created run")
			}
		})
	}
}

// Retirement cancels the actual accepted channel and closes its descriptor.
// Its durable record alone does not authorize a reconnect with retired input.
func TestJ7RunRetirementCancelsConnection(t *testing.T) {
	f := j7RunSetup(t)
	c := f.dial(t, 1)
	args := f.args()
	id := j7Call(t, c, 2, "j7_run_bind", j7Params(t, args), "")["run_id"].(string)
	f.f.store.mu.Lock()
	channel := f.life.channels[id]
	f.f.store.mu.Unlock()
	f.gen.set(args.Input.UID, "retiring", args.Input.Generation)
	select {
	case <-channel.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("retirement left queued work live")
	}
	c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if n, e := c.Read(b[:]); n != 0 || e == nil {
		t.Fatal("retired connection remained readable")
	}
	f.waitDisconnected(t, id)
	next := f.dial(t, 3)
	j7Call(t, next, 4, "j7_run_rebind", control.Object{"run_id": id}, "generation_inactive")
}

// All volatile connection authority is absent in a fresh adapter over the
// retained store. Only explicit launcher rebind establishes the new object;
// implicit adoption by a retry, caller label or owner row remains refused.
func TestJ7RunRestartRequiresLauncherRebind(t *testing.T) {
	f := j7RunSetup(t)
	c := f.dial(t, 1)
	id := j7Call(t, c, 2, "j7_run_bind", j7Params(t, f.args()), "")["run_id"].(string)
	c.Close()
	f.waitDisconnected(t, id)
	f.stop(t)
	f.f.reopen(t)
	l, e := newJ7Lifecycle(f.f.store, f.f.policy, f.gen, f.life.launcher)
	if e != nil {
		t.Fatal(e)
	}
	if len(l.channels) != 0 {
		t.Fatal("restart adopted channels")
	}
	// ServeConn on a real new accepted socket exercises the same scope hook as
	// Serve. This adapter has no saved connection token from the prior instance.
	listener, e := net.Listen("unix", fmt.Sprintf("@j7-restart-%d-%d", os.Getpid(), j7SocketCounter.Add(1)))
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	wire, e := control.New(l, l, l, l, l)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- wire.Serve(ctx, listener) }()
	defer func() { cancel(); <-done }()
	next, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	next.SetDeadline(time.Now().Add(3 * time.Second))
	nativeNegotiate(t, next, 3)
	j7Call(t, next, 2, "j7_run_bind", j7Params(t, f.args()), "run_identity_unavailable")
	j7Call(t, next, 4, "j7_run_rebind", control.Object{"run_id": id}, "")
}

// New optional protected pins cannot leak into legacy configuration, change
// instance/holder/schema or accept a service-writable reset/empty expectation.
func TestJ7RunConfigurationPins(t *testing.T) {
	cfg := strings.TrimSuffix(j7Config(j7RequestRole), "}") + `,"j7_policy":{"path":"/protected/policy/table","holder_uid":1001,"schema":"keymaker-j7-policy/1","instance":"11111111111111111111111111111111","identity_registration_number":1,"launcher_principal":{"uid":1002,"generation":"launcher"}},"j7_state":{"path":"/protected/state","minimum_reader_schema":4,"expected_version":1,"expected_digest":"` + strings.Repeat("a", 64) + `"}}`
	parsed, e := ParseConfig(strings.NewReader(cfg))
	if e != nil || parsed.J7Policy == nil || parsed.J7State == nil {
		t.Fatal("valid pins", e)
	}
	for _, bad := range []string{strings.Replace(cfg, `"holder_uid":1001`, `"holder_uid":1002`, 1), strings.Replace(cfg, `"minimum_reader_schema":4`, `"minimum_reader_schema":3`, 1), strings.Replace(cfg, `"expected_version":1`, `"expected_version":0`, 1), strings.Replace(cfg, `"launcher_principal":{`, `"unknown":1,"launcher_principal":{`, 1), strings.Replace(cfg, `"j7-request"`, `"legacy"`, 1)} {
		if _, e := ParseConfig(strings.NewReader(bad)); e == nil {
			t.Fatal("bad pins accepted")
		}
	}
}

// Publication, launcher cleanup and input retirement race on real native
// connections. Cleanup can always end the run; no raced rebind revives it.
func TestJ7RunConcurrentPublicationRetirement(t *testing.T) {
	f := j7RunSetup(t)
	a := f.dial(t, 1)
	args := f.args()
	id := j7Call(t, a, 2, "j7_run_bind", j7Params(t, args), "")["run_id"].(string)
	admin := f.dial(t, 3)
	reconnect := f.dial(t, 4)
	entered := make(chan struct{})
	release := make(chan struct{})
	f.f.store.j7Fault = func(point string) Code {
		if point == "policy-prepared" {
			close(entered)
			<-release
		}
		return ""
	}
	p := f.f.table(2)
	p.Rows[0].Use = []string{}
	raw := j7PolicyRaw(t, p)
	published := make(chan Code, 1)
	go func() { published <- f.f.policy.publish(context.Background(), raw) }()
	<-entered
	ended := make(chan control.Object, 1)
	go func() {
		nativeSend(t, admin, nativeRequest(5, "j7_run_end", control.Object{"run_id": id}))
		ended <- nativeReceive(t, admin)
	}()
	rebound := make(chan control.Object, 1)
	go func() {
		nativeSend(t, reconnect, nativeRequest(6, "j7_run_rebind", control.Object{"run_id": id}))
		rebound <- nativeReceive(t, reconnect)
	}()
	retired := make(chan struct{})
	go func() { f.gen.set(args.Input.UID, "retiring", args.Input.Generation); close(retired) }()
	close(release)
	if c := <-published; c != "" {
		t.Fatal("publication", c)
	}
	<-retired
	nativeResponse(t, <-ended, nativeID(5), "")
	response := <-rebound
	refusal, ok := response["error"].(control.Object)
	if !ok || refusal["code"] != "generation_inactive" && refusal["code"] != "run_identity_unavailable" {
		t.Fatal("raced rebind gained authority", response)
	}
	f.f.store.mu.Lock()
	defer f.f.store.mu.Unlock()
	if f.life.run(id).State != "ended" || len(f.f.store.j7.Denials) != 1 || f.life.channels[id] != nil {
		t.Fatal("raced cleanup lost end/withdrawal")
	}
}

// Legacy Native never dispatches lifecycle or signing through the new transport
// names. This uses the existing real legacy fixture, not a dummy signer in the
// new lifecycle constructor, and preserves its binding/result state.
func TestJ7RunLegacySurfaceStaysClosed(t *testing.T) {
	own := nativeOwnBinding()
	f := nativeBase(t, Principal{own.UID, nativeToken}, nil, &own)
	f.start()
	conn := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, conn, 1)
	before := f.store.Snapshot()
	for i, method := range []string{"j7_run_bind", "j7_run_end", "j7_run_rebind", "j7_sign", "j7_pubkey", "j7_enroll"} {
		j7Call(t, conn, i+2, method, control.Object{}, "operation_unsupported")
	}
	j7Call(t, conn, 1, "j7_run_bind", control.Object{}, "operation_unsupported")
	if !reflect.DeepEqual(before, f.store.Snapshot()) {
		t.Fatal("closed legacy routes changed bindings")
	}
}

// Withdrawing the protected station binding cancels the accepted run channel
// even while idle; its retained live label cannot restore an unbound identity.
func TestJ7RunIdentityWithdrawal(t *testing.T) {
	f := j7RunSetup(t)
	conn := f.dial(t, 1)
	id := j7Call(t, conn, 2, "j7_run_bind", j7Params(t, f.args()), "")["run_id"].(string)
	f.f.store.mu.Lock()
	channel := f.life.channels[id]
	f.f.store.mu.Unlock()
	if c := f.f.store.Unbind(fixtureOperator, fixtureOperator, f.f.binding.UID, f.f.binding.Generation); c != "" {
		t.Fatal("fixture withdrawal", c)
	}
	select {
	case <-channel.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("identity withdrawal left channel live")
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if n, e := conn.Read(b[:]); n != 0 || e == nil {
		t.Fatal("withdrawn identity connection survived")
	}
}

// A root-policy-approved current launcher can end stale history after its old
// incarnation retired; it cannot rebind/adopt that run or rewrite its origin or
// original launcher principal. This is cleanup authority, not new run admission.
func TestJ7RunLauncherIncarnationCleanup(t *testing.T) {
	f := j7RunSetup(t)
	old := f.life.launcher
	conn := f.dial(t, 1)
	id := j7Call(t, conn, 2, "j7_run_bind", j7Params(t, f.args()), "")["run_id"].(string)
	f.gen.set(old.UID, "active", "replacement-launcher")
	conn.Close()
	f.waitDisconnected(t, id)
	f.stop(t)
	f.life.launcher = Principal{old.UID, "replacement-launcher"}
	// A fresh lifecycle adapter models an explicitly updated protected launcher
	// configuration. No wire operation can change the original retained record.
	l, e := newJ7Lifecycle(f.f.store, f.f.policy, f.gen, f.life.launcher)
	if e != nil {
		t.Fatal(e)
	}
	address := fmt.Sprintf("@j7-cleanup-%d-%d", os.Getpid(), j7SocketCounter.Add(1))
	listener, e := net.Listen("unix", address)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	wire, e := control.New(l, l, l, l, l)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- wire.Serve(ctx, listener) }()
	defer func() { cancel(); <-done }()
	c, e := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	nativeNegotiate(t, c, 3)
	j7Call(t, c, 4, "j7_run_rebind", control.Object{"run_id": id}, "run_identity_unavailable")
	j7Call(t, c, 5, "j7_run_end", control.Object{"run_id": id}, "")
	f.f.store.mu.Lock()
	defer f.f.store.mu.Unlock()
	row := l.run(id)
	if row.State != "ended" || row.Launcher != old || row.Origin != f.f.origin {
		t.Fatal("launcher cleanup rewrote history")
	}
}

// Injected retained-count pressure isolates preflight rollback on real native
// connections. No synthetic row is committed or used as authority; valid dense
// persistence is separately tested by TestJ7RecoveryRetainedCapacity. This does
// not qualify native latency at the maximum history size.
func TestJ7RunCapacityPreservesState(t *testing.T) {
	f := j7RunSetup(t)
	a := f.dial(t, 1)
	id := j7Call(t, a, 2, "j7_run_bind", j7Params(t, f.args()), "")["run_id"].(string)
	b := f.dial(t, 3)
	s := f.f.store
	s.mu.Lock()
	saved := s.requests
	pressure := make([]retainedRequest, maxRetainedRequests)
	copy(pressure, saved)
	s.requests = pressure
	before := cloneJ7(s.j7)
	commit := s.journal.binding
	count := len(s.requests)
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.requests = saved; s.mu.Unlock() }()
	args := f.args()
	args.Input = Principal{f.f.uid + 201, "input-b"}
	j7Call(t, b, 4, "j7_run_bind", j7Params(t, args), "state_capacity_exceeded")
	j7Call(t, a, 5, "j7_run_end", control.Object{"run_id": id}, "state_capacity_exceeded")
	s.mu.Lock()
	defer s.mu.Unlock()
	if !reflect.DeepEqual(before, s.j7) || s.journal.binding != commit || len(s.requests) != count || s.failed {
		t.Fatal("preflight refusal changed live run or committed state")
	}
}

// A state witness covers the complete retained body, installed snapshot and
// binding commitment. Ordinary permitted refusal audit is intentionally separate.
type j7RunWitness struct {
	Body, Snapshot string
	Commit         bindingCommit
	Failed         bool
}

func j7RunWitnessOf(t *testing.T, f *j7RunFixture) j7RunWitness {
	t.Helper()
	s := f.f.store
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, e := canonical(s.disk(s.version, s.journal.binding))
	if e != nil {
		t.Fatal(e)
	}
	onDisk, e := os.ReadFile(filepath.Join(f.f.path, "bindings.json"))
	if e != nil {
		t.Fatal(e)
	}
	return j7RunWitness{string(raw), string(onDisk), s.journal.binding, s.failed}
}
func j7ActualChannel(t *testing.T, f *j7RunFixture, id string) (context.Context, *j7Channel) {
	t.Helper()
	f.f.store.mu.Lock()
	ch := f.life.channels[id]
	f.f.store.mu.Unlock()
	if ch == nil {
		t.Fatal("actual accepted channel missing")
	}
	return context.WithValue(t.Context(), j7ChannelKey{}, ch), ch
}

// After a delivered self-end acknowledgement, another mutation on that real
// socket must specifically refuse or see a clean close, never a timeout/partial
// response. A fresh launcher can recover the end and clean up another live run.
// This tests native connection lifetime, not external per-UID/FD isolation.
func TestJ7RunEndedChannelCannotMutateOtherRun(t *testing.T) {
	f := j7RunSetup(t)
	a := f.dial(t, 1)
	idA := j7Call(t, a, 2, "j7_run_bind", j7Params(t, f.args()), "")["run_id"].(string)
	b := f.dial(t, 3)
	args := f.args()
	args.Input = Principal{f.f.uid + 201, "input-b"}
	idB := j7Call(t, b, 4, "j7_run_bind", j7Params(t, args), "")["run_id"].(string)
	result := j7Call(t, a, 5, "j7_run_end", control.Object{"run_id": idA}, "")
	if result["state"] != "ended" {
		t.Fatal("self-end acknowledgement not delivered", result)
	}
	before := j7RunWitnessOf(t, f)
	a.SetDeadline(time.Now().Add(time.Second))
	raw, e := control.Marshal(nativeRequest(6, "j7_run_end", control.Object{"run_id": idB}))
	if e != nil {
		t.Fatal(e)
	}
	e = writeResponse(a, Packet(raw))
	if e != nil {
		if !errors.Is(e, syscall.EPIPE) && !errors.Is(e, syscall.ECONNRESET) {
			t.Fatal("unexpected post-end write failure", e)
		}
	} else {
		var header [4]byte
		n, err := io.ReadFull(a, header[:])
		if err != nil {
			if n != 0 || !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
				t.Fatal("post-end close was not clean", err)
			}
		} else {
			n := binary.BigEndian.Uint32(header[:])
			if n == 0 || n > 4096 {
				t.Fatal("unexpected post-end frame length", n)
			}
			body := make([]byte, n)
			if _, e := io.ReadFull(a, body); e != nil {
				t.Fatal("partial post-end response", e)
			}
			obj, e := control.Decode(body)
			if e != nil {
				t.Fatal(e)
			}
			nativeResponse(t, obj, nativeID(6), "run_identity_unavailable")
		}
	}
	if after := j7RunWitnessOf(t, f); after != before {
		t.Fatal("ended channel changed durable state")
	}
	f.f.store.mu.Lock()
	state := f.life.run(idB).State
	f.f.store.mu.Unlock()
	if state != "live" {
		t.Fatal("ended channel ended other run")
	}
	fresh := f.dial(t, 7)
	if recovered := j7Call(t, fresh, 5, "j7_run_end", control.Object{"run_id": idA}, ""); !reflect.DeepEqual(recovered, result) {
		t.Fatal("fresh end recovery changed result")
	}
	j7Call(t, fresh, 8, "j7_run_end", control.Object{"run_id": idB}, "")
	before = j7RunWitnessOf(t, f)
	j7Call(t, fresh, 8, "j7_run_end", control.Object{"run_id": idB}, "")
	if after := j7RunWitnessOf(t, f); after != before {
		t.Fatal("fresh idempotent end changed retained state")
	}
}

// The fixture injects cancellation after authoritative evidence entry, so a
// pre-admission check alone cannot satisfy the terminal no-effects control.
type j7EvidenceInterruption struct {
	GenerationSource
	before func()
}

func (g j7EvidenceInterruption) WithEvidence(ctx context.Context, conditions []GenerationCondition, fn func(context.Context) Code) Code {
	return g.GenerationSource.WithEvidence(ctx, conditions, func(ctx context.Context) Code { g.before(); return fn(ctx) })
}

// These direct adapter controls retain a capability from an actual accepted
// native connection, then cancel it between stages. Admission is not authority
// for a later mutation or release. They do not claim a second kernel identity.
func TestJ7RunCanceledCapabilityBoundaries(t *testing.T) {
	for _, phase := range []string{"admission", "handling-after-admission", "handling-in-evidence", "release-after-handling", "release-in-evidence", "hello-release"} {
		t.Run(phase, func(t *testing.T) {
			f := j7RunSetup(t)
			a := f.dial(t, 1)
			idA := j7Call(t, a, 2, "j7_run_bind", j7Params(t, f.args()), "")["run_id"].(string)
			b := f.dial(t, 3)
			args := f.args()
			args.Input = Principal{f.f.uid + 201, "input-b"}
			idB := j7Call(t, b, 4, "j7_run_bind", j7Params(t, args), "")["run_id"].(string)
			ctx, ch := j7ActualChannel(t, f, idA)
			peer := control.Peer{UID: f.life.launcher.UID, Generation: f.life.launcher.Generation}
			r := control.Request{ID: nativeID(5), Method: "j7_run_end", Params: control.Object{"run_id": idB}}
			if c := f.life.Admit(ctx, peer, r); c != "" {
				t.Fatal("valid admission positive", c)
			}
			var result control.Object
			if phase == "release-after-handling" || phase == "release-in-evidence" {
				var c control.Code
				result, c = f.life.Handle(ctx, peer, r)
				if c != "" {
					t.Fatal("valid handling positive", c)
				}
			} else if phase == "hello-release" {
				r.Method, r.Params = "hello", control.Object{}
				result = control.Object{"version": int64(1)}
			}
			before := j7RunWitnessOf(t, f)
			if phase == "handling-in-evidence" || phase == "release-in-evidence" {
				f.life.generations = j7EvidenceInterruption{f.gen, ch.cancel}
			} else {
				ch.cancel()
			}
			var code control.Code
			switch phase {
			case "admission":
				code = f.life.Admit(ctx, peer, r)
			case "handling-after-admission", "handling-in-evidence":
				_, code = f.life.Handle(ctx, peer, r)
			default:
				released := false
				code = f.life.WithActive(ctx, peer, r, result, func(context.Context) control.Code { released = true; return "" })
				if released {
					t.Fatal("canceled capability released a response")
				}
			}
			if after := j7RunWitnessOf(t, f); after != before {
				t.Fatal("canceled channel changed durable state")
			}
			if code != "run_identity_unavailable" {
				t.Fatal("canceled capability refusal", code)
			}
		})
	}
}

// A self-end has one internal permit for its exact committed acknowledgement,
// never for changed arguments/ID, hello, or a second release. The real wire
// delivery control is TestJ7RunEndedChannelCannotMutateOtherRun above.
func TestJ7RunSelfEndReleasePermit(t *testing.T) {
	f := j7RunSetup(t)
	a := f.dial(t, 1)
	id := j7Call(t, a, 2, "j7_run_bind", j7Params(t, f.args()), "")["run_id"].(string)
	ctx, _ := j7ActualChannel(t, f, id)
	peer := control.Peer{UID: f.life.launcher.UID, Generation: f.life.launcher.Generation}
	r := control.Request{ID: nativeID(3), Method: "j7_run_end", Params: control.Object{"run_id": id}}
	result, code := f.life.Handle(ctx, peer, r)
	if code != "" {
		t.Fatal("self-end prepare positive", code)
	}
	before := j7RunWitnessOf(t, f)
	for _, variant := range []string{"id", "arguments", "hello", "result"} {
		changed := r
		supplied := result
		switch variant {
		case "id":
			changed.ID = nativeID(4)
		case "arguments":
			changed.Params = control.Object{"run_id": strings.Repeat("f", 32)}
		case "hello":
			changed.Method, changed.Params = "hello", control.Object{}
		case "result":
			supplied = control.Object{"run_id": id, "state": "live"}
		}
		released := false
		code := f.life.WithActive(ctx, peer, changed, supplied, func(context.Context) control.Code { released = true; return "" })
		want := control.Code("run_identity_unavailable")
		if variant == "result" {
			want = "request_conflict"
		}
		if code != want || released {
			t.Fatal("self-end permit accepted changed request/result", variant, code)
		}
		if after := j7RunWitnessOf(t, f); after != before {
			t.Fatal("changed acknowledgement changed durable state")
		}
	}
	count := 0
	if c := f.life.WithActive(ctx, peer, r, result, func(context.Context) control.Code { count++; return "" }); c != "" || count != 1 {
		t.Fatal("exact self-end acknowledgement refused", c, count)
	}
	if c := f.life.WithActive(ctx, peer, r, result, func(context.Context) control.Code { count++; return "" }); c != "run_identity_unavailable" || count != 1 {
		t.Fatal("self-end permit reused", c, count)
	}
}

// An outstanding exact self-end reply cannot survive later account/binding
// retirement or EOF. Fresh launcher recovery after input retirement remains
// permitted; cancellation is never turned into new mutation authority.
func TestJ7RunSelfEndPermitRetirement(t *testing.T) {
	for _, phase := range []string{"input", "station", "launcher", "binding", "eof"} {
		t.Run(phase, func(t *testing.T) {
			f := j7RunSetup(t)
			a := f.dial(t, 1)
			id := j7Call(t, a, 2, "j7_run_bind", j7Params(t, f.args()), "")["run_id"].(string)
			ctx, ch := j7ActualChannel(t, f, id)
			peer := control.Peer{UID: f.life.launcher.UID, Generation: f.life.launcher.Generation}
			r := control.Request{ID: nativeID(3), Method: "j7_run_end", Params: control.Object{"run_id": id}}
			result, c := f.life.Handle(ctx, peer, r)
			if c != "" {
				t.Fatal("prepare positive", c)
			}
			want := control.Code("generation_inactive")
			switch phase {
			case "input":
				f.gen.set(f.args().Input.UID, "retiring", f.args().Input.Generation)
			case "station":
				f.gen.set(f.f.binding.UID, "retiring", f.f.binding.Generation)
			case "launcher":
				f.gen.set(f.life.launcher.UID, "retiring", f.life.launcher.Generation)
			case "binding":
				if c := f.f.store.Unbind(fixtureOperator, fixtureOperator, f.f.binding.UID, f.f.binding.Generation); c != "" {
					t.Fatal("withdrawal", c)
				}
				want = "binding_not_found"
			case "eof":
				a.Close()
				until := time.Now().Add(time.Second)
				for {
					ch.watchMu.Lock()
					closed := ch.closed
					ch.watchMu.Unlock()
					if closed {
						break
					}
					if time.Now().After(until) {
						t.Fatal("scope cleanup did not retire channel")
					}
					time.Sleep(time.Millisecond)
				}
				want = "run_identity_unavailable"
			}
			before := j7RunWitnessOf(t, f)
			released := false
			c = f.life.WithActive(ctx, peer, r, result, func(context.Context) control.Code { released = true; return "" })
			if c != want || released {
				t.Fatal("retired self-end permit released", phase, c, want)
			}
			if after := j7RunWitnessOf(t, f); after != before {
				t.Fatal("retired permit changed durable state")
			}
			if phase == "input" {
				fresh := f.dial(t, 4)
				if got := j7Call(t, fresh, 3, "j7_run_end", control.Object{"run_id": id}, ""); !reflect.DeepEqual(got, result) {
					t.Fatal("fresh retired-input cleanup refused")
				}
			}
		})
	}
}
