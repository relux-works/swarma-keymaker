package keymaker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	proof "github.com/relux-works/swarma-keymaker/internal/registration"
)

type nativeAdmissionGeneration struct {
	*fakeGenerations
	verdict          Code
	recheck          bool
	refusing         atomic.Bool
	lookups, watches atomic.Int32
	observed         chan struct{}
	once             sync.Once
}

func (g *nativeAdmissionGeneration) Lookup(ctx context.Context, uid uint32) (Generation, Code) {
	current, code := g.fakeGenerations.Lookup(ctx, uid)
	call := g.lookups.Add(1)
	if g.refusing.Load() && (!g.recheck || call >= 2) {
		g.once.Do(func() { close(g.observed) })
		switch g.verdict {
		case "generation_inactive":
			current.State = "retiring"
		case "generation_mismatch":
			if g.recheck {
				current.Generation = "replacement"
			} else {
				code = g.verdict
			}
		default:
			return Generation{}, g.verdict
		}
	}
	return current, code
}

func (g *nativeAdmissionGeneration) Watch(uid uint32, generation string) (<-chan struct{}, func()) {
	g.watches.Add(1)
	return g.fakeGenerations.Watch(uid, generation)
}

// These counters distinguish refusal reporting/workload accounting from actual
// native authority, effect-ID admission, method dispatch and success release.
type nativeAdmissionCalls struct {
	*Native
	identify, admit, handle, release atomic.Int32
}

func (n *nativeAdmissionCalls) Identify(ctx context.Context, c net.Conn) (control.Peer, control.Code) {
	n.identify.Add(1)
	return n.Native.Identify(ctx, c)
}
func (n *nativeAdmissionCalls) Admit(ctx context.Context, p control.Peer, r control.Request) control.Code {
	n.admit.Add(1)
	return n.Native.Admit(ctx, p, r)
}
func (n *nativeAdmissionCalls) Handle(ctx context.Context, p control.Peer, r control.Request) (control.Object, control.Code) {
	n.handle.Add(1)
	return n.Native.Handle(ctx, p, r)
}
func (n *nativeAdmissionCalls) WithActive(ctx context.Context, p control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	n.release.Add(1)
	return n.Native.WithActive(ctx, p, r, result, release)
}

func nativeAdmissionFixture(t *testing.T, verdict Code, recheck bool) (*nativeFixture, *nativeAdmissionGeneration, *nativeAdmissionCalls) {
	t.Helper()
	b := nativeOwnBinding()
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, &b)
	g := &nativeAdmissionGeneration{fakeGenerations: f.generation, verdict: verdict, recheck: recheck, observed: make(chan struct{})}
	g.refusing.Store(true)
	f.engine.Generations = g
	calls := &nativeAdmissionCalls{Native: f.native}
	var err error
	f.server.controlWire, err = control.New(calls, calls, calls, calls, f.native)
	if err != nil {
		t.Fatal(err)
	}
	return f, g, calls
}

func nativeAdmissionClosed(t *testing.T, c *net.UnixConn) {
	t.Helper()
	var b [1]byte
	n, err := c.Read(b[:])
	if n != 0 || !(errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET)) {
		t.Fatal("refused connection did not close without another frame", n, err)
	}
}

func nativeAdmissionUnchanged(t *testing.T, f *nativeFixture, g *nativeAdmissionGeneration, calls *nativeAdmissionCalls, before []byte) {
	t.Helper()
	if !bytes.Equal(before, nativeSnapshot(t, f)) {
		t.Fatal("generation refusal changed bindings or retained results")
	}
	if calls.identify.Load()+calls.admit.Load()+calls.handle.Load()+calls.release.Load() != 0 {
		t.Fatal("generation refusal entered native authority or execution")
	}
	if !g.recheck && g.watches.Load() != 0 {
		t.Fatal("failed initial generation admission subscribed a watcher")
	}
	f.generation.mu.Lock()
	watchers := len(f.generation.watchers[uint32(os.Getuid())])
	f.generation.mu.Unlock()
	if watchers != 0 {
		t.Fatal("generation refusal retained an accept watcher")
	}
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	if len(f.store.watchers) != 0 {
		t.Fatal("generation refusal looked up/subscribed a binding")
	}
}

func nativeAdmissionControl(t *testing.T, f *nativeFixture, g *nativeAdmissionGeneration) {
	t.Helper()
	g.refusing.Store(false)
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 30)
	nativeSend(t, c, nativeRequest(31, "pubkey", control.Object{}))
	nativeResponse(t, nativeReceive(t, c), nativeID(31), "")
}

// An authenticated UID rejected at accept or its confirmation gets exactly one
// typed, ID-bound refusal/audit, no binding/result effect and no method dispatch.
// Each case then admits an active hello and pubkey through the same real socket.
func TestNativeGenerationAdmissionRefusal(t *testing.T) {
	for _, verdict := range []Code{"generation_inactive", "generation_mismatch", "generation_source_unavailable", "generation_source_fenced"} {
		for _, recheck := range []bool{false, true} {
			name := string(verdict) + "/initial"
			if recheck {
				name = string(verdict) + "/recheck"
			}
			t.Run(name, func(t *testing.T) {
				f, g, calls := nativeAdmissionFixture(t, verdict, recheck)
				before, audit := nativeSnapshot(t, f), nativeAudit(t, f.store.journal)
				f.start()
				c := nativeDial(t, f.server.ControlPath)
				body, err := control.Marshal(nativeHello(1))
				if err != nil {
					t.Fatal(err)
				}
				if err := writeResponse(c, Packet(body)); err != nil {
					if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
						t.Fatalf("generation admission silently closed before response: %v", err)
					}
					t.Fatal(err)
				}
				body, code := ReadFrame(c)
				if code != "" || body == nil {
					t.Fatalf("generation admission silently closed: frame=%s bytes=%d", code, len(body))
				}
				obj, err := control.Decode(body)
				if err != nil {
					t.Fatal(err)
				}
				nativeResponse(t, obj, nativeID(1), verdict)
				nativeAdmissionClosed(t, c)
				records := nativeAudit(t, f.store.journal)[len(audit):]
				if len(records) != 1 || records[0].PeerUID == nil || *records[0].PeerUID != uint32(os.Getuid()) || records[0].RequestID == nil || *records[0].RequestID != nativeID(1) || records[0].Operation != "hello" || records[0].Result != "refused" || records[0].RefusalCode == nil || *records[0].RefusalCode != verdict || records[0].Generation != nil || records[0].Path != nil || records[0].PayloadDigest == nil {
					t.Fatal("generation admission refusal audit missing or misattributed", records)
				}
				nativeAdmissionUnchanged(t, f, g, calls, before)
				nativeAdmissionControl(t, f, g)
			})
		}
	}
}

// Generation refusal precedes negotiation/ID admission for every native method,
// including a fully configured helper. No nonce/signature is generated; after
// restoring activity the helper returns a verified proof as the positive control.
func TestNativeGenerationAdmissionMethods(t *testing.T) {
	for _, method := range []string{"pubkey", "register", "revoke", "sign_registration"} {
		t.Run(method, func(t *testing.T) {
			f, g, calls := nativeAdmissionFixture(t, "generation_inactive", false)
			tr := newHelperTrust(t, f, helperBody(t, f, uint32(os.Getuid())), map[string]string{strconv.Itoa(os.Getuid()): nativeToken}, true)
			entropy := &reviewHelperEntropy{}
			builder, err := proof.New(tr.clock, entropy, registrationSigner{f.master, helperPath})
			if err != nil {
				t.Fatal(err)
			}
			tr.helper.builder = builder
			f.native.Config.Helper = tr.helper
			before, audit := nativeSnapshot(t, f), nativeAudit(t, f.store.journal)
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			req := nativeRequest(1, method, control.Object{})
			if method == "register" {
				req = nativeRegisterRequest(1)
			} else if method == "revoke" {
				req = nativeRequest(1, method, control.Object{"registration_number": int64(1), "mode": "ephemeral"})
			} else if method == "sign_registration" {
				req = helperRequest(1)
			}
			nativeSend(t, c, req)
			nativeResponse(t, nativeReceive(t, c), nativeID(1), "generation_inactive")
			nativeAdmissionClosed(t, c)
			records := nativeAudit(t, f.store.journal)[len(audit):]
			if len(records) != 1 || records[0].Operation != method || records[0].RefusalCode == nil || *records[0].RefusalCode != "generation_inactive" || entropy.calls.Load() != 0 {
				t.Fatal("refused method had missing audit or nonce effect")
			}
			nativeAdmissionUnchanged(t, f, g, calls, before)
			g.refusing.Store(false)
			fresh := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, fresh, 30)
			helperCall(t, f, fresh, 31, "")
			if entropy.calls.Load() != 1 {
				t.Fatal("active helper nonce control absent")
			}
		})
	}
}

// Fatal first-frame errors retain the native framing/schema code and close,
// without generation authority or effects. An active hello/pubkey is nearby.
func TestNativeGenerationAdmissionMalformed(t *testing.T) {
	for _, kind := range []string{"oversize", "empty", "noncanonical", "truncated", "envelope"} {
		t.Run(kind, func(t *testing.T) {
			f, g, calls := nativeAdmissionFixture(t, "generation_inactive", false)
			before, audit := nativeSnapshot(t, f), nativeAudit(t, f.store.journal)
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			var frame []byte
			want, id := Code("frame_too_large"), any(nil)
			switch kind {
			case "oversize":
				frame = []byte{0, 1, 0, 1}
			case "empty":
				frame, want = []byte{0, 0, 0, 0}, "frame_malformed"
			case "noncanonical":
				frame, want = Packet([]byte(`{ "method":"hello"}`)), "ccj_noncanonical"
			case "truncated":
				frame, want = []byte{0, 0}, "frame_truncated"
			case "envelope":
				obj := nativeHello(1)
				delete(obj, "versions")
				body, err := control.Marshal(obj)
				if err != nil {
					t.Fatal(err)
				}
				frame, want, id = Packet(body), "request_malformed", nativeID(1)
			}
			if err := writeResponse(c, frame); err != nil {
				t.Fatal(err)
			}
			if kind == "truncated" {
				if err := c.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			nativeResponse(t, nativeReceive(t, c), id, want)
			nativeAdmissionClosed(t, c)
			records := nativeAudit(t, f.store.journal)[len(audit):]
			if len(records) != 1 || records[0].RefusalCode == nil || *records[0].RefusalCode != want {
				t.Fatal("fatal frame did not retain its audit verdict")
			}
			nativeAdmissionUnchanged(t, f, g, calls, before)
			nativeAdmissionControl(t, f, g)
		})
	}
}

// Silent/partial retired peers are closed at the original two-second admission
// deadline, while a second active connection uses both shared locks normally.
// The read wait holds no generation/Store lock or active-request slot.
func TestNativeGenerationAdmissionDeadline(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "silent"
		if partial {
			name = "partial"
		}
		t.Run(name, func(t *testing.T) {
			f, g, calls := nativeAdmissionFixture(t, "generation_inactive", false)
			before := nativeSnapshot(t, f)
			f.start()
			started := time.Now()
			c := nativeDial(t, f.server.ControlPath)
			select {
			case <-g.observed:
			case <-time.After(time.Second):
				t.Fatal("accept did not reach generation refusal")
			}
			if partial {
				if _, err := c.Write([]byte{0}); err != nil {
					t.Fatal(err)
				}
			}
			if !f.generation.mu.TryLock() {
				t.Fatal("silent refused peer held the generation lock")
			}
			f.generation.mu.Unlock()
			if !f.store.mu.TryLock() {
				t.Fatal("silent refused peer held the Store lock")
			}
			f.store.mu.Unlock()
			nativeAdmissionUnchanged(t, f, g, calls, before)
			if len(f.server.requests) != 0 {
				t.Fatal("silent refused peer held an active-request slot")
			}
			nativeAdmissionControl(t, f, g)
			if time.Since(started) >= time.Second {
				t.Fatal("active control waited for the silent peer's admission deadline")
			}
			nativeAdmissionClosed(t, c)
			elapsed := time.Since(started)
			if elapsed < 1800*time.Millisecond || elapsed > 2800*time.Millisecond {
				t.Fatal("retired read did not use bounded admission deadline", elapsed)
			}
		})
	}
}

// One rejected connection consumes one frame, emits one refusal/audit and never
// processes the pipelined second hello. The same listener then admits a control.
func TestNativeGenerationAdmissionOneFrame(t *testing.T) {
	f, g, calls := nativeAdmissionFixture(t, "generation_inactive", false)
	before, audit := nativeSnapshot(t, f), nativeAudit(t, f.store.journal)
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	a, _ := control.Marshal(nativeHello(1))
	b, _ := control.Marshal(nativeHello(2))
	if err := writeResponse(c, append(Packet(a), Packet(b)...)); err != nil {
		t.Fatal(err)
	}
	nativeResponse(t, nativeReceive(t, c), nativeID(1), "generation_inactive")
	nativeAdmissionClosed(t, c)
	if len(nativeAudit(t, f.store.journal))-len(audit) != 1 {
		t.Fatal("generation refusal read more than one frame")
	}
	nativeAdmissionUnchanged(t, f, g, calls, before)
	nativeAdmissionControl(t, f, g)
}

// An unestablished kernel peer is never read or attributed to a supplied UID.
// Generation lookup/audit stay untouched; a verified active connection succeeds.
func TestNativeGenerationAdmissionMissingPeer(t *testing.T) {
	f, g, calls := nativeAdmissionFixture(t, "generation_inactive", false)
	before, audit := nativeSnapshot(t, f), nativeAudit(t, f.store.journal)
	c := nativeDial(t, f.server.ControlPath)
	server, err := f.server.controlListener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	nativeSend(t, c, nativeHello(1))
	f.server.handleControl(context.Background(), server, Peer{UID: uint32(os.Getuid())}, "peer_identity_unavailable")
	nativeAdmissionClosed(t, c)
	if g.lookups.Load() != 0 || len(nativeAudit(t, f.store.journal)) != len(audit) {
		t.Fatal("unavailable peer was read or attributed")
	}
	nativeAdmissionUnchanged(t, f, g, calls, before)
	f.start()
	nativeAdmissionControl(t, f, g)
}
