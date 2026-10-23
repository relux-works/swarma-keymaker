package keymaker

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

// A first register result must not cross a target or caller retirement which
// wins before the actual socket write. The unretired control uses the same path.
func TestNativeMutationReleasePrincipals(t *testing.T) {
	for _, who := range []string{"control", "caller", "target", "target-reused"} {
		t.Run(who, func(t *testing.T) {
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
			nativeTarget(f)
			f.engine.Generations = delayedGenerationWatch{f.generation}
			probe := &nativeFenceProbe{native: f.native, method: "register"}
			probe.before = func() {
				switch who {
				case "caller":
					f.generation.set(uint32(os.Getuid()), "retiring", nativeToken)
				case "target":
					f.generation.set(30001, "retiring", nativeToken)
				case "target-reused":
					f.generation.set(30001, "active", "replacement")
				}
			}
			wire, err := control.New(f.native, f.native, f.native, probe, f.native)
			if err != nil {
				t.Fatal(err)
			}
			f.server.controlWire = wire
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			nativeSend(t, c, nativeRegisterRequest(2))
			got := nativeReceive(t, c)
			if who == "control" {
				nativeResponse(t, got, nativeID(2), "")
				return
			}
			if result, ok := got["result"]; ok {
				t.Fatalf("mutation release lost %s authority but emitted result %v", who, result)
			}
			want := Code("generation_inactive")
			if who == "target-reused" {
				want = "generation_mismatch"
			}
			nativeResponse(t, got, nativeID(2), want)
		})
	}
}

// An existing pubkey connection must not adopt a newly registered binding
// after its old one was revoked; a fresh connection is the positive control.
// Both lifecycle changes go through real daemon requests and an injected act verifier.
func TestNativeConnectionBindingPin(t *testing.T) {
	b := nativeOwnBinding()
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, fixtureAct{}, &b)
	f.start()
	old := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, old, 1)
	nativeSend(t, old, nativeRequest(2, "pubkey", control.Object{}))
	first := nativeResponse(t, nativeReceive(t, old), nativeID(2), "")
	op := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, op, 3)
	nativeSend(t, op, nativeRequest(4, "revoke", control.Object{"registration_number": int64(1), "mode": "operator", "operator_record": control.Object{"fixture": "trusted-test-verdict"}}))
	nativeResponse(t, nativeReceive(t, op), nativeID(4), "")
	reg := nativeRegisterRequest(5)
	params := reg["params"].(control.Object)
	params["target_uid"] = int64(os.Getuid())
	params["names"].(control.Object)["agent"] = "station-b"
	nativeSend(t, op, reg)
	second := nativeResponse(t, nativeReceive(t, op), nativeID(5), "")
	if reflect.DeepEqual(first, second) {
		t.Fatal("fixture did not replace the binding")
	}
	fresh := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, fresh, 6)
	nativeSend(t, fresh, nativeRequest(7, "pubkey", control.Object{}))
	if got := nativeResponse(t, nativeReceive(t, fresh), nativeID(7), ""); !reflect.DeepEqual(got, second) {
		t.Fatal("fresh connection failed positive control")
	}
	packet, err := control.Marshal(nativeRequest(8, "pubkey", control.Object{}))
	if err != nil {
		t.Fatal(err)
	}
	if err = writeResponse(old, Packet(packet)); err != nil {
		return
	}
	body, code := ReadFrame(old)
	if code != "" {
		t.Fatal(code)
	}
	if body == nil {
		return
	}
	got, err := control.Decode(body)
	if err != nil {
		t.Fatal(err)
	}
	if result, ok := got["result"]; ok {
		t.Fatalf("old control connection adopted replacement binding: %v", result)
	}
	nativeResponse(t, got, nativeID(8), "identity_revoked")
}

type nativeAcceptedGenerationProbe struct {
	delayedGenerationWatch
	lookups  atomic.Int32
	admitted chan struct{}
}

func (g *nativeAcceptedGenerationProbe) Lookup(ctx context.Context, uid uint32) (Generation, Code) {
	result, code := g.fakeGenerations.Lookup(ctx, uid)
	if g.lookups.Add(1) == 2 {
		close(g.admitted)
	}
	return result, code
}

// Delayed revocation notifications must not allow a socket accepted under g1
// to negotiate as g2 when its first frame arrives after authoritative reuse.
func TestNativeAcceptTupleBeforeHello(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(fmt.Sprint(change), func(t *testing.T) {
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
			g := &nativeAcceptedGenerationProbe{delayedGenerationWatch: delayedGenerationWatch{f.generation}, admitted: make(chan struct{})}
			f.engine.Generations = g
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			select {
			case <-g.admitted:
			case <-time.After(time.Second):
				t.Fatal("accept did not finish initial generation checks")
			}
			if change {
				f.generation.set(uint32(os.Getuid()), "active", "replacement")
			}
			func() {
				raw, err := control.Marshal(nativeHello(1))
				if err != nil {
					t.Fatal(err)
				}
				if err = writeResponse(c, Packet(raw)); err != nil {
					if change {
						return
					}
					t.Fatal(err)
				}
				body, code := ReadFrame(c)
				if code != "" {
					t.Fatal(code)
				}
				if body == nil {
					if change {
						return
					}
					t.Fatal("intact connection closed")
				}
				got, err := control.Decode(body)
				if err != nil {
					t.Fatal(err)
				}
				if !change {
					nativeResponse(t, got, nativeID(1), "")
					return
				}
				if _, ok := got["result"]; ok {
					t.Fatal("accepted tuple changed before hello but emitted success")
				}
				nativeResponse(t, got, nativeID(1), "generation_mismatch")
			}()
			if change {
				f.store.mu.Lock()
				retained := len(f.store.requests)
				f.store.mu.Unlock()
				if retained != 0 {
					t.Fatal("changed accept tuple retained a hello ID")
				}
				// A fresh socket may negotiate under the new incarnation.
				fresh := nativeDial(t, f.server.ControlPath)
				nativeNegotiate(t, fresh, 2)
			}
		})
	}
}

// A joint barrier already holding either principal orders the actual mutation
// write before retirement. The goroutine trying retirement must wait; no nested
// authority lookup is allowed, including when caller and target are identical.
func TestNativeMutationReleaseWins(t *testing.T) {
	for _, who := range []string{"caller", "target", "same-principal"} {
		t.Run(who, func(t *testing.T) {
			f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
			nativeTarget(f)
			f.engine.Generations = delayedGenerationWatch{f.generation}
			entered, allow := make(chan struct{}), make(chan struct{})
			var unblocked atomic.Bool
			unblock := func() {
				if unblocked.CompareAndSwap(false, true) {
					close(allow)
				}
			}
			defer unblock()
			probe := &nativeFenceProbe{native: f.native, method: "register", entered: entered, allow: allow}
			wire, err := control.New(f.native, f.native, f.native, probe, f.native)
			if err != nil {
				t.Fatal(err)
			}
			f.server.controlWire = wire
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			req := nativeRegisterRequest(2)
			uid := uint32(30001)
			if who != "target" {
				uid = uint32(os.Getuid())
			}
			if who == "same-principal" {
				req["params"].(control.Object)["target_uid"] = int64(uid)
			}
			nativeSend(t, c, req)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("mutation write did not enter joint barrier")
			}
			attempting, retired := make(chan struct{}), make(chan struct{})
			go func() { close(attempting); f.generation.set(uid, "retiring", nativeToken); close(retired) }()
			<-attempting
			select {
			case <-retired:
				t.Fatal("retirement overtook mutation write barrier")
			case <-time.After(25 * time.Millisecond):
			}
			unblock()
			nativeResponse(t, nativeReceive(t, c), nativeID(2), "")
			select {
			case <-retired:
			case <-time.After(time.Second):
				t.Fatal("retirement did not follow mutation release")
			}
		})
	}
}

// Hello and operator mutations do not consume a self binding. An unbound
// operator can register itself after hello and use its first pubkey on that
// same connection. The first pubkey then subjects that socket to revocation.
func TestNativeHelloDoesNotPinBinding(t *testing.T) {
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, fixtureAct{}, nil)
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	req := nativeRegisterRequest(2)
	req["params"].(control.Object)["target_uid"] = int64(os.Getuid())
	nativeSend(t, c, req)
	registered := nativeResponse(t, nativeReceive(t, c), nativeID(2), "")
	nativeSend(t, c, nativeRequest(3, "pubkey", control.Object{}))
	if got := nativeResponse(t, nativeReceive(t, c), nativeID(3), ""); !reflect.DeepEqual(got, registered) {
		t.Fatal("hello-only connection failed first binding use")
	}
	op := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, op, 4)
	nativeSend(t, op, nativeRequest(5, "revoke", control.Object{"registration_number": int64(1), "mode": "operator", "operator_record": control.Object{"fixture": "trusted-test-verdict"}}))
	nativeResponse(t, nativeReceive(t, op), nativeID(5), "")
	if err := c.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if n, err := c.Read(one[:]); n != 0 || err == nil {
		t.Fatal("revocation failed to close idle pinned connection")
	} else if e, ok := err.(interface{ Timeout() bool }); ok && e.Timeout() {
		t.Fatal("idle pinned connection remained open")
	}
}

// Historical exact retry on the same operator connection uses current caller
// authority and the original result, rather than reusing the fresh effect's
// target predicate. A new ID still requires the target to be active.
func TestNativeMutationHistoricalRelease(t *testing.T) {
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
	nativeTarget(f)
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	nativeSend(t, c, nativeRegisterRequest(2))
	original := nativeResponse(t, nativeReceive(t, c), nativeID(2), "")
	before := nativeSnapshot(t, f)
	f.generation.set(30001, "retiring", nativeToken)
	nativeSend(t, c, nativeRegisterRequest(2))
	if got := nativeResponse(t, nativeReceive(t, c), nativeID(2), ""); !reflect.DeepEqual(got, original) {
		t.Fatal("historical retry lost original result")
	}
	nativeSend(t, c, nativeRegisterRequest(3))
	nativeResponse(t, nativeReceive(t, c), nativeID(3), "generation_inactive")
	if !bytes.Equal(before, nativeSnapshot(t, f)) {
		t.Fatal("retry or refused new ID changed binding/result state")
	}
}

// Ephemeral cleanup retains the exact retired target predicate through its
// first write. A reused retired incarnation cannot inherit that authority;
// unchanged retired evidence admits the same real-daemon revoke path.
func TestNativeEphemeralReleaseEvidence(t *testing.T) {
	for _, change := range []bool{false, true} {
		t.Run(fmt.Sprint(change), func(t *testing.T) {
			operator := Principal{uint32(os.Getuid()), nativeToken}
			b := nativeOwnBinding()
			b.UID = 30001
			b.Lifetime = "ephemeral"
			b.Registrar = operator
			f := nativeBase(t, operator, nil, &b)
			f.generation.set(b.UID, "retiring", b.Generation)
			probe := &nativeFenceProbe{native: f.native, method: "revoke", before: func() {
				if change {
					f.generation.set(b.UID, "removed", "replacement")
				}
			}}
			wire, err := control.New(f.native, f.native, f.native, probe, f.native)
			if err != nil {
				t.Fatal(err)
			}
			f.server.controlWire = wire
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			nativeSend(t, c, nativeRequest(2, "revoke", control.Object{"registration_number": int64(1), "mode": "ephemeral", "operator_record": nil}))
			got := nativeReceive(t, c)
			if change {
				nativeResponse(t, got, nativeID(2), "generation_mismatch")
			} else {
				nativeResponse(t, got, nativeID(2), "")
			}
		})
	}
}
