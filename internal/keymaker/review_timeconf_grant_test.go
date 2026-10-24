//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	proof "github.com/relux-works/swarma-keymaker/internal/registration"
)

// The prepared proof's original exclusive authority must survive persistence
// and the final response barrier, even if newly collected evidence is fresher.
func TestReviewPreparedAuthoritySurvivesRelease(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "within-original-grant", true: "past-original-grant"}[expired], func(t *testing.T) {
			f, tr := helperSetup(t)
			p, clock, collector := fixtureTimeProvider(t, helperNow)
			collector.e.Tracking.Reference = helperNow.Add(-2047 * time.Second)
			h, e := NewRegistrationHelper(f.master, helperPath, tr.authority, p, bytes.NewReader(make([]byte, 16)))
			if e != nil {
				t.Fatal(e)
			}
			f.native.Config.Helper = h
			f.config.Helper = h
			probe := &nativeFenceProbe{native: f.native, method: "sign_registration", before: func() {
				d := 500 * time.Millisecond
				if expired {
					d = 2 * time.Second
				}
				clock.advance(d)
				collector.e.Tracking.Reference = helperNow.Add(d - time.Second)
			}}
			wire, e := control.New(f.native, f.native, f.native, probe, f.native)
			if e != nil {
				t.Fatal(e)
			}
			f.server.controlWire = wire
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			want := Code("")
			if expired {
				want = "clock_untrusted"
			}
			helperCall(t, f, c, 2, want)
		})
	}
}

// A retained same-ID envelope is prepared once per retry, with its fresh grant
// then held unchanged through release. Refreshed evidence cannot extend that
// grant at its exact endpoint or after it; no retry signs or draws entropy again.
func TestTimeConfidenceRetainedAuthoritySurvivesRelease(t *testing.T) {
	for _, d := range []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second} {
		t.Run(d.String(), func(t *testing.T) {
			f, tr := helperSetup(t)
			p, clock, collector := fixtureTimeProvider(t, helperNow)
			collector.e.Tracking.Reference = helperNow.Add(-2047 * time.Second)
			entropy := bytes.NewReader(make([]byte, 16))
			h, e := NewRegistrationHelper(f.master, helperPath, tr.authority, p, entropy)
			if e != nil {
				t.Fatal(e)
			}
			signer := &reloadCountingSigner{signer: registrationSigner{f.master, helperPath}}
			h.builder, e = proof.New(p, entropy, signer)
			if e != nil {
				t.Fatal(e)
			}
			f.native.Config.Helper = h
			f.config.Helper = h
			probe := &timeconfRetryFence{native: f.native, before: func() {
				clock.advance(d)
				collector.e.Tracking.Reference = helperNow.Add(d - time.Second)
			}}
			wire, e := control.New(f.native, f.native, f.native, probe, f.native)
			if e != nil {
				t.Fatal(e)
			}
			f.server.controlWire = wire
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			first := helperCall(t, f, c, 2, "")
			probe.armed.Store(true)
			want := Code("")
			if d >= time.Second {
				want = "clock_untrusted"
			}
			got := helperCall(t, f, c, 2, want)
			if !probe.hit.Load() {
				t.Fatal("retry boundary injection not reached")
			}
			if want == "" && !bytes.Equal(first, got) {
				t.Fatal("retry changed envelope")
			}
			if signer.calls.Load() != 1 || entropy.Len() != 0 {
				t.Fatal("retry minted another nonce/signature", signer.calls.Load(), entropy.Len())
			}
		})
	}
}

type timeconfRetryFence struct {
	native     *Native
	before     func()
	armed, hit atomic.Bool
}

func (f *timeconfRetryFence) WithActive(ctx context.Context, p control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	if r.Method == "sign_registration" && f.armed.CompareAndSwap(true, false) {
		f.before()
		f.hit.Store(true)
	}
	return f.native.WithActive(ctx, p, r, result, release)
}
