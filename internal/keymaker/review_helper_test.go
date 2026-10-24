package keymaker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-keymaker/internal/enrollment"
	proof "github.com/relux-works/swarma-keymaker/internal/registration"
)

type reviewHelperEntropy struct{ calls atomic.Int32 }

func (r *reviewHelperEntropy) Read(p []byte) (int, error) { r.calls.Add(1); return rand.Read(p) }

// Two fresh simultaneous socket requests must create one nonce, and a completely
// new Builder after Store restart must recover it without entropy/signature use.
func TestReviewHelperFirstRetry(t *testing.T) {
	f, tr := helperSetup(t)
	entropy := &reviewHelperEntropy{}
	builder, err := proof.New(tr.clock, entropy, registrationSigner{f.master, helperPath})
	if err != nil {
		t.Fatal(err)
	}
	tr.helper.builder = builder
	f.start()
	a, b := nativeDial(t, f.server.ControlPath), nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, a, 10)
	nativeNegotiate(t, b, 11)
	start := make(chan struct{})
	results := make(chan []byte, 2)
	var wg sync.WaitGroup
	for _, c := range []*net.UnixConn{a, b} {
		wg.Go(func() {
			var raw []byte
			defer func() { results <- raw }()
			<-start
			raw = helperCall(t, f, c, 2, "")
		})
	}
	close(start)
	wg.Wait()
	first, second := <-results, <-results
	if !bytes.Equal(first, second) || entropy.calls.Load() != 1 {
		t.Fatal("fresh concurrent retry minted distinct proof/entropy", entropy.calls.Load())
	}
	f.stop(t)
	tr.helper.builder, err = proof.New(tr.clock, reviewNoEntropy{t}, reviewNoSign{t})
	if err != nil {
		t.Fatal(err)
	}
	f.restart(t, nil)
	fresh := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, fresh, 12)
	got := helperCall(t, f, fresh, 2, "")
	if !bytes.Equal(first, got) {
		t.Fatal("fresh builder changed durable proof")
	}
	changed := helperRequest(2)
	changed["params"].(control.Object)["name"] = "sample_core_other"
	before := nativeSnapshot(t, f)
	nativeSend(t, fresh, changed)
	nativeResponse(t, nativeReceive(t, fresh), nativeID(2), "request_conflict")
	if !bytes.Equal(before, nativeSnapshot(t, f)) {
		t.Fatal("changed arguments wrote state")
	}
}

type reviewNoEntropy struct{ t *testing.T }

func (n reviewNoEntropy) Read([]byte) (int, error) {
	n.t.Error("restored result consumed entropy")
	return 0, os.ErrClosed
}

type reviewNoSign struct{ t *testing.T }

func (n reviewNoSign) Sign(context.Context, []byte) ([]byte, proof.Code) {
	n.t.Error("restored result signed again")
	return nil, "custody_unavailable"
}

// A valid generation-policy reload or a failing reload is ordered against the
// actual socket write. Before-release changes refuse; release-first completes,
// then a fresh retry sees the new policy. Controls keep A/self-pubkey available.
func TestReviewHelperReloadOrders(t *testing.T) {
	for _, kind := range []string{"valid-policy", "fence"} {
		for _, wins := range []bool{false, true} {
			label := kind + map[bool]string{false: "/reload-first", true: "/release-first"}[wins]
			t.Run(label, func(t *testing.T) {
				f, tr := helperSetup(t)
				modify := func() {
					if kind == "fence" {
						if e := os.WriteFile(tr.config, []byte("{}"), 0600); e != nil {
							t.Error(e)
						}
					} else {
						raw, e := os.ReadFile(tr.config)
						if e != nil {
							t.Error(e)
							return
						}
						var cfg enrollment.PinConfig
						if e = json.Unmarshal(raw, &cfg); e != nil {
							t.Error(e)
							return
						}
						cfg.Generations[strconv.Itoa(os.Getuid())] = "00000000000000000000000000000002"
						raw, e = json.Marshal(cfg)
						if e != nil {
							t.Error(e)
							return
						}
						if e = os.WriteFile(tr.config, raw, 0600); e != nil {
							t.Error(e)
						}
					}
				}
				entered, allow := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(allow) }) }
				defer unblock()
				p := &nativeFenceProbe{native: f.native, method: "sign_registration"}
				if wins {
					p.entered = entered
					p.allow = allow
				} else {
					p.before = func() {
						modify()
						code := tr.authority.Reload(context.Background())
						if (kind == "fence" && code != "enrollment_unverified") || (kind == "valid-policy" && code != "") {
							t.Error("reload code", code)
						}
					}
				}
				wire, e := control.New(f.native, f.native, f.native, p, f.native)
				if e != nil {
					t.Fatal(e)
				}
				f.server.controlWire = wire
				f.start()
				c := nativeDial(t, f.server.ControlPath)
				nativeNegotiate(t, c, 1)
				nativeSend(t, c, helperRequest(2))
				want := Code("generation_mismatch")
				if kind == "fence" {
					want = "enrollment_unverified"
				}
				if wins {
					select {
					case <-entered:
					case <-time.After(time.Second):
						t.Fatal("did not enter actual release")
					}
					modify()
					done := make(chan enrollment.Code, 1)
					go func() { done <- tr.authority.Reload(context.Background()) }()
					select {
					case <-done:
						t.Fatal("enrollment reload overtook actual write")
					case <-time.After(30 * time.Millisecond):
					}
					unblock()
					helperResult(t, nativeReceive(t, c), nativeID(2), "", tr.helper.key)
					select {
					case code := <-done:
						if (kind == "fence" && code != "enrollment_unverified") || (kind == "valid-policy" && code != "") {
							t.Fatal(code)
						}
					case <-time.After(time.Second):
						t.Fatal("reload deadlocked after write")
					}
				} else {
					helperResult(t, nativeReceive(t, c), nativeID(2), want, tr.helper.key)
				}
				fresh := nativeDial(t, f.server.ControlPath)
				nativeNegotiate(t, fresh, 3)
				before := nativeSnapshot(t, f)
				helperCall(t, f, fresh, 2, want)
				if !bytes.Equal(before, nativeSnapshot(t, f)) {
					t.Fatal("denied retry changed state")
				}
				healthy := nativeDial(t, f.server.ControlPath)
				nativeNegotiate(t, healthy, 5)
				nativeSend(t, healthy, nativeRequest(6, "pubkey", control.Object{}))
				nativeResponse(t, nativeReceive(t, healthy), nativeID(6), "")
			})
		}
	}
}

type reviewReloadFiles struct {
	helperFiles
	config  string
	armed   atomic.Bool
	entered chan struct{}
	resume  <-chan struct{}
}

func (f *reviewReloadFiles) Read(path string, limit int64) ([]byte, enrollment.Metadata, error) {
	if path == f.config && f.armed.CompareAndSwap(true, false) {
		close(f.entered)
		select {
		case <-f.resume:
		case <-time.After(4 * time.Second):
		}
	}
	return f.helperFiles.Read(path, limit)
}

type reviewHelperClockEntry struct {
	clock   *helperClock
	entered chan struct{}
	once    sync.Once
}

func (c *reviewHelperClockEntry) Sample(ctx context.Context) (timeconf.Sample, error) {
	c.once.Do(func() { close(c.entered) })
	return c.clock.Sample(ctx)
}

// Current UID reuse and trusted-time/key-window failures must also prevent a
// prepared proof reaching the actual response; post-audit time changes exercise
// the last Proof.Recheck, with an unchanged-clock positive control.
func TestReviewHelperReleaseNeighbors(t *testing.T) {
	for _, mode := range []string{"control", "uid-reused", "clock-rollback-after-audit", "key-expiry-after-audit"} {
		t.Run(mode, func(t *testing.T) {
			f, tr := helperSetup(t)
			f.engine.Generations = delayedGenerationWatch{f.generation}
			want := Code("")
			var before []byte
			p := &nativeFenceProbe{native: f.native, method: "sign_registration", before: func() {
				before = nativeSnapshot(t, f)
				switch mode {
				case "uid-reused":
					f.generation.set(uint32(os.Getuid()), "active", "replacement")
					want = "generation_mismatch"
				case "clock-rollback-after-audit", "key-expiry-after-audit":
					at := helperNow.Add(-time.Second)
					want = "clock_untrusted"
					if mode == "key-expiry-after-audit" {
						at = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
						want = "key_not_valid_now"
					}
					f.store.journal.mu.Lock()
					f.store.journal.writer = &helperAuditClock{file: f.store.journal.file, clock: tr.clock, at: at, expired: true}
					f.store.journal.mu.Unlock()
				}
			}}
			wire, e := control.New(f.native, f.native, f.native, p, f.native)
			if e != nil {
				t.Fatal(e)
			}
			f.server.controlWire = wire
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			nativeSend(t, c, helperRequest(2))
			obj := nativeReceive(t, c)
			helperResult(t, obj, nativeID(2), want, tr.helper.key)
			if mode != "control" && !bytes.Equal(before, nativeSnapshot(t, f)) {
				t.Fatal("denied release modified prepared result")
			}
		})
	}
}
