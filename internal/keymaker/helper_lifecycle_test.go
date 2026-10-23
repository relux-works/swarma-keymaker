package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-registrar/envelope"
	format "github.com/relux-works/swarma-registrar/registration"
)

func helperRequest(n int) control.Object {
	return nativeRequest(n, "sign_registration", control.Object{"name": helperName, "aud": helperAudience})
}
func helperCall(t *testing.T, f *nativeFixture, c *net.UnixConn, n int, want Code) []byte {
	t.Helper()
	nativeSend(t, c, helperRequest(n))
	return helperResult(t, nativeReceive(t, c), nativeID(n), want, f.native.Config.Helper.key)
}

// Exact retries retain the original nonce/envelope, including concurrent clients,
// timeout changes and a real Store/journal restart. Changed args cannot reuse ID.
func TestHelperDurableRetry(t *testing.T) {
	f, trust := helperSetup(t)
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	first := helperCall(t, f, c, 2, "")
	changed := helperRequest(2)
	changed["params"].(control.Object)["aud"] = "changed.invalid"
	before := nativeSnapshot(t, f)
	nativeSend(t, c, changed)
	nativeResponse(t, nativeReceive(t, c), nativeID(2), "request_conflict")
	if !bytes.Equal(before, nativeSnapshot(t, f)) {
		t.Fatal("conflict changed retained state")
	}
	retry := helperRequest(2)
	retry["timeout_ms"] = int64(1000)
	nativeSend(t, c, retry)
	if got := helperResult(t, nativeReceive(t, c), nativeID(2), "", trust.helper.key); !bytes.Equal(first, got) {
		t.Fatal("same-ID retry minted a new nonce")
	}
	d := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, d, 3)
	var wg sync.WaitGroup
	for _, conn := range []*net.UnixConn{c, d} {
		wg.Go(func() {
			if got := helperCall(t, f, conn, 2, ""); !bytes.Equal(first, got) {
				t.Error("concurrent retry minted a new nonce")
			}
		})
	}
	wg.Wait()
	f.restart(t, nil)
	fresh := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, fresh, 4)
	if got := helperCall(t, f, fresh, 2, ""); !bytes.Equal(first, got) {
		t.Fatal("restart minted a new nonce")
	}
	trust.clock.set(helperNow.Add(120*time.Second), true)
	helperCall(t, f, fresh, 2, "request_expired")
	if got := helperCall(t, f, fresh, 5, ""); bytes.Equal(first, got) {
		t.Fatal("fresh ID reused expired proof")
	}
}

// A failed reload, unreconciled startup, closed custody, unhealthy clock and
// expired key each refuse on B without closing A or general control admission.
// Each scenario has an independently healthy signing control.
func TestHelperAvailability(t *testing.T) {
	for _, scenario := range []string{"failed-reload", "unreconciled", "closed-master", "clock", "key-window", "entropy"} {
		t.Run(scenario, func(t *testing.T) {
			for _, bad := range []bool{true, false} {
				name := "control"
				if bad {
					name = "negative"
				}
				t.Run(name, func(t *testing.T) {
					f, trust := helperSetup(t)
					want := Code("")
					if bad {
						switch scenario {
						case "failed-reload":
							os.WriteFile(trust.config, []byte("{}"), 0600)
							trust.authority.Reload(context.Background())
							want = "enrollment_unverified"
						case "unreconciled":
							trust.helper.authority = enrollmentUnreconciled(trust)
							want = "enrollment_unverified"
						case "clock":
							trust.clock.set(helperNow, false)
							want = "clock_untrusted"
						case "key-window":
							trust.clock.set(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), true)
							want = "key_not_valid_now"
						case "closed-master":
							f.master.Close()
							want = "custody_unavailable"
						case "entropy":
							builder, err := newFailingEntropyBuilder(f, trust)
							if err != nil {
								t.Fatal(err)
							}
							trust.helper.builder = builder
							want = "entropy_unavailable"
						}
					}
					f.start()
					c := nativeDial(t, f.server.ControlPath)
					nativeNegotiate(t, c, 1)
					before := nativeSnapshot(t, f)
					helperCall(t, f, c, 2, want)
					if bad && !bytes.Equal(before, nativeSnapshot(t, f)) {
						t.Fatal("unavailable helper retained success")
					}
					nativeNegotiate(t, nativeDial(t, f.server.ControlPath), 3)
					a := nativeDial(t, f.server.Path)
					writeResponse(a, Packet([]byte{11}))
					raw, code := ReadFrame(a)
					if code != "" || len(raw) == 0 || (raw[0] != 12 && !(bad && scenario == "closed-master" && raw[0] == 5)) {
						t.Fatal("helper fault killed surface A", code)
					}
				})
			}
		})
	}
}

// Both complete real-socket signatures verify in their own domain and fail in
// the other. A surface-A host-key selector also refuses before signing.
func TestHelperDomainSeparation(t *testing.T) {
	f, _ := helperSetup(t)
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	raw := helperCall(t, f, c, 2, "")
	reg, err := envelope.Parse(raw, envelope.Registration)
	if err != nil {
		t.Fatal(err)
	}
	b := nativeOwnBinding()
	public, code := f.master.Public(b.Path)
	if code != "" {
		t.Fatal(code)
	}
	body := validBody(public, "git")
	req, code := parseAgent(body)
	if code != "" {
		t.Fatal(code)
	}
	if ed25519.Verify(public, req.data, reg.Signature) {
		t.Fatal("helper signature verified as SSHSIG")
	}
	hostPublic, err := base64.RawURLEncoding.DecodeString(f.native.Config.Helper.key[len("ed25519:"):])
	if err != nil || bytes.Equal(public, hostPublic) {
		t.Fatal("purpose keys are not separate")
	}
	a := nativeDial(t, f.server.Path)
	writeResponse(a, Packet(validBody(hostPublic, "git")))
	rejected, code := ReadFrame(a)
	if code != "" || !bytes.Equal(rejected, []byte{5}) {
		t.Fatal("purpose-2 key usable on surface A")
	}
	writeResponse(a, Packet(body))
	response, code := ReadFrame(a)
	if code != "" || len(response) == 0 || response[0] != 14 {
		t.Fatal("surface A control")
	}
	r := wireReader{b: response[1:]}
	blob := r.string()
	sig := wireReader{b: blob}
	algorithm := sig.string()
	signature := sig.string()
	if r.bad || len(r.b) != 0 || sig.bad || len(sig.b) != 0 || string(algorithm) != "ssh-ed25519" || !ed25519.Verify(public, req.data, signature) {
		t.Fatal("surface A signature invalid")
	}
	if ed25519.Verify(hostPublic, reg.Preimage, signature) {
		t.Fatal("surface A signature verified as registration/1")
	}
	original, err := format.Verify(raw)
	if err != nil {
		t.Fatal(err)
	}
	canonical, _, err := format.Build(*original, helperAudience)
	if err != nil {
		t.Fatal(err)
	}
	cross, err := format.Assemble(canonical, signature)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = format.Verify(cross); err == nil {
		t.Fatal("SSHSIG accepted as registrar envelope")
	}
}

// Retirement/revocation before release suppress success. Conversely a held
// actual-write barrier orders a later retirement/revocation after the envelope.
// Delayed notifications ensure the authoritative fence, rather than idle-close,
// is the refusal witness. Binding notification closure is permitted too.
func TestHelperReleaseOrdering(t *testing.T) {
	for _, change := range []string{"retire", "revoke"} {
		t.Run(change, func(t *testing.T) {
			for _, wins := range []bool{false, true} {
				name := "authority-wins"
				if wins {
					name = "release-wins"
				}
				t.Run(name, func(t *testing.T) {
					f, _ := helperSetup(t)
					f.engine.Generations = delayedGenerationWatch{f.generation}
					b := nativeOwnBinding()
					modify := func() {
						if change == "retire" {
							f.generation.set(b.UID, "retiring", b.Generation)
						} else {
							if c := f.store.Revoke(context.Background(), f.config.Operator, f.config.Operator, 1, approvedAct{}); c != "" {
								t.Error(c)
							}
						}
					}
					probe := &nativeFenceProbe{native: f.native, method: "sign_registration"}
					entered, allow := make(chan struct{}), make(chan struct{})
					var once sync.Once
					unblock := func() { once.Do(func() { close(allow) }) }
					defer unblock()
					if wins {
						probe.entered = entered
						probe.allow = allow
					} else {
						probe.before = modify
					}
					wire, e := control.New(f.native, f.native, f.native, probe, f.native)
					if e != nil {
						t.Fatal(e)
					}
					f.server.controlWire = wire
					f.start()
					c := nativeDial(t, f.server.ControlPath)
					nativeNegotiate(t, c, 1)
					nativeSend(t, c, helperRequest(2))
					if !wins {
						raw, code := ReadFrame(c)
						if code != "" {
							t.Fatal(code)
						}
						if raw != nil {
							obj, e := control.Decode(raw)
							if e != nil {
								t.Fatal(e)
							}
							want := Code("generation_inactive")
							if change == "revoke" {
								want = "identity_revoked"
							}
							helperResult(t, obj, nativeID(2), want, f.native.Config.Helper.key)
						}
						return
					}
					select {
					case <-entered:
					case <-time.After(time.Second):
						t.Fatal("release did not enter barrier")
					}
					attempted, changed := make(chan struct{}), make(chan struct{})
					go func() { close(attempted); modify(); close(changed) }()
					<-attempted
					select {
					case <-changed:
						t.Fatal("authority transition overtook actual write")
					case <-time.After(25 * time.Millisecond):
					}
					unblock()
					helperResult(t, nativeReceive(t, c), nativeID(2), "", f.native.Config.Helper.key)
					select {
					case <-changed:
					case <-time.After(time.Second):
						t.Fatal("authority transition remained blocked")
					}
				})
			}
		})
	}
}

// Audit latency cannot release an expired proof, even though preparation and
// its first release validation succeeded. One nanosecond before expiry passes.
func TestHelperExpiryAfterAudit(t *testing.T) {
	for _, expired := range []bool{true, false} {
		name := "control"
		if expired {
			name = "expired"
		}
		t.Run(name, func(t *testing.T) {
			f, trust := helperSetup(t)
			probe := &nativeFenceProbe{native: f.native, method: "sign_registration"}
			probe.before = func() {
				f.store.journal.mu.Lock()
				f.store.journal.writer = &helperAuditClock{file: f.store.journal.file, clock: trust.clock, at: helperNow.Add(120 * time.Second), expired: expired}
				f.store.journal.mu.Unlock()
			}
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
				want = "request_expired"
			}
			helperCall(t, f, c, 2, want)
		})
	}
}

type helperAuditClock struct {
	file    *os.File
	clock   *helperClock
	at      time.Time
	expired bool
}

func (w *helperAuditClock) Write(b []byte) (int, error) { return w.file.Write(b) }
func (w *helperAuditClock) Sync() error {
	e := w.file.Sync()
	at := w.at
	if !w.expired {
		at = at.Add(-time.Nanosecond)
	}
	w.clock.set(at, true)
	return e
}

// Exact parameter shape prevents caller body/key/nonce/time selectors, beside a
// valid helper request over the same connection. Refusals never retain an ID.
func TestHelperSchema(t *testing.T) {
	for _, field := range []string{"body", "key", "nonce", "iat", "ttl", "path", "exe"} {
		t.Run(field, func(t *testing.T) {
			f, _ := helperSetup(t)
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			request := helperRequest(2)
			request["params"].(control.Object)[field] = "untrusted"
			before := nativeSnapshot(t, f)
			nativeSend(t, c, request)
			nativeResponse(t, nativeReceive(t, c), nativeID(2), "request_malformed")
			if !bytes.Equal(before, nativeSnapshot(t, f)) {
				t.Fatal("schema refusal wrote state")
			}
			helperCall(t, f, c, 2, "")
		})
	}
}

// A failed result persistence closes admission; no signed proof is released.
// The healthy writer returns a verified envelope and retains the exact result.
func TestHelperAuditFailure(t *testing.T) {
	for _, fail := range []bool{true, false} {
		name := "control"
		if fail {
			name = "sync-failure"
		}
		t.Run(name, func(t *testing.T) {
			f, _ := helperSetup(t)
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			if fail {
				f.store.journal.mu.Lock()
				f.store.journal.writer = &faultFile{file: f.store.journal.file, syncFail: true}
				f.store.journal.mu.Unlock()
			}
			nativeSend(t, c, helperRequest(2))
			if !fail {
				helperResult(t, nativeReceive(t, c), nativeID(2), "", f.native.Config.Helper.key)
				return
			}
			raw, code := ReadFrame(c)
			if code != "" {
				t.Fatal(code)
			}
			if raw != nil {
				obj, e := control.Decode(raw)
				if e != nil {
					t.Fatal(e)
				}
				nativeResponse(t, obj, nativeID(2), "audit_unavailable")
			}
		})
	}
}

// A retained result is recovery data, not authority. A fresh connection after
// binding revocation or failed enrollment reload cannot recover its envelope.
// The unchanged authority retry is a positive control for each refusal class.
func TestHelperRetryAuthority(t *testing.T) {
	for _, change := range []string{"revoke", "reload", "window", "generation"} {
		t.Run(change, func(t *testing.T) {
			for _, bad := range []bool{true, false} {
				name := "control"
				if bad {
					name = "negative"
				}
				t.Run(name, func(t *testing.T) {
					f, trust := helperSetup(t)
					f.start()
					c := nativeDial(t, f.server.ControlPath)
					nativeNegotiate(t, c, 1)
					first := helperCall(t, f, c, 2, "")
					c.Close()
					want := Code("")
					if bad {
						switch change {
						case "revoke":
							if c := f.store.Revoke(context.Background(), f.config.Operator, f.config.Operator, 1, approvedAct{}); c != "" {
								t.Fatal(c)
							}
							want = "identity_revoked"
						case "reload":
							os.WriteFile(trust.config, []byte("{}"), 0600)
							trust.authority.Reload(context.Background())
							want = "enrollment_unverified"
						case "window":
							trust.clock.set(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), true)
							want = "key_not_valid_now"
						case "generation":
							f.generation.set(uint32(os.Getuid()), "active", "00000000000000000000000000000002")
							want = "binding_not_found"
						}
					}
					fresh := nativeDial(t, f.server.ControlPath)
					nativeNegotiate(t, fresh, 3)
					before := nativeSnapshot(t, f)
					raw := helperCall(t, f, fresh, 2, want)
					if bad && !bytes.Equal(before, nativeSnapshot(t, f)) {
						t.Fatal("refused retained result changed state")
					}
					if !bad && !bytes.Equal(first, raw) {
						t.Fatal("healthy retained result changed")
					}
				})
			}
		})
	}
}

// A reload that fences enrollment before the release barrier wins over an
// already-built proof. An unchanged authority reaches the actual socket write.
func TestHelperReloadBeforeRelease(t *testing.T) {
	for _, bad := range []bool{true, false} {
		name := "control"
		if bad {
			name = "fenced"
		}
		t.Run(name, func(t *testing.T) {
			f, trust := helperSetup(t)
			probe := &nativeFenceProbe{native: f.native, method: "sign_registration"}
			if bad {
				probe.before = func() { os.WriteFile(trust.config, []byte("{}"), 0600); trust.authority.Reload(context.Background()) }
			}
			wire, e := control.New(f.native, f.native, f.native, probe, f.native)
			if e != nil {
				t.Fatal(e)
			}
			f.server.controlWire = wire
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			want := Code("")
			if bad {
				want = "enrollment_unverified"
			}
			helperCall(t, f, c, 2, want)
		})
	}
}

// The helper has its own admitted key/name budget in addition to shared native
// budgets: burst four, then exact refusal without state effects, then recovery.
func TestHelperRateBudget(t *testing.T) {
	f, _ := helperSetup(t)
	var clockMu sync.Mutex
	at := time.Now()
	f.engine.rateNow = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return at }
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	for n := 2; n < 6; n++ {
		helperCall(t, f, c, n, "")
	}
	before := nativeSnapshot(t, f)
	helperCall(t, f, c, 6, "rate_limited")
	if !bytes.Equal(before, nativeSnapshot(t, f)) {
		t.Fatal("helper rate refusal wrote result")
	}
	clockMu.Lock()
	at = at.Add(time.Second)
	clockMu.Unlock()
	helperCall(t, f, c, 6, "")
}

// Losing the connection after durable preparation cannot mint a replacement
// nonce. Restart recovers the exact verified envelope, without any prior reply.
func TestHelperLostResponse(t *testing.T) {
	f, trust := helperSetup(t)
	probe := &nativeFenceProbe{native: f.native, method: "sign_registration", before: func() { f.cancel() }}
	wire, e := control.New(f.native, f.native, f.native, probe, f.native)
	if e != nil {
		t.Fatal(e)
	}
	f.server.controlWire = wire
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, c, 1)
	nativeSend(t, c, helperRequest(2))
	raw, code := ReadFrame(c)
	if code != "" {
		t.Fatal(code)
	}
	if raw != nil {
		obj, e := control.Decode(raw)
		if e != nil {
			t.Fatal(e)
		}
		if obj["result"] != nil {
			t.Fatal("lost response released a proof")
		}
	}
	f.stop(t)
	f.store.mu.Lock()
	entry, cod := f.store.retained(Principal{uint32(os.Getuid()), nativeToken}, control.Request{ID: nativeID(2), Method: "sign_registration", Params: control.Object{"name": helperName, "aud": helperAudience}})
	if cod != "" || entry == nil {
		f.store.mu.Unlock()
		t.Fatal("prepared proof not retained", cod)
	}
	result, cod := f.store.resultObject(entry)
	f.store.mu.Unlock()
	if cod != "" {
		t.Fatal(cod)
	}
	saved, cod := helperEnvelope(result)
	if cod != "" {
		t.Fatal(cod)
	}
	f.restart(t, nil)
	fresh := nativeDial(t, f.server.ControlPath)
	nativeNegotiate(t, fresh, 3)
	recovered := helperCall(t, f, fresh, 2, "")
	if !bytes.Equal(saved, recovered) {
		t.Fatal("lost response retry minted another nonce")
	}
	if _, e := format.Verify(recovered); e != nil {
		t.Fatal("recovered envelope invalid", e)
	}
	if trust.helper.key == "" {
		t.Fatal("fixture key missing")
	}
}
