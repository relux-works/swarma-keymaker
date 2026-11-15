//go:build linux

package keymaker

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

func j7SigningPolicy(t *testing.T, f *j7SignFixture, version uint64) *j7PolicyTable {
	t.Helper()
	f.f.store.mu.Lock()
	raw, _ := canonical(f.f.store.j7.Policy)
	f.f.store.mu.Unlock()
	p, e := decodeJ7Policy(raw, f.f.store.j7.Instance, f.f.binding.Number)
	if e != nil {
		t.Fatal(e)
	}
	p.Version = version
	return p
}

// The actual socket callback is wrapped, not replaced. A publication ordered
// before release refuses; a publication trying during the callback must wait.
type j7SigningFenceProbe struct {
	a       *j7RequestCustody
	before  func()
	entered chan struct{}
	allow   <-chan struct{}
	once    atomic.Bool
}

func (p *j7SigningFenceProbe) WithActive(ctx context.Context, peer control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	if r.Method != "j7_sign" || !p.once.CompareAndSwap(false, true) {
		return p.a.WithActive(ctx, peer, r, result, release)
	}
	if p.before != nil {
		p.before()
	}
	return p.a.WithActive(ctx, peer, r, result, func(ctx context.Context) control.Code {
		if p.entered != nil {
			close(p.entered)
			select {
			case <-p.allow:
			case <-ctx.Done():
				return control.DeadlineExceeded
			}
		}
		return release(ctx)
	})
}

// Cross-origin authority cannot borrow a retained consent or an enrolled grant;
// a known correctly bound origin still obtains its own consent. Invalid run
// labels/IDs never enter the caller schema, and real unbound sockets stay closed.
func TestJ7SigningCrossOrigin(t *testing.T) {
	f := j7SigningSetup(t)
	unknown := f.dial(t, 1)
	j7Call(t, unknown, 2, "j7_pubkey", control.Object{}, "run_identity_unavailable")
	a := f.dial(t, 3)
	f.bind(t, a, 4, f.f.origin, f.f.uid+200)
	j7ResultEvent(t, j7Call(t, a, 5, "j7_sign", f.consent(t), ""))
	other := f.f.origin
	other.Event = strings.Repeat("f", 64)
	b := f.dial(t, 6)
	f.bind(t, b, 7, other, f.f.uid+201)
	j7Call(t, b, 8, "j7_sign", f.consent(t), "CONSENT_NOT_FOR_RUN")
	j7Call(t, b, 5, "j7_sign", f.consent(t), "request_conflict")
	f.f.store.mu.Lock()
	records := len(f.f.store.j7Signing.Records)
	f.f.store.mu.Unlock()
	if records != 1 {
		t.Fatal("foreign origin acquired retained consent")
	}
	j7ResultEvent(t, j7Call(t, a, 9, "j7_sign", f.consent(t), ""))
}

// Withdrawal before the actual response-write fence wins; removal after the
// held callback cannot overtake it. This proves the exercised real Unix write
// ordering, not external broker isolation or power-loss recovery.
func TestJ7SigningWithdrawalActualWrite(t *testing.T) {
	for _, order := range []string{"withdrawal-wins", "release-wins"} {
		t.Run(order, func(t *testing.T) {
			probe := &j7SigningFenceProbe{}
			f := j7SigningSetupFence(t, func(a *j7RequestCustody) control.ReleaseFence { probe.a = a; return probe })
			c := f.dial(t, 1)
			f.bind(t, c, 2, f.f.origin, f.f.uid+200)
			p := j7SigningPolicy(t, f, 2)
			p.Rows[0].Consent = []j7ConsentPermission{}
			allow := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(allow) }) }
			defer unblock()
			if order == "withdrawal-wins" {
				probe.before = func() { f.f.publish(t, p) }
			} else {
				probe.entered = make(chan struct{})
				probe.allow = allow
			}
			nativeSend(t, c, nativeRequest(3, "j7_sign", f.consent(t)))
			if order == "withdrawal-wins" {
				nativeResponse(t, nativeReceive(t, c), nativeID(3), "CONSENT_NOT_FOR_RUN")
				f.f.store.mu.Lock()
				state := f.f.store.j7Signing.Records[0].Release
				f.f.store.mu.Unlock()
				if state != "prepared" {
					t.Fatal("withdrawn consent reached handoff")
				}
				return
			}
			select {
			case <-probe.entered:
			case <-time.After(time.Second):
				t.Fatal("actual signing callback did not enter")
			}
			attempted, finished := make(chan struct{}), make(chan Code, 1)
			go func() { close(attempted); finished <- f.f.policy.publish(t.Context(), j7PolicyRaw(t, p)) }()
			<-attempted
			select {
			case <-finished:
				t.Fatal("withdrawal overtook actual signature write")
			case <-time.After(25 * time.Millisecond):
			}
			unblock()
			j7ResultEvent(t, nativeResponse(t, nativeReceive(t, c), nativeID(3), ""))
			select {
			case c := <-finished:
				if c != "" {
					t.Fatal(c)
				}
			case <-time.After(time.Second):
				t.Fatal("publication did not follow write")
			}
			// A retained result is not current authority after withdrawal.
			j7Call(t, c, 3, "j7_sign", f.consent(t), "CONSENT_NOT_FOR_RUN")
		})
	}
}

// Identical retries keep their bytes, but changed input or a different protected
// run under the same kernel peer/requestID conflicts without another signature.
func TestJ7SigningRetryInput(t *testing.T) {
	f := j7SigningSetup(t)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	params := f.consent(t)
	old := j7Call(t, c, 3, "j7_sign", params, "")
	changed := f.contract
	changed.Note = "different"
	raw, _ := j7Compact(changed)
	next := j7TypedParams(t, "consent_v3", j7ConsentInput{Contract: j7Encode64(raw)})
	p := j7SigningPolicy(t, f, 2)
	triple := j7ConsentTriple(raw)
	triple.AndUse = true
	p.Rows[0].Consent = append(p.Rows[0].Consent, triple)
	f.f.publish(t, p)
	j7Call(t, c, 3, "j7_sign", next, "request_conflict")
	if again := j7Call(t, c, 3, "j7_sign", params, ""); !reflect.DeepEqual(old, again) {
		t.Fatal("exact retry re-signed")
	}
}

// The real rental verifier finishes outside final locks. A withdrawal published
// during its final observation must suppress BOTH first and retained-result
// disclosure at the actual socket callback, despite earlier valid authority.
func TestJ7SigningWithdrawalAfterEvidence(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(fmt.Sprint(retry), func(t *testing.T) {
			f := j7SigningSetup(t)
			c := f.dial(t, 1)
			f.bind(t, c, 2, f.f.origin, f.f.uid+200)
			consent := j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
			grant, node, ev := j7IssueFixture(t, f, consent)
			p := j7SigningPolicy(t, f, 2)
			p.Rows[0].Use = []string{grant.ID()}
			f.f.publish(t, p)
			params := j7EnvelopeParams(t, f, grant, ev)
			if retry {
				j7ResultEvent(t, j7Call(t, c, 4, "j7_sign", params, ""))
			}
			p = j7SigningPolicy(t, f, 3)
			p.Rows[0].Use = []string{}
			p.Rows[0].Deny = []string{grant.ID()}
			var published atomic.Bool
			node.mu.Lock()
			at := node.utxos + 3
			node.onUTXO = func(n int) {
				if n == at {
					f.f.publish(t, p)
					published.Store(true)
				}
			}
			node.mu.Unlock()
			j7Call(t, c, 4, "j7_sign", params, "GRANT_NOT_FOR_RUN")
			if !published.Load() {
				t.Fatal("final evidence withdrawal control was not exercised")
			}
			f.f.store.mu.Lock()
			rec := f.f.store.j7SigningRecord(f.a.launcher, nativeID(4))
			state := rec.Release
			failed := f.f.store.failed
			f.f.store.mu.Unlock()
			want := "prepared"
			if retry {
				want = "released"
			}
			if state != want || failed {
				t.Fatal("withdrawal changed handoff or fenced healthy state", state, failed)
			}
		})
	}
}
