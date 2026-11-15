//go:build linux

package keymaker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-keymaker/internal/control"
)

type j7PreparedFence struct {
	a    *j7RequestCustody
	once atomic.Bool
}

func (p *j7PreparedFence) WithActive(ctx context.Context, peer control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	if r.Method == "j7_sign" && p.once.CompareAndSwap(false, true) {
		return "CONSENT_NOT_FOR_RUN"
	}
	return p.a.WithActive(ctx, peer, r, result, release)
}

// A real signed grant containing a prepared-but-unreleased consent cannot
// enroll. Rebinding the retained run and releasing the exact prepared consent
// enables the neighboring enrollment without re-signing or changing its bytes.
func TestJ7EnrollmentRequiresReleasedConsent(t *testing.T) {
	probe := &j7PreparedFence{}
	f := j7SigningSetupFence(t, func(a *j7RequestCustody) control.ReleaseFence { probe.a = a; return probe })
	c := f.dial(t, 1)
	run := f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	j7Call(t, c, 3, "j7_sign", f.consent(t), "CONSENT_NOT_FOR_RUN")
	c.Close()
	f.f.store.mu.Lock()
	prior := f.f.store.requests[f.f.store.requestIndex[requestKey{f.a.launcher, nativeID(3)}]]
	stored, e := control.Decode(prior.Result)
	state := f.f.store.j7SigningRecord(f.a.launcher, nativeID(3)).Release
	f.f.store.mu.Unlock()
	if e != nil || state != "prepared" {
		t.Fatal("known-unreleased fixture", e, state)
	}
	event := j7ResultEvent(t, stored)
	grant, _, evidence := j7IssueFixture(t, f, event)
	// EOF cleanup must remove the volatile association before trusted rebind.
	for i := 0; i < 1000; i++ {
		f.f.store.mu.Lock()
		gone := f.a.channels[run] == nil
		f.f.store.mu.Unlock()
		if gone {
			break
		}
		time.Sleep(time.Millisecond)
	}
	d := f.dial(t, 10)
	j7Call(t, d, 11, "j7_run_rebind", control.Object{"run_id": run}, "")
	params := j7GrantParams(t, f, grant, evidence)
	j7Call(t, d, 12, "j7_enroll", params, "GRANT_NOT_FOR_RUN")
	f.f.store.mu.Lock()
	count := len(f.f.store.j7Signing.Enrollments)
	f.f.store.mu.Unlock()
	if count != 0 {
		t.Fatal("unreleased consent enrolled")
	}
	again := j7Call(t, d, 3, "j7_sign", f.consent(t), "")
	if !reflect.DeepEqual(stored, again) {
		t.Fatal("prepared retry changed exact consent")
	}
	j7Call(t, d, 12, "j7_enroll", params, "")
}

// Durable denial survives restart and blocks retained signature/enrollment
// retries. Only newer explicit operator use lifts it. A standing and-use entry
// can admit a genuinely new exact consent/grant after a renewed withdrawal.
func TestJ7SigningDurableDenyAndStandingConsent(t *testing.T) {
	f := j7SigningSetup(t)
	c := f.dial(t, 1)
	run := f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	consent := j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
	grant, _, evidence := j7IssueFixture(t, f, consent)
	enrollment := j7GrantParams(t, f, grant, evidence)
	j7Call(t, c, 4, "j7_enroll", enrollment, "")
	envelope := j7EnvelopeParams(t, f, grant, evidence)
	original := j7Call(t, c, 5, "j7_sign", envelope, "")
	p := j7SigningPolicy(t, f, 2)
	p.Rows[0].Deny = []string{grant.ID()}
	f.f.publish(t, p)
	j7Call(t, c, 4, "j7_enroll", enrollment, "GRANT_NOT_FOR_RUN")
	j7Call(t, c, 5, "j7_sign", envelope, "GRANT_NOT_FOR_RUN")
	c.Close()
	j7RestartSigning(t, f)
	d := f.dial(t, 10)
	j7Call(t, d, 11, "j7_run_rebind", control.Object{"run_id": run}, "")
	j7Call(t, d, 4, "j7_enroll", enrollment, "GRANT_NOT_FOR_RUN")
	j7Call(t, d, 5, "j7_sign", envelope, "GRANT_NOT_FOR_RUN")
	p = j7SigningPolicy(t, f, 3)
	p.Rows[0].Deny = []string{}
	p.Rows[0].Use = []string{grant.ID()}
	f.f.publish(t, p)
	if again := j7Call(t, d, 5, "j7_sign", envelope, ""); !reflect.DeepEqual(again, original) {
		t.Fatal("explicit relist changed retained bytes")
	}
	p = j7SigningPolicy(t, f, 4)
	p.Rows[0].Use = []string{}
	p.Rows[0].Deny = []string{grant.ID()}
	f.f.publish(t, p)
	nextConsent := j7ResultEvent(t, j7Call(t, d, 20, "j7_sign", f.consent(t), ""))
	next, _, nextEvidence := j7IssueFixture(t, f, nextConsent)
	if next.ID() == grant.ID() || next.Grant.Seal == grant.Grant.Seal {
		t.Fatal("standing control is not a new grant/seal")
	}
	j7Call(t, d, 21, "j7_enroll", j7GrantParams(t, f, next, nextEvidence), "")
	j7ResultEvent(t, j7Call(t, d, 22, "j7_sign", j7EnvelopeParams(t, f, next, nextEvidence), ""))
	j7Call(t, d, 5, "j7_sign", envelope, "GRANT_NOT_FOR_RUN")
	p = j7SigningPolicy(t, f, 5)
	p.Rows[0].Consent = []j7ConsentPermission{}
	f.f.publish(t, p)
	j7Call(t, d, 23, "j7_sign", f.consent(t), "CONSENT_NOT_FOR_RUN")
	j7ResultEvent(t, j7Call(t, d, 24, "j7_sign", j7EnvelopeParams(t, f, next, nextEvidence), ""))
}

// A listed owner row cannot substitute for the exact admission-origin row.
// Both the original origin's enrollment and the owner's explicit use are valid
// controls under the same request key; a different admission obtains no result.
func TestJ7SigningGrantOrigin(t *testing.T) {
	f := j7SigningSetup(t)
	p := j7SigningPolicy(t, f, 2)
	owner := j7PolicyRow{Origin: j7OriginKey{Kind: "owner_command"}, Use: []string{}, Delegate: []string{}, Consent: append([]j7ConsentPermission{}, p.Rows[0].Consent...), Deny: []string{}}
	other := f.f.origin
	other.Event = strings.Repeat("f", 64)
	p.Rows = append(p.Rows, owner, j7PolicyRow{Origin: other.key(), Use: []string{}, Delegate: []string{}, Consent: []j7ConsentPermission{}, Deny: []string{}})
	f.f.publish(t, p)
	a := f.dial(t, 1)
	f.bind(t, a, 2, f.f.origin, f.f.uid+200)
	consent := j7ResultEvent(t, j7Call(t, a, 3, "j7_sign", f.consent(t), ""))
	grant, node, ev := j7IssueFixture(t, f, consent)
	j7Call(t, a, 4, "j7_enroll", j7GrantParams(t, f, grant, ev), "")
	p = j7SigningPolicy(t, f, 3)
	p.Rows[1].Use = []string{grant.ID()}
	f.f.publish(t, p)
	envelope := j7EnvelopeParams(t, f, grant, ev)
	j7ResultEvent(t, j7Call(t, a, 5, "j7_sign", envelope, ""))
	b := f.dial(t, 10)
	run := f.bind(t, b, 11, other, f.f.uid+201)
	node.mu.Lock()
	before := node.calls
	node.mu.Unlock()
	j7Call(t, b, 12, "j7_sign", envelope, "GRANT_NOT_FOR_RUN")
	node.mu.Lock()
	after := node.calls
	node.mu.Unlock()
	if before != after {
		t.Fatal("foreign origin reached live-evidence journal")
	}
	j7Call(t, a, 13, "j7_run_end", control.Object{"run_id": run}, "")
	c := f.dial(t, 20)
	f.bind(t, c, 21, j7Origin{Kind: "owner_command", Command: strings.Repeat("a", 64)}, f.f.uid+201)
	j7ResultEvent(t, j7Call(t, c, 22, "j7_sign", envelope, ""))
}

// Removing and-use before enrollment or never granting it prevents enrollment
// even with a complete valid externally signed grant and exact released event.
func TestJ7EnrollmentAndUse(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprint(remove), func(t *testing.T) {
			f := j7SigningSetup(t)
			if !remove {
				p := j7SigningPolicy(t, f, 2)
				p.Rows[0].Consent[0].AndUse = false
				f.f.publish(t, p)
			}
			c := f.dial(t, 1)
			f.bind(t, c, 2, f.f.origin, f.f.uid+200)
			event := j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
			grant, _, ev := j7IssueFixture(t, f, event)
			if remove {
				p := j7SigningPolicy(t, f, 2)
				p.Rows[0].Consent = []j7ConsentPermission{}
				f.f.publish(t, p)
			}
			j7Call(t, c, 4, "j7_enroll", j7GrantParams(t, f, grant, ev), "GRANT_NOT_FOR_RUN")
			f.f.store.mu.Lock()
			count := len(f.f.store.j7Signing.Enrollments)
			f.f.store.mu.Unlock()
			if count != 0 {
				t.Fatal("missing and-use admitted enrollment")
			}
		})
	}
}

func j7GrantParams(t *testing.T, f *j7SignFixture, g rental.SignedGrant, evidence j7Evidence) control.Object {
	t.Helper()
	raw, e := json.Marshal(g)
	if e != nil {
		t.Fatal(e)
	}
	object, _ := j7Compact(j7GrantInput{Contract: j7Encode64(f.raw), Grant: j7Encode64(raw)})
	ev, _ := j7Compact(evidence)
	return control.Object{"object_b64": j7Encode64(object), "evidence_b64": j7Encode64(ev)}
}
func j7EnvelopeParams(t *testing.T, f *j7SignFixture, g rental.SignedGrant, evidence j7Evidence) control.Object {
	t.Helper()
	raw, e := json.Marshal(g)
	if e != nil {
		t.Fatal(e)
	}
	obj := j7EnvelopeInput{Contract: j7Encode64(f.raw), Grant: j7Encode64(raw), Instruction: j7Encode64([]byte("fixture instruction")), Transport: "matrix", To: f.contract.Agent, Action: "instruct", Room: "!fixture:example.test", MXID: "@fixture:example.test"}
	params := j7TypedParams(t, "envelope_v3", obj)
	ev, _ := j7Compact(evidence)
	params["evidence_b64"] = j7Encode64(ev)
	return params
}

// No grant exists at first consent. An independent fixture issuer incorporates
// its exact released event, the actual rental verifier admits the node graph,
// and only then does enrollment enable envelope signing. A spent-seal neighbor
// must fail the same live-evidence path without another retained signature.
func TestJ7FirstConsentAndEnrollment(t *testing.T) {
	f := j7SigningSetup(t)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	consent := j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
	grant, node, evidence := j7IssueFixture(t, f, consent)
	envelope := j7EnvelopeParams(t, f, grant, evidence)
	j7Call(t, c, 4, "j7_sign", envelope, "GRANT_NOT_FOR_RUN")
	enroll := j7GrantParams(t, f, grant, evidence)
	out := j7Call(t, c, 5, "j7_enroll", enroll, "")
	if out["grant_id"] != grant.ID() {
		t.Fatal("recomputed enrollment id")
	}
	if retry := j7Call(t, c, 5, "j7_enroll", enroll, ""); !reflect.DeepEqual(out, retry) {
		t.Fatal("enrollment retry changed result")
	}
	result := j7Call(t, c, 6, "j7_sign", envelope, "")
	event := j7ResultEvent(t, result)
	if event.Kind != 8185 || event.Content != "" || len(event.Tags) != 8 || event.Tags[2][1] != grant.ID() || event.Tags[4][1] != j7Hash([]byte("fixture instruction")) {
		t.Fatal("typed envelope bytes")
	}
	if retry := j7Call(t, c, 6, "j7_sign", envelope, ""); !reflect.DeepEqual(result, retry) {
		t.Fatal("envelope retry changed signature/time/nonce")
	}
	node.mu.Lock()
	node.spent = true
	node.mu.Unlock()
	j7Call(t, c, 7, "j7_sign", envelope, "delegation_evidence_unavailable")
	f.f.store.mu.Lock()
	count := len(f.f.store.j7Signing.Enrollments)
	records := len(f.f.store.j7Signing.Records)
	f.f.store.mu.Unlock()
	if count != 1 || records != 3 {
		t.Fatal("forbidden duplicate enrollment or retained signature")
	}
}

// Downgrading and-use after preparation but before the actual first release
// cannot leave preparation-time auto-enrollment authority in retained history.
// Relisting and-use permits a fresh consent, not enrollment from that old event.
func TestJ7EnrollmentAndUseAtFirstRelease(t *testing.T) {
	probe := &j7SigningFenceProbe{}
	f := j7SigningSetupFence(t, func(a *j7RequestCustody) control.ReleaseFence { probe.a = a; return probe })
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	p := j7SigningPolicy(t, f, 2)
	p.Rows[0].Consent[0].AndUse = false
	probe.before = func() { f.f.publish(t, p) }
	event := j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
	f.f.store.mu.Lock()
	andUse := f.f.store.j7SigningRecord(f.a.launcher, nativeID(3)).Consent.AndUse
	f.f.store.mu.Unlock()
	if andUse {
		t.Fatal("prepared and-use survived first release downgrade")
	}
	p = j7SigningPolicy(t, f, 3)
	p.Rows[0].Consent[0].AndUse = true
	f.f.publish(t, p)
	g, _, ev := j7IssueFixture(t, f, event)
	j7Call(t, c, 4, "j7_enroll", j7GrantParams(t, f, g, ev), "GRANT_NOT_FOR_RUN")
	fresh := j7ResultEvent(t, j7Call(t, c, 5, "j7_sign", f.consent(t), ""))
	next, _, ev := j7IssueFixture(t, f, fresh)
	j7Call(t, c, 6, "j7_enroll", j7GrantParams(t, f, next, ev), "")
}

// A fully valid externally signed grant cannot enroll a different valid consent
// event from the same synthetic request key. Only the exact endpoint-released
// event is enrollment evidence; a nearby original event/grant pair succeeds.
func TestJ7EnrollmentExactConsent(t *testing.T) {
	f := j7SigningSetup(t)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	original := j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
	altered := original
	altered.CreatedAt++
	altered.ID = j7EventID(altered)
	id, _ := hex.DecodeString(altered.ID)
	var digest [32]byte
	copy(digest[:], id)
	sig, e := f.a.key.request(f.f.store, f.f.binding, &digest)
	if e != nil {
		t.Fatal("synthetic alternate consent", e)
	}
	altered.Sig = hex.EncodeToString(sig)
	clear(sig)
	bad, _, ev := j7IssueFixture(t, f, altered)
	j7Call(t, c, 4, "j7_enroll", j7GrantParams(t, f, bad, ev), "GRANT_NOT_FOR_RUN")
	f.f.store.mu.Lock()
	count := len(f.f.store.j7Signing.Enrollments)
	f.f.store.mu.Unlock()
	if count != 0 {
		t.Fatal("different consent event enrolled")
	}
	good, _, ev := j7IssueFixture(t, f, original)
	j7Call(t, c, 5, "j7_enroll", j7GrantParams(t, f, good, ev), "")
}
