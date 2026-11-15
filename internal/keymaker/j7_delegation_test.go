//go:build linux

package keymaker

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-keymaker/internal/control"
)

func j7DelegationServe(t *testing.T, f *j7SignFixture, fence control.ReleaseFence) {
	t.Helper()
	if fence == nil {
		fence = f.a
	}
	wire, e := control.New(f.a, f.a, f.a, fence, f.a)
	if e != nil {
		t.Fatal(e)
	}
	address := fmt.Sprintf("@j7-delegation-%d-%d", os.Getpid(), j7SocketCounter.Add(1))
	listener, e := net.Listen("unix", address)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- wire.Serve(ctx, listener); close(done) }()
	f.socket, f.stop, f.done = address, cancel, done
	t.Cleanup(func() {
		cancel()
		listener.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("delegation server did not stop")
		}
	})
}
func j7DelegationSetup(t *testing.T) *j7SignFixture { return j7DelegationSetupFence(t, nil) }
func j7DelegationSetupFence(t *testing.T, makeFence func(*j7RequestCustody) control.ReleaseFence) *j7SignFixture {
	t.Helper()
	f := j7SigningSetup(t)
	f.stop()
	<-f.done
	if c := f.f.store.migrateJ7Delegation(t.Context(), j7Head(t, f.f.store)); c != "" {
		t.Fatal("stopped schema6 migration", c)
	}
	f.raw = []byte(strings.Replace(j7P2RootBytes(), `"grantee_key":"`+j7P2TestKey+`"`, `"grantee_key":"`+f.public+`"`, 1))
	// Only the common grant projection is needed by the pre-existing W issuer.
	f.contract.Profile = "swarma-trust-contract/2"
	f.contract.Actions = []string{"instruct", "review"}
	table := f.f.table(2)
	table.Rows[0].Use = []string{}
	triple := j7ConsentTriple(f.raw)
	triple.AndUse = true
	table.Rows[0].Consent = []j7ConsentPermission{triple}
	f.f.publish(t, table)
	var fence control.ReleaseFence
	if makeFence != nil {
		fence = makeFence(f.a)
	}
	j7DelegationServe(t, f, fence)
	return f
}
func j7DelegationIssue(t *testing.T, f *j7SignFixture, c *net.UnixConn) (rental.SignedGrant, *j7NodeFixture, j7Evidence) {
	t.Helper()
	event := j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
	return j7IssueFixture(t, f, event)
}
func j7DelegationParams(t *testing.T, f *j7SignFixture, g rental.SignedGrant, e j7Evidence) control.Object {
	t.Helper()
	child := `{"profile":"swarma-trust-contract/2","network":"regtest","landlord_name":"id/test-owner","agent_name":"id/test-worker","grantee_key":"` + j7P2TestKey + `","actions":["instruct"],"repos":[],"spend_budget":0,"not_before":1800000000,"not_after":1900000000,"scope_text_sha256":"","parent_grant_id":"` + g.ID() + `","ordinal":1,"delegate":{"depth":0,"actions":[],"budget":0,"slots":[],"notaries":[],"checkpoint":""},"note":""}`
	grant, _ := json.Marshal(g)
	p := j7TypedParams(t, "delegation_request_v3", j7DelegationRequestInput{ParentContract: j7Encode64(f.raw), ParentGrant: j7Encode64(grant), ChildContract: j7Encode64([]byte(child))})
	ev, _ := j7Compact(e)
	p["evidence_b64"] = j7Encode64(ev)
	return p
}
func j7DelegationList(t *testing.T, f *j7SignFixture, id string, version uint64, use, delegate bool) {
	t.Helper()
	table := f.f.table(version)
	table.Rows[0].Use = []string{}
	table.Rows[0].Delegate = []string{}
	if use {
		table.Rows[0].Use = []string{id}
	}
	if delegate {
		table.Rows[0].Delegate = []string{id}
	}
	triple := j7ConsentTriple(f.raw)
	triple.AndUse = true
	table.Rows[0].Consent = []j7ConsentPermission{triple}
	f.f.publish(t, table)
}

// A real socket bootstraps root consent, real W issuance and an explicitly listed
// Delegate parent. A future child window is allowed, signed by P's bound key.
// Use/and_use cannot grant delegation; this is not native/P17 qualification.
func TestJ7DelegationRootConsentBootstrap(t *testing.T) {
	f := j7DelegationSetup(t)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	g, _, ev := j7DelegationIssue(t, f, c)
	p := j7DelegationParams(t, f, g, ev)
	j7Call(t, c, 4, "j7_sign", p, "GRANT_NOT_FOR_RUN")
	j7DelegationList(t, f, g.ID(), 3, true, false)
	j7Call(t, c, 5, "j7_sign", p, "GRANT_NOT_FOR_RUN")
	j7DelegationList(t, f, g.ID(), 4, false, true)
	result := j7Call(t, c, 6, "j7_sign", p, "")
	event := j7ResultEvent(t, result)
	if event.Kind != 8186 || event.Pubkey != f.public || event.Pubkey == j7P2TestKey || event.Tags[1][1] != g.ID() || event.Tags[3][1] != "1" || len(event.Tags) != 5 || result["profile"] != "swarma-delegation-request-v1/draft" {
		t.Fatal("request binding", event)
	}
	if got := j7Call(t, c, 6, "j7_sign", p, ""); !reflect.DeepEqual(got, result) {
		t.Fatal("retry changed exact signed bytes")
	}
	newer := j7ResultEvent(t, j7Call(t, c, 7, "j7_sign", p, ""))
	if newer.Tags[4][1] == event.Tags[4][1] {
		t.Fatal("new request reused nonce")
	}
	if f.f.store.validateJ7() != nil {
		t.Fatal("retained schema6 state invalid")
	}
}

func j7DelegationReady(t *testing.T) (*j7SignFixture, *net.UnixConn, rental.SignedGrant, *j7NodeFixture, control.Object) {
	t.Helper()
	f := j7DelegationSetup(t)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	g, n, ev := j7DelegationIssue(t, f, c)
	j7DelegationList(t, f, g.ID(), 3, false, true)
	return f, c, g, n, j7DelegationParams(t, f, g, ev)
}
func j7DelegationInput(t *testing.T, p control.Object) j7DelegationRequestInput {
	t.Helper()
	raw, code := j7Decode64(p["object_b64"].(string), j7ObjectLimit)
	var v j7DelegationRequestInput
	if code != "" || json.Unmarshal(raw, &v) != nil {
		t.Fatal("test input")
	}
	return v
}
func j7DelegationWithInput(t *testing.T, p control.Object, v j7DelegationRequestInput) control.Object {
	t.Helper()
	out := j7TypedParams(t, "delegation_request_v3", v)
	out["evidence_b64"] = p["evidence_b64"]
	return out
}
func j7DelegationCount(f *j7SignFixture) int {
	f.f.store.mu.Lock()
	defer f.f.store.mu.Unlock()
	return len(f.f.store.j7Signing.Records)
}

// Exact endpoint refusal codes distinguish child bounds and selectors. No
// invalid request adds a retained signing result beside a full W-node positive.
func TestJ7DelegationTypedBoundary(t *testing.T) {
	f, c, _, _, p := j7DelegationReady(t)
	base := j7DelegationInput(t, p)
	before := j7DelegationCount(f)
	for i, name := range []string{"origin", "run_id", "key", "path", "purpose", "kind", "digest", "event", "tags", "created_at", "nonce", "live", "minimum_reader_schema"} {
		bad := control.Object{}
		for k, v := range p {
			bad[k] = v
		}
		bad[name] = "caller"
		j7Call(t, c, 10+i, "j7_sign", bad, "request_malformed")
	}
	cases := []struct {
		name, from, to string
		code           Code
	}{
		{"parent", `"parent_grant_id":"`, `"parent_grant_id":"f`, "CONTRACT_PARENT"},
		{"wrongparent", base64ChildID(base), strings.Repeat("a", 64), "PARENT_ID_MISMATCH"},
		{"subject", `"regtest"`, `"main"`, "SUBJECT_MISMATCH"},
		{"ordinal", `"ordinal":1`, `"ordinal":2`, "CHILD_ORDINAL"},
		{"rootordinal", `"ordinal":1`, `"ordinal":0`, "CONTRACT_PARENT"},
		{"executor", `"id/test-worker"`, `"id/test-other-worker"`, "CHILD_AGENT_NOT_ALLOWED"},
		{"grantee", j7P2TestKey, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "CHILD_GRANTEE_NOT_ALLOWED"},
		{"actions", `["instruct"]`, `["review"]`, "CHILD_ACTIONS_WIDER"},
		{"window", `"not_after":1900000000`, `"not_after":2100000000`, "CHILD_WINDOW_NOT_NESTED"},
		{"depth", `"depth":0`, `"depth":1`, "CONTRACT_PARENT"},
	}
	raw, _ := j7Decode64(base.ChildContract, 8192)
	for i, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			bad := base
			changed := strings.Replace(string(raw), v.from, v.to, 1)
			if changed == string(raw) {
				t.Fatal("unapplied negative")
			}
			bad.ChildContract = j7Encode64([]byte(changed))
			j7Call(t, c, 40+i, "j7_sign", j7DelegationWithInput(t, p, bad), v.code)
		})
	}
	for i, mutate := range []func(*j7DelegationRequestInput){
		func(v *j7DelegationRequestInput) { v.ParentContract += "=" },
		func(v *j7DelegationRequestInput) { v.ParentGrant = j7Encode64([]byte(`{}`)) },
		func(v *j7DelegationRequestInput) { v.ChildContract = j7Encode64([]byte(strings.Repeat("a", 8193))) },
		func(v *j7DelegationRequestInput) {
			v.ParentContract = j7Encode64([]byte(strings.Replace(string(f.raw), `"note":""`, `"note":"changed"`, 1)))
		},
	} {
		bad := base
		mutate(&bad)
		want := Code("request_malformed")
		if i == 3 {
			want = "CONTRACT_HASH"
		}
		j7Call(t, c, 60+i, "j7_sign", j7DelegationWithInput(t, p, bad), want)
	}
	// Unknown nested selectors and over-limit aggregate are rejected before authority.
	rawObject, _ := j7Decode64(p["object_b64"].(string), j7ObjectLimit)
	for i, b := range [][]byte{append(rawObject[:len(rawObject)-1], []byte(`,"nonce":"caller"}`)...), []byte(`{"parent_contract_b64":"` + strings.Repeat("a", 32768) + `","parent_grant_b64":"x","child_contract_b64":"x"}`)} {
		bad := control.Object{}
		for k, v := range p {
			bad[k] = v
		}
		bad["object_b64"] = j7Encode64(b)
		j7Call(t, c, 70+i, "j7_sign", bad, "request_malformed")
	}
	if j7DelegationCount(f) != before {
		t.Fatal("refusal retained a signing result")
	}
	j7ResultEvent(t, j7Call(t, c, 80, "j7_sign", p, ""))
	// Same valid /2 grant does not open enrollment or envelope signing.
	var ev j7Evidence
	b, _ := j7Decode64(p["evidence_b64"].(string), 1024)
	json.Unmarshal(b, &ev)
	var g rental.SignedGrant
	b, _ = j7Decode64(base.ParentGrant, 16384)
	json.Unmarshal(b, &g)
	j7Call(t, c, 81, "j7_enroll", j7GrantParams(t, f, g, ev), "operation_unsupported")
	j7Call(t, c, 82, "j7_sign", j7EnvelopeParams(t, f, g, ev), "operation_unsupported")
}
func base64ChildID(v j7DelegationRequestInput) string {
	b, _ := j7Decode64(v.ChildContract, 8192)
	var c struct {
		Parent string `json:"parent_grant_id"`
	}
	json.Unmarshal(b, &c)
	return c.Parent
}

// Removing Use records its denial but does not withdraw separately listed
// Delegate. Removing Delegate wins even when Use is present, including retries.
func TestJ7DelegationDelegateIndependentOfUse(t *testing.T) {
	f, c, g, _, p := j7DelegationReady(t)
	j7DelegationList(t, f, g.ID(), 4, true, true)
	result := j7Call(t, c, 4, "j7_sign", p, "")
	j7DelegationList(t, f, g.ID(), 5, false, true)
	if got := j7Call(t, c, 4, "j7_sign", p, ""); !reflect.DeepEqual(got, result) {
		t.Fatal("use withdrawal altered delegate result")
	}
	f.f.store.mu.Lock()
	denied := false
	for _, d := range f.f.store.j7.Denials {
		denied = denied || d.Grant == g.ID()
	}
	f.f.store.mu.Unlock()
	if !denied {
		t.Fatal("lost independent use denial")
	}
	j7DelegationList(t, f, g.ID(), 6, true, false)
	j7Call(t, c, 4, "j7_sign", p, "GRANT_NOT_FOR_RUN")
	j7Call(t, c, 5, "j7_sign", p, "GRANT_NOT_FOR_RUN")
	j7DelegationList(t, f, g.ID(), 7, false, true)
	j7ResultEvent(t, j7Call(t, c, 5, "j7_sign", p, ""))
}

// Same key and kernel peer do not confer the first channel's origin. A real
// other-origin and an unbound connection both refuse beside the authorized run.
func TestJ7DelegationOriginPermission(t *testing.T) {
	f, c, _, _, p := j7DelegationReady(t)
	unknown := f.dial(t, 10)
	j7Call(t, unknown, 11, "j7_sign", p, "run_identity_unavailable")
	other := f.f.origin
	other.Event = strings.Repeat("d", 64)
	b := f.dial(t, 12)
	f.bind(t, b, 13, other, f.f.uid+201)
	before := j7DelegationCount(f)
	j7Call(t, b, 14, "j7_sign", p, "GRANT_NOT_FOR_RUN")
	if j7DelegationCount(f) != before {
		t.Fatal("other origin retained result")
	}
	j7ResultEvent(t, j7Call(t, c, 15, "j7_sign", p, ""))
	j7Call(t, b, 15, "j7_sign", p, "request_conflict")
}

// A missing node or a newly spent seal blocks first AND retained disclosure.
// Restoration of a transient node failure permits exactly the earlier result;
// observed spent closure remains refused. No fabricated LIVE callback is used.
func TestJ7DelegationFullVerifierFirstAndRetry(t *testing.T) {
	for _, mode := range []string{"unavailable", "spent"} {
		t.Run(mode, func(t *testing.T) {
			f, c, _, n, p := j7DelegationReady(t)
			old := j7Call(t, c, 4, "j7_sign", p, "")
			before := j7DelegationCount(f)
			n.mu.Lock()
			if mode == "spent" {
				n.spent = true
			} else {
				n.unavailable = true
			}
			n.mu.Unlock()
			j7Call(t, c, 4, "j7_sign", p, "delegation_evidence_unavailable")
			j7Call(t, c, 5, "j7_sign", p, "delegation_evidence_unavailable")
			if j7DelegationCount(f) != before {
				t.Fatal("unproved request retained result")
			}
			n.mu.Lock()
			n.spent = false
			n.unavailable = false
			n.mu.Unlock()
			if mode == "unavailable" {
				if got := j7Call(t, c, 4, "j7_sign", p, ""); !reflect.DeepEqual(old, got) {
					t.Fatal("recovery re-signed")
				}
			} else {
				j7Call(t, c, 4, "j7_sign", p, "delegation_evidence_unavailable")
			}
		})
	}
}

// Purpose8 is neither a request adapter nor a v3 signer. The valid purpose7
// endpoint is paired with an explicit wrong-role attempt with no retained result.
func TestJ7DelegationPurpose8OnV3Refused(t *testing.T) {
	f, c, _, _, p := j7DelegationReady(t)
	wrong := j7Fixture(t, j7DelegationRole)
	if _, e := newJ7RequestCustody(f.a.j7Lifecycle, wrong, f.a.clock, f.a.evidence); e == nil {
		t.Fatal("purpose8 request adapter accepted")
	}
	before := j7DelegationCount(f)
	f.a.key.mu.Lock()
	f.a.key.role = j7DelegationRole
	f.a.key.mu.Unlock()
	j7Call(t, c, 4, "j7_sign", p, "custody_unavailable")
	if j7DelegationCount(f) != before {
		t.Fatal("purpose8 retained request")
	}
	f.a.key.mu.Lock()
	f.a.key.role = j7RequestRole
	f.a.key.mu.Unlock()
	j7ResultEvent(t, j7Call(t, c, 5, "j7_sign", p, ""))
	for i, op := range []string{"sign_child_grant", "invocation_v4", "consent_v4", "kind8186", "raw_digest", "batch"} {
		j7Call(t, c, 10+i, "j7_sign", j7TypedParams(t, op, control.Object{}), "operation_unsupported")
	}
}

type j7DelegationFence struct {
	a      *j7RequestCustody
	mu     sync.Mutex
	before func()
	inside func(context.Context) control.Code
}

func (p *j7DelegationFence) set(before func(), inside func(context.Context) control.Code) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.before, p.inside = before, inside
}
func (p *j7DelegationFence) WithActive(ctx context.Context, peer control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	if r.Params["operation"] != "delegation_request_v3" {
		return p.a.WithActive(ctx, peer, r, result, release)
	}
	p.mu.Lock()
	before, inside := p.before, p.inside
	p.mu.Unlock()
	if before != nil {
		before()
	}
	return p.a.WithActive(ctx, peer, r, result, func(ctx context.Context) control.Code {
		if inside != nil {
			if c := inside(ctx); c != "" {
				return c
			}
		}
		return release(ctx)
	})
}

// A second full node check is required after Handle, on first release and retry.
// The explicit node failure is planted only at that boundary, not before parsing.
func TestJ7DelegationFreshProofBeforeCallback(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(fmt.Sprint(retry), func(t *testing.T) {
			probe := &j7DelegationFence{}
			f := j7DelegationSetupFence(t, func(a *j7RequestCustody) control.ReleaseFence { probe.a = a; return probe })
			c := f.dial(t, 1)
			f.bind(t, c, 2, f.f.origin, f.f.uid+200)
			g, n, ev := j7DelegationIssue(t, f, c)
			j7DelegationList(t, f, g.ID(), 3, false, true)
			p := j7DelegationParams(t, f, g, ev)
			if retry {
				j7Call(t, c, 4, "j7_sign", p, "")
			}
			var applied atomic.Bool
			probe.set(func() { n.mu.Lock(); n.unavailable = true; n.mu.Unlock(); applied.Store(true) }, nil)
			j7Call(t, c, 4, "j7_sign", p, "delegation_evidence_unavailable")
			if !applied.Load() {
				t.Fatal("boundary plant not applied")
			}
			f.f.store.mu.Lock()
			rec := f.f.store.j7SigningRecord(f.a.launcher, nativeID(4))
			state := rec.Release
			f.f.store.mu.Unlock()
			want := "prepared"
			if retry {
				want = "released"
			}
			if state != want {
				t.Fatal("unproved result entered callback", state)
			}
			probe.set(nil, nil)
			n.mu.Lock()
			n.unavailable = false
			n.mu.Unlock()
			c = j7DelegationReconnect(t, f, c, 30, rec.Run)
			j7ResultEvent(t, j7Call(t, c, 4, "j7_sign", p, ""))
		})
	}
}

// Withdrawal after Handle but before the final node observation wins on both
// initial and retained release. While the actual callback holds the policy gate,
// a concurrent operator removal must wait; its later retry is refused.
func TestJ7DelegationWithdrawalAtRelease(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(fmt.Sprint(retry), func(t *testing.T) {
			probe := &j7DelegationFence{}
			f := j7DelegationSetupFence(t, func(a *j7RequestCustody) control.ReleaseFence { probe.a = a; return probe })
			c := f.dial(t, 1)
			f.bind(t, c, 2, f.f.origin, f.f.uid+200)
			g, _, ev := j7DelegationIssue(t, f, c)
			j7DelegationList(t, f, g.ID(), 3, false, true)
			p := j7DelegationParams(t, f, g, ev)
			if retry {
				j7Call(t, c, 4, "j7_sign", p, "")
			}
			probe.set(func() { j7DelegationList(t, f, g.ID(), 4, true, false) }, nil)
			j7Call(t, c, 4, "j7_sign", p, "GRANT_NOT_FOR_RUN")
			f.f.store.mu.Lock()
			rec := f.f.store.j7SigningRecord(f.a.launcher, nativeID(4))
			state := rec.Release
			healthy := !f.f.store.failed
			f.f.store.mu.Unlock()
			want := "prepared"
			if retry {
				want = "released"
			}
			if state != want || !healthy {
				t.Fatal("withdrawal changed release/fence", state, healthy)
			}
		})
	}
	t.Run("actual-callback-wins", func(t *testing.T) {
		probe := &j7DelegationFence{}
		f := j7DelegationSetupFence(t, func(a *j7RequestCustody) control.ReleaseFence { probe.a = a; return probe })
		c := f.dial(t, 1)
		f.bind(t, c, 2, f.f.origin, f.f.uid+200)
		g, _, ev := j7DelegationIssue(t, f, c)
		j7DelegationList(t, f, g.ID(), 3, false, true)
		p := j7DelegationParams(t, f, g, ev)
		entered, allow := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(allow) }) }
		defer unblock()
		probe.set(nil, func(ctx context.Context) control.Code {
			close(entered)
			select {
			case <-allow:
				return ""
			case <-ctx.Done():
				return control.DeadlineExceeded
			}
		})
		nativeSend(t, c, nativeRequest(4, "j7_sign", p))
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("callback not reached")
		}
		table := f.f.table(4)
		table.Rows[0].Use = []string{}
		table.Rows[0].Delegate = []string{}
		attempted, removed := make(chan struct{}), make(chan Code, 1)
		go func() { close(attempted); removed <- f.f.policy.publish(t.Context(), j7PolicyRaw(t, table)) }()
		<-attempted
		select {
		case c := <-removed:
			t.Fatal("withdrawal overtook callback", c)
		case <-time.After(25 * time.Millisecond):
		}
		unblock()
		j7ResultEvent(t, nativeResponse(t, nativeReceive(t, c), nativeID(4), ""))
		if code := <-removed; code != "" {
			t.Fatal(code)
		}
		probe.set(nil, nil)
		j7Call(t, c, 4, "j7_sign", p, "GRANT_NOT_FOR_RUN")
	})
}

// Two authenticated runs race one global ID. Overlapping imported-verifier
// journal access may refuse evidence; it cannot create a second retained result.
// After the race the owning run retries exact bytes and every other run conflicts.
func TestJ7DelegationConcurrentSameID(t *testing.T) {
	f, a, _, _, p := j7DelegationReady(t)
	f.f.store.mu.Lock()
	runA := f.f.store.j7.Runs[0].ID
	f.f.store.mu.Unlock()
	b := f.dial(t, 10)
	runB := f.bind(t, b, 11, f.f.origin, f.f.uid+201)
	before := j7DelegationCount(f)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, c := range []*net.UnixConn{a, b} {
		wg.Add(1)
		go func(c *net.UnixConn) { defer wg.Done(); <-start; nativeSend(t, c, nativeRequest(20, "j7_sign", p)) }(c)
	}
	close(start)
	wg.Wait()
	responses := []control.Object{nativeReceive(t, a), nativeReceive(t, b)}
	for _, response := range responses {
		if err, ok := response["error"].(control.Object); ok {
			code := Code(err["code"].(string))
			if code != "request_conflict" && code != "delegation_evidence_unavailable" {
				t.Fatal("unexpected race refusal", code)
			}
			nativeResponse(t, response, nativeID(20), code)
		} else {
			j7ResultEvent(t, nativeResponse(t, response, nativeID(20), ""))
		}
	}
	if j7DelegationCount(f) != before+1 {
		t.Fatal("same ID did not retain exactly one result")
	}
	f.f.store.mu.Lock()
	rec := *f.f.store.j7SigningRecord(f.a.launcher, nativeID(20))
	prior, _ := f.f.store.retained(f.a.launcher, control.Request{ID: nativeID(20), Method: "j7_sign", Params: p})
	result, code := f.f.store.resultObject(prior)
	f.f.store.mu.Unlock()
	if code != "" {
		t.Fatal(code)
	}
	owner, other, ownerRun, otherRun := a, b, runA, runB
	if rec.Run != runA {
		owner, other, ownerRun, otherRun = b, a, runB, runA
	}
	if rec.Run != ownerRun {
		t.Fatal("result bound outside race")
	}
	owner = j7DelegationReconnect(t, f, owner, 30, ownerRun)
	other = j7DelegationReconnect(t, f, other, 40, otherRun)
	if got := j7Call(t, owner, 20, "j7_sign", p, ""); !reflect.DeepEqual(got, result) {
		t.Fatal("concurrent retained retry re-signed")
	}
	changed := j7DelegationInput(t, p)
	raw, _ := j7Decode64(changed.ChildContract, 8192)
	changed.ChildContract = j7Encode64([]byte(strings.Replace(string(raw), `"note":""`, `"note":"changed"`, 1)))
	j7Call(t, owner, 20, "j7_sign", j7DelegationWithInput(t, p, changed), "request_conflict")
	j7Call(t, other, 20, "j7_sign", p, "request_conflict")
}

// Withdrawal observed during the second full rental.Check must be re-read under
// the final policy gate; an earlier preliminary Delegate lookup cannot suffice.
func TestJ7DelegationWithdrawalInsideFinalEvidence(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(fmt.Sprint(retry), func(t *testing.T) {
			f, c, g, n, p := j7DelegationReady(t)
			if retry {
				j7Call(t, c, 4, "j7_sign", p, "")
			}
			table := j7SigningPolicy(t, f, 4)
			table.Rows[0].Delegate = []string{}
			table.Rows[0].Use = []string{g.ID()}
			var applied atomic.Bool
			n.mu.Lock()
			at := n.utxos + 3
			n.onUTXO = func(count int) {
				if count == at {
					f.f.publish(t, table)
					applied.Store(true)
				}
			}
			n.mu.Unlock()
			j7Call(t, c, 4, "j7_sign", p, "GRANT_NOT_FOR_RUN")
			if !applied.Load() {
				t.Fatal("final observation plant not applied")
			}
			f.f.store.mu.Lock()
			rec := f.f.store.j7SigningRecord(f.a.launcher, nativeID(4))
			state := rec.Release
			healthy := !f.f.store.failed
			f.f.store.mu.Unlock()
			want := "prepared"
			if retry {
				want = "released"
			}
			if state != want || !healthy {
				t.Fatal("withdrawal entered callback", state, healthy)
			}
		})
	}
}

// Clock movement across the final live-parent observation refuses stale proof;
// restoring trusted time releases the already prepared exact result normally.
func TestJ7DelegationProofFreshness(t *testing.T) {
	for _, delta := range []int64{-1, 3} {
		t.Run(fmt.Sprint(delta), func(t *testing.T) {
			f, c, _, n, p := j7DelegationReady(t)
			old := f.a.clock
			now, _ := old.UTC()
			n.mu.Lock()
			at := n.utxos + 3
			n.onUTXO = func(count int) {
				if count == at {
					f.a.clock = j7SigningClock{now.Add(time.Duration(delta) * time.Second), true}
				}
			}
			n.mu.Unlock()
			j7Call(t, c, 4, "j7_sign", p, "delegation_evidence_unavailable")
			n.mu.Lock()
			n.onUTXO = nil
			n.mu.Unlock()
			f.a.clock = old
			f.f.store.mu.Lock()
			run := f.f.store.j7SigningRecord(f.a.launcher, nativeID(4)).Run
			f.f.store.mu.Unlock()
			c = j7DelegationReconnect(t, f, c, 30, run)
			j7ResultEvent(t, j7Call(t, c, 4, "j7_sign", p, ""))
		})
	}
}

func j7DelegationReconnect(t *testing.T, f *j7SignFixture, old *net.UnixConn, id int, run string) *net.UnixConn {
	t.Helper()
	old.Close()
	until := time.Now().Add(time.Second)
	gone := false
	for time.Now().Before(until) {
		f.f.store.mu.Lock()
		gone = f.a.channels[run] == nil
		f.f.store.mu.Unlock()
		if gone {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !gone {
		t.Fatal("old authority lifetime still active")
	}
	c := f.dial(t, id)
	j7Call(t, c, id+1, "j7_run_rebind", control.Object{"run_id": run}, "")
	return c
}

// One genuinely issued synthetic parent is presented to two holders of the same
// test identity: schema5 remains unavailable; explicitly migrated6 signs. No
// caller field selects a floor and no synthetic LIVE verdict is injected.
func TestJ7DelegationSchemaFloorPairedEndpoint(t *testing.T) {
	six, c, g, _, p := j7DelegationReady(t)
	five := j7SigningSetup(t)
	if five.public != six.public {
		t.Fatal("fixture identities differ")
	}
	five.a.evidence = six.a.evidence
	j7DelegationList(t, five, g.ID(), 2, false, true)
	old := five.dial(t, 10)
	five.bind(t, old, 11, five.f.origin, five.f.uid+200)
	before := j7DelegationCount(five)
	j7Call(t, old, 12, "j7_sign", p, "operation_unsupported")
	if j7DelegationCount(five) != before {
		t.Fatal("schema5 retained new operation")
	}
	j7ResultEvent(t, j7Call(t, c, 4, "j7_sign", p, ""))
}

// The parent's recipient selects custody, never the proposed child's recipient.
// A fully signed unrelated parent still cannot borrow this holder's request key.
func TestJ7DelegationBoundParentKey(t *testing.T) {
	f, c, g, _, p := j7DelegationReady(t)
	corpus := j7DelegationReadCorpus(t)
	foreign, e := rental.ParseSignedGrant(j7RefDecode(t, corpus.ParentGrant))
	if e != nil {
		t.Fatal(e)
	}
	j7DelegationList(t, f, foreign.ID(), 4, false, true)
	v := j7DelegationRequestInput{ParentContract: corpus.ParentContract, ParentGrant: corpus.ParentGrant, ChildContract: corpus.ChildContract}
	bad := j7TypedParams(t, "delegation_request_v3", v)
	ev, _ := json.Marshal(j7Evidence{Format: "keymaker-j7-evidence/1", Issuance: corpus.IssuanceID})
	bad["evidence_b64"] = j7Encode64(ev)
	before := j7DelegationCount(f)
	j7Call(t, c, 4, "j7_sign", bad, "peer_binding_mismatch")
	if j7DelegationCount(f) != before {
		t.Fatal("foreign parent retained signature")
	}
	j7DelegationList(t, f, g.ID(), 5, false, true)
	j7ResultEvent(t, j7Call(t, c, 5, "j7_sign", p, ""))
}

// Ordinal chooses one signed row, not any matching executor/key elsewhere.
// Full endpoint controls include a valid row2 and its terms under wrong ordinal1.
func TestJ7DelegationChildFit(t *testing.T) {
	f := j7DelegationSetup(t)
	second := "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	f.raw = []byte(strings.Replace(string(f.raw), `],"notaries":[`, `,{"executor":"id/test-second-worker","grantee":"`+second+`","cap":0,"notary":"id/test-notary"}],"notaries":[`, 1))
	table := j7SigningPolicy(t, f, 3)
	table.Rows[0].Consent = []j7ConsentPermission{j7ConsentTriple(f.raw)}
	f.f.publish(t, table)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	g, _, ev := j7DelegationIssue(t, f, c)
	j7DelegationList(t, f, g.ID(), 4, false, true)
	p := j7DelegationParams(t, f, g, ev)
	v := j7DelegationInput(t, p)
	raw, _ := j7Decode64(v.ChildContract, 8192)
	child := strings.Replace(strings.Replace(string(raw), "id/test-worker", "id/test-second-worker", 1), j7P2TestKey, second, 1)
	v.ChildContract = j7Encode64([]byte(child))
	before := j7DelegationCount(f)
	j7Call(t, c, 4, "j7_sign", j7DelegationWithInput(t, p, v), "CHILD_AGENT_NOT_ALLOWED")
	if j7DelegationCount(f) != before {
		t.Fatal("cross-row terms retained result")
	}
	v.ChildContract = j7Encode64([]byte(strings.Replace(child, `"ordinal":1`, `"ordinal":2`, 1)))
	j7ResultEvent(t, j7Call(t, c, 5, "j7_sign", j7DelegationWithInput(t, p, v), ""))
	j7ResultEvent(t, j7Call(t, c, 6, "j7_sign", p, ""))
}

// Land requests fit exact repository bytes of a delegable land parent. A valid
// alternate repository spelling outside that set refuses without signing.
func TestJ7DelegationRepositoryFit(t *testing.T) {
	f := j7DelegationSetup(t)
	const repo = "https://git.example/team/project"
	root := strings.Replace(string(f.raw), `["instruct","review"]`, `["instruct","land","review"]`, 1)
	root = strings.Replace(root, `"repos":[]`, `"repos":["`+repo+`"]`, 1)
	root = strings.Replace(root, `"depth":1,"actions":["instruct"]`, `"depth":1,"actions":["instruct","land"]`, 1)
	f.raw = []byte(root)
	f.contract.Actions = []string{"instruct", "land", "review"}
	f.contract.Repos = []string{repo}
	table := j7SigningPolicy(t, f, 3)
	table.Rows[0].Consent = []j7ConsentPermission{j7ConsentTriple(f.raw)}
	f.f.publish(t, table)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	g, _, ev := j7DelegationIssue(t, f, c)
	j7DelegationList(t, f, g.ID(), 4, false, true)
	p := j7DelegationParams(t, f, g, ev)
	v := j7DelegationInput(t, p)
	raw, _ := j7Decode64(v.ChildContract, 8192)
	child := strings.Replace(strings.Replace(string(raw), `"actions":["instruct"]`, `"actions":["land"]`, 1), `"repos":[]`, `"repos":["`+repo+`"]`, 1)
	v.ChildContract = j7Encode64([]byte(strings.Replace(child, repo, repo+".git", 1)))
	before := j7DelegationCount(f)
	j7Call(t, c, 4, "j7_sign", j7DelegationWithInput(t, p, v), "CHILD_REPOS_WIDER")
	if j7DelegationCount(f) != before {
		t.Fatal("wider repo retained result")
	}
	v.ChildContract = j7Encode64([]byte(child))
	j7ResultEvent(t, j7Call(t, c, 5, "j7_sign", j7DelegationWithInput(t, p, v), ""))
}

type j7DelegationCountingReader struct {
	source io.Reader
	calls  atomic.Int64
}

func (r *j7DelegationCountingReader) Read(b []byte) (int, error) {
	r.calls.Add(1)
	return r.source.Read(b)
}

// A retained retry must not invoke secret signing again, even if another barrier
// would hide a newly generated result. Count only the synthetic key's nonce draws.
func TestJ7DelegationRetainedSigningInvocation(t *testing.T) {
	f, c, _, _, p := j7DelegationReady(t)
	counter := &j7DelegationCountingReader{source: rand.Reader}
	f.a.key.mu.Lock()
	f.a.key.entropy = counter
	f.a.key.mu.Unlock()
	first := j7Call(t, c, 4, "j7_sign", p, "")
	f.a.key.mu.Lock()
	calls := counter.calls.Load()
	f.a.key.mu.Unlock()
	if calls == 0 {
		t.Fatal("signing control not exercised")
	}
	nativeSend(t, c, nativeRequest(4, "j7_sign", p))
	response := nativeReceive(t, c)
	f.a.key.mu.Lock()
	after := counter.calls.Load()
	f.a.key.mu.Unlock()
	if after != calls {
		t.Fatal("retained request invoked signing again")
	}
	if got := nativeResponse(t, response, nativeID(4), ""); !reflect.DeepEqual(got, first) {
		t.Fatal("retained signing result changed")
	}
}

// Malformed nested /2 bytes reach the new canonical rules, not /1 fallback.
// A valid complete root still signs, while an unlisted valid root does not.
func TestJ7DelegationRootConsentCanonical(t *testing.T) {
	f := j7DelegationSetup(t)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	before := j7DelegationCount(f)
	for i, v := range []struct {
		from, to string
		want     Code
	}{
		{`"cap":0`, `"cap":01`, "CONTRACT_ENCODING"},
		{`"cap":0,`, `"cap":0,"cap":0,`, "CONTRACT_DELEGATE"},
		{`"profile":"swarma-trust-contract/2",`, `"profile":"swarma-trust-contract/2","profile":"swarma-trust-contract/2",`, "CONTRACT_ENCODING"},
		{`"ordinal":0`, `"ordinal":1`, "CONTRACT_PARENT"},
		{`"note":""`, `"note":"unlisted terms"`, "CONSENT_NOT_FOR_RUN"},
	} {
		raw := strings.Replace(string(f.raw), v.from, v.to, 1)
		if raw == string(f.raw) {
			t.Fatal("root negative not applied")
		}
		j7Call(t, c, 10+i, "j7_sign", j7TypedParams(t, "consent_v3", j7ConsentInput{Contract: j7Encode64([]byte(raw))}), v.want)
	}
	if j7DelegationCount(f) != before {
		t.Fatal("invalid/unlisted root retained consent")
	}
	// Canonical depth0 roots and canonical children are outside the narrowly
	// approved delegable-root consent prerequisite, even before policy matching.
	root, code := parseJ7ProfileContract(f.raw)
	if code != "" {
		t.Fatal(code)
	}
	root.Delegate = j7Delegate{Actions: []string{}, Slots: []j7DelegateSlot{}, Notaries: []j7DelegateNotary{}}
	for i := 0; i < 2; i++ {
		if i == 1 {
			root.Parent = strings.Repeat("a", 64)
			root.Ordinal = 1
		}
		raw, _ := j7Compact(root)
		if _, code := parseJ7ProfileContract(raw); code != "" {
			t.Fatal("invalid prerequisite control", code)
		}
		j7Call(t, c, 30+i, "j7_sign", j7TypedParams(t, "consent_v3", j7ConsentInput{Contract: j7Encode64(raw)}), "operation_unsupported")
	}
	if j7DelegationCount(f) != before {
		t.Fatal("unsupported consent retained a result")
	}
	j7ResultEvent(t, j7Call(t, c, 20, "j7_sign", f.consent(t), ""))
}

// Each unavailable authority refuses the actual new socket operation without a
// retained result. Restoring the synthetic authority permits the same ID; this
// does not qualify the generation provider or real custody on the host.
func TestJ7DelegationAuthorityFailures(t *testing.T) {
	for _, mode := range []string{"clock", "entropy", "issuer", "epoch", "generation"} {
		t.Run(mode, func(t *testing.T) {
			f, c, _, _, p := j7DelegationReady(t)
			before := j7DelegationCount(f)
			var restore func()
			var want Code
			f.f.store.mu.Lock()
			run := f.f.store.j7.Runs[0].ID
			switch mode {
			case "clock":
				old := f.a.clock
				f.a.clock = j7SigningClock{time.Unix(1700000000, 0), false}
				restore = func() { f.a.clock = old }
				want = "clock_untrusted"
			case "entropy":
				old := f.a.entropy
				f.a.entropy = strings.NewReader("")
				restore = func() { f.a.entropy = old }
				want = "entropy_unavailable"
			case "issuer":
				old := f.a.evidence.policies[f.contract.Agent]
				bad := old
				bad.IssuerPubkey = strings.Repeat("f", 64)
				f.a.evidence.policies[f.contract.Agent] = bad
				restore = func() { f.a.evidence.policies[f.contract.Agent] = old }
				want = "delegation_evidence_unavailable"
			case "epoch":
				f.a.key.mu.Lock()
				old := f.a.key.epoch
				f.a.key.epoch = "wrong"
				f.a.key.mu.Unlock()
				restore = func() { f.a.key.mu.Lock(); f.a.key.epoch = old; f.a.key.mu.Unlock() }
				want = "custody_unavailable"
			case "generation":
				f.gen.mu.Lock()
				old := f.gen.entries[f.f.binding.UID]
				bad := old
				bad.State = "retired"
				f.gen.entries[f.f.binding.UID] = bad
				f.gen.mu.Unlock()
				restore = func() { f.gen.mu.Lock(); f.gen.entries[f.f.binding.UID] = old; f.gen.mu.Unlock() }
				want = "generation_inactive"
			}
			f.f.store.mu.Unlock()
			j7Call(t, c, 20, "j7_sign", p, want)
			if j7DelegationCount(f) != before {
				t.Fatal("missing authority retained a signed result")
			}
			f.f.store.mu.Lock()
			restore()
			f.f.store.mu.Unlock()
			if mode == "generation" {
				c = j7DelegationReconnect(t, f, c, 30, run)
			}
			j7ResultEvent(t, j7Call(t, c, 20, "j7_sign", p, ""))
		})
	}
}

// The complete valid three-object collection remains accepted at32767/32768
// aggregate bytes (padding only its JSON wrapper, not signed P/C/grant bytes).
// The adjacent aggregate and frame ceilings reject without another result.
// This does not claim all individual maxima fit together under the aggregate.
func TestJ7DelegationAggregateAndFrameCaps(t *testing.T) {
	f, c, _, _, p := j7DelegationReady(t)
	raw, code := j7Decode64(p["object_b64"].(string), j7ObjectLimit)
	if code != "" {
		t.Fatal(code)
	}
	before := j7DelegationCount(f)
	for i, size := range []int{32767, 32768, 32769} {
		if len(raw) > size {
			t.Fatal("positive collection exceeds intended boundary")
		}
		padded := append(append([]byte{}, raw...), []byte(strings.Repeat(" ", size-len(raw)))...)
		bounded := control.Object{"operation": p["operation"], "object_b64": j7Encode64(padded), "evidence_b64": p["evidence_b64"]}
		want := Code("")
		if size > 32768 {
			want = "request_malformed"
		}
		result := j7Call(t, c, 20+i, "j7_sign", bounded, want)
		if want == "" {
			j7ResultEvent(t, result)
			j7DelegationWaitReleased(t, f, 20+i)
		}
	}
	if j7DelegationCount(f) != before+2 {
		t.Fatal("over-cap aggregate retained result")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 65537)
	if n, e := c.Write(header[:]); e != nil || n != 4 {
		t.Fatal("frame plant setup", n, e)
	}
	nativeResponse(t, nativeReceive(t, c), nil, "frame_too_large")
	if j7DelegationCount(f) != before+2 {
		t.Fatal("over-cap frame retained result")
	}
}

// The one exceptional read targets construction after the guarded clock read.
// All other reads are inside the parent window, including release after a step
// backwards. The atomic counter is a clock fixture, not a time provider proof.
type j7ConstructionClock struct {
	base, exception int64
	at              int32
	reads           atomic.Int32
}

func (c *j7ConstructionClock) UTC() (time.Time, bool) {
	value := c.base
	if c.reads.Add(1) == c.at {
		value = c.exception
	}
	return time.Unix(value, 0), true
}
func j7WindowFixture(t *testing.T, operation string, fence control.ReleaseFence) (*j7SignFixture, *net.UnixConn, control.Object) {
	t.Helper()
	var f *j7SignFixture
	if operation == "delegation_request_v3" {
		f = j7DelegationSetup(t)
	} else {
		f = j7SigningSetup(t)
	}
	// Make the lower boundary a representable trusted time, rather than Unix0.
	f.contract.NotBefore = 1700000000
	if operation == "delegation_request_v3" {
		f.raw = []byte(strings.Replace(string(f.raw), `"not_before":1,`, `"not_before":1700000000,`, 1))
	} else {
		f.raw, _ = j7Compact(f.contract)
	}
	table := j7SigningPolicy(t, f, 3)
	triple := j7ConsentTriple(f.raw)
	triple.AndUse = true
	table.Rows[0].Consent = []j7ConsentPermission{triple}
	f.f.publish(t, table)
	if fence != nil {
		if probe, ok := fence.(*j7RetainedWindowFence); ok {
			probe.a = f.a
		}
		f.stop()
		<-f.done
		j7DelegationServe(t, f, fence)
	}
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	if operation == "consent_v3" {
		return f, c, f.consent(t)
	}
	g, _, ev := j7DelegationIssue(t, f, c)
	if operation == "delegation_request_v3" {
		j7DelegationList(t, f, g.ID(), 4, false, true)
		return f, c, j7DelegationParams(t, f, g, ev)
	}
	j7Call(t, c, 4, "j7_enroll", j7GrantParams(t, f, g, ev), "")
	return f, c, j7EnvelopeParams(t, f, g, ev)
}

// Exact construction timestamps, not merely an earlier clock observation, must
// obey the upper bound for all signers and the lower bound for grant operations.
// Consent-before-start is intentionally valid; each rejection has an independent
// in-window control and retains/signs nothing. These are real Unix/W fixtures.
func TestJ7DelegationCreationTimeBoundary(t *testing.T) {
	for _, operation := range []string{"consent_v3", "envelope_v3", "delegation_request_v3"} {
		for _, position := range []string{"end", "just-inside", "below-start", "at-start"} {
			t.Run(operation+"/"+position, func(t *testing.T) {
				f, c, p := j7WindowFixture(t, operation, nil)
				base, _ := f.a.clock.UTC()
				value := f.contract.NotAfter
				switch position {
				case "just-inside":
					value--
				case "below-start":
					value = f.contract.NotBefore - 1
				case "at-start":
					value = f.contract.NotBefore
				}
				at := int32(4)
				if operation == "consent_v3" {
					at = 3
				}
				clock := &j7ConstructionClock{base: base.Unix(), exception: value, at: at}
				f.a.clock = clock
				before := j7DelegationCount(f)
				counter := &j7DelegationCountingReader{source: rand.Reader}
				f.a.key.mu.Lock()
				f.a.key.entropy = counter
				f.a.key.mu.Unlock()
				nativeSend(t, c, nativeRequest(20, "j7_sign", p))
				response := nativeReceive(t, c)
				valid := position != "end" && (position != "below-start" || operation == "consent_v3")
				if !valid {
					if j7DelegationCount(f) != before || counter.calls.Load() != 0 {
						t.Fatal("out-of-window creation retained or signed a result")
					}
					nativeResponse(t, response, nativeID(20), "delegation_evidence_unavailable")
					f.f.store.mu.Lock()
					e := f.f.store.validateJ7()
					f.f.store.mu.Unlock()
					if e != nil {
						t.Fatal("creation refusal corrupted retained state", e)
					}
					// The same ID works after a trusted backward step and launcher rebind;
					// no invalid prepared event exists for a retry to disclose.
					f.a.clock = j7SigningClock{base, true}
					f.f.store.mu.Lock()
					run := f.f.store.j7.Runs[0].ID
					f.f.store.mu.Unlock()
					c = j7DelegationReconnect(t, f, c, 30, run)
					j7ResultEvent(t, j7Call(t, c, 20, "j7_sign", p, ""))
				} else {
					event := j7ResultEvent(t, nativeResponse(t, response, nativeID(20), ""))
					if event.CreatedAt != value {
						t.Fatal("construction timestamp changed", event.CreatedAt, value)
					}
					j7DelegationWaitReleased(t, f, 20)
				}
				if clock.reads.Load() < at {
					t.Fatal("exceptional construction read was not exercised")
				}
			})
		}
	}
}

type j7RetainedWindowFence struct {
	a         *j7RequestCustody
	operation string
	plant     func(control.Object)
	callbacks atomic.Int64
}

func (f *j7RetainedWindowFence) WithActive(ctx context.Context, peer control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	if r.Params["operation"] != f.operation {
		return f.a.WithActive(ctx, peer, r, result, release)
	}
	if f.plant != nil {
		f.plant(result)
	}
	return f.a.WithActive(ctx, peer, r, result, func(ctx context.Context) control.Code { f.callbacks.Add(1); return release(ctx) })
}

// Plant a correctly signed but invalid-window retained fixture. This models
// legacy corrupt history only, never an operator recovery or a production API.
func j7PlantRetainedWindow(t *testing.T, f *j7SignFixture, id int, result control.Object, at int64) []byte {
	t.Helper()
	event := j7ResultEvent(t, result)
	event.CreatedAt = at
	event.ID = j7EventID(event)
	digestBytes, _ := hex.DecodeString(event.ID)
	var digest [32]byte
	copy(digest[:], digestBytes)
	signature, e := f.a.key.request(f.f.store, f.f.binding, &digest)
	if e != nil {
		t.Fatal("synthetic fault signature", e)
	}
	event.Sig = hex.EncodeToString(signature)
	erase(signature)
	changed := j7SignedResult(event, result["profile"].(string))
	j7ResultEvent(t, changed)
	for k := range result {
		delete(result, k)
	}
	for k, v := range changed {
		result[k] = v
	}
	s := f.f.store
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.j7SigningRecord(f.a.launcher, nativeID(id))
	index, ok := s.requestIndex[requestKey{f.a.launcher, nativeID(id)}]
	if rec == nil || !ok {
		t.Fatal("missing fault target")
	}
	encoded, e := control.Marshal(result)
	if e != nil {
		t.Fatal(e)
	}
	s.requests[index].Result = encoded
	rec.ResultHash = j7Hash(encoded)
	rec.EventID = event.ID
	if code := s.commitJ7(t.Context()); code != "" {
		t.Fatal("retained fixture fault persistence", code)
	}
	if s.validateJ7Signing() == nil {
		t.Fatal("fault did not violate stored time invariant")
	}
	raw, e := os.ReadFile(f.f.path + "/bindings.json")
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

// Correctly signed, hash-associated retained data must still obey its ORIGINAL
// event window before first/retry callback. A backward clock and new launcher
// channel cannot release invalid history. The explicit fixture fault remains
// preserved and fenced; an ordinary call/retry with valid bytes is the control.
func TestJ7DelegationRetainedWindowRelease(t *testing.T) {
	for _, operation := range []string{"consent_v3", "envelope_v3", "delegation_request_v3"} {
		for _, retry := range []bool{false, true} {
			positions := []string{"end"}
			if operation != "consent_v3" {
				positions = append(positions, "below-start")
			}
			for _, position := range positions {
				t.Run(fmt.Sprintf("%s/%s/retry-%v", operation, position, retry), func(t *testing.T) {
					probe := &j7RetainedWindowFence{operation: operation}
					f, c, p := j7WindowFixture(t, operation, probe)
					probe.a = f.a
					valid := j7Call(t, c, 10, "j7_sign", p, "")
					j7ResultEvent(t, valid)
					j7DelegationWaitReleased(t, f, 10)
					if got := j7Call(t, c, 10, "j7_sign", p, ""); !reflect.DeepEqual(got, valid) {
						t.Fatal("valid retry changed bytes")
					}
					j7DelegationWaitReleased(t, f, 10)
					callbacks := probe.callbacks.Load()
					at := f.contract.NotAfter
					if position == "below-start" {
						at = f.contract.NotBefore - 1
					}
					id := 20
					var before []byte
					if retry {
						id = 10
						f.a.clock = j7SigningClock{time.Unix(f.contract.NotAfter, 0), true}
						j7PlantRetainedWindow(t, f, id, valid, at)
						inside, _ := fixtureAuditClock{}.UTC()
						f.a.clock = j7SigningClock{inside, true}
						f.f.store.mu.Lock()
						run := f.f.store.j7.Runs[0].ID
						f.f.store.mu.Unlock()
						c = j7DelegationReconnect(t, f, c, 30, run)
						before, _ = os.ReadFile(f.f.path + "/bindings.json")
					} else {
						probe.plant = func(result control.Object) { before = j7PlantRetainedWindow(t, f, id, result, at) }
					}
					nativeSend(t, c, nativeRequest(id, "j7_sign", p))
					response := nativeReceive(t, c)
					if probe.callbacks.Load() != callbacks {
						t.Fatal("out-of-window retained event reached callback")
					}
					nativeResponse(t, response, nativeID(id), "j7_state_fenced")
					after, e := os.ReadFile(f.f.path + "/bindings.json")
					if e != nil || !reflect.DeepEqual(before, after) {
						t.Fatal("invalid retained fixture was rewritten", e)
					}
					f.f.store.mu.Lock()
					failed := f.f.store.failed
					f.f.store.mu.Unlock()
					if !failed {
						t.Fatal("invalid retained state was not fenced")
					}
				})
			}
		}
	}
}

// Profile1 is a real signed W parent, not an incomplete/ID-only negative.
// Frozen parent-ID/depth ordering wins without admitting delegation. A nearby
// genuine profile2 parent signs; schema5's unsupported surface stays separate.
func TestJ7DelegationProfile1ParentOrder(t *testing.T) {
	f := j7SigningSetup(t)
	f.stop()
	<-f.done
	if code := f.f.store.migrateJ7Delegation(t.Context(), j7Head(t, f.f.store)); code != "" {
		t.Fatal(code)
	}
	j7DelegationServe(t, f, nil)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	g, _, evidence := j7DelegationIssue(t, f, c)
	j7DelegationList(t, f, g.ID(), 3, false, true)
	now, _ := f.a.clock.UTC()
	if code := f.a.evidence.check(t.Context(), g, evidence, now.Unix()); code != "" {
		t.Fatal("profile1 full W control", code)
	}
	p := j7DelegationParams(t, f, g, evidence)
	before := j7DelegationCount(f)
	t.Run("correct-parent", func(t *testing.T) { j7Call(t, c, 20, "j7_sign", p, "NOT_DELEGABLE") })
	input := j7DelegationInput(t, p)
	raw, _ := j7Decode64(input.ChildContract, 8192)
	input.ChildContract = j7Encode64([]byte(strings.Replace(string(raw), g.ID(), strings.Repeat("f", 64), 1)))
	t.Run("different-parent", func(t *testing.T) {
		j7Call(t, c, 21, "j7_sign", j7DelegationWithInput(t, p, input), "PARENT_ID_MISMATCH")
	})
	if j7DelegationCount(f) != before {
		t.Fatal("profile1 refusal retained a signature")
	}
	positive, conn, _, _, params := j7DelegationReady(t)
	j7ResultEvent(t, j7Call(t, conn, 20, "j7_sign", params, ""))
	j7DelegationWaitReleased(t, positive, 20)
}
