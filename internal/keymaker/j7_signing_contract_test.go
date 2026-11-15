//go:build linux

package keymaker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

func j7SigningTerms(t *testing.T, f *j7SignFixture, action string) {
	t.Helper()
	f.contract.Actions = []string{action}
	f.contract.Repos = []string{}
	f.contract.Budget = 0
	if action == "land" {
		f.contract.Repos = []string{"https://example.test/team/repository"}
	}
	if action == "spend" {
		f.contract.Budget = 100
	}
	f.raw, _ = j7Compact(f.contract)
	p := j7SigningPolicy(t, f, 2)
	triple := j7ConsentTriple(f.raw)
	triple.AndUse = true
	p.Rows[0].Consent = []j7ConsentPermission{triple}
	f.f.publish(t, p)
}

// Every supported action has a positive complete endpoint event and neighboring
// wrong target/body/terms/full-grant/encoding cases. Refusals retain no result.
// The node is a graph fixture; these cases make no network interoperability claim.
func TestJ7SigningEnvelopeContracts(t *testing.T) {
	for _, action := range []string{"instruct", "review", "land", "spend"} {
		t.Run(action, func(t *testing.T) {
			f := j7SigningSetup(t)
			j7SigningTerms(t, f, action)
			c := f.dial(t, 1)
			f.bind(t, c, 2, f.f.origin, f.f.uid+200)
			consent := j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
			g, _, ev := j7IssueFixture(t, f, consent)
			j7Call(t, c, 4, "j7_enroll", j7GrantParams(t, f, g, ev), "")
			params := j7EnvelopeParams(t, f, g, ev)
			raw, _ := j7Decode64(params["object_b64"].(string), j7ObjectLimit)
			var good j7EnvelopeInput
			json.Unmarshal(raw, &good)
			good.Action = action
			if action == "land" {
				good.Repo = f.contract.Repos[0]
			}
			if action == "spend" {
				good.Amount = 100
			}
			for i, mutate := range []func(*j7EnvelopeInput){
				func(v *j7EnvelopeInput) { v.To = "id/other-agent" }, func(v *j7EnvelopeInput) { v.Room = "room" }, func(v *j7EnvelopeInput) { v.MXID = "@no-server" }, func(v *j7EnvelopeInput) { v.Instruction = "" }, func(v *j7EnvelopeInput) { v.Grant = j7Encode64([]byte(g.ID())) },
				func(v *j7EnvelopeInput) {
					b, _ := j7Decode64(v.Grant, 16384)
					v.Grant = j7Encode64([]byte(strings.Replace(string(b), g.Signature, strings.Repeat("0", 128), 1)))
				},
				func(v *j7EnvelopeInput) {
					terms := f.contract
					terms.Note = "altered counterparty terms"
					b, _ := j7Compact(terms)
					v.Contract = j7Encode64(b)
				}, func(v *j7EnvelopeInput) { v.Contract = j7Encode64(append(append([]byte{}, f.raw...), '\n')) }, func(v *j7EnvelopeInput) { v.Transport = "raw" }, func(v *j7EnvelopeInput) { v.Repo = "https://elsewhere.test/other/repository" }, func(v *j7EnvelopeInput) { v.Amount = 101 }, func(v *j7EnvelopeInput) { v.Instruction = strings.Repeat("A", 12000) },
			} {
				bad := good
				mutate(&bad)
				p := j7TypedParams(t, "envelope_v3", bad)
				p["evidence_b64"] = params["evidence_b64"]
				j7Call(t, c, 10+i, "j7_sign", p, "request_malformed")
			}
			p := j7TypedParams(t, "envelope_v3", good)
			p["evidence_b64"] = params["evidence_b64"]
			event := j7ResultEvent(t, j7Call(t, c, 30, "j7_sign", p, ""))
			if event.Kind != 8185 || event.Tags[3][1] != action || event.Tags[4][1] != j7Hash([]byte("fixture instruction")) {
				t.Fatal("complete action binding")
			}
			if action == "land" && event.Tags[8][1] != good.Repo || action == "spend" && event.Tags[8][1] != "100" {
				t.Fatal("complete action-specific terms")
			}
			f.f.store.mu.Lock()
			records := len(f.f.store.j7Signing.Records)
			e := f.f.store.validateJ7Signing()
			f.f.store.mu.Unlock()
			if records != 3 || e != nil {
				t.Fatal("malformed requests retained a result or invalid history", records, e)
			}
		})
	}
}

type j7SigningClock struct {
	value   time.Time
	trusted bool
}

func (c j7SigningClock) UTC() (time.Time, bool) { return c.value, c.trusted }

// Real custody/clock/generation and adopted node-verifier failures disclose no
// signed object and keep no signing result. Each has a valid neighboring call;
// injected generation evidence is not distinct-UID/native qualification.
func TestJ7SigningAuthorityFailures(t *testing.T) {
	for _, mode := range []string{"clock", "expired", "launcher-role", "custody", "closed", "unloaded", "purpose8", "node", "issuer-pin", "entropy", "retired"} {
		t.Run(mode, func(t *testing.T) {
			f := j7SigningSetup(t)
			c := f.dial(t, 1)
			run := f.bind(t, c, 2, f.f.origin, f.f.uid+200)
			consent := j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
			g, n, ev := j7IssueFixture(t, f, consent)
			j7Call(t, c, 4, "j7_enroll", j7GrantParams(t, f, g, ev), "")
			f.f.store.mu.Lock()
			before := len(f.f.store.j7Signing.Records)
			originalClock := f.a.clock
			originalEntropy := f.a.entropy
			var restore func()
			code := Code("")
			switch mode {
			case "clock":
				f.a.clock = j7SigningClock{}
				code = "clock_untrusted"
				restore = func() { f.a.clock = originalClock }
			case "expired":
				f.a.clock = j7SigningClock{time.Unix(f.contract.NotAfter, 0), true}
				code = "delegation_evidence_unavailable"
				restore = func() { f.a.clock = originalClock }
			case "launcher-role":
				launcher := f.a.launcher
				f.a.launcher.UID++
				code = "role_not_permitted"
				restore = func() { f.a.launcher = launcher }
			case "custody":
				f.a.key.mu.Lock()
				epoch := f.a.key.epoch
				f.a.key.epoch = "wrong"
				f.a.key.mu.Unlock()
				code = "custody_unavailable"
				restore = func() { f.a.key.mu.Lock(); f.a.key.epoch = epoch; f.a.key.mu.Unlock() }
			case "closed":
				f.a.key.mu.Lock()
				f.a.key.closed = true
				f.a.key.mu.Unlock()
				code = "custody_unavailable"
				restore = func() { f.a.key.mu.Lock(); f.a.key.closed = false; f.a.key.mu.Unlock() }
			case "unloaded":
				f.a.key.mu.Lock()
				seed := f.a.key.seed
				f.a.key.seed = nil
				f.a.key.mu.Unlock()
				code = "custody_unavailable"
				restore = func() { f.a.key.mu.Lock(); f.a.key.seed = seed; f.a.key.mu.Unlock() }
			case "purpose8":
				f.a.key.mu.Lock()
				f.a.key.role = j7DelegationRole
				f.a.key.mu.Unlock()
				code = "custody_unavailable"
				restore = func() { f.a.key.mu.Lock(); f.a.key.role = j7RequestRole; f.a.key.mu.Unlock() }
			case "node":
				n.mu.Lock()
				n.unavailable = true
				n.mu.Unlock()
				code = "delegation_evidence_unavailable"
				restore = func() { n.mu.Lock(); n.unavailable = false; n.mu.Unlock() }
			case "issuer-pin":
				original := f.a.evidence.policies[f.contract.Agent]
				bad := original
				bad.IssuerPubkey = strings.Repeat("f", 64)
				f.a.evidence.policies[f.contract.Agent] = bad
				code = "delegation_evidence_unavailable"
				restore = func() { f.a.evidence.policies[f.contract.Agent] = original }
			case "entropy":
				f.a.entropy = bytes.NewReader(nil)
				code = "entropy_unavailable"
				restore = func() { f.a.entropy = originalEntropy }
			case "retired":
				f.gen.mu.Lock()
				entry := f.gen.entries[f.f.binding.UID]
				bad := entry
				bad.State = "retired"
				f.gen.entries[f.f.binding.UID] = bad
				f.gen.mu.Unlock()
				code = "generation_inactive"
				restore = func() { f.gen.mu.Lock(); f.gen.entries[f.f.binding.UID] = entry; f.gen.mu.Unlock() }
			}
			f.f.store.mu.Unlock()
			params := j7EnvelopeParams(t, f, g, ev)
			j7Call(t, c, 5, "j7_sign", params, code)
			if code == "custody_unavailable" {
				want := custodyProtectionFailed
				if mode == "closed" {
					want = custodyClosed
				}
				if mode == "unloaded" {
					want = custodyUnloaded
				}
				rows := nativeAudit(t, f.f.store.journal)
				last := rows[len(rows)-1]
				if last.RequestID == nil || *last.RequestID != nativeID(5) || last.RefusalCode == nil || *last.RefusalCode != "custody_unavailable" || last.CustodyCause == nil || *last.CustodyCause != want {
					t.Fatal("request-scoped custody audit cause lost", mode)
				}
			}

			f.f.store.mu.Lock()
			after := len(f.f.store.j7Signing.Records)
			restore()
			f.f.store.mu.Unlock()
			if before != after {
				t.Fatal("unavailable authority retained a signing result")
			}
			if mode == "retired" {
				c.Close()
				j7RestartSigning(t, f)
				c = f.dial(t, 20)
				j7Call(t, c, 21, "j7_run_rebind", control.Object{"run_id": run}, "")
			}
			j7ResultEvent(t, j7Call(t, c, 6, "j7_sign", params, ""))
		})
	}
}

// No caller selector, asserted digest/live receipt or alternate transport spelling
// can enter through sign/pubkey/enroll, even for a named unavailable operation.
func TestJ7SigningSelectorSchemas(t *testing.T) {
	f := j7SigningSetup(t)
	c := f.dial(t, 1)
	f.bind(t, c, 2, f.f.origin, f.f.uid+200)
	for i, field := range []string{"kind", "purpose", "path", "uid", "origin", "key", "event_id", "nonce", "digest", "batch"} {
		p := f.consent(t)
		p[field] = fmt.Sprint(i)
		j7Call(t, c, 10+i, "j7_sign", p, "request_malformed")
	}
	for i, method := range []string{"j7_pubkey", "j7_enroll"} {
		j7Call(t, c, 30+i, method, control.Object{"purpose": 7}, "request_malformed")
	}
	p := j7TypedParams(t, "delegation_request_v3", control.Object{})
	p["object_b64"] = "!!!"
	j7Call(t, c, 32, "j7_sign", p, "request_malformed")
	p = f.consent(t)
	p["evidence_b64"] = j7Encode64([]byte(`{"format":"keymaker-j7-evidence/1","issuance_txid":"","live":true}`))
	j7Call(t, c, 33, "j7_sign", p, "request_malformed")
	j7ResultEvent(t, j7Call(t, c, 34, "j7_sign", f.consent(t), ""))
}
