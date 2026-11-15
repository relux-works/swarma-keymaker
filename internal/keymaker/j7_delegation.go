//go:build linux

package keymaker

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-keymaker/internal/control"
)

type j7DelegationRequestInput struct {
	ParentContract string `json:"parent_contract_b64"`
	ParentGrant    string `json:"parent_grant_b64"`
	ChildContract  string `json:"child_contract_b64"`
}
type j7DelegationPlan struct {
	parent, child j7ProfileContract
	childRaw      []byte
}

func j7ParseRequestForSchema(r control.Request, schema int) (j7Plan, Code) {
	if schema != j7DelegationSchema || r.Method != "j7_sign" {
		return j7ParseRequest(r)
	}
	var v j7SignParams
	if code := j7DecodeArgs(r.Params, &v); code != "" {
		return j7Plan{}, code
	}
	if v.Operation == "delegation_request_v3" {
		return j7ParseDelegation(v)
	}
	if v.Operation != "consent_v3" {
		return j7ParseRequest(r)
	}
	var p j7Plan
	raw, code := j7Decode64(v.Object, j7ObjectLimit)
	if code != "" {
		return p, code
	}
	var input j7ConsentInput
	if code = j7StrictObject(raw, &input); code != "" {
		return p, code
	}
	raw, code = j7Decode64(input.Contract, 8192)
	if code != "" {
		return p, code
	}
	if !j7Profile2ConsentHint(raw) {
		return j7ParseRequest(r)
	}
	c, code := parseJ7ProfileContract(raw)
	if code != "" {
		return p, code
	}
	if c.Profile != "swarma-trust-contract/2" || c.Parent != "" || c.Ordinal != 0 || c.Delegate.Depth != 1 {
		return p, "operation_unsupported"
	}
	ev, code := j7DecodeEvidence(v.Evidence, false)
	if code != "" {
		return p, code
	}
	return j7Plan{operation: "consent_v3", contract: c.common(), contractRaw: raw, evidence: ev, consent: j7ConsentTriple(raw)}, ""
}

// This is only dispatch into a strict parser, never acceptance of normalized
// JSON. Recognizing the first profile value also routes malformed nested /2
// bytes (for example cap:01) to their exact lexical refusal. /1 keeps its route.
func j7Profile2ConsentHint(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, e := d.Token()
	if e == nil && first == json.Delim('{') {
		name, e := d.Token()
		if e == nil && name == "profile" {
			value, e := d.Token()
			if e == nil {
				if value == "swarma-trust-contract/1" {
					return false
				}
				if value == "swarma-trust-contract/2" {
					return true
				}
			}
		}
	}
	var hint struct {
		Profile string `json:"profile"`
	}
	return json.Unmarshal(raw, &hint) == nil && hint.Profile == "swarma-trust-contract/2"
}

func j7ParseDelegation(v j7SignParams) (j7Plan, Code) {
	p := j7Plan{operation: "delegation_request_v3"}
	raw, code := j7Decode64(v.Object, j7ObjectLimit)
	if code != "" {
		return p, code
	}
	var input j7DelegationRequestInput
	if code = j7StrictObject(raw, &input); code != "" {
		return p, code
	}
	pr, code := j7Decode64(input.ParentContract, 8192)
	if code != "" {
		return p, code
	}
	cr, code := j7Decode64(input.ChildContract, 8192)
	if code != "" {
		return p, code
	}
	gr, code := j7Decode64(input.ParentGrant, 16384)
	if code != "" {
		return p, code
	}
	g, e := rental.ParseSignedGrant(gr)
	if e != nil {
		return p, "request_malformed"
	}
	// Binding order: hash before canonical profile, then common/scope/budget/tags.
	if j7Hash(pr) != g.Grant.ContractSHA256 {
		return p, "CONTRACT_HASH"
	}
	pc, code := parseJ7ProfileContract(pr)
	if code != "" {
		return p, code
	}
	if code = j7BindProfileContract(pr, pc, g.Grant); code != "" {
		return p, code
	}
	cc, code := parseJ7ProfileContract(cr)
	if code != "" {
		return p, code
	}
	if code = j7ChildParentIdentity(pc, cc, g.ID()); code != "" {
		return p, code
	}
	if pc.Profile != "swarma-trust-contract/2" || cc.Profile != "swarma-trust-contract/2" {
		return p, "operation_unsupported"
	}
	p.evidence, code = j7DecodeEvidence(v.Evidence, true)
	if code != "" {
		return p, code
	}
	p.contract, p.contractRaw, p.grant, p.delegation = pc.common(), pr, &g, &j7DelegationPlan{parent: pc, child: cc, childRaw: cr}
	return p, ""
}

// Child fitting follows the live-parent observation at the endpoint. Disk
// integrity uses the same comparisons without claiming a fresh chain verdict.
func (p j7Plan) childFits() Code {
	if p.delegation == nil {
		return ""
	}
	return j7ChildFits(p.delegation.parent, p.delegation.child)
}
func (p j7Plan) delegationEvent(public string, now int64, nonce []byte) rental.Event {
	return rental.Event{Kind: 8186, Pubkey: public, CreatedAt: now, Content: "", Tags: [][]string{{"t", "swarma-delegation-request-v1"}, {"parent", p.grant.ID()}, {"contract", j7Hash(p.delegation.childRaw)}, {"ordinal", strconv.FormatInt(p.delegation.child.Ordinal, 10)}, {"nonce", hex.EncodeToString(nonce)}}}
}
func j7ValidateEventForSchema(raw []byte, schema int) (rental.Event, bool) {
	if event, ok := j7ValidateEvent(raw); ok {
		return event, true
	}
	var event rental.Event
	if schema != j7DelegationSchema || len(raw) > 16384 || j7StrictObject(raw, &event) != "" {
		return event, false
	}
	canonical, e := j7Compact(event)
	if e != nil || !bytes.Equal(canonical, raw) || event.Kind != 8186 || event.Content != "" || !j7Public(event.Pubkey) || event.CreatedAt < 1 || event.CreatedAt > j7MaxTime || event.ID != j7EventID(event) || !rental.VerifySignature(event.Pubkey, event.ID, event.Sig) || len(event.Sig) != 128 || strings.ToLower(event.Sig) != event.Sig || len(event.Tags) != 5 {
		return event, false
	}
	for i, name := range []string{"t", "parent", "contract", "ordinal", "nonce"} {
		if len(event.Tags[i]) != 2 || event.Tags[i][0] != name {
			return event, false
		}
	}
	ordinal, e := strconv.ParseInt(event.Tags[3][1], 10, 64)
	return event, e == nil && ordinal >= 1 && ordinal <= 16 && strconv.FormatInt(ordinal, 10) == event.Tags[3][1] && event.Tags[0][1] == "swarma-delegation-request-v1" && validDigest(event.Tags[1][1]) && validDigest(event.Tags[2][1]) && validDigest(event.Tags[4][1])
}
func (p j7Plan) validDelegationEvent(event rental.Event, profile any) bool {
	if p.delegation == nil || p.grant == nil || event.Kind != 8186 || profile != "swarma-delegation-request-v1/draft" || event.Pubkey != p.grant.Grant.GranteeKey || event.CreatedAt < p.contract.NotBefore || event.CreatedAt >= p.contract.NotAfter {
		return false
	}
	return event.Tags[1][1] == p.grant.ID() && event.Tags[2][1] == j7Hash(p.delegation.childRaw) && event.Tags[3][1] == strconv.FormatInt(p.delegation.child.Ordinal, 10)
}
