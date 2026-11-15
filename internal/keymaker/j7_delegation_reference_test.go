package keymaker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-keymaker/internal/control"
)

// Independent test-only reader. Lexing is a direct byte grammar (not the
// product's Decoder.Token/re-encoding tree), and every rule/field table below
// comes from the frozen specification. It calls no product parse/bind/hash/build
// helper. Same author and shared crypto libraries remain explicit limits.
type j7RefValue struct {
	kind   byte
	s      string
	i      int64
	names  []string
	values []*j7RefValue
}
type j7RefScanner struct {
	b   []byte
	at  int
	bad bool
}

func (s *j7RefScanner) take(c byte) bool {
	if s.at >= len(s.b) || s.b[s.at] != c {
		s.bad = true
		return false
	}
	s.at++
	return true
}
func (s *j7RefScanner) text() string {
	if !s.take('"') {
		return ""
	}
	var out []byte
	for s.at < len(s.b) {
		c := s.b[s.at]
		s.at++
		if c == '"' {
			return string(out)
		}
		if c == '\\' {
			if s.at >= len(s.b) {
				break
			}
			c = s.b[s.at]
			s.at++
			if c != '"' && c != '\\' {
				s.bad = true
				return ""
			}
		} else if c < 32 || c > 126 {
			s.bad = true
			return ""
		}
		out = append(out, c)
	}
	s.bad = true
	return ""
}
func (s *j7RefScanner) value() *j7RefValue {
	n := &j7RefValue{}
	if s.bad || s.at >= len(s.b) {
		s.bad = true
		return n
	}
	switch s.b[s.at] {
	case '"':
		n.kind = 's'
		n.s = s.text()
	case '{', '[':
		open := s.b[s.at]
		s.at++
		close := byte('}')
		n.kind = 'o'
		if open == '[' {
			close = ']'
			n.kind = 'a'
		}
		if s.at < len(s.b) && s.b[s.at] == close {
			s.at++
			return n
		}
		for !s.bad {
			if open == '{' {
				n.names = append(n.names, s.text())
				if !s.take(':') {
					return n
				}
			}
			n.values = append(n.values, s.value())
			if s.bad || s.at >= len(s.b) {
				s.bad = true
				return n
			}
			if s.b[s.at] == close {
				s.at++
				return n
			}
			if !s.take(',') {
				return n
			}
		}
	default:
		n.kind = 'n'
		start := s.at
		for s.at < len(s.b) && s.b[s.at] >= '0' && s.b[s.at] <= '9' {
			s.at++
		}
		raw := string(s.b[start:s.at])
		number, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || strconv.FormatInt(number, 10) != raw || number < 0 {
			s.bad = true
		}
		n.i = number
	}
	return n
}
func j7RefRead(raw []byte) *j7RefValue {
	s := &j7RefScanner{b: raw}
	n := s.value()
	if s.bad || s.at != len(raw) {
		return nil
	}
	return n
}
func (n *j7RefValue) keys(keys ...string) bool {
	return n != nil && n.kind == 'o' && slices.Equal(n.names, keys)
}
func (n *j7RefValue) get(name string) *j7RefValue {
	if n != nil {
		for i, k := range n.names {
			if k == name {
				return n.values[i]
			}
		}
	}
	return &j7RefValue{}
}
func (n *j7RefValue) list() ([]string, bool) {
	if n == nil || n.kind != 'a' {
		return nil, false
	}
	out := []string{}
	for _, v := range n.values {
		if v.kind != 's' {
			return nil, false
		}
		out = append(out, v.s)
	}
	return out, true
}
func j7RefHex(s string, n int) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == n && hex.EncodeToString(b) == s
}
func j7RefKey(s string) bool {
	if !j7RefHex(s, 32) {
		return false
	}
	b, _ := hex.DecodeString(s)
	_, e := schnorr.ParsePubKey(b)
	return e == nil
}

var j7RefName = regexp.MustCompile(`^id/[a-z0-9_.-]{1,252}$`)

func j7RefSorted(v []string) bool {
	for i := 1; i < len(v); i++ {
		if v[i-1] >= v[i] {
			return false
		}
	}
	return true
}
func j7RefRepo(s string) bool {
	if len(s) > 200 {
		return false
	}
	u, e := url.Parse(s)
	if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Port() != "" || u.RawPath != "" || u.String() != s {
		return false
	}
	labels := strings.Split(u.Host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range []byte(l) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) < 2 || parts[0] != "" {
		return false
	}
	for _, p := range parts[1:] {
		if p == "" || p == "." || p == ".." {
			return false
		}
		for _, c := range []byte(p) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("_.-", rune(c))) {
				return false
			}
		}
	}
	return true
}

type j7RefTerms struct {
	profile, network, landlord, agent, key, parent, text, note string
	actions, repos                                             []string
	budget, before, after, ordinal                             int64
	delegate                                                   *j7RefValue
}

func j7ReferenceContract(raw []byte) (j7RefTerms, string) {
	var c j7RefTerms
	if len(raw) == 0 || len(raw) > 8192 {
		return c, "CONTRACT_ENCODING"
	}
	n := j7RefRead(raw)
	if n == nil {
		return c, "CONTRACT_ENCODING"
	}
	base := []string{"profile", "network", "landlord_name", "agent_name", "grantee_key", "actions", "repos", "spend_budget", "not_before", "not_after"}
	one := append(append([]string{}, base...), "note")
	two := append(append([]string{}, base...), "scope_text_sha256", "parent_grant_id", "ordinal", "delegate", "note")
	second := n.keys(two...)
	if !second && !n.keys(one...) {
		return c, "CONTRACT_ENCODING"
	}
	for _, name := range n.names {
		v := n.get(name)
		want := byte('s')
		switch name {
		case "actions", "repos":
			want = 'a'
			if _, ok := v.list(); !ok {
				return c, "CONTRACT_ENCODING"
			}
		case "spend_budget", "not_before", "not_after", "ordinal":
			want = 'n'
		case "delegate":
			continue
		}
		if v.kind != want {
			return c, "CONTRACT_ENCODING"
		}
	}
	c = j7RefTerms{profile: n.get("profile").s, network: n.get("network").s, landlord: n.get("landlord_name").s, agent: n.get("agent_name").s, key: n.get("grantee_key").s, parent: n.get("parent_grant_id").s, text: n.get("scope_text_sha256").s, note: n.get("note").s, budget: n.get("spend_budget").i, before: n.get("not_before").i, after: n.get("not_after").i, ordinal: n.get("ordinal").i, delegate: n.get("delegate")}
	c.actions, _ = n.get("actions").list()
	c.repos, _ = n.get("repos").list()
	profile := "swarma-trust-contract/1"
	if second {
		profile = "swarma-trust-contract/2"
	}
	if c.profile != profile {
		return c, "CONTRACT_PROFILE"
	}
	if c.network != "main" && c.network != "regtest" || !j7RefName.MatchString(c.landlord) || !j7RefName.MatchString(c.agent) || c.landlord == c.agent || !j7RefKey(c.key) || c.after <= c.before || c.after > 253402300799 || c.text != "" && !j7RefHex(c.text, 32) {
		return c, "CONTRACT_FIELD"
	}
	if len(c.actions) == 0 || !j7RefSorted(c.actions) {
		return c, "CONTRACT_ACTIONS"
	}
	for _, a := range c.actions {
		if a != "instruct" && a != "land" && a != "review" && a != "spend" {
			return c, "CONTRACT_ACTIONS"
		}
	}
	if !j7RefSorted(c.repos) || len(c.repos) > 16 || (len(c.repos) > 0) != slices.Contains(c.actions, "land") {
		return c, "CONTRACT_REPOS"
	}
	for _, r := range c.repos {
		if !j7RefRepo(r) {
			return c, "CONTRACT_REPOS"
		}
	}
	if c.budget > 2100000000000000 || (c.budget > 0) != slices.Contains(c.actions, "spend") {
		return c, "CONTRACT_BUDGET"
	}
	if len(c.note) > 280 {
		return c, "CONTRACT_NOTE"
	}
	if !second {
		return c, ""
	}
	if c.ordinal > 16 || (c.parent == "") != (c.ordinal == 0) || c.parent != "" && !j7RefHex(c.parent, 32) {
		return c, "CONTRACT_PARENT"
	}
	d := c.delegate
	if c.parent != "" && d.kind == 'o' && len(d.names) > 0 && d.names[0] == "depth" && d.values[0].kind == 'n' && d.values[0].i != 0 {
		return c, "CONTRACT_PARENT"
	}
	if !d.keys("depth", "actions", "budget", "slots", "notaries", "checkpoint") {
		return c, "CONTRACT_DELEGATE"
	}
	for i, k := range []byte{'n', 'a', 'n', 'a', 'a', 's'} {
		if d.values[i].kind != k {
			return c, "CONTRACT_DELEGATE"
		}
	}
	depth, budget := d.get("depth").i, d.get("budget").i
	slots, notaries := d.get("slots").values, d.get("notaries").values
	if depth == 1 && len(notaries) == 0 {
		return c, "DELEGATE_NO_NOTARY"
	}
	acts, ok := d.get("actions").list()
	if !ok {
		return c, "CONTRACT_DELEGATE"
	}
	if depth == 0 {
		if len(acts) != 0 || budget != 0 || len(slots) != 0 || len(notaries) != 0 || d.get("checkpoint").s != "" {
			return c, "CONTRACT_DELEGATE"
		}
		return c, ""
	}
	if depth != 1 || len(acts) == 0 || !j7RefSorted(acts) || budget != 0 || len(slots) < 1 || len(slots) > 16 || len(notaries) > 4 || !j7RefHex(d.get("checkpoint").s, 32) {
		return c, "CONTRACT_DELEGATE"
	}
	for _, a := range acts {
		if a == "spend" || !slices.Contains(c.actions, a) {
			return c, "CONTRACT_DELEGATE"
		}
	}
	names := []string{}
	for _, v := range notaries {
		if !v.keys("name", "registration", "owner") || v.get("name").kind != 's' || v.get("owner").kind != 's' {
			return c, "CONTRACT_DELEGATE"
		}
		r := v.get("registration")
		if !r.keys("txid", "vout") || r.get("txid").kind != 's' || r.get("vout").kind != 'n' || !j7RefHex(r.get("txid").s, 32) || r.get("vout").i > 4294967295 {
			return c, "CONTRACT_DELEGATE"
		}
		owner := v.get("owner").s
		if !j7RefHex(owner, 33) || !strings.HasPrefix(owner, "02") && !strings.HasPrefix(owner, "03") {
			return c, "CONTRACT_DELEGATE"
		}
		b, _ := hex.DecodeString(owner)
		if _, e := btcec.ParsePubKey(b); e != nil {
			return c, "CONTRACT_DELEGATE"
		}
		name := v.get("name").s
		if !j7RefName.MatchString(name) {
			return c, "CONTRACT_DELEGATE"
		}
		names = append(names, name)
	}
	if !j7RefSorted(names) {
		return c, "CONTRACT_DELEGATE"
	}
	var sum int64
	for _, v := range slots {
		if !v.keys("executor", "grantee", "cap", "notary") {
			return c, "CONTRACT_DELEGATE"
		}
		for i, k := range []byte{'s', 's', 'n', 's'} {
			if v.values[i].kind != k {
				return c, "CONTRACT_DELEGATE"
			}
		}
		cap := v.get("cap").i
		if cap > 2100000000000000 {
			return c, "CONTRACT_DELEGATE"
		}
		sum += cap
		if !j7RefName.MatchString(v.get("executor").s) || v.get("executor").s == c.landlord || !j7RefKey(v.get("grantee").s) || !slices.Contains(names, v.get("notary").s) {
			return c, "CONTRACT_DELEGATE"
		}
	}
	if sum > budget {
		return c, "CONTRACT_DELEGATE"
	}
	return c, ""
}
func j7ReferenceFit(p, c j7RefTerms, id string) string {
	if c.parent != id {
		return "PARENT_ID_MISMATCH"
	}
	if p.parent != "" || p.ordinal != 0 {
		return "CHAIN_DEPTH"
	}
	if p.delegate.get("depth").i != 1 {
		return "NOT_DELEGABLE"
	}
	if p.network != c.network || p.landlord != c.landlord {
		return "SUBJECT_MISMATCH"
	}
	rows := p.delegate.get("slots").values
	if c.ordinal < 1 || c.ordinal > int64(len(rows)) {
		return "CHILD_ORDINAL"
	}
	row := rows[c.ordinal-1]
	if c.agent != row.get("executor").s {
		return "CHILD_AGENT_NOT_ALLOWED"
	}
	if c.key != row.get("grantee").s {
		return "CHILD_GRANTEE_NOT_ALLOWED"
	}
	acts, _ := p.delegate.get("actions").list()
	for _, a := range c.actions {
		if !slices.Contains(acts, a) {
			return "CHILD_ACTIONS_WIDER"
		}
	}
	for _, r := range c.repos {
		if !slices.Contains(p.repos, r) {
			return "CHILD_REPOS_WIDER"
		}
	}
	if c.budget > row.get("cap").i {
		return "CHILD_BUDGET_OVER"
	}
	if c.before < p.before || c.after > p.after {
		return "CHILD_WINDOW_NOT_NESTED"
	}
	return ""
}
func j7RefSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func j7RefJSON(v any) []byte {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		panic("reference JSON")
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
func j7ReferenceRequest(raw, pc, pg, cc []byte) string {
	p, code := j7ReferenceContract(pc)
	if code != "" {
		return code
	}
	c, code := j7ReferenceContract(cc)
	if code != "" {
		return code
	}
	g, e := rental.ParseSignedGrant(pg)
	if e != nil {
		return "PARENT_INVALID"
	}
	id := j7RefSHA(pg)
	if g.Grant.ContractSHA256 != j7RefSHA(pc) || g.Grant.GranteeKey != p.key || g.Grant.Network != p.network || g.Grant.LandlordName != p.landlord || g.Grant.AgentName != p.agent || g.Grant.NotBefore != p.before || g.Grant.NotAfter != p.after || g.Grant.BudgetSat() != p.budget {
		return "PARENT_BINDING"
	}
	wantScope := []string{}
	if slices.Contains(p.actions, "spend") {
		wantScope = append(wantScope, "pay")
	}
	if slices.Contains(p.actions, "land") {
		wantScope = append(wantScope, "repository.push")
	}
	if !slices.Equal(wantScope, g.Grant.Scope) {
		return "PARENT_BINDING"
	}
	tags := [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", j7RefSHA(pc)}, {"booking", j7RefSHA(append(append([]byte{}, pc...), []byte("booking")...))}, {"privacy", j7RefSHA([]byte("swarma-trust-privacy-v1"))}}
	if !bytes.Equal(j7RefJSON(tags), j7RefJSON(g.Grant.Consent.ConsentEvent.Tags)) {
		return "PARENT_BINDING"
	}
	if code = j7ReferenceFit(p, c, id); code != "" {
		return code
	}
	shape := j7RefRead(raw)
	if shape == nil || !shape.keys("id", "pubkey", "created_at", "kind", "tags", "content", "sig") {
		return "DELEGATION_REQUEST"
	}
	var event rental.Event
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&event) != nil || !bytes.Equal(j7RefJSON(event), raw) || event.Kind != 8186 || event.Content != "" || event.Pubkey != p.key || event.CreatedAt < p.before || event.CreatedAt >= p.after || len(event.Tags) != 5 {
		return "DELEGATION_REQUEST"
	}
	for i, k := range []string{"t", "parent", "contract", "ordinal", "nonce"} {
		if len(event.Tags[i]) != 2 || event.Tags[i][0] != k {
			return "DELEGATION_REQUEST"
		}
	}
	if event.Tags[0][1] != "swarma-delegation-request-v1" || event.Tags[1][1] != id || event.Tags[2][1] != j7RefSHA(cc) || event.Tags[3][1] != strconv.FormatInt(c.ordinal, 10) || !j7RefHex(event.Tags[4][1], 32) {
		return "DELEGATION_REQUEST"
	}
	hash := j7RefSHA(j7RefJSON([]any{0, event.Pubkey, event.CreatedAt, event.Kind, event.Tags, event.Content}))
	if event.ID != hash || !j7RefHex(event.Sig, 64) {
		return "DELEGATION_REQUEST"
	}
	sigb, _ := hex.DecodeString(event.Sig)
	sig, e := schnorr.ParseSignature(sigb)
	keyb, _ := hex.DecodeString(event.Pubkey)
	key, e2 := schnorr.ParsePubKey(keyb)
	h, _ := hex.DecodeString(hash)
	if e != nil || e2 != nil || !sig.Verify(h, key) {
		return "DELEGATION_REQUEST"
	}
	return ""
}

type j7DelegationCorpus struct {
	Format         string                   `json:"format"`
	TestOnly       bool                     `json:"test_only"`
	Source         string                   `json:"source"`
	Note           string                   `json:"note"`
	ParentContract string                   `json:"parent_contract_b64"`
	ParentGrant    string                   `json:"parent_grant_b64"`
	ChildContract  string                   `json:"child_contract_b64"`
	Consent        string                   `json:"consent_event_b64"`
	Funding        string                   `json:"funding_tx_hex"`
	Seal           string                   `json:"seal_tx_hex"`
	Issuance       string                   `json:"issuance_tx_hex"`
	IssuanceID     string                   `json:"issuance_txid"`
	Positive       []j7DelegationCorpusCase `json:"positive"`
	Negative       []j7DelegationCorpusCase `json:"negative"`
}
type j7DelegationCorpusCase struct {
	ID       string `json:"id"`
	Event    string `json:"event_b64"`
	Preimage string `json:"preimage_hex"`
	Expected string `json:"expected"`
}

func j7DelegationReadCorpus(t *testing.T) j7DelegationCorpus {
	t.Helper()
	b, e := os.ReadFile("../../vectors/j7/delegation.json")
	var f j7DelegationCorpus
	if e != nil || json.Unmarshal(b, &f) != nil || !f.TestOnly || f.Format != "keymaker-j7-delegation-vectors/1" || len(f.Positive) != 2 || len(f.Negative) != 17 {
		t.Fatal("delegation corpus identity", e)
	}
	return f
}
func j7RefDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		t.Fatal("corpus encoding")
	}
	return b
}

// Static full request objects are checked against independent canonical/semantic
// rules and literal NIP01 preimages. Correctly signed wrong terms are refusals,
// not evidence of a live grant or external kind allocation/interoperability.
func TestJ7DelegationRequestIndependentVectors(t *testing.T) {
	f := j7DelegationReadCorpus(t)
	pc, pg, cc := j7RefDecode(t, f.ParentContract), j7RefDecode(t, f.ParentGrant), j7RefDecode(t, f.ChildContract)
	params := j7TypedParams(t, "delegation_request_v3", j7DelegationRequestInput{ParentContract: f.ParentContract, ParentGrant: f.ParentGrant, ChildContract: f.ChildContract})
	ev, _ := json.Marshal(j7Evidence{Format: "keymaker-j7-evidence/1", Issuance: f.IssuanceID})
	params["evidence_b64"] = base64.RawURLEncoding.EncodeToString(ev)
	plan, code := j7ParseRequestForSchema(control.Request{Method: "j7_sign", Params: params}, 6)
	if code != "" || plan.childFits() != "" {
		t.Fatal("product full fixture", code)
	}
	for _, group := range [][]j7DelegationCorpusCase{f.Positive, f.Negative} {
		for _, v := range group {
			t.Run(v.ID, func(t *testing.T) {
				raw := j7RefDecode(t, v.Event)
				want := v.Expected
				if want == "valid" {
					want = ""
				}
				if got := j7ReferenceRequest(raw, pc, pg, cc); got != want {
					t.Fatalf("independent result %s want %s", got, want)
				}
				event, ok := j7ValidateEventForSchema(raw, 6)
				accepted := ok && plan.validDelegationEvent(event, "swarma-delegation-request-v1/draft")
				if accepted != (want == "") {
					t.Fatal("product/reference disagreement")
				}
				var e rental.Event
				if json.Unmarshal(raw, &e) != nil {
					t.Fatal("fixture event")
				}
				literal := j7RefJSON([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content})
				if hex.EncodeToString(literal) != v.Preimage {
					t.Fatal("literal preimage drift")
				}
			})
		}
	}
}

// Paired known violations test the independent reader itself: malformed bytes,
// a nested membership defect and active D12 cannot pass via its happy path.
func TestJ7DelegationReferenceContractControls(t *testing.T) {
	f := j7DelegationReadCorpus(t)
	raw := string(j7RefDecode(t, f.ParentContract))
	for _, v := range []struct{ from, to, want string }{
		{`"cap":0`, `"cap":1`, "CONTRACT_DELEGATE"},
		{`"cap":0`, `"cap":-1`, "CONTRACT_ENCODING"},
		{`"cap":0,`, `"cap":0,"cap":0,`, "CONTRACT_DELEGATE"},
		{`"profile":"swarma-trust-contract/2"`, `"profile":"swarma-trust-contract/1"`, "CONTRACT_PROFILE"},
		{`"not_before":1700000000`, `"not_before":1700003600`, "CONTRACT_FIELD"},
	} {
		bad := strings.Replace(raw, v.from, v.to, 1)
		if bad == raw {
			t.Fatal("reference control not applied")
		}
		if _, code := j7ReferenceContract([]byte(bad)); code != v.want {
			t.Fatalf("independent control %s want %s", code, v.want)
		}
	}
	if _, code := j7ReferenceContract([]byte(raw)); code != "" {
		t.Fatal("reference rejects valid neighbor", code)
	}
}
