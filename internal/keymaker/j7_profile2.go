package keymaker

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"slices"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// This codec implements the active v3 profile at the fixed published revision.
// It does not apply pending v4/J2/J5 rules or perform child notary admission.
type j7ProfileContract struct {
	Profile   string     `json:"profile"`
	Network   string     `json:"network"`
	Landlord  string     `json:"landlord_name"`
	Agent     string     `json:"agent_name"`
	Grantee   string     `json:"grantee_key"`
	Actions   []string   `json:"actions"`
	Repos     []string   `json:"repos"`
	Budget    int64      `json:"spend_budget"`
	NotBefore int64      `json:"not_before"`
	NotAfter  int64      `json:"not_after"`
	ScopeText string     `json:"scope_text_sha256"`
	Parent    string     `json:"parent_grant_id"`
	Ordinal   int64      `json:"ordinal"`
	Delegate  j7Delegate `json:"delegate"`
	Note      string     `json:"note"`
}
type j7Delegate struct {
	Depth      int64              `json:"depth"`
	Actions    []string           `json:"actions"`
	Budget     int64              `json:"budget"`
	Slots      []j7DelegateSlot   `json:"slots"`
	Notaries   []j7DelegateNotary `json:"notaries"`
	Checkpoint string             `json:"checkpoint"`
}
type j7DelegateSlot struct {
	Executor string `json:"executor"`
	Grantee  string `json:"grantee"`
	Cap      int64  `json:"cap"`
	Notary   string `json:"notary"`
}
type j7DelegateNotary struct {
	Name         string               `json:"name"`
	Registration j7NotaryRegistration `json:"registration"`
	Owner        string               `json:"owner"`
}
type j7NotaryRegistration struct {
	TxID string `json:"txid"`
	Vout int64  `json:"vout"`
}

func (c j7ProfileContract) common() j7Contract {
	return j7Contract{Profile: c.Profile, Network: c.Network, Landlord: c.Landlord, Agent: c.Agent, Grantee: c.Grantee, Actions: c.Actions, Repos: c.Repos, Budget: c.Budget, NotBefore: c.NotBefore, NotAfter: c.NotAfter, Note: c.Note}
}

// Keep ordered members (including duplicate names) until the owning rule judges
// them. In particular a nested duplicate belongs to rule9, not an outer map.
type j7ContractMember struct {
	name  string
	value *j7ContractNode
}
type j7ContractNode struct {
	kind   byte
	object []j7ContractMember
	array  []*j7ContractNode
	text   string
	number int64
}

func j7ReadContractNode(d *json.Decoder) (*j7ContractNode, error) {
	t, e := d.Token()
	if e != nil {
		return nil, e
	}
	n := &j7ContractNode{}
	switch v := t.(type) {
	case string:
		if !j7ASCII(v) {
			return nil, failure("non-ASCII contract")
		}
		n.kind = 's'
		n.text = v
	case json.Number:
		x, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || x < 0 || strconv.FormatInt(x, 10) != string(v) {
			return nil, failure("noncanonical integer")
		}
		n.kind = 'n'
		n.number = x
	case json.Delim:
		if v == '{' {
			n.kind = 'o'
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, err
				}
				s, ok := key.(string)
				if !ok || !j7ASCII(s) {
					return nil, failure("invalid contract key")
				}
				child, err := j7ReadContractNode(d)
				if err != nil {
					return nil, err
				}
				n.object = append(n.object, j7ContractMember{s, child})
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, failure("invalid contract object")
			}
		} else if v == '[' {
			n.kind = 'a'
			for d.More() {
				child, err := j7ReadContractNode(d)
				if err != nil {
					return nil, err
				}
				n.array = append(n.array, child)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, failure("invalid contract array")
			}
		} else {
			return nil, failure("invalid contract delimiter")
		}
	default:
		return nil, failure("invalid contract scalar")
	}
	return n, nil
}
func (n *j7ContractNode) append(b []byte) []byte {
	switch n.kind {
	case 's':
		return strconv.AppendQuote(b, n.text)
	case 'n':
		return strconv.AppendInt(b, n.number, 10)
	case 'a':
		b = append(b, '[')
		for i, v := range n.array {
			if i > 0 {
				b = append(b, ',')
			}
			b = v.append(b)
		}
		return append(b, ']')
	case 'o':
		b = append(b, '{')
		for i, v := range n.object {
			if i > 0 {
				b = append(b, ',')
			}
			b = strconv.AppendQuote(b, v.name)
			b = append(b, ':')
			b = v.value.append(b)
		}
		return append(b, '}')
	}
	return b
}
func (n *j7ContractNode) members(names ...string) bool {
	if n == nil || n.kind != 'o' || len(n.object) != len(names) {
		return false
	}
	for i, s := range names {
		if n.object[i].name != s {
			return false
		}
	}
	return true
}
func (n *j7ContractNode) strings() ([]string, bool) {
	if n == nil || n.kind != 'a' {
		return nil, false
	}
	v := []string{}
	for _, x := range n.array {
		if x.kind != 's' {
			return nil, false
		}
		v = append(v, x.text)
	}
	return v, true
}

var j7ContractNames = []string{"profile", "network", "landlord_name", "agent_name", "grantee_key", "actions", "repos", "spend_budget", "not_before", "not_after", "note"}
var j7Profile2Names = []string{"profile", "network", "landlord_name", "agent_name", "grantee_key", "actions", "repos", "spend_budget", "not_before", "not_after", "scope_text_sha256", "parent_grant_id", "ordinal", "delegate", "note"}

func parseJ7ProfileContract(raw []byte) (j7ProfileContract, Code) {
	var c j7ProfileContract
	if len(raw) == 0 || len(raw) > 8192 {
		return c, "CONTRACT_ENCODING"
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	n, e := j7ReadContractNode(d)
	if e != nil {
		return c, "CONTRACT_ENCODING"
	}
	if _, e = d.Token(); e != io.EOF || !bytes.Equal(n.append(nil), raw) {
		return c, "CONTRACT_ENCODING"
	}
	second := n.members(j7Profile2Names...)
	if !second && !n.members(j7ContractNames...) {
		return c, "CONTRACT_ENCODING"
	}
	// All outer types except delegate are owned by rule1. Type-check before values.
	for _, m := range n.object {
		want := byte('s')
		switch m.name {
		case "actions", "repos":
			want = 'a'
		case "spend_budget", "not_before", "not_after", "ordinal":
			want = 'n'
		case "delegate":
			continue
		}
		if m.value.kind != want {
			return c, "CONTRACT_ENCODING"
		}
		if want == 'a' {
			if _, ok := m.value.strings(); !ok {
				return c, "CONTRACT_ENCODING"
			}
		}
	}
	// Decode only common/scalar fields now: delegate's types are rule9's concern.
	for _, m := range n.object {
		v := m.value
		switch m.name {
		case "profile":
			c.Profile = v.text
		case "network":
			c.Network = v.text
		case "landlord_name":
			c.Landlord = v.text
		case "agent_name":
			c.Agent = v.text
		case "grantee_key":
			c.Grantee = v.text
		case "actions":
			c.Actions, _ = v.strings()
		case "repos":
			c.Repos, _ = v.strings()
		case "spend_budget":
			c.Budget = v.number
		case "not_before":
			c.NotBefore = v.number
		case "not_after":
			c.NotAfter = v.number
		case "scope_text_sha256":
			c.ScopeText = v.text
		case "parent_grant_id":
			c.Parent = v.text
		case "ordinal":
			c.Ordinal = v.number
		case "note":
			c.Note = v.text
		}
	}
	profile := "swarma-trust-contract/1"
	if second {
		profile = "swarma-trust-contract/2"
	}
	if c.Profile != profile {
		return c, "CONTRACT_PROFILE"
	}
	if c.Network != "main" && c.Network != "regtest" || !j7NamePattern.MatchString(c.Landlord) || !j7NamePattern.MatchString(c.Agent) || c.Agent == c.Landlord || !j7Public(c.Grantee) || c.NotAfter <= c.NotBefore || c.NotAfter > j7MaxTime || c.ScopeText != "" && !validDigest(c.ScopeText) {
		return c, "CONTRACT_FIELD"
	}
	if !j7Sorted(c.Actions) || len(c.Actions) == 0 {
		return c, "CONTRACT_ACTIONS"
	}
	for _, a := range c.Actions {
		if !slices.Contains([]string{"instruct", "land", "review", "spend"}, a) {
			return c, "CONTRACT_ACTIONS"
		}
	}
	if !j7Sorted(c.Repos) || len(c.Repos) > 16 || slices.Contains(c.Actions, "land") != (len(c.Repos) > 0) {
		return c, "CONTRACT_REPOS"
	}
	for _, r := range c.Repos {
		if !j7Repo(r) {
			return c, "CONTRACT_REPOS"
		}
	}
	if c.Budget > j7MaxMoney || slices.Contains(c.Actions, "spend") != (c.Budget > 0) {
		return c, "CONTRACT_BUDGET"
	}
	if len(c.Note) > 280 {
		return c, "CONTRACT_NOTE"
	}
	if !second {
		return c, ""
	}
	dn := n.object[13].value
	if c.Ordinal > 16 || c.Parent != "" && !validDigest(c.Parent) || (c.Parent == "") != (c.Ordinal == 0) {
		return c, "CONTRACT_PARENT"
	}
	if c.Parent != "" && dn.kind == 'o' && len(dn.object) > 0 && dn.object[0].name == "depth" && dn.object[0].value.kind == 'n' && dn.object[0].value.number != 0 {
		return c, "CONTRACT_PARENT"
	}
	if code := j7ParseDelegate(dn, c.Actions, c.Landlord, &c.Delegate); code != "" {
		return c, code
	}
	return c, ""
}
func j7ParseDelegate(n *j7ContractNode, actions []string, landlord string, out *j7Delegate) Code {
	if !n.members("depth", "actions", "budget", "slots", "notaries", "checkpoint") {
		return "CONTRACT_DELEGATE"
	}
	for i, k := range []byte{'n', 'a', 'n', 'a', 'a', 's'} {
		if n.object[i].value.kind != k {
			return "CONTRACT_DELEGATE"
		}
	}
	if n.object[0].value.number == 1 && len(n.object[4].value.array) == 0 {
		return "DELEGATE_NO_NOTARY"
	}
	for _, s := range n.object[3].value.array {
		if !s.members("executor", "grantee", "cap", "notary") {
			return "CONTRACT_DELEGATE"
		}
		for i, k := range []byte{'s', 's', 'n', 's'} {
			if s.object[i].value.kind != k {
				return "CONTRACT_DELEGATE"
			}
		}
	}
	for _, a := range n.object[4].value.array {
		if !a.members("name", "registration", "owner") || a.object[0].value.kind != 's' || a.object[2].value.kind != 's' {
			return "CONTRACT_DELEGATE"
		}
		r := a.object[1].value
		if !r.members("txid", "vout") || r.object[0].value.kind != 's' || r.object[1].value.kind != 'n' {
			return "CONTRACT_DELEGATE"
		}
	}
	if _, ok := n.object[1].value.strings(); !ok {
		return "CONTRACT_DELEGATE"
	}
	if json.Unmarshal(n.append(nil), out) != nil {
		return "CONTRACT_DELEGATE"
	}
	x := out
	if x.Depth == 0 {
		if len(x.Actions) != 0 || x.Budget != 0 || len(x.Slots) != 0 || len(x.Notaries) != 0 || x.Checkpoint != "" {
			return "CONTRACT_DELEGATE"
		}
		return ""
	}
	if x.Depth != 1 || !j7Sorted(x.Actions) || len(x.Actions) == 0 || x.Budget > j7MaxMoney || len(x.Slots) == 0 || len(x.Slots) > 16 || len(x.Notaries) > 4 || !validDigest(x.Checkpoint) {
		return "CONTRACT_DELEGATE"
	}
	for _, a := range x.Actions {
		if a == "spend" || !slices.Contains(actions, a) {
			return "CONTRACT_DELEGATE"
		}
	}
	// D12 forbids delegable spend. Future-spend vector outcomes are not active.
	if x.Budget != 0 {
		return "CONTRACT_DELEGATE"
	}
	names := []string{}
	for _, a := range x.Notaries {
		b, e := hex.DecodeString(a.Owner)
		valid := e == nil && len(b) == 33 && hex.EncodeToString(b) == a.Owner && (b[0] == 2 || b[0] == 3)
		if valid {
			_, e = btcec.ParsePubKey(b)
			valid = e == nil
		}
		if !j7NamePattern.MatchString(a.Name) || !validDigest(a.Registration.TxID) || a.Registration.Vout > 4294967295 || !valid {
			return "CONTRACT_DELEGATE"
		}
		names = append(names, a.Name)
	}
	if !j7Sorted(names) {
		return "CONTRACT_DELEGATE"
	}
	var total int64
	for _, s := range x.Slots {
		if !j7NamePattern.MatchString(s.Executor) || s.Executor == landlord || !j7Public(s.Grantee) || s.Cap > j7MaxMoney || s.Cap > x.Budget-total || !slices.Contains(names, s.Notary) {
			return "CONTRACT_DELEGATE"
		}
		total += s.Cap
	}
	return ""
}
func j7BindProfileContract(raw []byte, c j7ProfileContract, g rental.Grant) Code {
	if j7Hash(raw) != g.ContractSHA256 {
		return "CONTRACT_HASH"
	}
	if c.Network != g.Network || c.Landlord != g.LandlordName || c.Agent != g.AgentName || c.Grantee != g.GranteeKey || c.NotBefore != g.NotBefore || c.NotAfter != g.NotAfter {
		return "CONTRACT_MISMATCH"
	}
	if !slices.Equal(c.common().scope(), g.Scope) {
		return "SCOPE_MISMATCH"
	}
	if c.Budget != g.BudgetSat() {
		return "BUDGET_MISMATCH"
	}
	triple := j7ConsentTriple(raw)
	if !slices.EqualFunc(g.Consent.ConsentEvent.Tags, [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", triple.Contract}, {"booking", triple.Booking}, {"privacy", triple.Privacy}}, func(a, b []string) bool { return slices.Equal(a, b) }) {
		return "CONSENT_TAGS"
	}
	return ""
}
func j7ChildParentIdentity(p, c j7ProfileContract, id string) Code {
	if c.Parent != id {
		return "PARENT_ID_MISMATCH"
	}
	if p.Parent != "" || p.Ordinal != 0 {
		return "CHAIN_DEPTH"
	}
	if p.Delegate.Depth != 1 {
		return "NOT_DELEGABLE"
	}
	return ""
}
func j7ChildFits(p, c j7ProfileContract) Code {
	if c.Network != p.Network || c.Landlord != p.Landlord {
		return "SUBJECT_MISMATCH"
	}
	if c.Ordinal < 1 || c.Ordinal > int64(len(p.Delegate.Slots)) {
		return "CHILD_ORDINAL"
	}
	row := p.Delegate.Slots[c.Ordinal-1]
	if c.Agent != row.Executor {
		return "CHILD_AGENT_NOT_ALLOWED"
	}
	if c.Grantee != row.Grantee {
		return "CHILD_GRANTEE_NOT_ALLOWED"
	}
	for _, a := range c.Actions {
		if !slices.Contains(p.Delegate.Actions, a) {
			return "CHILD_ACTIONS_WIDER"
		}
	}
	for _, r := range c.Repos {
		if !slices.Contains(p.Repos, r) {
			return "CHILD_REPOS_WIDER"
		}
	}
	if c.Budget > row.Cap {
		return "CHILD_BUDGET_OVER"
	}
	if c.NotBefore < p.NotBefore || c.NotAfter > p.NotAfter {
		return "CHILD_WINDOW_NOT_NESTED"
	}
	return ""
}
