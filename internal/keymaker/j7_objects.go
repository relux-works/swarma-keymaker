package keymaker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

const j7ObjectLimit = 32768
const j7MaxTime = int64(253402300799)
const j7MaxMoney = int64(2100000000000000)

// These are the LIP-0013 fixed-order bytes, not CCJ-1 or a v4 domain.
type j7Contract struct {
	Profile   string   `json:"profile"`
	Network   string   `json:"network"`
	Landlord  string   `json:"landlord_name"`
	Agent     string   `json:"agent_name"`
	Grantee   string   `json:"grantee_key"`
	Actions   []string `json:"actions"`
	Repos     []string `json:"repos"`
	Budget    int64    `json:"spend_budget"`
	NotBefore int64    `json:"not_before"`
	NotAfter  int64    `json:"not_after"`
	Note      string   `json:"note"`
}

func j7Compact(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}
func j7Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func j7ASCII(s string) bool {
	for _, c := range []byte(s) {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

var j7NamePattern = regexp.MustCompile(`^id/[a-z0-9_.-]{1,252}$`)
var j7RepoPattern = regexp.MustCompile(`^https://[a-z0-9-]+(?:\.[a-z0-9-]+)+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$`)

func j7Public(s string) bool {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != s {
		return false
	}
	_, e = schnorr.ParsePubKey(b)
	return e == nil
}
func j7Repo(s string) bool {
	if len(s) > 200 || !j7RepoPattern.MatchString(s) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(s, "https://"), "/")
	for _, l := range strings.Split(parts[0], ".") {
		if len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
	}
	for _, p := range parts[1:] {
		if p == "." || p == ".." {
			return false
		}
	}
	return true
}
func j7Sorted(s []string) bool {
	if s == nil {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i-1] >= s[i] {
			return false
		}
	}
	return true
}
func parseJ7Contract(raw []byte) (j7Contract, Code) {
	var c j7Contract
	var profile map[string]json.RawMessage
	if len(raw) > 0 && len(raw) <= 8192 && StrictJSON(bytes.NewReader(raw), &profile) == nil {
		var name string
		if json.Unmarshal(profile["profile"], &name) == nil && name != "swarma-trust-contract/1" && name != "" {
			return c, "operation_unsupported"
		}
	}
	if len(raw) == 0 || len(raw) > 8192 || messageRequired(raw, reflect.TypeFor[j7Contract]()) != nil || StrictJSON(bytes.NewReader(raw), &c) != nil {
		return c, "request_malformed"
	}
	same, e := j7Compact(c)
	if e != nil || !bytes.Equal(raw, same) {
		return c, "request_malformed"
	}
	for _, s := range append(append([]string{c.Profile, c.Network, c.Landlord, c.Agent, c.Grantee, c.Note}, c.Actions...), c.Repos...) {
		if !j7ASCII(s) {
			return c, "request_malformed"
		}
	}
	if c.Profile != "swarma-trust-contract/1" || c.Network != "main" && c.Network != "regtest" || !j7NamePattern.MatchString(c.Landlord) || !j7NamePattern.MatchString(c.Agent) || c.Agent == c.Landlord || !j7Public(c.Grantee) || c.NotBefore < 0 || c.NotAfter <= c.NotBefore || c.NotAfter > j7MaxTime || !j7Sorted(c.Actions) || len(c.Actions) == 0 || !j7Sorted(c.Repos) || len(c.Repos) > 16 || len(c.Note) > 280 {
		return c, "request_malformed"
	}
	for _, a := range c.Actions {
		if !slices.Contains([]string{"instruct", "land", "review", "spend"}, a) {
			return c, "request_malformed"
		}
	}
	for _, s := range c.Repos {
		if !j7Repo(s) {
			return c, "request_malformed"
		}
	}
	if slices.Contains(c.Actions, "land") != (len(c.Repos) > 0) || c.Budget < 0 || c.Budget > j7MaxMoney || slices.Contains(c.Actions, "spend") != (c.Budget > 0) {
		return c, "request_malformed"
	}
	return c, ""
}
func j7ConsentTriple(raw []byte) j7ConsentPermission {
	return j7ConsentPermission{Contract: j7Hash(raw), Booking: j7Hash(append(append([]byte{}, raw...), []byte("booking")...)), Privacy: j7Hash([]byte("swarma-trust-privacy-v1"))}
}
func (c j7Contract) scope() []string {
	s := []string{}
	if slices.Contains(c.Actions, "spend") {
		s = append(s, "pay")
	}
	if slices.Contains(c.Actions, "land") {
		s = append(s, "repository.push")
	}
	return s
}
func j7BindContract(raw []byte, c j7Contract, g rental.Grant) Code {
	triple := j7ConsentTriple(raw)
	if g.ContractSHA256 != triple.Contract || c.Network != g.Network || c.Landlord != g.LandlordName || c.Agent != g.AgentName || c.Grantee != g.GranteeKey || c.NotBefore != g.NotBefore || c.NotAfter != g.NotAfter || c.Budget != g.BudgetSat() || !slices.Equal(c.scope(), g.Scope) {
		return "request_malformed"
	}
	want := [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", triple.Contract}, {"booking", triple.Booking}, {"privacy", triple.Privacy}}
	a, _ := j7Compact(want)
	b, _ := j7Compact(g.Consent.ConsentEvent.Tags)
	if !bytes.Equal(a, b) {
		return "request_malformed"
	}
	return ""
}
func j7Decode64(s string, limit int) ([]byte, Code) {
	if len(s) > base64.RawURLEncoding.EncodedLen(limit) {
		return nil, "request_malformed"
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(b) > limit || base64.RawURLEncoding.EncodeToString(b) != s {
		return nil, "request_malformed"
	}
	return b, ""
}
func j7Encode64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func j7StrictObject(raw []byte, v any) Code {
	if len(raw) == 0 || len(raw) > j7ObjectLimit || messageRequired(raw, reflect.TypeOf(v).Elem()) != nil || StrictJSON(bytes.NewReader(raw), v) != nil {
		return "request_malformed"
	}
	return ""
}

type j7Evidence struct {
	Format   string `json:"format"`
	Issuance string `json:"issuance_txid"`
}

func j7DecodeEvidence(encoded string, grant bool) (j7Evidence, Code) {
	var e j7Evidence
	b, c := j7Decode64(encoded, 1024)
	if c != "" {
		return e, c
	}
	if c = j7StrictObject(b, &e); c != "" {
		return e, c
	}
	if e.Format != "keymaker-j7-evidence/1" || grant && !validDigest(e.Issuance) || !grant && e.Issuance != "" {
		return e, "request_malformed"
	}
	return e, ""
}

type j7SignParams struct {
	Operation string `json:"operation"`
	Object    string `json:"object_b64"`
	Evidence  string `json:"evidence_b64"`
}
type j7EnrollParams struct {
	Object   string `json:"object_b64"`
	Evidence string `json:"evidence_b64"`
}
type j7ConsentInput struct {
	Contract string `json:"contract_b64"`
}
type j7GrantInput struct {
	Contract string `json:"contract_b64"`
	Grant    string `json:"grant_b64"`
}
type j7EnvelopeInput struct {
	Contract    string `json:"contract_b64"`
	Grant       string `json:"grant_b64"`
	Instruction string `json:"instruction_b64"`
	Transport   string `json:"transport"`
	To          string `json:"to"`
	Action      string `json:"action"`
	Room        string `json:"room"`
	MXID        string `json:"mxid"`
	Repo        string `json:"repo"`
	Amount      int64  `json:"amount"`
}

func j7MatrixID(s string, sigil byte, colon bool) bool {
	if len(s) < 2 || len(s) > 255 || s[0] != sigil || colon && !strings.Contains(s[1:], ":") {
		return false
	}
	for _, c := range []byte(s[1:]) {
		if c <= 32 || c > 126 {
			return false
		}
	}
	return true
}
func j7EventID(e rental.Event) string {
	b, _ := j7Compact([]any{0, e.Pubkey, e.CreatedAt, e.Kind, e.Tags, e.Content})
	return j7Hash(b)
}

// Retained signed bytes have the same closed profile as newly built events.
// This is integrity validation, never authority to forward a caller's event.
func j7ValidateEvent(raw []byte) (rental.Event, bool) {
	var e rental.Event
	if len(raw) > 16384 || j7StrictObject(raw, &e) != "" {
		return e, false
	}
	encoded, err := j7Compact(e)
	if err != nil || !bytes.Equal(encoded, raw) || !j7Public(e.Pubkey) || e.CreatedAt < 1 || e.CreatedAt > j7MaxTime || e.Content != "" || e.ID != j7EventID(e) {
		return e, false
	}
	signature, err := hex.DecodeString(e.Sig)
	public, _ := hex.DecodeString(e.Pubkey)
	id, _ := hex.DecodeString(e.ID)
	if err != nil || len(signature) != 64 || hex.EncodeToString(signature) != e.Sig || !j7Verify(public, id, signature) {
		return e, false
	}
	for _, tag := range e.Tags {
		if len(tag) != 2 {
			return e, false
		}
		for _, v := range tag {
			if len(v) > 512 || !j7ASCII(v) {
				return e, false
			}
		}
	}
	if e.Kind == 8181 {
		names := []string{"t", "contract", "booking", "privacy"}
		if len(e.Tags) != 4 {
			return e, false
		}
		for i, n := range names {
			if e.Tags[i][0] != n {
				return e, false
			}
		}
		return e, e.Tags[0][1] == "swarma-rental-consent-v1" && validDigest(e.Tags[1][1]) && validDigest(e.Tags[2][1]) && validDigest(e.Tags[3][1])
	}
	if e.Kind != 8185 || len(e.Tags) < 8 || len(e.Tags) > 9 {
		return e, false
	}
	for i, n := range []string{"t", "to", "grant", "action", "body", "room", "mxid", "nonce"} {
		if e.Tags[i][0] != n {
			return e, false
		}
	}
	if e.Tags[0][1] != "swarma-instruction-v1" || !j7NamePattern.MatchString(e.Tags[1][1]) || !validDigest(e.Tags[2][1]) || !validDigest(e.Tags[4][1]) || !validDigest(e.Tags[7][1]) || !j7MatrixID(e.Tags[5][1], '!', false) || !j7MatrixID(e.Tags[6][1], '@', true) {
		return e, false
	}
	switch e.Tags[3][1] {
	case "instruct", "review":
		return e, len(e.Tags) == 8
	case "land":
		return e, len(e.Tags) == 9 && e.Tags[8][0] == "repo" && j7Repo(e.Tags[8][1])
	case "spend":
		if len(e.Tags) != 9 || e.Tags[8][0] != "amount" {
			return e, false
		}
		v, err := strconv.ParseInt(e.Tags[8][1], 10, 64)
		return e, err == nil && v > 0 && v <= j7MaxMoney && strconv.FormatInt(v, 10) == e.Tags[8][1]
	}
	return e, false
}
func j7SignedResult(e rental.Event, profile string) map[string]any {
	b, _ := j7Compact(e)
	return map[string]any{"profile": profile, "signed_object_b64": j7Encode64(b), "object_id": e.ID, "public_key": e.Pubkey}
}
