package staticgate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-registrar/ccj"
)

// The only scalars used are CSV indices 1, 2 and 3 (not row numbers) of
// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv.
// TestPublishedKeys compares both columns to the published literals below.
// These are public test data and must never approve anything real.
const (
	approverSecret = "b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef"
	approverPublic = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
	otherSecret    = "c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9"
	otherPublic    = "dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8"
	thirdSecret    = "0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710"
	thirdPublic    = "25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517"
)

// callerKey is 32 bytes of 0x88 in the association key spelling: a format
// example, not a key anyone holds.
const callerKey = "ed25519:iIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIg"

// M0-shaped examples; the verifier itself deliberately stays generation-opaque.
const callerGeneration = "0123456789abcdef0123456789abcdef"
const workerGeneration = "fedcba9876543210fedcba9876543210"

const vectorFile = "../vectors/staticgate/vectors.json"

// vector is one row of vectors/staticgate/vectors.json.
type vector struct {
	ID    string `json:"id"`
	Claim string `json:"claim"`
	// Expect is "pass" or the exact refusal code.
	Expect string `json:"expect"`
	// Checks names the verifier checks that, removed together, let a
	// negative pass. The first one is the check that refuses it.
	Checks []string `json:"checks,omitempty"`
	// Control is the passing vector this negative stands beside.
	Control string `json:"control,omitempty"`
	// Limit marks a stated limit: a pass that is not protection.
	Limit        bool         `json:"limit,omitempty"`
	StatementHex string       `json:"statement_hex"`
	Signature    string       `json:"signature"`
	Inputs       vectorInputs `json:"inputs"`
}

type vectorInputs struct {
	ApproverKey     string `json:"approver_key"`
	StatementDigest string `json:"statement_digest"`
	MachineIDSHA256 string `json:"machine_id_sha256"`
	Now             string `json:"now"`
	Class           string `json:"class"`
	Consumer        string `json:"consumer"`
	Section         string `json:"section"`
	Association     string `json:"association,omitempty"`
}

type verifier func([]byte, []byte, Inputs) (Statement, error)

func (v vector) run(t *testing.T, verify verifier) (Statement, error) {
	t.Helper()
	raw, err := hex.DecodeString(v.StatementHex)
	if err != nil {
		t.Fatalf("%s: statement_hex: %v", v.ID, err)
	}
	now, err := time.Parse(time.RFC3339Nano, v.Inputs.Now)
	if err != nil {
		t.Fatalf("%s: now: %v", v.ID, err)
	}
	in := Inputs{
		ApproverKey: hex32(t, v.Inputs.ApproverKey), StatementDigest: hex32(t, v.Inputs.StatementDigest),
		MachineIDSHA256: hex32(t, v.Inputs.MachineIDSHA256), Now: now, Class: Class(v.Inputs.Class),
		Consumer: Consumer(v.Inputs.Consumer), Section: []byte(v.Inputs.Section), Association: []byte(v.Inputs.Association),
	}
	return verify(raw, []byte(v.Signature), in)
}

func hex32(t *testing.T, s string) (out [32]byte) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad 32-byte hex %q", s)
	}
	copy(out[:], b)
	return out
}

// ---- statement construction (test only; product code has no signer) ----

var (
	machineID      = sha256.Sum256([]byte("0123456789abcdef0123456789abcdef\n"))
	otherMachineID = sha256.Sum256([]byte("fedcba9876543210fedcba9876543210\n"))
	notBefore      = time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	notAfter       = time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	inside         = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
)

// genuine returns a fresh copy of the example statement. Section contents of
// broker_time and broker_d5 are placeholders: their owner has not frozen
// them. The verifier compares every section as opaque bytes.
func genuine() map[string]any {
	return map[string]any{
		"v": int64(1), "kind": Tag, "milestone": Milestone,
		"gate_id":    "00112233445566778899aabbccddeeff",
		"host":       map[string]any{"label": "host-a", "machine_id_sha256": hex.EncodeToString(machineID[:])},
		"not_before": notBefore.Format(timeLayout), "not_after": notAfter.Format(timeLayout),
		"approver":    map[string]any{"alg": "bip340", "key": approverPublic, "label": "static-gate-example"},
		"association": map[string]any{"caller_generation": callerGeneration, "caller_key": callerKey, "caller_uid": int64(38601)},
		"keymaker": map[string]any{
			"service_uid": int64(38600), "binary_sha256": strings.Repeat("3", 64),
			"config_sha256": strings.Repeat("4", 64), "j7_request_key": strings.Repeat("5", 64),
		},
		"dispatcher": map[string]any{
			"service_uid": int64(38602), "receiver": strings.Repeat("6", 32), "policy_sha256": strings.Repeat("7", 64),
			"config_sha256": strings.Repeat("9", 64),
			"worker":        map[string]any{"generation": workerGeneration, "uid": int64(38603)},
		},
		"source":      map[string]any{"service_uid": int64(38604), "generation": "s-example-1", "config_sha256": strings.Repeat("a", 64)},
		"broker_time": map[string]any{"example_hold_seconds": int64(30), "example_in_flight": int64(1)},
		"broker_d5":   map[string]any{"example_acknowledged_head": strings.Repeat("8", 64)},
	}
}

func enc(v any) []byte {
	b, err := ccj.Marshal(v, ccj.RegistrationMalformed)
	if err != nil {
		panic(err)
	}
	return b
}

func signDigest(secret string, digest [32]byte) string {
	b, _ := hex.DecodeString(secret)
	private, _ := btcec.PrivKeyFromBytes(b)
	sig, err := schnorr.Sign(private, digest[:]) // deterministic RFC 6979 nonce
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(sig.Serialize())
}

func sign(secret string, raw []byte) string { return signDigest(secret, Digest(raw)) }

var consumers = []Consumer{Keymaker, Dispatcher, Source, BrokerTime, BrokerD5}

func consumesAssociation(c Consumer) bool { return c == Dispatcher }

// expected returns the inputs a correctly configured consumer holds for the
// genuine statement, with the digest pin set to the statement under test so
// that each negative is refused by its own check and not by the pin.
func expected(raw []byte, c Consumer) vectorInputs {
	g := genuine()
	digest := Digest(raw)
	in := vectorInputs{
		ApproverKey: approverPublic, StatementDigest: hex.EncodeToString(digest[:]),
		MachineIDSHA256: hex.EncodeToString(machineID[:]), Now: inside.Format(time.RFC3339Nano),
		Class: string(ClassStart), Consumer: string(c),
	}
	if section, ok := g[string(c)]; ok {
		in.Section = string(enc(section))
	}
	if consumesAssociation(c) {
		in.Association = string(enc(g["association"]))
	}
	return in
}

type builder struct{ out []vector }

func (b *builder) add(id, claim, expect string, checks []check, control string, raw []byte, sig string, in vectorInputs) {
	v := vector{ID: id, Claim: claim, Expect: expect, Control: control, StatementHex: hex.EncodeToString(raw), Signature: sig, Inputs: in}
	for _, c := range checks {
		v.Checks = append(v.Checks, string(c))
	}
	b.out = append(b.out, v)
}

// neg adds a validly signed, correctly pinned statement that one check refuses.
func (b *builder) neg(id, claim string, code Code, checks []check, raw []byte, c Consumer, edit func(*vectorInputs)) {
	in := expected(raw, c)
	if edit != nil {
		edit(&in)
	}
	b.add(id, claim, string(code), checks, "genuine-"+string(c), raw, sign(approverSecret, raw), in)
}

func (b *builder) pass(id, claim string, raw []byte, c Consumer, edit func(*vectorInputs)) {
	in := expected(raw, c)
	if edit != nil {
		edit(&in)
	}
	b.add(id, claim, "pass", nil, "", raw, sign(approverSecret, raw), in)
}

func with(edit func(g map[string]any)) []byte {
	g := genuine()
	edit(g)
	return enc(g)
}

func nest(objects int) any {
	var v any = int64(1)
	for range objects {
		v = map[string]any{"a": v}
	}
	return v
}

type leaf struct {
	path   string
	mutate func()
}

// leaves lists every scalar under v with a closure that changes only it.
func leaves(v any, path string) []leaf {
	var out []leaf
	o, ok := v.(map[string]any)
	if !ok {
		panic("section vectors expect nested objects of scalars")
	}
	names := make([]string, 0, len(o))
	for name := range o {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		switch x := o[name].(type) {
		case map[string]any:
			out = append(out, leaves(x, path+name+".")...)
		case int64:
			out = append(out, leaf{path + name, func() { o[name] = x + 1 }})
		case string:
			last := byte('0')
			if x[len(x)-1] == '0' {
				last = '1'
			}
			out = append(out, leaf{path + name, func() { o[name] = x[:len(x)-1] + string(last) }})
		default:
			panic("unexpected leaf type")
		}
	}
	return out
}

func buildVectors() []vector {
	b := &builder{}
	g := enc(genuine())
	text := string(g)
	ck := func(c ...check) []check { return c }
	now := func(t time.Time) func(*vectorInputs) {
		return func(in *vectorInputs) { in.Now = t.Format(time.RFC3339Nano) }
	}

	// Positive controls: every consumer verifies the one genuine statement.
	for _, c := range consumers {
		b.pass("genuine-"+string(c), "the genuine statement verifies for consumer "+string(c), g, c, nil)
	}

	// Step 1 pins raw bytes before a bounded parse, then compares the key.
	selfSigned := func(public, secret string) ([]byte, string) {
		raw := with(func(g map[string]any) { g["approver"].(map[string]any)["key"] = public })
		return raw, sign(secret, raw)
	}
	raw, sig := selfSigned(otherPublic, otherSecret)
	b.add("key-other-signer", "a statement naming and signed by another key refuses; the signature check would also refuse it", string(CodeKey), ck(ckKey, ckSignature), "genuine-keymaker", raw, sig, expected(raw, Keymaker))
	raw, sig = selfSigned(thirdPublic, thirdSecret)
	b.add("key-grant-key-signer", "a statement naming and signed by a key with another purpose (stand-in for the grant key) refuses", string(CodeKey), ck(ckKey, ckSignature), "genuine-keymaker", raw, sig, expected(raw, Keymaker))
	raw = with(func(g map[string]any) { g["approver"].(map[string]any)["key"] = otherPublic })
	b.neg("key-member-differs", "approver.key must equal the pinned key even when the pinned key signed the bytes", CodeKey, ck(ckKey), raw, Keymaker, nil)
	b.neg("key-pin-zero", "an all-zero key pin refuses", CodeKey, ck(ckKey, ckSignature), g, Keymaker, func(in *vectorInputs) { in.ApproverKey = strings.Repeat("0", 64) })
	raw = with(func(g map[string]any) { delete(g, "approver") })
	b.neg("key-approver-missing", "a statement without approver has no key equal to the pin; the member check would also refuse it", CodeKey, ck(ckKey, ckMembers), raw, Keymaker, nil)
	for _, tc := range []struct {
		id  string
		key any
	}{
		{"uppercase", strings.ToUpper(approverPublic)},
		{"nonhex", strings.Repeat("z", 64)},
		{"nonstring", int64(1)},
	} {
		raw := with(func(g map[string]any) { g["approver"].(map[string]any)["key"] = tc.key })
		b.neg("key-member-"+tc.id, "an unreadable or malformed approver.key refuses with KEY before shape", CodeKey, ck(ckKey, ckShape), raw, Keymaker, nil)
	}

	for _, tc := range []struct {
		id   string
		edit func(map[string]any)
	}{
		{"unreadable", func(g map[string]any) { g["approver"] = "unreadable" }},
		{"key-missing", func(g map[string]any) { delete(g["approver"].(map[string]any), "key") }},
	} {
		b.neg("key-approver-"+tc.id, "an unreadable approver key refuses with KEY before shape", CodeKey, ck(ckKey, ckShape), with(tc.edit), Keymaker, nil)
	}

	// Step 1, digest pin.
	second := with(func(g map[string]any) { g["gate_id"] = "ffeeddccbbaa99887766554433221100" })
	secondDigest := Digest(second)
	b.neg("pin-other-statement", "a validly signed statement whose digest is not the pinned one refuses", CodePin, ck(ckPin), g, Keymaker, func(in *vectorInputs) { in.StatementDigest = hex.EncodeToString(secondDigest[:]) })
	b.neg("pin-zero", "an all-zero digest pin refuses", CodePin, ck(ckPin), g, Keymaker, func(in *vectorInputs) { in.StatementDigest = strings.Repeat("0", 64) })

	// Step 2, bytes: size, codec rules, canonical re-encoding, depth.
	pad := func(preimage int) []byte {
		extra := preimage - (len(Tag) + 1 + len(g))
		return with(func(g map[string]any) {
			a := g["approver"].(map[string]any)
			a["label"] = a["label"].(string) + strings.Repeat("x", extra)
		})
	}
	b.pass("size-8192", "a preimage of exactly 8192 bytes verifies", pad(MaxPreimage), Keymaker, nil)
	b.neg("form-size-8193", "a preimage of 8193 bytes refuses", CodeForm, ck(ckSize), pad(MaxPreimage+1), Keymaker, nil)
	b.out[len(b.out)-1].Control = "size-8192"
	b.pass("depth-8", "container depth 8 verifies", with(func(g map[string]any) { g["broker_d5"] = nest(7) }), Keymaker, nil)
	b.neg("form-depth-9", "container depth 9 refuses", CodeForm, ck(ckDepth), with(func(g map[string]any) { g["broker_d5"] = nest(8) }), Keymaker, nil)
	b.out[len(b.out)-1].Control = "depth-8"
	replace := func(old, new string) []byte {
		if strings.Count(text, old) != 1 {
			panic("replacement is not unique: " + old)
		}
		return []byte(strings.Replace(text, old, new, 1))
	}
	codec := ck(ckCodec, ckCanonical)
	b.neg("form-duplicate-top", "a duplicate top-level name refuses", CodeForm, codec, replace(`"v":1}`, `"v":1,"v":1}`), Keymaker, nil)
	b.neg("form-duplicate-nested", "a duplicate name inside a section refuses", CodeForm, codec, replace(`"example_in_flight":1}`, `"example_in_flight":1,"example_in_flight":1}`), Keymaker, nil)
	b.neg("form-number-fraction", "a non-integer number spelling refuses", CodeForm, codec, replace(`"v":1}`, `"v":1.0}`), Keymaker, nil)
	b.neg("form-whitespace", "whitespace inside the statement refuses", CodeForm, ck(ckCanonical), replace(`{"approver":`, `{ "approver":`), Keymaker, nil)
	b.neg("form-final-lf", "a final LF refuses", CodeForm, ck(ckCanonical), []byte(text+"\n"), Keymaker, nil)
	b.neg("form-unsorted", "members out of scalar order refuse", CodeForm, ck(ckCanonical), []byte(`{"v":1,`+strings.TrimSuffix(text[1:], `,"v":1}`)+`}`), Keymaker, nil)
	b.neg("form-escape-name", "a name spelled with a needless escape refuses", CodeForm, ck(ckCanonical), replace(`"kind":`, `"\u006bind":`), Keymaker, nil)
	b.neg("form-escape-solidus", "a value spelled with an escaped solidus refuses", CodeForm, ck(ckCanonical), replace(`"kind":"swarma-s7 static-gate/1"`, `"kind":"swarma-s7 static-gate\/1"`), Keymaker, nil)
	b.neg("form-duplicate-escaped", "duplicate names are detected after escape decoding", CodeForm, codec, replace(`"v":1}`, `"v":1,"\u0076":1}`), Keymaker, nil)
	for _, number := range []struct{ id, token string }{
		{"leading-zero", "01"}, {"negative-zero", "-0"}, {"plus", "+1"},
		{"exponent", "1e3"}, {"overflow", "9223372036854775808"},
	} {
		b.neg("form-number-"+number.id, "a non-CCJ-1 integer token inside a section refuses", CodeForm, codec, replace(`"example_in_flight":1}`, `"example_in_flight":`+number.token+`}`), Keymaker, nil)
	}
	b.neg("form-trailing-x", "trailing non-JSON bytes refuse", CodeForm, codec, []byte(text+"x"), Keymaker, nil)
	b.neg("form-trailing-object", "two adjacent JSON objects refuse", CodeForm, codec, []byte(text+" {}"), Keymaker, nil)
	b.neg("form-bom", "a BOM before the object refuses", CodeForm, codec, []byte("\xef\xbb\xbf"+text), Keymaker, nil)
	b.neg("form-control-string", "a raw control character in a string refuses", CodeForm, codec, replace(`"host-a"`, "\"host-\x01a\""), Keymaker, nil)
	b.neg("form-utf8-string", "raw invalid UTF-8 in a string refuses", CodeForm, codec, replace(`"host-a"`, "\"host-\xffa\""), Keymaker, nil)
	b.pass("value-A", "a literal A in a value verifies", replace(`"host-a"`, `"host-A"`), Keymaker, nil)
	b.neg("form-escape-value", "a needless Unicode escape for A in a value refuses", CodeForm, ck(ckCanonical), replace(`"host-a"`, `"host-\u0041"`), Keymaker, nil)
	b.out[len(b.out)-1].Control = "value-A"
	arrays := func(n int) []byte {
		return replace(`"example_in_flight":1}`, `"example_in_flight":`+strings.Repeat("[", n)+"1"+strings.Repeat("]", n)+`}`)
	}
	b.pass("array-depth-8", "arrays at container depth 8 verify", arrays(6), Keymaker, nil)
	b.neg("form-array-depth-9", "arrays at container depth 9 refuse", CodeForm, ck(ckDepth), arrays(7), Keymaker, nil)
	b.out[len(b.out)-1].Control = "array-depth-8"
	b.neg("form-array-depth-bomb", "a bounded 1024-array depth bomb refuses without a panic", CodeForm, ck(ckCodec, ckCanonical, ckDepth), arrays(1024), Keymaker, nil)
	b.out[len(b.out)-1].Control = "array-depth-8"

	// Multi-fault controls pin precedence without treating malformed bytes as valid.
	for _, tc := range []struct {
		id     string
		raw    []byte
		checks []check
	}{
		{"size", pad(MaxPreimage + 1), ck(ckPin, ckSize)},
		{"codec", replace(`"v":1}`, `"v":1,"v":1}`), ck(ckPin, ckCodec, ckCanonical)},
	} {
		b.neg("order-pin-before-"+tc.id, "a wrong digest pin refuses before bounded parsing", CodePin, tc.checks, tc.raw, Keymaker, func(in *vectorInputs) { in.StatementDigest = strings.Repeat("0", 64) })
	}
	raw = with(func(g map[string]any) {
		g["approver"].(map[string]any)["key"] = otherPublic
		g["milestone"] = "G1.1"
	})
	b.neg("order-key-before-form", "on parseable pinned bytes a wrong key refuses before form", CodeKey, ck(ckKey, ckFixed), raw, Keymaker, nil)

	// Step 2, closed members.
	for _, m := range members {
		if m.name == "approver" {
			continue // refused earlier by the key check: key-approver-missing
		}
		checks := ck(ckMembers)
		if m.name == "not_before" || m.name == "not_after" {
			checks = ck(ckMembers, ckWindowWidth, ckWindowNow)
		}
		c := Keymaker
		if m.name == "keymaker" || m.name == "association" {
			c = BrokerTime
		}
		if m.name == "host" {
			checks = ck(ckMembers, ckHost)
		}
		b.neg("form-missing-"+m.name, "a statement without "+m.name+" refuses", CodeForm, checks, with(func(g map[string]any) { delete(g, m.name) }), c, nil)
	}
	b.neg("form-extra-member", "an unknown member refuses", CodeForm, ck(ckMembers), with(func(g map[string]any) { g["extra"] = int64(1) }), Keymaker, nil)

	// Step 2, exact v, kind and milestone.
	fixed := func(id, claim, name string, value any) {
		b.neg("form-"+id, claim, CodeForm, ck(ckFixed), with(func(g map[string]any) { g[name] = value }), Keymaker, nil)
	}
	fixed("v-2", "v other than 1 refuses", "v", int64(2))
	fixed("v-string", "v as a string refuses", "v", "1")
	fixed("kind-other", "another kind refuses even when signed under this tag", "kind", "swarma-s7 static-gate/2")
	fixed("milestone-other", "another milestone refuses", "milestone", "G1.1")

	// Step 2, shapes of the members this format owns.
	shape := func(id, claim string, c Consumer, checks []check, edit func(g map[string]any)) {
		b.neg("form-"+id, claim, CodeForm, checks, with(edit), c, nil)
	}
	sub := func(name, key string, value any) func(map[string]any) {
		return func(g map[string]any) { g[name].(map[string]any)[key] = value }
	}
	only := ck(ckShape)
	shape("gate-id-uppercase", "gate_id in uppercase hex refuses", Keymaker, only, func(g map[string]any) { g["gate_id"] = "00112233445566778899AABBCCDDEEFF" })
	shape("gate-id-short", "gate_id of 31 digits refuses", Keymaker, only, func(g map[string]any) { g["gate_id"] = "00112233445566778899aabbccddeef" })
	shape("host-extra", "an unknown host member refuses", Keymaker, only, sub("host", "extra", int64(1)))
	shape("host-label-empty", "an empty host label refuses", Keymaker, only, sub("host", "label", ""))
	shape("approver-alg", "an approver algorithm other than bip340 refuses", Keymaker, only, sub("approver", "alg", "ed25519"))
	shape("approver-label-empty", "an empty approver label refuses", Keymaker, only, sub("approver", "label", ""))
	shape("approver-extra", "an unknown approver member refuses", Keymaker, only, sub("approver", "extra", int64(1)))
	shape("association-no-caller-key", "an association without caller_key refuses", BrokerTime, only, func(g map[string]any) { delete(g["association"].(map[string]any), "caller_key") })
	shape("association-extra", "an unknown association member refuses", BrokerTime, only, sub("association", "registration", int64(1)))
	shape("caller-key-hex", "a caller key in hex refuses", BrokerTime, only, sub("association", "caller_key", strings.Repeat("8", 64)))
	shape("caller-key-no-prefix", "a caller key without the ed25519: prefix refuses", BrokerTime, only, sub("association", "caller_key", callerKey[len("ed25519:"):]))
	shape("caller-key-padded", "a padded caller key refuses", BrokerTime, only, sub("association", "caller_key", callerKey+"="))
	shape("caller-key-noncanonical", "a caller key whose last digit carries stray bits refuses", BrokerTime, only, sub("association", "caller_key", callerKey[:len(callerKey)-1]+"h"))
	shape("caller-key-std-alphabet", "a caller key in the standard base64 alphabet refuses", BrokerTime, only, sub("association", "caller_key", "ed25519:"+strings.Repeat("+", 42)+"A"))
	shape("caller-key-31-bytes", "a caller key of 31 bytes refuses", BrokerTime, only, sub("association", "caller_key", "ed25519:"+strings.Repeat("iI", 20)+"iA"))
	shape("caller-key-33-bytes", "a caller key of 33 bytes refuses", BrokerTime, only, sub("association", "caller_key", "ed25519:"+strings.Repeat("iI", 22)))
	shape("association-generation-empty", "an empty caller generation refuses", BrokerTime, only, sub("association", "caller_generation", ""))
	shape("association-uid-negative", "a negative caller UID refuses", BrokerTime, only, sub("association", "caller_uid", int64(-1)))
	shape("association-uid-wide", "a caller UID above 32 bits refuses", BrokerTime, only, sub("association", "caller_uid", int64(1)<<32))
	shape("association-uid-string", "a caller UID as a string refuses", BrokerTime, only, sub("association", "caller_uid", "38601"))
	shape("section-string", "a section that is not an object refuses", Keymaker, only, func(g map[string]any) { g["broker_d5"] = "8888" })
	shape("section-array", "a section that is an array refuses", Keymaker, only, func(g map[string]any) { g["broker_d5"] = []any{int64(1)} })
	shape("section-empty", "an empty section refuses", Keymaker, only, func(g map[string]any) { g["broker_d5"] = map[string]any{} })
	times := ck(ckShape, ckWindowWidth, ckWindowNow)
	shape("time-fraction", "fractional seconds refuse", Keymaker, times, func(g map[string]any) { g["not_before"] = "2026-11-17T00:00:00.0Z" })
	shape("time-offset", "a numeric UTC offset refuses", Keymaker, times, func(g map[string]any) { g["not_before"] = "2026-11-17T00:00:00+00:00" })
	shape("time-lowercase", "lowercase t and z refuse", Keymaker, times, func(g map[string]any) { g["not_after"] = "2026-11-19t00:00:00z" })
	shape("time-no-such-day", "a date that does not exist refuses", Keymaker, times, func(g map[string]any) { g["not_after"] = "2026-11-31T00:00:00Z" })

	// Step 3, signature.
	sigNeg := func(id, claim string, raw []byte, sig string) {
		b.add("signature-"+id, claim, string(CodeSignature), ck(ckSignature), "genuine-keymaker", raw, sig, expected(raw, Keymaker))
	}
	otherTag := sha256.Sum256(append([]byte("swarma-s7 static-gate/2\n"), g...))
	sigNeg("other-tag", "a signature over another tag refuses", g, signDigest(approverSecret, otherTag))
	sigNeg("no-tag", "a signature over the bare statement bytes refuses", g, signDigest(approverSecret, sha256.Sum256(g)))
	sigNeg("final-lf-preimage", "a signature over the preimage with a final LF refuses", g, signDigest(approverSecret, sha256.Sum256([]byte(Tag+"\n"+text+"\n"))))
	sigNeg("other-key", "a signature by another key over the genuine bytes refuses", g, sign(otherSecret, g))
	sigNeg("other-statement", "a signature made for another statement refuses", g, sign(approverSecret, second))
	good := sign(approverSecret, g)
	sigNeg("uppercase-hex", "an uppercase hex signature refuses", g, strings.ToUpper(good))
	sigNeg("truncated", "a short signature refuses", g, good[:126])
	sigNeg("trailing-lf", "a signature with a final LF refuses", g, good+"\n")
	sigNeg("empty", "an empty signature refuses", g, "")
	flipped := []byte(good)
	flipped[127] ^= 1 // '0'<->'1', '2'<->'3', ...: still lowercase hex
	sigNeg("bit-flip", "a signature with one changed digit refuses", g, string(flipped))
	// Hand-encode field boundaries; never ask a signer to construct invalid values.
	const fieldP = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
	const orderN = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
	const nonLiftable = "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34" // BIP-340 CSV index 5
	sigNeg("r-at-p", "a hand-encoded r equal to p refuses", g, fieldP+good[64:])
	sigNeg("s-at-n", "a hand-encoded s equal to N refuses", g, good[:64]+orderN)
	sigNeg("r-nonliftable", "a hand-encoded non-liftable R x-coordinate refuses", g, nonLiftable+good[64:])
	for _, key := range []struct{ id, x string }{{"at-p", fieldP}, {"nonliftable", nonLiftable}} {
		raw := with(func(g map[string]any) { g["approver"].(map[string]any)["key"] = key.x })
		in := expected(raw, Keymaker)
		in.ApproverKey = key.x // self-consistent pin; only signature verification can reject this point
		b.add("signature-key-"+key.id, "an unusable pinned key matching approver.key refuses with SIGNATURE", string(CodeSignature), ck(ckSignature), "genuine-keymaker", raw, good, in)
	}

	// Step 4, host.
	b.neg("host-other-machine", "another machine-id refuses", CodeHost, ck(ckHost), g, Keymaker, func(in *vectorInputs) { in.MachineIDSHA256 = hex.EncodeToString(otherMachineID[:]) })
	b.neg("host-zero", "an all-zero machine-id digest refuses", CodeHost, ck(ckHost), g, Keymaker, func(in *vectorInputs) { in.MachineIDSHA256 = strings.Repeat("0", 64) })

	// Step 5, window and class.
	end := func(in *vectorInputs) { in.Class = string(ClassEnd) }
	b.pass("window-at-not-before", "now equal to not_before verifies", g, Keymaker, now(notBefore))
	b.pass("window-last-instant", "one nanosecond before not_after verifies", g, Keymaker, now(notAfter.Add(-time.Nanosecond)))
	window := func(id, claim, control string, checks []check, raw []byte, edit func(*vectorInputs)) {
		b.neg("window-"+id, claim, CodeWindow, checks, raw, Keymaker, edit)
		b.out[len(b.out)-1].Control = control
	}
	window("not-yet-valid", "one second before not_before a start refuses", "window-at-not-before", ck(ckWindowNow), g, now(notBefore.Add(-time.Second)))
	window("at-not-after", "at not_after a start refuses", "window-last-instant", ck(ckWindowNow), g, now(notAfter))
	window("expired-start", "after not_after a start (bind, sign, dispatch, lease) refuses", "end-after-expiry", ck(ckWindowNow), g, now(notAfter.Add(time.Hour)))
	b.pass("end-after-expiry", "after not_after an end (run end, sweep, release, cancel) still verifies", g, Keymaker, func(in *vectorInputs) { in.Now = notAfter.Add(time.Hour).Format(time.RFC3339Nano); end(in) })
	b.pass("end-before-not-before", "an end is not compared with the clock at all", g, Keymaker, func(in *vectorInputs) { in.Now = notBefore.Add(-time.Hour).Format(time.RFC3339Nano); end(in) })
	b.pass("end-inside-window", "an end also verifies inside the window", g, Keymaker, end)
	b.pass("end-zero-now", "an end with zero Now verifies because only the clock comparison is skipped", g, Keymaker, func(in *vectorInputs) { in.Now = time.Time{}.Format(time.RFC3339Nano); end(in) })
	window("zero-now-start", "a start with zero Now refuses", "genuine-keymaker", ck(ckWindowNow), g, now(time.Time{}))
	window("class-unknown", "an operation class other than start or end refuses", "genuine-keymaker", ck(ckClass), g, func(in *vectorInputs) { in.Class = "bind" })
	window("class-empty", "an unset operation class refuses", "genuine-keymaker", ck(ckClass), g, func(in *vectorInputs) { in.Class = "" })
	span := func(d time.Duration) []byte {
		return with(func(g map[string]any) { g["not_after"] = notBefore.Add(d).Format(timeLayout) })
	}
	b.pass("width-72h", "a window of exactly 72 hours verifies", span(MaxWindow), Keymaker, nil)
	b.pass("width-72h-end", "an end with a window of exactly 72 hours verifies", span(MaxWindow), Keymaker, end)
	window("width-72h-1s", "a window of 72 hours and one second refuses a start", "width-72h", ck(ckWindowWidth), span(MaxWindow+time.Second), nil)
	window("width-72h-1s-end", "a window of 72 hours and one second refuses an end too", "width-72h-end", ck(ckWindowWidth), span(MaxWindow+time.Second), end)
	window("width-zero-end", "an empty window refuses an end", "end-inside-window", ck(ckWindowWidth), span(0), end)
	window("width-negative-end", "not_after before not_before refuses an end", "end-inside-window", ck(ckWindowWidth), span(-time.Hour), end)
	window("width-zero-start", "an empty window refuses a start", "window-at-not-before", ck(ckWindowWidth, ckWindowNow), span(0), now(notBefore))
	window("width-negative-start", "an inverted window refuses a start", "window-at-not-before", ck(ckWindowWidth, ckWindowNow), span(-time.Hour), now(notBefore))

	// Step 6, the consumer's own section: every member changed one at a time.
	for _, c := range consumers {
		edited := genuine()
		for i := range leaves(edited[string(c)], "") {
			edited = genuine()
			l := leaves(edited[string(c)], "")[i]
			l.mutate()
			b.neg("scope-"+string(c)+"-"+l.path, string(c)+"."+l.path+" changed in the signed statement refuses consumer "+string(c), CodeScopeMismatch, ck(ckSection), enc(edited), c, nil)
			b.out[len(b.out)-1].Control = "genuine-" + string(c)
		}
	}
	for _, c := range []Consumer{Dispatcher} {
		edited := genuine()
		for i := range leaves(edited["association"], "") {
			edited = genuine()
			l := leaves(edited["association"], "")[i]
			l.mutate()
			b.neg("scope-association-"+l.path+"-"+string(c), "association."+l.path+" changed in the signed statement refuses consumer "+string(c), CodeScopeMismatch, ck(ckAssociation), enc(edited), c, nil)
			b.out[len(b.out)-1].Control = "genuine-" + string(c)
		}
	}
	scope := func(id, claim string, c Consumer, checks []check, raw []byte, edit func(*vectorInputs)) {
		b.neg("scope-"+id, claim, CodeScopeMismatch, checks, raw, c, edit)
		b.out[len(b.out)-1].Control = "genuine-" + string(c)
	}
	scope("keymaker-member-removed", "a section with one member fewer refuses", Keymaker, ck(ckSection), with(func(g map[string]any) { delete(g["keymaker"].(map[string]any), "config_sha256") }), nil)
	scope("keymaker-member-added", "a section with one member more refuses", Keymaker, ck(ckSection), with(sub("keymaker", "extra", int64(1))), nil)
	swapped := with(func(g map[string]any) { g["broker_time"], g["broker_d5"] = g["broker_d5"], g["broker_time"] })
	scope("swap-broker-time", "broker_d5 content in the broker_time member refuses the time consumer", BrokerTime, ck(ckSection), swapped, nil)
	scope("swap-broker-d5", "broker_time content in the broker_d5 member refuses the D5 consumer", BrokerD5, ck(ckSection), swapped, nil)
	swapped = with(func(g map[string]any) { g["source"], g["dispatcher"] = g["dispatcher"], g["source"] })
	scope("swap-source", "dispatcher content in the source member refuses the source consumer", Source, ck(ckSection), swapped, nil)
	scope("swap-dispatcher", "source content in the dispatcher member refuses the dispatcher", Dispatcher, ck(ckSection), swapped, nil)
	scope("stand-in-d5-for-time", "the time consumer cannot be configured with the broker_d5 bytes", BrokerTime, ck(ckSection), g, func(in *vectorInputs) { in.Section = string(enc(genuine()["broker_d5"])) })
	respell := func(id, claim, generation string) {
		scope("generation-"+id+"-source", claim, Source, ck(ckSection), with(sub("source", "generation", generation)), nil)
	}
	respell("case", "a source generation differing only in letter case refuses", "S-example-1")
	respell("trailing-space", "a source generation with a trailing space refuses", "s-example-1 ")
	respell("lookalike", "a source generation with a look-alike letter (U+0435 for e) refuses", "s-\u0435xample-1")
	scope("generation-worker-replaced", "a different 32-lowercase-hex worker generation refuses the dispatcher", Dispatcher, ck(ckSection), with(func(g map[string]any) {
		g["dispatcher"].(map[string]any)["worker"].(map[string]any)["generation"] = strings.Repeat("a", 32)
	}), nil)
	nfc := with(sub("source", "generation", "s-caf\u00e9-1"))
	nfd := with(sub("source", "generation", "s-cafe\u0301-1"))
	composed := func(in *vectorInputs) {
		in.Section = string(enc(map[string]any{"config_sha256": strings.Repeat("a", 64), "generation": "s-caf\u00e9-1", "service_uid": int64(38604)}))
	}
	b.pass("generation-nfc", "a non-hex non-ASCII section generation verifies when the bytes are equal", nfc, Source, composed)
	scope("generation-nfd", "the same section generation in decomposed form refuses: nothing is normalised", Source, ck(ckSection), nfd, composed)
	b.out[len(b.out)-1].Control = "generation-nfc"
	scope("consumer-unknown", "an unknown consumer name refuses", Keymaker, ck(ckSection), g, func(in *vectorInputs) { in.Consumer = "unknown" })
	scope("consumer-is-member", "a member that is not a section cannot be consumed", Keymaker, ck(ckSection), g, func(in *vectorInputs) { in.Consumer = "host" })
	scope("section-expected-empty", "an empty expected section refuses", BrokerD5, ck(ckSection), g, func(in *vectorInputs) { in.Section = "" })
	scope("section-expected-spaced", "expected bytes that are not canonical refuse", BrokerD5, ck(ckSection), g, func(in *vectorInputs) { in.Section = strings.Replace(in.Section, ":", ": ", 1) })
	scope("association-expected-missing", "the dispatcher must supply the expected association", Dispatcher, ck(ckAssociation), g, func(in *vectorInputs) { in.Association = "" })
	b.pass("association-keymaker-not-supplied", "a mutated association verifies for Keymaker when no association is supplied", with(sub("association", "caller_uid", int64(38602))), Keymaker, nil)
	scope("association-supplied-keymaker", "Keymaker compares a supplied association even though it does not require it", Keymaker, ck(ckAssociation), with(sub("association", "caller_uid", int64(38602))), func(in *vectorInputs) { in.Association = string(enc(genuine()["association"])) })
	b.out[len(b.out)-1].Control = "association-keymaker-not-supplied"
	scope("association-supplied-broker", "an association supplied by a broker consumer is compared too", BrokerTime, ck(ckAssociation), g, func(in *vectorInputs) {
		in.Association = `{"caller_generation":"` + callerGeneration + `","caller_key":"` + callerKey + `","caller_uid":38602}`
	})

	// Sections remain opaque objects even when their values are not scalars.
	arraySection := func(mutate bool) []byte {
		return with(func(g map[string]any) {
			n := int64(1)
			if mutate {
				n++
			}
			g["broker_time"] = map[string]any{"items": []any{true, false, nil, []any{n, "A"}}}
		})
	}
	arrayRaw := arraySection(false)
	arrayExpected := func(in *vectorInputs) { in.Section = `{"items":[true,false,null,[1,"A"]]}` }
	b.pass("section-array-values", "a section containing booleans, null and nested arrays verifies byte for byte", arrayRaw, BrokerTime, arrayExpected)
	scope("array-element", "one changed element inside a nested array refuses", BrokerTime, ck(ckSection), arraySection(true), arrayExpected)
	b.out[len(b.out)-1].Control = "section-array-values"

	// Stated limits. These pass, and passing is the limit: they are not protection.
	b.pass("limit-second-statement", "LIMIT: a second, different statement signed by the same key verifies once it is the pinned one; superseding is not detected", second, Keymaker, nil)
	b.out[len(b.out)-1].Limit = true
	b.pass("limit-clock-set-back", "LIMIT: the verifier sees only the supplied clock reading; a host clock set back into an expired window verifies", g, Keymaker, now(notAfter.Add(-time.Minute)))
	b.out[len(b.out)-1].Limit = true
	return b.out
}

func marshalVectors(t *testing.T, vs []vector) []byte {
	t.Helper()
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", " ")
	if err := encoder.Encode(vs); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	data, err := os.ReadFile(filepath.FromSlash(vectorFile))
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(data, &vs); err != nil {
		t.Fatal(err)
	}
	return vs
}

func codeOf(err error) (string, string) {
	if err == nil {
		return "pass", ""
	}
	var refusal *Error
	if !errors.As(err, &refusal) {
		return "untyped: " + err.Error(), ""
	}
	return string(refusal.Code), refusal.check
}

// ---- tests ----

// Claim: the scalar/public pairs equal published CSV indices 1, 2 and 3, and changing a scalar fails that comparison.
func TestPublishedKeys(t *testing.T) {
	// Literal secret key/public key columns from bip-0340/test-vectors.csv;
	// independent of the constants used by the vector generator.
	published := []struct {
		index                                  int
		scalar, public, wantScalar, wantPublic string
	}{
		{1, approverSecret, approverPublic,
			"B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
			"DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"},
		{2, otherSecret, otherPublic,
			"C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
			"DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8"},
		{3, thirdSecret, thirdPublic,
			"0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
			"25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517"},
	}
	for _, row := range published {
		matches := func(scalar, public string) bool {
			return strings.ToUpper(scalar) == row.wantScalar && strings.ToUpper(public) == row.wantPublic
		}
		if !matches(row.scalar, row.public) {
			t.Errorf("CSV index %d: pair differs from published columns", row.index)
		}
		changed := []byte(row.scalar)
		changed[0] ^= 1
		if matches(string(changed), row.public) {
			t.Errorf("CSV index %d: planted scalar change was not detected", row.index)
		}
		b, _ := hex.DecodeString(row.scalar)
		_, derived := btcec.PrivKeyFromBytes(b)
		if got := hex.EncodeToString(schnorr.SerializePubKey(derived)); got != row.public {
			t.Errorf("CSV index %d: derived public key differs", row.index)
		}
	}
}

// Claim: the committed vector file is byte-identical to this suite's generated statements and inputs.
// Regenerate with STATICGATE_WRITE_VECTORS=1.
func TestVectorFileIsGenerated(t *testing.T) {
	want := marshalVectors(t, buildVectors())
	path := filepath.FromSlash(vectorFile)
	if os.Getenv("STATICGATE_WRITE_VECTORS") == "1" {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		genuineRaw := enc(genuine())
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), "genuine.ccj"), genuineRaw, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(filepath.Dir(path), "genuine.sig"), []byte(sign(approverSecret, genuineRaw)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("vectors/staticgate/vectors.json differs from the generated vectors")
	}
}

// Claim: genuine.ccj and genuine.sig equal the genuine vector byte for byte and carry the documented preimage digest.
func TestGenuineFiles(t *testing.T) {
	dir := filepath.Dir(filepath.FromSlash(vectorFile))
	raw, err := os.ReadFile(filepath.Join(dir, "genuine.ccj"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(filepath.Join(dir, "genuine.sig"))
	if err != nil {
		t.Fatal(err)
	}
	first := loadVectors(t)[0]
	if first.ID != "genuine-keymaker" || hex.EncodeToString(raw) != first.StatementHex || string(sig) != first.Signature {
		t.Fatal("genuine.ccj or genuine.sig is not the genuine vector")
	}
	if got := sha256.Sum256(append([]byte("swarma-s7 static-gate/1\n"), raw...)); got != Digest(raw) || hex.EncodeToString(got[:]) != first.Inputs.StatementDigest {
		t.Fatal("preimage digest is not SHA-256(tag || LF || statement)")
	}
	spec, err := os.ReadFile("../spec/keymaker-static-gate.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 1491 || len(sig) != 128 || bytes.HasSuffix(raw, []byte("\n")) || bytes.HasSuffix(sig, []byte("\n")) ||
		!bytes.Contains(spec, raw) || !bytes.Contains(spec, []byte(first.Inputs.StatementDigest)) {
		t.Fatal("genuine bytes, sizes, digest or spec example differ")
	}
}

// Claim: example UIDs use the managed range and M0 caller/worker generations use lowercase hex, except explicit shape negatives.
func TestExampleValues(t *testing.T) {
	for _, v := range loadVectors(t) {
		raw, _ := hex.DecodeString(v.StatementHex)
		value, err := strictParse(raw)
		if err != nil {
			continue
		} // malformed byte rows are not copyable examples
		var walk func(any, string)
		walk = func(value any, path string) {
			o, ok := value.(map[string]any)
			if !ok {
				return
			}
			for name, child := range o {
				p := path + name
				if name == "uid" || strings.HasSuffix(name, "_uid") {
					explicitShape := v.ID == "form-association-uid-negative" || v.ID == "form-association-uid-wide" || v.ID == "form-association-uid-string"
					if !explicitShape {
						n, ok := child.(int64)
						if !ok || n < 30000 || n > 59999 {
							t.Errorf("%s: %s is not a managed example UID", v.ID, p)
						}
					}
				}
				if p == "association.caller_generation" || p == "dispatcher.worker.generation" {
					if v.ID != "form-association-generation-empty" && !isHex(child, 32) {
						t.Errorf("%s: %s is not M0-shaped", v.ID, p)
					}
				}
				walk(child, p+".")
			}
		}
		walk(value, "")
	}
	if !isHex(callerGeneration, 32) || !isHex(workerGeneration, 32) || isHex("non-hex", 32) {
		t.Fatal("example shape planted control failed")
	}
}

// Claim (planted control): Keymaker accepts an omitted association, but restoring its old requirement rejects the same positive.
func TestAssociationRequirement(t *testing.T) {
	var positive vector
	for _, v := range loadVectors(t) {
		if v.ID == "association-keymaker-not-supplied" {
			positive = v
		}
	}
	if positive.ID == "" {
		t.Fatal("missing optional-association control")
	}
	if _, err := positive.run(t, Verify); err != nil {
		t.Fatalf("optional association: %v", err)
	}
	saved := members
	members = append([]member(nil), members...)
	defer func() { members = saved }()
	for i := range members {
		if members[i].name == "keymaker" {
			members[i].association = true
		}
	}
	if _, err := positive.run(t, Verify); !errors.Is(err, ErrScopeMismatch) {
		t.Fatalf("restored Keymaker requirement: got %v, want SCOPE_MISMATCH", err)
	}
}

// Claim: every row gives its exact outcome through Verify and the engine; each negative names its check and passing neighbour.
func TestVectors(t *testing.T) {
	vs := loadVectors(t)
	byID := map[string]vector{}
	for _, v := range vs {
		if _, dup := byID[v.ID]; dup {
			t.Fatalf("duplicate vector id %s", v.ID)
		}
		byID[v.ID] = v
	}
	strict := engine{parse: strictParse}
	for _, v := range vs {
		t.Run(v.ID, func(t *testing.T) {
			statement, err := v.run(t, Verify)
			got, by := codeOf(err)
			engineStatement, engineErr := v.run(t, strict.verify)
			engineCode, engineCheck := codeOf(engineErr)
			if statement != engineStatement || got != engineCode || by != engineCheck {
				t.Fatalf("Verify differs from strict engine: %s/%s vs %s/%s", got, by, engineCode, engineCheck)
			}
			if got != v.Expect {
				t.Fatalf("got %s (%s), want %s", got, by, v.Expect)
			}
			if v.Expect == "pass" {
				if len(v.Checks) != 0 || v.Control != "" {
					t.Fatal("a passing vector names no check and no control")
				}
				if statement.Digest != hex32(t, v.Inputs.StatementDigest) || statement.GateID == "" {
					t.Fatal("passing statement lacks its digest or gate_id")
				}
				return
			}
			if statement != (Statement{}) {
				t.Fatal("a refusal returned a non-zero statement")
			}
			if len(v.Checks) == 0 || by != v.Checks[0] {
				t.Fatalf("refused by check %q, vector names %v", by, v.Checks)
			}
			control, ok := byID[v.Control]
			if !ok || control.Expect != "pass" {
				t.Fatalf("control %q is not a passing vector", v.Control)
			}
			if _, err := control.run(t, Verify); err != nil {
				t.Fatalf("control %s refuses: %v", v.Control, err)
			}
			checkNeighbour(t, v, control)
		})
	}
}

// checkNeighbour restricts input-side negatives to one changed field with
// identical bytes/signature. Consumer-name tests alone must change consumer:
// no passing row can use an unknown consumer. Precedence rows intentionally
// combine a bad pin and malformed bytes, so are not input-only negatives.
func checkNeighbour(t *testing.T, v, control vector) {
	t.Helper()
	sameRaw := v.StatementHex == control.StatementHex
	sameSig := v.Signature == control.Signature
	// These checks are purely input-side unless deliberately combined with
	// malformed bytes by the two refusal-order vectors.
	first := check(v.Checks[0])
	pinOrder := v.ID == "order-pin-before-size" || v.ID == "order-pin-before-codec"
	if (first == ckHost || first == ckClass || first == ckWindowNow || (first == ckPin && !pinOrder)) && (!sameRaw || !sameSig) {
		t.Fatal("input-side negative must keep the control's bytes and signature")
	}
	a, b := v.Inputs, control.Inputs
	consumerTest := v.ID == "scope-consumer-unknown" || v.ID == "scope-consumer-is-member"
	if a.Consumer != b.Consumer && !consumerTest {
		t.Fatal("negative and control have different consumers")
	}
	if !sameRaw {
		// Statement mutations necessarily change the digest pin and signature.
		a.StatementDigest = b.StatementDigest
	}
	if v.ID == "signature-key-at-p" || v.ID == "signature-key-nonliftable" {
		// A key-validity test, not an input-only key-pin test.
		raw, _ := hex.DecodeString(v.StatementHex)
		value, err := strictParse(raw)
		if err != nil || object(value.(map[string]any), "approver")["key"] != v.Inputs.ApproverKey {
			t.Fatal("unusable key is not consistently pinned")
		}
		a.ApproverKey = b.ApproverKey
	}
	if a == b {
		if sameRaw && sameSig {
			t.Fatal("negative is identical to its control")
		}
		return
	}
	if !sameRaw || !sameSig {
		t.Fatal("input-side negative also changed statement bytes or signature")
	}
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	changed := ""
	for i := 0; i < va.NumField(); i++ {
		if va.Field(i).String() != vb.Field(i).String() {
			if changed != "" {
				t.Fatal("input-side negative changes more than one field")
			}
			changed = va.Type().Field(i).Name
		}
	}
	allowed := map[check][]string{
		ckKey: {"ApproverKey"}, ckPin: {"StatementDigest"}, ckHost: {"MachineIDSHA256"},
		ckClass: {"Class"}, ckWindowNow: {"Now", "Class"},
		ckSection: {"Section", "Consumer"}, ckAssociation: {"Association"},
	}
	for _, field := range allowed[check(v.Checks[0])] {
		if field == changed {
			return
		}
	}
	t.Fatalf("input field %s does not belong to check %s", changed, v.Checks[0])
}

var allChecks = []check{
	ckSize, ckCodec, ckKey, ckPin, ckCanonical, ckDepth, ckMembers, ckFixed, ckShape,
	ckSignature, ckHost, ckClass, ckWindowWidth, ckWindowNow, ckSection, ckAssociation,
}

// lenientParse is a deliberately broken test-only codec: last duplicate wins,
// trailing bytes/BOMs are ignored, raw controls repaired, invalid UTF-8 replaced
// and lossy number spellings accepted. It is never an acceptance oracle.
func lenientParse(raw []byte) (any, error) {
	raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	var repaired bytes.Buffer
	quoted, escaped := false, false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if quoted {
			if c < 0x20 {
				fmt.Fprintf(&repaired, `\u%04x`, c)
			} else {
				repaired.WriteByte(c)
			}
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
		}
		if c == '+' || c == '-' || (c >= '0' && c <= '9') {
			end := i + 1
			for end < len(raw) && strings.ContainsRune("0123456789.eE+-", rune(raw[end])) {
				end++
			}
			n, err := strconv.ParseFloat(string(raw[i:end]), 64)
			if err != nil {
				return nil, err
			}
			repaired.WriteString(strconv.FormatInt(int64(n), 10))
			i = end - 1
			continue
		}
		repaired.WriteByte(c)
	}
	decoder := json.NewDecoder(bytes.NewReader(repaired.Bytes()))
	decoder.UseNumber()
	var v any
	if err := decoder.Decode(&v); err != nil {
		return nil, err
	}
	return lenientValue(v), nil
}

func lenientValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for name, child := range x {
			x[name] = lenientValue(child)
		}
	case []any:
		for i, child := range x {
			x[i] = lenientValue(child)
		}
	case json.Number:
		f, _ := x.Float64()
		return int64(f)
	}
	return v
}

// Claim (planted control): each negative passes with its named checks removed, refuses with any one retained, and every check has a negative.
// Limit: the plant removes a check through the unexported engine, which the
// exported Verify never does; it does not mutate the source text.
func TestPlantedControls(t *testing.T) {
	refusedBy := map[check]int{}
	alone := map[check]int{}
	for _, v := range loadVectors(t) {
		if v.Expect == "pass" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			planted := func(skip int) engine {
				e := engine{off: map[check]bool{}, parse: strictParse}
				for i, name := range v.Checks {
					if i == skip {
						continue
					}
					e.off[check(name)] = true
					if check(name) == ckCodec {
						e.parse = lenientParse
					}
				}
				return e
			}
			if _, err := v.run(t, planted(-1).verify); err != nil {
				t.Fatalf("with %v removed the negative still refuses: %v", v.Checks, err)
			}
			for i, name := range v.Checks {
				if _, err := v.run(t, planted(i).verify); err == nil {
					t.Fatalf("check %s is not needed to refuse this negative", name)
				}
			}
			refusedBy[check(v.Checks[0])]++
			if len(v.Checks) == 1 {
				alone[check(v.Checks[0])]++
			}
		})
	}
	for _, c := range allChecks {
		if refusedBy[c] == 0 {
			t.Errorf("no negative is refused by check %s", c)
		}
		if alone[c] == 0 && c != ckCodec {
			t.Errorf("no negative depends on check %s alone", c)
		}
	}
	t.Logf("negatives per refusing check: %v", refusedBy)
}

// Claim: the vector set covers every refusal code, every consumer and both classes.
func TestVectorCoverage(t *testing.T) {
	seen := map[string]int{}
	for _, v := range loadVectors(t) {
		seen[v.Expect]++
		seen["consumer:"+v.Inputs.Consumer]++
		seen["class:"+v.Inputs.Class]++
	}
	for _, want := range []string{"pass", string(CodeKey), string(CodePin), string(CodeForm), string(CodeSignature), string(CodeHost), string(CodeWindow), string(CodeScopeMismatch),
		"consumer:keymaker", "consumer:dispatcher", "consumer:source", "consumer:broker_time", "consumer:broker_d5", "class:start", "class:end"} {
		if seen[want] == 0 {
			t.Errorf("no vector for %s", want)
		}
	}
	t.Logf("vector counts: %v", seen)
}

// Claim (planted control): a wrong raw digest pin never invokes the parser, while the correctly pinned positive does.
func TestPinBeforeParse(t *testing.T) {
	v := loadVectors(t)[0]
	calls := 0
	e := engine{parse: func(raw []byte) (any, error) { calls++; return strictParse(raw) }}
	bad := v
	bad.Inputs.StatementDigest = strings.Repeat("0", 64)
	if _, err := bad.run(t, e.verify); !errors.Is(err, ErrPin) || calls != 0 {
		t.Fatalf("wrong pin: got %v, parse calls %d", err, calls)
	}
	if _, err := v.run(t, e.verify); err != nil || calls != 1 {
		t.Fatalf("correct pin: got %v, parse calls %d", err, calls)
	}
}

// Claim: PIN precedes bounded-parse FORM, then KEY precedes canonical FORM, SIGNATURE, HOST, WINDOW and SCOPE_MISMATCH.
func TestRefusalOrder(t *testing.T) {
	bad := with(func(g map[string]any) {
		g["approver"].(map[string]any)["key"] = otherPublic
		g["milestone"] = "G1.1"
		g["keymaker"].(map[string]any)["service_uid"] = int64(38699)
	})
	keyFixed := with(func(g map[string]any) {
		g["milestone"] = "G1.1"
		g["keymaker"].(map[string]any)["service_uid"] = int64(38699)
	})
	formFixed := with(func(g map[string]any) { g["keymaker"].(map[string]any)["service_uid"] = int64(38699) })
	in := func(raw []byte, pin, host, late bool) Inputs {
		v := expected(raw, Keymaker)
		out := Inputs{ApproverKey: hex32(t, approverPublic), MachineIDSHA256: otherMachineID, Now: notAfter, Class: ClassStart,
			Consumer: Keymaker, Section: []byte(v.Section), Association: []byte(v.Association)}
		if pin {
			out.StatementDigest = Digest(raw)
		}
		if host {
			out.MachineIDSHA256 = machineID
		}
		if !late {
			out.Now = inside
		}
		return out
	}
	badSig := []byte(sign(otherSecret, bad))
	steps := []struct {
		raw  []byte
		sig  []byte
		in   Inputs
		want error
	}{
		{[]byte("{"), badSig, in([]byte("{"), false, false, true), ErrPin},
		{[]byte("{"), badSig, in([]byte("{"), true, false, true), ErrForm},
		{bad, badSig, in(bad, false, false, true), ErrPin},
		{bad, badSig, in(bad, true, false, true), ErrKey},
		{keyFixed, badSig, in(keyFixed, true, false, true), ErrForm},
		{formFixed, badSig, in(formFixed, true, false, true), ErrSignature},
		{formFixed, []byte(sign(approverSecret, formFixed)), in(formFixed, true, false, true), ErrHost},
		{formFixed, []byte(sign(approverSecret, formFixed)), in(formFixed, true, true, true), ErrWindow},
		{formFixed, []byte(sign(approverSecret, formFixed)), in(formFixed, true, true, false), ErrScopeMismatch},
		{enc(genuine()), []byte(sign(approverSecret, enc(genuine()))), in(enc(genuine()), true, true, false), nil},
	}
	for _, v := range loadVectors(t) {
		if strings.HasPrefix(v.ID, "order-") {
			_, err := v.run(t, Verify)
			if code, _ := codeOf(err); code != v.Expect {
				t.Errorf("%s: got %v, want %s", v.ID, err, v.Expect)
			}
		}
	}
	for i, step := range steps {
		if _, err := Verify(step.raw, step.sig, step.in); !errors.Is(err, step.want) {
			t.Errorf("step %d: got %v, want %v", i, err, step.want)
		}
	}
}

// Claim: correctly digest-pinned unreadable or non-object bytes refuse with FORM, never a panic or pass, beside a valid positive.
func TestUnreadableBytes(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, []byte("null"), []byte("[]"), []byte(`"x"`), []byte("{"), {0xff, 0xfe}, []byte(`{"approver":{"key":"\ud800"}}`),
		[]byte(strings.Repeat("[", 17) + strings.Repeat("]", 17))} {
		_, err := Verify(raw, nil, Inputs{StatementDigest: Digest(raw)})
		if !errors.Is(err, ErrForm) {
			t.Errorf("%q: got %v, want FORM", raw, err)
		}
	}
	if _, err := loadVectors(t)[0].run(t, Verify); err != nil {
		t.Fatalf("valid neighbour: %v", err)
	}
}

// Claim: zero Inputs refuse a genuine statement with PIN; nothing defaults open, beside a valid positive.
func TestZeroInputsRefuse(t *testing.T) {
	g := enc(genuine())
	if _, err := Verify(g, []byte(sign(approverSecret, g)), Inputs{}); !errors.Is(err, ErrPin) {
		t.Fatalf("got %v, want PIN", err)
	}
	if _, err := loadVectors(t)[0].run(t, Verify); err != nil {
		t.Fatalf("valid neighbour: %v", err)
	}
}

// Claim: error text is the stable code plus failed check, and errors.Is distinguishes codes beside a valid positive.
func TestErrorText(t *testing.T) {
	raw := []byte("{")
	_, err := Verify(raw, nil, Inputs{StatementDigest: Digest(raw)})
	if err == nil || err.Error() != "STATIC_GATE_FORM: codec" || errors.Is(err, ErrKey) || !errors.Is(err, ErrForm) {
		t.Fatalf("unexpected error %v", err)
	}
	if ErrWindow.Error() != "STATIC_GATE_WINDOW" {
		t.Fatal("sentinel text is not the bare code")
	}
	if _, err := loadVectors(t)[0].run(t, Verify); err != nil {
		t.Fatalf("valid neighbour: %v", err)
	}
}

// Claim (LIMIT, not protection): two signed statements pass without the digest pin; the protected pin selects only one.
func TestLimitTwoStatementsWithoutPin(t *testing.T) {
	first := enc(genuine())
	second := with(func(g map[string]any) { g["gate_id"] = "ffeeddccbbaa99887766554433221100" })
	v := expected(first, Keymaker)
	in := Inputs{ApproverKey: hex32(t, approverPublic), StatementDigest: Digest(first), MachineIDSHA256: machineID, Now: inside,
		Class: ClassStart, Consumer: Keymaker, Section: []byte(v.Section), Association: []byte(v.Association)}
	noPin := engine{off: map[check]bool{ckPin: true}, parse: strictParse}
	for name, raw := range map[string][]byte{"first": first, "second": second} {
		if _, err := noPin.verify(raw, []byte(sign(approverSecret, raw)), in); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Verify(second, []byte(sign(approverSecret, second)), in); !errors.Is(err, ErrPin) {
		t.Errorf("with the pin on the first statement, the second gives %v, want PIN", err)
	}
	in.StatementDigest = Digest(second)
	if _, err := Verify(second, []byte(sign(approverSecret, second)), in); err != nil {
		t.Errorf("after the pin is moved, the second statement refuses: %v", err)
	}
}

// Claim (LIMIT, not protection): a start refused after expiry passes when the supplied host clock is set back into the window.
func TestLimitClockSetBack(t *testing.T) {
	g := enc(genuine())
	v := expected(g, Keymaker)
	in := Inputs{ApproverKey: hex32(t, approverPublic), StatementDigest: Digest(g), MachineIDSHA256: machineID,
		Class: ClassStart, Consumer: Keymaker, Section: []byte(v.Section), Association: []byte(v.Association)}
	sig := []byte(sign(approverSecret, g))
	in.Now = notAfter.Add(24 * time.Hour)
	if _, err := Verify(g, sig, in); !errors.Is(err, ErrWindow) {
		t.Fatalf("true time after expiry: got %v, want WINDOW", err)
	}
	in.Now = notAfter.Add(-time.Minute)
	if _, err := Verify(g, sig, in); err != nil {
		t.Fatalf("clock set back: %v", err)
	}
}

// Claim: one row admits an extra section; without the row its presence refuses, and with the row its absence refuses.
func TestSectionTableRow(t *testing.T) {
	extended := with(func(g map[string]any) { g["example_extra"] = map[string]any{"a": int64(1)} })
	in := func(raw []byte) Inputs {
		return Inputs{ApproverKey: hex32(t, approverPublic), StatementDigest: Digest(raw), MachineIDSHA256: machineID, Now: inside, Class: ClassStart,
			Consumer: "example_extra", Section: []byte(`{"a":1}`)}
	}
	if _, err := Verify(extended, []byte(sign(approverSecret, extended)), in(extended)); !errors.Is(err, ErrForm) {
		t.Fatalf("without the row: got %v, want FORM", err)
	}
	saved := members
	members = append(append([]member(nil), members...), member{name: "example_extra", section: true})
	defer func() { members = saved }()
	if _, err := Verify(extended, []byte(sign(approverSecret, extended)), in(extended)); err != nil {
		t.Fatalf("with the row: %v", err)
	}
	g := enc(genuine())
	if _, err := Verify(g, []byte(sign(approverSecret, g)), in(g)); !errors.Is(err, ErrForm) {
		t.Fatalf("with the row, a statement lacking the section: got %v, want FORM", err)
	}
}

// Claim: the documented example call compiles and verifies the genuine files.
func ExampleVerify() {
	raw, _ := os.ReadFile(filepath.FromSlash("../vectors/staticgate/genuine.ccj"))
	sig, _ := os.ReadFile(filepath.FromSlash("../vectors/staticgate/genuine.sig"))
	var key, pinnedDigest [32]byte
	hex.Decode(key[:], []byte(approverPublic))
	// Literal digest supplied by the protected install for the genuine vector.
	hex.Decode(pinnedDigest[:], []byte("a9112c6bc3bfbf86661f0a637c7ad820ecaff1f777be6cc48d2a23b3e27dda41"))
	statement, err := Verify(raw, sig, Inputs{
		ApproverKey:     key,          // from the protected install
		StatementDigest: pinnedDigest, // from the protected install, never Digest(raw)
		MachineIDSHA256: machineID,    // SHA-256 of the machine-id file content
		Now:             inside,       // the host clock
		Class:           ClassStart,   // bind, sign, dispatch or lease
		Consumer:        BrokerD5,     // this consumer's own section
		Section:         []byte(`{"example_acknowledged_head":"` + strings.Repeat("8", 64) + `"}`),
	})
	fmt.Println(statement.GateID, err)
	_, err = Verify(raw, sig, Inputs{})
	fmt.Println(err)
	// Output:
	// 00112233445566778899aabbccddeeff <nil>
	// STATIC_GATE_PIN: pin
}
