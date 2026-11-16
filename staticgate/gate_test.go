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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-registrar/ccj"
)

// The only keys used are rows 1, 2 and 3 of the published BIP-340 test
// vectors. They are public test data and must never approve anything real.
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

func (v vector) run(t *testing.T, e engine) (Statement, error) {
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
	return e.verify(raw, []byte(v.Signature), in)
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
		"association": map[string]any{"caller_generation": "g-example-1", "caller_key": callerKey, "caller_uid": int64(28601)},
		"keymaker": map[string]any{
			"service_uid": int64(28600), "binary_sha256": strings.Repeat("3", 64),
			"config_sha256": strings.Repeat("4", 64), "j7_request_key": strings.Repeat("5", 64),
		},
		"dispatcher": map[string]any{
			"service_uid": int64(28602), "receiver": strings.Repeat("6", 32), "policy_sha256": strings.Repeat("7", 64),
			"config_sha256": strings.Repeat("9", 64),
			"worker":        map[string]any{"generation": "w-example-1", "uid": int64(28603)},
		},
		"source":      map[string]any{"service_uid": int64(28604), "generation": "s-example-1", "config_sha256": strings.Repeat("a", 64)},
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

func consumesAssociation(c Consumer) bool { return c == Keymaker || c == Dispatcher }

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
	b.add(id, claim, string(code), checks, "genuine-"+string(Keymaker), raw, sign(approverSecret, raw), in)
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

	// Step 1, key pin.
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
	shape("association-uid-string", "a caller UID as a string refuses", BrokerTime, only, sub("association", "caller_uid", "28601"))
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
	window("class-unknown", "an operation class other than start or end refuses", "genuine-keymaker", ck(ckClass), g, func(in *vectorInputs) { in.Class = "bind" })
	window("class-empty", "an unset operation class refuses", "genuine-keymaker", ck(ckClass), g, func(in *vectorInputs) { in.Class = "" })
	span := func(d time.Duration) []byte {
		return with(func(g map[string]any) { g["not_after"] = notBefore.Add(d).Format(timeLayout) })
	}
	b.pass("width-72h", "a window of exactly 72 hours verifies", span(MaxWindow), Keymaker, nil)
	window("width-72h-1s", "a window of 72 hours and one second refuses a start", "width-72h", ck(ckWindowWidth), span(MaxWindow+time.Second), nil)
	window("width-72h-1s-end", "a window of 72 hours and one second refuses an end too", "width-72h", ck(ckWindowWidth), span(MaxWindow+time.Second), end)
	window("width-zero-end", "an empty window refuses an end", "end-after-expiry", ck(ckWindowWidth), span(0), end)
	window("width-negative-end", "not_after before not_before refuses an end", "end-after-expiry", ck(ckWindowWidth), span(-time.Hour), end)
	window("width-zero-start", "an empty window refuses a start", "genuine-keymaker", ck(ckWindowWidth, ckWindowNow), span(0), now(notBefore))

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
	for _, c := range []Consumer{Keymaker, Dispatcher} {
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
		for _, c := range []Consumer{Keymaker, Dispatcher} {
			scope("generation-"+id+"-"+string(c), claim, c, ck(ckAssociation), with(sub("association", "caller_generation", generation)), nil)
		}
	}
	respell("case", "a caller generation differing only in letter case refuses", "G-example-1")
	respell("trailing-space", "a caller generation with a trailing space refuses", "g-example-1 ")
	respell("lookalike", "a caller generation with a look-alike letter (U+0435 for e) refuses", "g-\u0435xample-1")
	scope("generation-worker-case", "a worker generation differing only in letter case refuses the dispatcher", Dispatcher, ck(ckSection), with(func(g map[string]any) {
		g["dispatcher"].(map[string]any)["worker"].(map[string]any)["generation"] = "W-example-1"
	}), nil)
	nfc := with(sub("association", "caller_generation", "g-caf\u00e9-1"))
	nfd := with(sub("association", "caller_generation", "g-cafe\u0301-1"))
	composed := func(in *vectorInputs) {
		in.Association = `{"caller_generation":"g-caf` + "\u00e9" + `-1","caller_key":"` + callerKey + `","caller_uid":28601}`
	}
	b.pass("generation-nfc", "a non-ASCII generation verifies when the bytes are equal", nfc, Dispatcher, composed)
	scope("generation-nfd", "the same generation in decomposed form refuses: nothing is normalised", Dispatcher, ck(ckAssociation), nfd, composed)
	b.out[len(b.out)-1].Control = "generation-nfc"
	scope("consumer-unknown", "an unknown consumer name refuses", Consumer("unknown"), ck(ckSection), g, func(in *vectorInputs) { in.Section = `{"a":1}` })
	b.out[len(b.out)-1].Control = "genuine-keymaker"
	scope("consumer-is-member", "a member that is not a section cannot be consumed", Consumer("host"), ck(ckSection), g, func(in *vectorInputs) { in.Section = string(enc(genuine()["host"])) })
	b.out[len(b.out)-1].Control = "genuine-keymaker"
	scope("section-expected-empty", "an empty expected section refuses", BrokerD5, ck(ckSection), g, func(in *vectorInputs) { in.Section = "" })
	scope("section-expected-spaced", "expected bytes that are not canonical refuse", BrokerD5, ck(ckSection), g, func(in *vectorInputs) { in.Section = strings.Replace(in.Section, ":", ": ", 1) })
	scope("association-expected-missing", "the dispatcher must supply the expected association", Dispatcher, ck(ckAssociation), g, func(in *vectorInputs) { in.Association = "" })
	scope("association-expected-missing-keymaker", "Keymaker must supply the expected association", Keymaker, ck(ckAssociation), g, func(in *vectorInputs) { in.Association = "" })
	scope("association-supplied-broker", "an association supplied by a broker consumer is compared too", BrokerTime, ck(ckAssociation), g, func(in *vectorInputs) {
		in.Association = `{"caller_generation":"g-example-1","caller_key":"` + callerKey + `","caller_uid":28602}`
	})

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

// Claim: the test keys are the published BIP-340 rows, not generated secrets.
func TestPublishedKeys(t *testing.T) {
	for secret, public := range map[string]string{approverSecret: approverPublic, otherSecret: otherPublic, thirdSecret: thirdPublic} {
		b, _ := hex.DecodeString(secret)
		_, derived := btcec.PrivKeyFromBytes(b)
		if got := hex.EncodeToString(schnorr.SerializePubKey(derived)); got != public {
			t.Errorf("public key for published row: got %s want %s", got, public)
		}
	}
}

// Claim: the committed vector file is exactly what this suite generates, so a
// reader of the file and a reader of the test see the same statements.
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

// Claim: the readable genuine statement and signature files are the genuine
// vector byte for byte, with no final LF, and carry the documented digest.
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
}

// Claim: every committed vector gives exactly its stated result through the
// exported Verify, every negative is refused by the check it names, and every
// negative stands beside a control that passes.
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
			statement, err := v.run(t, strict)
			got, by := codeOf(err)
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
			if _, err := control.run(t, strict); err != nil {
				t.Fatalf("control %s refuses: %v", v.Control, err)
			}
		})
	}
}

var allChecks = []check{
	ckSize, ckCodec, ckKey, ckPin, ckCanonical, ckDepth, ckMembers, ckFixed, ckShape,
	ckSignature, ckHost, ckClass, ckWindowWidth, ckWindowNow, ckSection, ckAssociation,
}

// lenientParse stands in for a decoder without the codec rules: it keeps the
// last duplicate and accepts any number spelling. Test only.
func lenientParse(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
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

// Claim (planted control): each check is what refuses its negatives. With the
// checks a vector names removed, the negative verifies; with any single one of
// them still in place, it does not. Every check has at least one negative that
// names it alone or first, so no check is untested.
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
			if _, err := v.run(t, planted(-1)); err != nil {
				t.Fatalf("with %v removed the negative still refuses: %v", v.Checks, err)
			}
			for i, name := range v.Checks {
				if _, err := v.run(t, planted(i)); err == nil {
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

// Claim: checks run in the specified order. A statement that violates every
// step refuses with the earliest code, and repairing steps one at a time
// walks through KEY, PIN, FORM, SIGNATURE, HOST, WINDOW, SCOPE_MISMATCH.
func TestRefusalOrder(t *testing.T) {
	bad := with(func(g map[string]any) {
		g["approver"].(map[string]any)["key"] = otherPublic
		g["milestone"] = "G1.1"
		g["keymaker"].(map[string]any)["service_uid"] = int64(1)
	})
	keyFixed := with(func(g map[string]any) {
		g["milestone"] = "G1.1"
		g["keymaker"].(map[string]any)["service_uid"] = int64(1)
	})
	formFixed := with(func(g map[string]any) { g["keymaker"].(map[string]any)["service_uid"] = int64(1) })
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
		{bad, badSig, in(bad, false, false, true), ErrKey},
		{keyFixed, badSig, in(keyFixed, false, false, true), ErrPin},
		{keyFixed, badSig, in(keyFixed, true, false, true), ErrForm},
		{formFixed, badSig, in(formFixed, true, false, true), ErrSignature},
		{formFixed, []byte(sign(approverSecret, formFixed)), in(formFixed, true, false, true), ErrHost},
		{formFixed, []byte(sign(approverSecret, formFixed)), in(formFixed, true, true, true), ErrWindow},
		{formFixed, []byte(sign(approverSecret, formFixed)), in(formFixed, true, true, false), ErrScopeMismatch},
	}
	for i, step := range steps {
		if _, err := Verify(step.raw, step.sig, step.in); !errors.Is(err, step.want) {
			t.Errorf("step %d: got %v, want %v", i, err, step.want)
		}
	}
}

// Claim: bytes that cannot be parsed refuse with FORM, never with a panic or a
// pass, whatever the other inputs are.
func TestUnreadableBytes(t *testing.T) {
	for _, raw := range [][]byte{nil, {}, []byte("null"), []byte("[]"), []byte(`"x"`), []byte("{"), {0xff, 0xfe}, []byte(`{"approver":{"key":"\ud800"}}`),
		[]byte(strings.Repeat("[", 17) + strings.Repeat("]", 17))} {
		_, err := Verify(raw, nil, Inputs{})
		if !errors.Is(err, ErrForm) {
			t.Errorf("%q: got %v, want FORM", raw, err)
		}
	}
}

// Claim: the zero Inputs refuse a genuine statement; nothing defaults open.
func TestZeroInputsRefuse(t *testing.T) {
	g := enc(genuine())
	if _, err := Verify(g, []byte(sign(approverSecret, g)), Inputs{}); !errors.Is(err, ErrKey) {
		t.Fatalf("got %v, want KEY", err)
	}
}

// Claim: the error text is the stable code followed by the failed check, and
// errors.Is distinguishes codes.
func TestErrorText(t *testing.T) {
	_, err := Verify([]byte("{"), nil, Inputs{})
	if err == nil || err.Error() != "STATIC_GATE_FORM: codec" || errors.Is(err, ErrKey) || !errors.Is(err, ErrForm) {
		t.Fatalf("unexpected error %v", err)
	}
	if ErrWindow.Error() != "STATIC_GATE_WINDOW" {
		t.Fatal("sentinel text is not the bare code")
	}
}

// LIMIT, not protection: without the digest pin, two different statements
// signed by the approver inside their windows both verify under the same
// inputs. The pin only selects one of them; it sits in the same trust domain.
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

// LIMIT, not protection: the verifier has no clock of its own. The same
// expired statement refuses a start at the true time and verifies when the
// supplied reading is set back inside the window.
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

// Claim: adding one closed section is one table row. With a row for an
// invented `example_extra` section, the statement that carries it verifies
// for the new consumer and the statement without it refuses with FORM; without
// the row the same statement refuses with FORM. The row is removed afterwards.
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
	var key [32]byte
	hex.Decode(key[:], []byte(approverPublic))
	statement, err := Verify(raw, sig, Inputs{
		ApproverKey:     key,         // from the protected install
		StatementDigest: Digest(raw), // in production: the pinned value, not recomputed
		MachineIDSHA256: machineID,   // SHA-256 of the machine-id file content
		Now:             inside,      // the host clock
		Class:           ClassStart,  // bind, sign, dispatch or lease
		Consumer:        BrokerD5,    // this consumer's own section
		Section:         []byte(`{"example_acknowledged_head":"` + strings.Repeat("8", 64) + `"}`),
	})
	fmt.Println(statement.GateID, err)
	_, err = Verify(raw, sig, Inputs{})
	fmt.Println(err)
	// Output:
	// 00112233445566778899aabbccddeeff <nil>
	// STATIC_GATE_KEY: key
}
