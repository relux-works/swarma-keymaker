package stationcaller

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

const testID = "0123456789abcdef0123456789abcdef"

var testPlan = "sha256:" + strings.Repeat("a", 64)

func packet(body string) []byte {
	b := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(b, uint32(len(body)))
	copy(b[4:], body)
	return b
}
func objectFrame(t *testing.T, o control.Object) []byte {
	t.Helper()
	b, err := control.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return packet(string(b))
}
func pubResult() PublicKeyResult {
	return PublicKeyResult{Key: "ed25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Path: "m/6'/1'/2'/2147483647'", RegistrationNumber: 1, Epoch: "epoch"}
}
func sigResult() SignatureResult {
	return SignatureResult{Key: pubResult().Key, Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}
}
func requestObject() control.Object {
	return control.Object{"method": string(SignMethod), "params": control.Object{"plan_id": testPlan, "profile": string(DispatcherRequest)}, "request_id": testID, "timeout_ms": int64(1)}
}
func responseObject() control.Object {
	p := pubResult()
	return control.Object{"request_id": testID, "result": control.Object{"key": p.Key, "master_epoch": p.Epoch, "path": p.Path, "registration_number": p.RegistrationNumber}}
}
func badRequest(t *testing.T, frame []byte, want error) {
	t.Helper()
	r, err := DecodeRequestFrame(frame)
	if !errors.Is(err, want) || r != (Request{}) {
		t.Fatalf("request: %#v, %v; want zero and %v", r, err, want)
	}
}
func badResponse(t *testing.T, m Method, frame []byte, want error) {
	t.Helper()
	r, err := DecodeResponseFrame(m, frame)
	if !errors.Is(err, want) || !reflect.DeepEqual(r, Response{}) {
		t.Fatalf("response: %#v, %v; want zero and %v", r, err, want)
	}
}

// Both profiles and pubkey have exact canonical bytes and typed values; timeout
// endpoints are accepted. This is wire equivalence, not a signing control.
func TestRequestReferenceBytes(t *testing.T) {
	for _, tc := range []struct {
		r    Request
		body string
	}{
		{Request{ID: testID, TimeoutMS: 1, Method: PubkeyMethod}, `{"method":"station_caller_pubkey","params":{},"request_id":"` + testID + `","timeout_ms":1}`},
		{Request{ID: testID, TimeoutMS: 2000, Method: SignMethod, Profile: DispatcherRequest, PlanID: testPlan}, `{"method":"sign_station_caller","params":{"plan_id":"` + testPlan + `","profile":"dispatcher-request/1"},"request_id":"` + testID + `","timeout_ms":2000}`},
		{Request{ID: testID, TimeoutMS: 1, Method: SignMethod, Profile: CallerDelegation, PlanID: testPlan}, `{"method":"sign_station_caller","params":{"plan_id":"` + testPlan + `","profile":"caller-delegation/1"},"request_id":"` + testID + `","timeout_ms":1}`},
	} {
		frame, err := EncodeRequestFrame(tc.r)
		if err != nil || !bytes.Equal(frame, packet(tc.body)) {
			t.Fatalf("encode: %q %v", frame, err)
		}
		r, err := DecodeRequestFrame(packet(tc.body))
		if err != nil || r != tc.r {
			t.Fatalf("decode: %#v %v", r, err)
		}
	}
}

// Every unsupported profile spelling is refused in both directions with no
// partial value; both published profiles remain nearby positive controls.
func TestSignProfileVocabulary(t *testing.T) {
	for _, profile := range []Profile{"", "dispatcher-request/2", "Dispatcher-request/1", "dispatcher-request/1 ", "caller-delegation/2", "grant/1"} {
		t.Run(string(profile), func(t *testing.T) {
			o := requestObject()
			o["params"].(control.Object)["profile"] = string(profile)
			badRequest(t, objectFrame(t, o), ErrRequest)
			b, err := EncodeRequestFrame(Request{ID: testID, TimeoutMS: 1, Method: SignMethod, Profile: profile, PlanID: testPlan})
			if err != ErrRequest || b != nil {
				t.Fatalf("encoded invalid profile: %q %v", b, err)
			}
		})
	}
	for _, p := range []Profile{DispatcherRequest, CallerDelegation} {
		b, err := EncodeRequestFrame(Request{ID: testID, TimeoutMS: 1, Method: SignMethod, Profile: p, PlanID: testPlan})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeRequestFrame(b); err != nil {
			t.Fatal(err)
		}
	}
}

// Closed envelope/params reject missing, unknown and mistyped fields; native
// IDs/plan IDs/timeouts keep exact source types and bounds, without coercion.
func TestRequestSchemaAndBounds(t *testing.T) {
	cases := []struct {
		name   string
		change func(control.Object)
	}{
		{"missing-method", func(o control.Object) { delete(o, "method") }},
		{"extra-envelope", func(o control.Object) { o["extra"] = true }},
		{"hello", func(o control.Object) { o["method"] = "hello" }},
		{"generic-sign", func(o control.Object) { o["method"] = "sign" }},
		{"method-type", func(o control.Object) { o["method"] = int64(1) }},
		{"params-null", func(o control.Object) { o["params"] = nil }},
		{"params-array", func(o control.Object) { o["params"] = []any{} }},
		{"missing-profile", func(o control.Object) { delete(o["params"].(control.Object), "profile") }},
		{"missing-plan", func(o control.Object) { delete(o["params"].(control.Object), "plan_id") }},
		{"profile-type", func(o control.Object) { o["params"].(control.Object)["profile"] = int64(1) }},
		{"plan-type", func(o control.Object) { o["params"].(control.Object)["plan_id"] = nil }},
		{"extra-identity", func(o control.Object) { o["params"].(control.Object)["uid"] = int64(1) }},
		{"pubkey-with-params", func(o control.Object) { o["method"] = string(PubkeyMethod) }},
	}
	for _, field := range []string{"request_id", "timeout_ms", "params"} {
		f := field
		cases = append(cases, struct {
			name   string
			change func(control.Object)
		}{"missing-" + f, func(o control.Object) { delete(o, f) }})
	}
	for _, id := range []any{nil, int64(1), "", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32)} {
		v := id
		cases = append(cases, struct {
			name   string
			change func(control.Object)
		}{"id", func(o control.Object) { o["request_id"] = v }})
	}
	for _, ms := range []any{nil, "1", int64(0), int64(-1), int64(2001)} {
		v := ms
		cases = append(cases, struct {
			name   string
			change func(control.Object)
		}{"timeout", func(o control.Object) { o["timeout_ms"] = v }})
	}
	for _, plan := range []string{"", strings.Repeat("a", 64), "sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("g", 64), testPlan + "a"} {
		v := plan
		cases = append(cases, struct {
			name   string
			change func(control.Object)
		}{"plan", func(o control.Object) { o["params"].(control.Object)["plan_id"] = v }})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { o := requestObject(); tc.change(o); badRequest(t, objectFrame(t, o), ErrRequest) })
	}
	for _, r := range []Request{{}, {ID: testID, TimeoutMS: 0, Method: PubkeyMethod}, {ID: testID, TimeoutMS: 2001, Method: PubkeyMethod}, {ID: testID, TimeoutMS: 1, Method: PubkeyMethod, Profile: DispatcherRequest}, {ID: testID, TimeoutMS: 1, Method: PubkeyMethod, PlanID: testPlan}, {ID: testID, TimeoutMS: 1, Method: "hello"}} {
		if b, err := EncodeRequestFrame(r); err != ErrRequest || b != nil {
			t.Fatalf("encoded invalid request %#v: %q %v", r, b, err)
		}
	}
}

// Success encodings have exact result members and method context. Opaque epochs
// preserve Unicode normalization distinctions, permitted canonical controls and
// the full frame cap; no UUID/ASCII or arbitrary short epoch cap is invented.
func TestResponseReferenceAndEpochBounds(t *testing.T) {
	p := pubResult()
	s := sigResult()
	for _, tc := range []struct {
		method Method
		r      Response
		body   string
	}{
		{PubkeyMethod, Response{ID: testID, PublicKey: &p}, `{"request_id":"` + testID + `","result":{"key":"` + p.Key + `","master_epoch":"epoch","path":"` + p.Path + `","registration_number":1}}`},
		{SignMethod, Response{ID: testID, Signature: &s}, `{"request_id":"` + testID + `","result":{"key":"` + s.Key + `","sig":"` + s.Signature + `"}}`},
	} {
		b, err := EncodeResponseFrame(tc.method, tc.r)
		if err != nil || !bytes.Equal(b, packet(tc.body)) {
			t.Fatalf("encode: %q %v", b, err)
		}
		r, err := DecodeResponseFrame(tc.method, packet(tc.body))
		if err != nil || !reflect.DeepEqual(r, tc.r) {
			t.Fatalf("decode: %#v %v", r, err)
		}
		other := PubkeyMethod
		if tc.method == PubkeyMethod {
			other = SignMethod
		}
		badResponse(t, other, b, ErrResponse)
	}
	for _, epoch := range []string{"é", "e\u0301", "😀\u00a0", "\x00\x1f\x7f\n\r\t\b\f\"\\/"} {
		p.Epoch = epoch
		b, err := EncodeResponseFrame(PubkeyMethod, Response{ID: testID, PublicKey: &p})
		if err != nil {
			t.Fatal(err)
		}
		r, err := DecodeResponseFrame(PubkeyMethod, b)
		if err != nil || r.PublicKey.Epoch != epoch {
			t.Fatalf("epoch altered: %#v %v", r, err)
		}
	}
	p = pubResult()
	p.Epoch = "x"
	b, err := EncodeResponseFrame(PubkeyMethod, Response{ID: testID, PublicKey: &p})
	if err != nil {
		t.Fatal(err)
	}
	p.Epoch = strings.Repeat("x", MaxFrame-(len(b)-4)+1)
	b, err = EncodeResponseFrame(PubkeyMethod, Response{ID: testID, PublicKey: &p})
	if err != nil || len(b) != MaxFrame+4 {
		t.Fatalf("max frame: %d %v", len(b), err)
	}
	if r, err := DecodeResponseFrame(PubkeyMethod, b); err != nil || r.PublicKey.Epoch != p.Epoch {
		t.Fatal("maximum control", err)
	}
	p.Epoch += "x"
	if b, err := EncodeResponseFrame(PubkeyMethod, Response{ID: testID, PublicKey: &p}); err != ErrCanonical || b != nil {
		t.Fatalf("oversized encoded: %d %v", len(b), err)
	}
}

// Result grammar rejects foreign shapes, extra/missing/mistyped members and
// noncanonical key/signature/path/number/epoch values, returning no partial success.
func TestResponseSchemaAndFields(t *testing.T) {
	for _, field := range []string{"key", "path", "registration_number", "master_epoch"} {
		o := responseObject()
		delete(o["result"].(control.Object), field)
		badResponse(t, PubkeyMethod, objectFrame(t, o), ErrResponse)
		o = responseObject()
		o["result"].(control.Object)[field] = nil
		badResponse(t, PubkeyMethod, objectFrame(t, o), ErrResponse)
	}
	changes := []func(control.Object){
		func(o control.Object) { o["extra"] = true }, func(o control.Object) { o["error"] = control.Object{} }, func(o control.Object) { delete(o, "request_id") },
		func(o control.Object) { o["request_id"] = nil }, func(o control.Object) { o["request_id"] = "bad" }, func(o control.Object) { o["request_id"] = int64(1) },
		func(o control.Object) { o["result"] = nil }, func(o control.Object) { o["result"] = []any{} }, func(o control.Object) { o["result"].(control.Object)["extra"] = true },
	}
	for _, change := range changes {
		o := responseObject()
		change(o)
		badResponse(t, PubkeyMethod, objectFrame(t, o), ErrResponse)
	}
	for _, n := range []any{int64(0), int64(-1), "1", control.MaxInteger + 1} {
		o := responseObject()
		o["result"].(control.Object)["registration_number"] = n
		if n == control.MaxInteger+1 {
			p := pubResult()
			p.RegistrationNumber = MaxRegistrationNumber + 1
			if b, err := EncodeResponseFrame(PubkeyMethod, Response{ID: testID, PublicKey: &p}); err != ErrResponse || b != nil {
				t.Fatal("unsafe integer encoded")
			}
			continue
		}
		badResponse(t, PubkeyMethod, objectFrame(t, o), ErrResponse)
	}
	for _, n := range []int64{1, MaxRegistrationNumber} {
		p := pubResult()
		p.RegistrationNumber = n
		b, err := EncodeResponseFrame(PubkeyMethod, Response{ID: testID, PublicKey: &p})
		if err != nil {
			t.Fatal(err)
		}
		r, err := DecodeResponseFrame(PubkeyMethod, b)
		if err != nil || r.PublicKey.RegistrationNumber != n {
			t.Fatal("number control", err)
		}
	}
	for _, path := range []string{"", "m/1'/1'/2'/3'", "m/6'/0'/1'/1'", "m/6'/1'/1'/0'", "m/6'/1'/0'/1'", "m/6'/1'/2'/3", "m/6'/1'/2'/2147483648'", "m/6'/01'/2'/3'", "m/6'/+1'/2'/3'", "m/06'/1'/2'/3'", "m/6'/1'/2'/3'/4'", "m/6'/1'/2'", "M/6'/1'/2'/3'"} {
		o := responseObject()
		o["result"].(control.Object)["path"] = path
		badResponse(t, PubkeyMethod, objectFrame(t, o), ErrResponse)
	}
	for _, key := range []string{"", pubResult().Key + "=", strings.Replace(pubResult().Key, "ed25519:", "Ed25519:", 1), "ed25519:" + strings.Repeat("A", 42), "ed25519:" + strings.Repeat("A", 42) + "B", "ed25519:" + strings.Repeat("/", 43), "ed25519:" + strings.Repeat("A", 42) + "\n"} {
		o := responseObject()
		o["result"].(control.Object)["key"] = key
		badResponse(t, PubkeyMethod, objectFrame(t, o), ErrResponse)
	}
	for _, sig := range []any{nil, int64(1), "", sigResult().Signature + "=", strings.Repeat("A", 85), strings.Repeat("A", 85) + "B", strings.Repeat("/", 86)} {
		o := control.Object{"request_id": testID, "result": control.Object{"key": pubResult().Key, "sig": sig}}
		badResponse(t, SignMethod, objectFrame(t, o), ErrResponse)
	}
	for _, o := range []control.Object{{"request_id": testID, "result": control.Object{"key": pubResult().Key}}, {"request_id": testID, "result": control.Object{"key": pubResult().Key, "sig": sigResult().Signature, "extra": true}}} {
		badResponse(t, SignMethod, objectFrame(t, o), ErrResponse)
	}
	o := responseObject()
	o["result"].(control.Object)["master_epoch"] = ""
	badResponse(t, PubkeyMethod, objectFrame(t, o), ErrResponse)
	p := pubResult()
	p.Epoch = string([]byte{255})
	if b, err := EncodeResponseFrame(PubkeyMethod, Response{ID: testID, PublicKey: &p}); err != ErrCanonical || b != nil {
		t.Fatal("invalid epoch UTF8 encoded")
	}
	p = pubResult()
	s := sigResult()
	for _, r := range []Response{{}, {ID: testID, PublicKey: &p, Signature: &s}, {ID: testID, PublicKey: &p, Refusal: &Refusal{Code: Unqualified}}, {PublicKey: &p}, {ID: "bad", Signature: &s}} {
		if b, err := EncodeResponseFrame(PubkeyMethod, r); err != ErrResponse || b != nil {
			t.Fatal("invalid union encoded", err)
		}
	}
	if b, err := EncodeResponseFrame("hello", Response{ID: testID, PublicKey: &p}); err != ErrResponse || b != nil {
		t.Fatal("foreign response method")
	}
}

// The closed refusal vocabulary preserves retryability exactly, including the
// three full proposed names and null IDs before request parsing. A decoded wire
// refusal succeeds as a value; malformed errors never masquerade as one.
func TestRefusalVocabularyAndRetryability(t *testing.T) {
	groups := []struct {
		codes string
		retry bool
	}{
		{"rate_limited busy generation_source_unavailable enrollment_unavailable audit_unavailable request_deadline_exceeded", true},
		{"frame_too_large frame_truncated frame_malformed ccj_noncanonical request_malformed request_conflict version_unsupported hello_required hello_already_negotiated operation_unsupported registration_malformed registration_signature_invalid registration_id_mismatch custody_unavailable peer_identity_unavailable generation_source_fenced generation_inactive generation_mismatch binding_not_found peer_binding_mismatch binding_conflict role_not_permitted identity_revoked persistent_revoke_requires_operator operator_record_unavailable operator_record_invalid path_not_hardened path_invalid purpose_unknown name_invalid name_unknown name_registry_invalid index_exhausted sign_data_not_sshsig sshsig_malformed namespace_not_permitted sign_key_mismatch sign_flags_unsupported agent_message_unsupported request_expired enrollment_unverified enrollment_unsupported host_revoked uid_map_required uid_not_permitted name_not_permitted audience_mismatch key_not_enrolled key_not_valid_now entropy_unavailable clock_untrusted state_capacity_exceeded provision_state_invalid binding_provisioned message_too_large signer_identity_unavailable signer_identity_malformed signer_identity_mismatch station_caller_unqualified station_caller_plan_unavailable station_caller_plan_invalid", false},
	}
	for _, g := range groups {
		for _, code := range strings.Fields(g.codes) {
			t.Run(code, func(t *testing.T) {
				id := testID
				if framingCode(code) {
					id = ""
				}
				r := Response{ID: id, Refusal: &Refusal{Code: code, Retryable: g.retry}}
				b, err := EncodeResponseFrame(SignMethod, r)
				if err != nil {
					t.Fatal(err)
				}
				got, err := DecodeResponseFrame(SignMethod, b)
				if err != nil || !reflect.DeepEqual(got, r) {
					t.Fatalf("wire refusal lost: %#v %v", got, err)
				}
				r.Refusal.Retryable = !g.retry
				if b, err := EncodeResponseFrame(SignMethod, r); err != ErrResponse || b != nil {
					t.Fatal("wrong retryability encoded")
				}
				o := control.Object{"error": control.Object{"code": code, "retryable": !g.retry}, "request_id": nil}
				badResponse(t, SignMethod, objectFrame(t, o), ErrResponse)
			})
		}
	}
	for _, id := range []any{nil, testID} {
		o := control.Object{"error": control.Object{"code": Unqualified, "retryable": false}, "request_id": id}
		r, err := DecodeResponseFrame(PubkeyMethod, objectFrame(t, o))
		if err != nil || r.Refusal == nil {
			t.Fatal("null/echo control", err)
		}
	}
	for _, code := range []string{"", "plan_invalid", "plan_unavailable", "station_caller_plan_invalid ", "foreign_error"} {
		o := control.Object{"error": control.Object{"code": code, "retryable": false}, "request_id": nil}
		badResponse(t, SignMethod, objectFrame(t, o), ErrResponse)
	}
	for _, e := range []any{nil, control.Object{"code": Unqualified}, control.Object{"code": Unqualified, "retryable": int64(0)}, control.Object{"code": int64(1), "retryable": false}, control.Object{"code": Unqualified, "retryable": false, "detail": "extra"}} {
		badResponse(t, PubkeyMethod, objectFrame(t, control.Object{"error": e, "request_id": nil}), ErrResponse)
	}
	badResponse(t, PubkeyMethod, objectFrame(t, control.Object{"error": control.Object{"code": "ccj_noncanonical", "retryable": false}, "request_id": testID}), ErrResponse)
}

// Canonical grammar families are grounded in base CCJ-1, not a permissive JSON
// parser. The same valid request is the nearby control for every wire mutation.
func TestCanonicalGrammarFamilies(t *testing.T) {
	good := `{"method":"station_caller_pubkey","params":{},"request_id":"` + testID + `","timeout_ms":1}`
	cases := map[string]string{
		"bom": "\xef\xbb\xbf" + good, "utf16": "\xff\xfe{\x00}", "invalid-utf8": strings.Replace(good, "pubkey", "pub\xffkey", 1),
		"space": " " + good, "newline": good + "\n", "CR": good + "\r", "CRLF": good + "\r\n", "mixed-line": strings.Replace(good, ",", ",\n\r", 1),
		"unicode-blank": "\u00a0" + good, "raw-control": strings.Replace(good, "pubkey", "pub\x00key", 1),
		"comment": good + "//comment", "block-comment": strings.Replace(good, "{}", "{/*comment*/}", 1), "yaml": "method: station_caller_pubkey\n",
		"escape-slash": strings.Replace(good, "station_caller_pubkey", `station\u005fcaller_pubkey`, 1), "surrogate": strings.Replace(good, "station_caller_pubkey", `\ud800`, 1),
		"duplicate": strings.Replace(good, `"params":{}`, `"params":{},"params":{}`, 1), "unsorted": strings.Replace(good, `"method":"station_caller_pubkey","params":{}`, `"params":{},"method":"station_caller_pubkey"`, 1),
		"float": strings.Replace(good, `"timeout_ms":1`, `"timeout_ms":1.0`, 1), "exponent": strings.Replace(good, `"timeout_ms":1`, `"timeout_ms":1e0`, 1), "negative-zero": strings.Replace(good, `"timeout_ms":1`, `"timeout_ms":-0`, 1),
		"leading-zero": strings.Replace(good, `"timeout_ms":1`, `"timeout_ms":01`, 1), "hex": strings.Replace(good, `"timeout_ms":1`, `"timeout_ms":0x1`, 1), "unsafe-integer": strings.Replace(good, `"timeout_ms":1`, `"timeout_ms":9007199254740992`, 1),
		"second-document": good + "{}", "root-array": "[]", "depth17": `{"a":` + strings.Repeat("[", 16) + "0" + strings.Repeat("]", 16) + "}",
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			badRequest(t, packet(bad), ErrCanonical)
			if _, err := DecodeRequestFrame(packet(good)); err != nil {
				t.Fatal("valid control", err)
			}
		})
	}
	// Sixteen containers meet CCJ-1's depth bound but still fail this closed schema.
	badRequest(t, packet(`{"a":`+strings.Repeat("[", 15)+"0"+strings.Repeat("]", 15)+"}"), ErrRequest)
	for _, token := range []string{"null", "{}", "true", `"1"`} {
		badRequest(t, packet(strings.Replace(good, `"timeout_ms":1`, `"timeout_ms":`+token, 1)), ErrRequest)
	}
}

// Exact frames refuse every truncated prefix, zero/huge headers and trailing
// data before returning any typed value; a complete nearby frame succeeds.
func TestFrameBoundaries(t *testing.T) {
	good, _ := EncodeRequestFrame(Request{ID: testID, Method: PubkeyMethod, TimeoutMS: 1})
	for n := 0; n < len(good); n++ {
		badRequest(t, good[:n], ErrFrameTruncated)
	}
	badRequest(t, make([]byte, 4), ErrFrameMalformed)
	for _, n := range []uint32{MaxFrame + 1, ^uint32(0)} {
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, n)
		badRequest(t, header, ErrFrameTooLarge)
	}
	for _, tail := range [][]byte{{0}, good} {
		badRequest(t, append(append([]byte{}, good...), tail...), ErrTrailingData)
	}
	p := pubResult()
	b, _ := EncodeResponseFrame(PubkeyMethod, Response{ID: testID, PublicKey: &p})
	badResponse(t, PubkeyMethod, b[:len(b)-1], ErrFrameTruncated)
	badResponse(t, PubkeyMethod, append(b, 0), ErrTrailingData)
	if _, err := DecodeRequestFrame(good); err != nil {
		t.Fatal(err)
	}
}

// Accepted seed frames re-encode identically; every failed parse returns zero.
// This seed check is not a claim of exhaustive fuzzing or signature validity.
func FuzzRequestFrame(f *testing.F) {
	b, _ := EncodeRequestFrame(Request{ID: testID, TimeoutMS: 1, Method: SignMethod, Profile: DispatcherRequest, PlanID: testPlan})
	f.Add(b)
	f.Add([]byte{})
	f.Add(packet(`{}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRequestFrame(b)
		if err != nil {
			if r != (Request{}) {
				t.Fatal("partial value")
			}
			return
		}
		encoded, err := EncodeRequestFrame(r)
		if err != nil || !bytes.Equal(encoded, b) {
			t.Fatal("accepted bytes changed", err)
		}
	})
}
