package messageauthor

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

const wireID = "0123456789abcdef0123456789abcdef"
const wireKey = "bip340:eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g"
const wireT = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func wireRequest() Request {
	return Request{ID: wireID, TimeoutMS: 2000, Method: SignMethod, Preimage: []byte("fixture")}
}
func frame(body string) []byte {
	b := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(b, uint32(len(body)))
	copy(b[4:], body)
	return b
}
func bodyRequest(params string) string {
	return `{"method":"sign_message_author","params":` + params + `,"request_id":"` + wireID + `","timeout_ms":2000}`
}
func reqErr(t *testing.T, b []byte, want error) {
	t.Helper()
	q, e := DecodeRequestFrame(b)
	if e != want || !reflect.DeepEqual(q, Request{}) {
		t.Fatalf("request refusal/zero: %v want %v", e, want)
	}
}
func respErr(t *testing.T, q Request, b []byte) {
	t.Helper()
	r, e := DecodeResponseFrame(q, b)
	if e != ErrResponse || !reflect.DeepEqual(r, Response{}) {
		t.Fatalf("response refusal/zero: %v", e)
	}
}

// Fixed-header and complete-frame bounds reject before parsing, with nearby
// accepted endpoints. This proves codec bounds, not a network allocation policy.
func TestMessageAuthorFrameLimits(t *testing.T) {
	for _, n := range []uint32{0, 1, MaxFrame, MaxFrame + 1, ^uint32(0)} {
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], n)
		got, e := FrameLength(h)
		want := error(nil)
		if n == 0 {
			want = ErrFrameMalformed
		}
		if n > MaxFrame {
			want = ErrFrameTooLarge
		}
		if e != want || want == nil && got != int(n) || want != nil && got != 0 {
			t.Fatalf("cap header accepted: %d %d %v", n, got, e)
		}
	}
	good, e := EncodeRequestFrame(wireRequest())
	if e != nil {
		t.Fatal(e)
	}
	reqErr(t, good[:3], ErrFrameTruncated)
	reqErr(t, good[:len(good)-1], ErrFrameTruncated)
	reqErr(t, append(append([]byte{}, good...), 0), ErrTrailingData)
	for _, s := range []string{" {}", `{"a":0,"a":1}`, `{"b":0,"a":1}`, `{"a":-0}`, `{"a":1.0}`, `{"a":"\u0061"}`, `{"a":"\/"}`, `{"a":9007199254740992}`, strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17), "{\"a\":\"\xff\"}"} {
		reqErr(t, frame(s), ErrCanonical)
	}
	q := wireRequest()
	q.Preimage = make([]byte, 1<<20)
	if n := testing.AllocsPerRun(10, func() {
		b, e := EncodeRequestFrame(q)
		if e != ErrRequest || b != nil {
			t.Fatal("obvious oversize encoded")
		}
	}); n != 0 {
		t.Fatal("obvious oversize allocated", n)
	}
	q.Preimage = make([]byte, MaxPreimage)
	if _, e := EncodeRequestFrame(q); e != nil {
		t.Fatal("max preimage control", e)
	}
	q.Preimage = make([]byte, MaxPreimage+1)
	if b, e := EncodeRequestFrame(q); e != ErrRequest || b != nil {
		t.Fatal("oversize copied")
	}
	reqErr(t, frame(bodyRequest(`{"preimage":"`+strings.Repeat("A", 32769)+`"}`)), ErrRequest)
}

// Both exact methods are representable; received selectors, alternate encodings
// and boundary-invalid IDs/deadlines never become a typed request.
func TestMessageAuthorClosedRequests(t *testing.T) {
	for _, m := range []Method{IdentityMethod, SignMethod} {
		for _, ms := range []int64{1, 2000} {
			q := wireRequest()
			q.Method = m
			q.TimeoutMS = ms
			if m == IdentityMethod {
				q.Preimage = nil
			}
			b, e := EncodeRequestFrame(q)
			if e != nil {
				t.Fatal(e)
			}
			got, e := DecodeRequestFrame(b)
			if e != nil || !reflect.DeepEqual(got, q) {
				t.Fatal("valid request", e)
			}
		}
	}
	for _, field := range []string{"algorithm", "key", "path", "uid", "generation", "purpose", "profile", "digest", "hash", "attestation", "import", "export", "owner", "run"} {
		p, _ := json.Marshal(map[string]any{field: "x", "preimage": "Zml4dHVyZQ"})
		reqErr(t, frame(bodyRequest(string(p))), ErrRequest)
	}
	for _, p := range []string{`{}`, `{"preimage":null}`, `{"preimage":"Zg="}`, `{"preimage":"Zh"}`, `{"preimage":"+w"}`, `{"preimage":"_w=="}`, `{"preimage":[]}`} {
		reqErr(t, frame(bodyRequest(p)), ErrRequest)
	}
	for _, change := range []func(*Request){func(q *Request) { q.Method = "export" }, func(q *Request) { q.ID = strings.Repeat("A", 32) }, func(q *Request) { q.TimeoutMS = 0 }, func(q *Request) { q.TimeoutMS = 2001 }, func(q *Request) { q.Method = IdentityMethod }} {
		q := wireRequest()
		change(&q)
		if b, e := EncodeRequestFrame(q); e != ErrRequest || b != nil {
			t.Fatal("invalid request encoded")
		}
	}
	// The wire codec intentionally carries an empty/foreign-domain P. Provider
	// admission, not this inert byte conversion, decides its signing refusal.
	q := wireRequest()
	q.Preimage = []byte{}
	if b, e := EncodeRequestFrame(q); e != nil {
		t.Fatal(e)
	} else if got, e := DecodeRequestFrame(b); e != nil || len(got.Preimage) != 0 {
		t.Fatal("opaque input transport", e)
	}
}

// Replies must match the caller's outstanding ID/method and closed alternatives;
// parsing public bytes does not authenticate a signature or a certificate.
func TestMessageAuthorResponseContext(t *testing.T) {
	q := wireRequest()
	r := Response{ID: q.ID, Signature: &SignatureResult{wireKey, make([]byte, 64)}}
	f, e := EncodeResponseFrame(q, r)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := DecodeResponseFrame(q, f); e != nil || !reflect.DeepEqual(got, r) {
		t.Fatal("valid signature shape", e)
	}
	wrong := q
	wrong.ID = strings.Repeat("b", 32)
	respErr(t, wrong, f)
	wrong = q
	wrong.Method = IdentityMethod
	wrong.Preimage = nil
	respErr(t, wrong, f)
	r.ID = strings.Repeat("b", 32)
	if b, e := EncodeResponseFrame(q, r); e != ErrResponse || b != nil {
		t.Fatal("wrong response ID accepted")
	}
	r.ID = ""
	if b, e := EncodeResponseFrame(q, r); e != ErrResponse || b != nil {
		t.Fatal("null success accepted")
	}
	iq := Request{ID: wireID, TimeoutMS: 1, Method: IdentityMethod}
	ir := Response{ID: wireID, Identity: &IdentityResult{wireKey, wireT, []byte("{}")}}
	f, e = EncodeResponseFrame(iq, ir)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := DecodeResponseFrame(iq, f); e != nil || !reflect.DeepEqual(got, ir) {
		t.Fatal("identity control", e)
	}
	for _, modify := range []func(*IdentityResult){func(p *IdentityResult) { p.KeyID = "ed25519:" + strings.Repeat("A", 43) }, func(p *IdentityResult) {
		p.KeyID = "bip340:" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{255}, 32))
	}, func(p *IdentityResult) { p.AuthorAttestation = strings.ToUpper(wireT) }, func(p *IdentityResult) { p.Attestation = nil }, func(p *IdentityResult) { p.Attestation = make([]byte, MaxAttestation+1) }} {
		v := *ir.Identity
		modify(&v)
		if b, e := EncodeResponseFrame(iq, Response{ID: wireID, Identity: &v}); e != ErrResponse || b != nil {
			t.Fatal("invalid identity accepted")
		}
	}
	for _, raw := range []string{`{"request_id":"` + wireID + `","result":{"key_id":"` + wireKey + `","signature":"AA"}}`, `{"request_id":"` + wireID + `","result":{"key_id":"` + wireKey + `","signature":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 64)) + `","x":0}}`, `{"error":{"code":"invented","retryable":false},"request_id":null}`, `{"error":{"code":"busy","retryable":false},"request_id":null}`} {
		respErr(t, q, frame(raw))
	}
	r = Response{ID: wireID, Signature: &SignatureResult{wireKey, make([]byte, 64)}, Refusal: &Refusal{"busy", true}}
	if b, e := EncodeResponseFrame(q, r); e != ErrResponse || b != nil {
		t.Fatal("alternatives accepted")
	}
	// Decoded/encoded values cannot alias input or future results.
	ir.Identity.Attestation = bytes.Repeat([]byte{1}, MaxAttestation)
	f, e = EncodeResponseFrame(iq, ir)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeResponseFrame(iq, f)
	if e != nil {
		t.Fatal(e)
	}
	got.Identity.Attestation[0] = 2
	again, e := DecodeResponseFrame(iq, f)
	if e != nil || again.Identity.Attestation[0] != 1 {
		t.Fatal("reply alias")
	}
	q = wireRequest()
	f, e = EncodeRequestFrame(q)
	if e != nil {
		t.Fatal(e)
	}
	v, e := DecodeRequestFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	q.Preimage[0] = 0
	f[4] = 0
	if string(v.Preimage) != "fixture" {
		t.Fatal("request alias")
	}
}

// Every codec-local refusal preserves its specified retry bit and null-ID
// framing rule. It does not register any production code or imply no commit.
func TestMessageAuthorRefusals(t *testing.T) {
	codes := strings.Fields("busy rate_limited generation_source_unavailable audit_unavailable request_deadline_exceeded frame_too_large frame_truncated frame_malformed ccj_noncanonical request_malformed request_conflict version_unsupported hello_required hello_already_negotiated operation_unsupported peer_identity_unavailable generation_source_fenced generation_inactive generation_mismatch binding_not_found peer_binding_mismatch binding_conflict identity_revoked role_not_permitted custody_unavailable entropy_unavailable clock_untrusted key_not_enrolled key_not_valid_now sign_key_mismatch state_capacity_exceeded signer_preimage_too_large signer_tag_malformed signer_domain_refused signer_payload_invalid signer_identity_unavailable signer_identity_malformed signer_identity_mismatch message_author_unqualified")
	for i, c := range codes {
		retry := i < 5
		for _, id := range []string{"", wireID} {
			r := Response{ID: id, Refusal: &Refusal{c, retry}}
			b, e := EncodeResponseFrame(wireRequest(), r)
			if framingCode(c) && id != "" {
				if e != ErrResponse || b != nil {
					t.Fatal("framing echo")
				}
				continue
			}
			if e != nil {
				t.Fatal(c, e)
			}
			got, e := DecodeResponseFrame(wireRequest(), b)
			if e != nil || !reflect.DeepEqual(got, r) {
				t.Fatal(c, e)
			}
			r.Refusal.Retryable = !retry
			if b, e := EncodeResponseFrame(wireRequest(), r); e != ErrResponse || b != nil {
				t.Fatal("retry bit accepted", c)
			}
		}
	}
}

type wireVector struct{ Name, Kind, Body, Error string }

// The frozen corpus contains literal bytes and declared verdicts, not generated
// expectations from this codec. Its independent reader is in reference_test.go.
func TestMessageAuthorWireCorpus(t *testing.T) {
	raw, e := os.ReadFile("testdata/wire-v1/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var rows []wireVector
	if json.Unmarshal(raw, &rows) != nil {
		t.Fatal("corpus")
	}
	if len(rows) < 8 {
		t.Fatal("missing vectors")
	}
	for _, v := range rows {
		t.Run(v.Name, func(t *testing.T) {
			f := frame(v.Body)
			if v.Kind == "request" {
				q, e := DecodeRequestFrame(f)
				if v.Error != "" {
					if e != ErrRequest || !reflect.DeepEqual(q, Request{}) {
						t.Fatal("corpus request refusal", e)
					}
					return
				}
				if e != nil {
					t.Fatal(e)
				}
				b, e := EncodeRequestFrame(q)
				if e != nil || !bytes.Equal(b, f) {
					t.Fatal("literal request", e)
				}
				referenceFrame(t, b)
			} else {
				q := wireRequest()
				if v.Kind == "identity" {
					q.Method = IdentityMethod
					q.Preimage = nil
				}
				r, e := DecodeResponseFrame(q, f)
				if v.Error != "" {
					if e != ErrResponse || !reflect.DeepEqual(r, Response{}) {
						t.Fatal("corpus response refusal", e)
					}
					return
				}
				if e != nil {
					t.Fatal(e)
				}
				b, e := EncodeResponseFrame(q, r)
				if e != nil || !bytes.Equal(b, f) {
					t.Fatal("literal response", e)
				}
				referenceFrame(t, b)
			}
		})
	}
}
