package messageauthor

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// This stdlib-only reader takes literal wire bytes without using the product
// CCJ parser or its encoder. Canonical rejection is tested separately; positive
// shapes/values are independently compared, not only round-tripped.
func referenceFrame(t *testing.T, b []byte) {
	t.Helper()
	if len(b) < 4 || int(binary.BigEndian.Uint32(b)) != len(b)-4 {
		t.Fatal("reference length")
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(b[4:], &obj) != nil {
		t.Fatal("reference JSON")
	}
	var id *string
	if json.Unmarshal(obj["request_id"], &id) != nil {
		t.Fatal("reference ID")
	}
	if raw, ok := obj["method"]; ok {
		if len(obj) != 4 {
			t.Fatal("reference request fields")
		}
		var m string
		var ms int64
		var params map[string]string
		if json.Unmarshal(raw, &m) != nil || json.Unmarshal(obj["timeout_ms"], &ms) != nil || json.Unmarshal(obj["params"], &params) != nil || id == nil {
			t.Fatal("reference request")
		}
		want := Request{ID: *id, Method: Method(m), TimeoutMS: ms}
		switch m {
		case "message_author_identity":
			if len(params) != 0 {
				t.Fatal("reference identity")
			}
		case "sign_message_author":
			if len(params) != 1 {
				t.Fatal("reference sign")
			}
			var e error
			want.Preimage, e = base64.RawURLEncoding.Strict().DecodeString(params["preimage"])
			if e != nil {
				t.Fatal(e)
			}
		default:
			t.Fatal("reference method")
		}
		got, e := DecodeRequestFrame(b)
		if e != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("independent request values", e)
		}
		return
	}
	if len(obj) != 2 {
		t.Fatal("reference response fields")
	}
	if raw, ok := obj["error"]; ok {
		var r struct {
			Code      string
			Retryable bool
		}
		if json.Unmarshal(raw, &r) != nil {
			t.Fatal("reference refusal")
		}
		got, e := DecodeResponseFrame(wireRequest(), b)
		if e != nil || got.Refusal == nil || got.Refusal.Code != r.Code || got.Refusal.Retryable != r.Retryable || (id == nil && got.ID != "") {
			t.Fatal("independent refusal", e)
		}
		return
	}
	var r map[string]string
	if json.Unmarshal(obj["result"], &r) != nil || id == nil {
		t.Fatal("reference result")
	}
	q := wireRequest()
	if _, ok := r["attestation"]; ok {
		q.Method = IdentityMethod
		q.Preimage = nil
		if len(r) != 3 {
			t.Fatal("reference identity fields")
		}
		got, e := DecodeResponseFrame(q, b)
		a, err := base64.RawURLEncoding.Strict().DecodeString(r["attestation"])
		if e != nil || err != nil || got.Identity == nil || got.ID != *id || got.Identity.KeyID != r["key_id"] || got.Identity.AuthorAttestation != r["author_attestation"] || !bytes.Equal(got.Identity.Attestation, a) {
			t.Fatal("independent identity", e)
		}
	} else {
		if len(r) != 2 {
			t.Fatal("reference sign fields")
		}
		got, e := DecodeResponseFrame(q, b)
		s, err := base64.RawURLEncoding.Strict().DecodeString(r["signature"])
		if e != nil || err != nil || got.Signature == nil || got.ID != *id || got.Signature.KeyID != r["key_id"] || !bytes.Equal(got.Signature.Signature, s) {
			t.Fatal("independent signature", e)
		}
	}
}

// Payload manifests bind the exact public corpus without self/commit hash cycles.
func TestMessageAuthorWireManifest(t *testing.T) {
	b, e := os.ReadFile("testdata/wire-v1/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	m, e := os.ReadFile("testdata/wire-v1/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		SHA      string `json:"vectors_sha256"`
		TestOnly bool   `json:"test_only"`
		Commit   string `json:"envelope_commit"`
	}
	if json.Unmarshal(m, &v) != nil {
		t.Fatal("manifest")
	}
	sum := sha256.Sum256(b)
	if !v.TestOnly || v.SHA != hex.EncodeToString(sum[:]) || v.Commit != "065e25f69da8b28cdf3ea35d9fcd7fc4aacc4d5e" {
		t.Fatal("corpus identity")
	}
}
