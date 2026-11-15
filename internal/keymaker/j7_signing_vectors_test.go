package keymaker

import (
	"bytes"
	"encoding/base64"
	"os"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-keymaker/internal/control"
)

// Complete synthetic consent/grant/envelopes are parsed by the product and the
// independently adopted rental verifier. Malformed or correctly signed wrong
// shapes stay invalid beside positives. These are draft/offline bytes, not live
// grant evidence, custody isolation or external network interoperability.
func TestJ7SigningPublicVectors(t *testing.T) {
	var f struct {
		Format      string `json:"format"`
		TestOnly    bool   `json:"test_only"`
		Note        string `json:"note"`
		Source      string `json:"source"`
		Contract    string `json:"contract_b64"`
		Grant       string `json:"grant_b64"`
		Instruction string `json:"instruction_b64"`
		Positive    []struct {
			ID       string `json:"id"`
			Event    string `json:"event_b64"`
			Expected string `json:"expected"`
		} `json:"positive"`
		Negative []struct {
			ID       string `json:"id"`
			Event    string `json:"event_b64"`
			Expected string `json:"expected"`
		} `json:"negative"`
	}
	raw, e := os.ReadFile("../../vectors/j7/signing.json")
	if e != nil || StrictJSON(bytes.NewReader(raw), &f) != nil || !f.TestOnly || f.Format != "keymaker-j7-signing-vectors/1" || len(f.Positive) != 5 || len(f.Negative) != 8 {
		t.Fatal("signing fixture identity", e)
	}
	decode := func(s string) []byte {
		b, e := base64.RawURLEncoding.Strict().DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	contract := decode(f.Contract)
	c, code := parseJ7Contract(contract)
	if code != "" {
		t.Fatal(code)
	}
	grant, e := rental.ParseSignedGrant(decode(f.Grant))
	if e != nil || j7BindContract(contract, c, grant.Grant) != "" {
		t.Fatal("full externally signed grant control", e)
	}
	for _, v := range f.Positive {
		t.Run(v.ID, func(t *testing.T) {
			b := decode(v.Event)
			event, ok := j7ValidateEvent(b)
			if !ok || v.Expected != "valid" {
				t.Fatal("positive draft event refused")
			}
			result := control.Object{"signed_object_b64": v.Event, "object_id": event.ID, "public_key": event.Pubkey}
			j7ResultEvent(t, result)
			if v.ID == "consent" {
				if !reflect.DeepEqual(event, grant.Grant.Consent.ConsentEvent) {
					t.Fatal("consent not complete grant consent")
				}
			} else if event.Tags[2][1] != grant.ID() || event.Tags[4][1] != j7Hash(decode(f.Instruction)) {
				t.Fatal("grant/body preimage mismatch")
			}
		})
	}
	for _, v := range f.Negative {
		t.Run(v.ID, func(t *testing.T) {
			if _, ok := j7ValidateEvent(decode(v.Event)); ok || v.Expected != "invalid" {
				t.Fatal("negative draft event admitted")
			}
		})
	}
}
