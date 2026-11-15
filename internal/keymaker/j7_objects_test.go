package keymaker

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// Fixed-order trust bytes are accepted beside lexical/schema/value mutations;
// this is byte-profile validation, not chain liveness or deployment authority.
func TestJ7ObjectsContractProfile(t *testing.T) {
	c := j7Contract{Profile: "swarma-trust-contract/1", Network: "regtest", Landlord: "id/test-owner", Agent: "id/test-executor", Grantee: "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", Actions: []string{"instruct"}, Repos: []string{}, NotBefore: 100, NotAfter: 1000}
	if got := j7ConsentTriple([]byte("contract")).Privacy; got != "c0436d6368755b1aeaa7fe0e87bddcc5e09dd32e8c6921806e316f28e9c02aad" {
		t.Fatal("published privacy hash", got)
	}
	raw, _ := j7Compact(c)
	if _, code := parseJ7Contract(raw); code != "" {
		t.Fatal("valid contract", code)
	}
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return append(b, '\n') },
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"spend_budget":0`), []byte(`"spend_budget":-1`), 1)
		},
		func(b []byte) []byte { return bytes.Replace(b, []byte(`"repos":[]`), []byte(`"repos":null`), 1) },
		func(b []byte) []byte { return bytes.Replace(b, []byte(`"note":""`), []byte(`"note":"\u0041"`), 1) },
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"profile":`), []byte(`"extra":0,"profile":`), 1)
		},
		func(b []byte) []byte { return bytes.Replace(b, []byte(`"instruct"`), []byte(`"raw"`), 1) },
		func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"not_after":1000`), []byte(`"not_after":100`), 1)
		},
	} {
		if _, code := parseJ7Contract(mutate(append([]byte{}, raw...))); code != "request_malformed" {
			t.Fatal("malformed contract accepted", code)
		}
	}
	if _, code := parseJ7Contract(raw); code != "" {
		t.Fatal("positive neighbor", code)
	}
}

// Canonical base64url and the complete evidence object prevent alternate
// spelling and asserted live verdicts from entering the typed input contract.
func TestJ7ObjectsClosedEncoding(t *testing.T) {
	raw := []byte(`{"format":"keymaker-j7-evidence/1","issuance_txid":""}`)
	enc := base64.RawURLEncoding.EncodeToString(raw)
	if b, c := j7Decode64(enc, 1024); c != "" || !bytes.Equal(b, raw) {
		t.Fatal("canonical positive", c)
	}
	for _, s := range []string{enc + "=", enc + "\n", strings.Repeat("A", 2048)} {
		if _, c := j7Decode64(s, 1024); c != "request_malformed" {
			t.Fatal("alternate base64 accepted", c)
		}
	}
	if _, c := j7DecodeEvidence(enc, false); c != "" {
		t.Fatal("empty evidence positive", c)
	}
	for _, s := range []string{`{}`, `{"format":"keymaker-j7-evidence/1","issuance_txid":"","live":true}`, `{"format":"keymaker-j7-evidence/1","issuance_txid":null}`} {
		if _, c := j7DecodeEvidence(base64.RawURLEncoding.EncodeToString([]byte(s)), false); c != "request_malformed" {
			t.Fatal("asserted evidence accepted", c)
		}
	}
}
