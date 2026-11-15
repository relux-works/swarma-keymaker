package keymaker

import (
	"strings"
	"testing"
)

const j7P2TestKey = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"

func j7P2RootBytes() string {
	return `{"profile":"swarma-trust-contract/2","network":"regtest","landlord_name":"id/test-owner","agent_name":"id/test-executor","grantee_key":"` + j7P2TestKey + `","actions":["instruct","review"],"repos":[],"spend_budget":0,"not_before":1,"not_after":2000000000,"scope_text_sha256":"","parent_grant_id":"","ordinal":0,"delegate":{"depth":1,"actions":["instruct"],"budget":0,"slots":[{"executor":"id/test-worker","grantee":"` + j7P2TestKey + `","cap":0,"notary":"id/test-notary"}],"notaries":[{"name":"id/test-notary","registration":{"txid":"` + strings.Repeat("1", 64) + `","vout":0},"owner":"02` + j7P2TestKey + `"}],"checkpoint":"` + strings.Repeat("2", 64) + `"},"note":""}`
}

// Frozen member/rule precedence is exercised beside a valid delegable root;
// these generic bytes are independent of the private exact upstream corpus.
func TestJ7Profile2CanonicalRules(t *testing.T) {
	root := j7P2RootBytes()
	if _, c := parseJ7ProfileContract([]byte(root)); c != "" {
		t.Fatal("root", c)
	}
	cases := []struct {
		name, from, to string
		code           Code
	}{
		{"profile", `"swarma-trust-contract/2"`, `"swarma-trust-contract/1"`, "CONTRACT_PROFILE"},
		{"network", `"regtest"`, `"other"`, "CONTRACT_FIELD"},
		{"action", `["instruct","review"]`, `["review","instruct"]`, "CONTRACT_ACTIONS"},
		{"repo", `"repos":[]`, `"repos":["https://git.example/a"]`, "CONTRACT_REPOS"},
		{"budget", `"spend_budget":0`, `"spend_budget":1`, "CONTRACT_BUDGET"},
		{"negative", `"cap":0`, `"cap":-1`, "CONTRACT_ENCODING"},
		{"largeinteger", `"cap":0`, `"cap":9223372036854775808`, "CONTRACT_ENCODING"},
		{"null", `"slots":[`, `"slots":null,"unused":[`, "CONTRACT_ENCODING"},
		{"fraction", `"cap":0`, `"cap":0.0`, "CONTRACT_ENCODING"},
		{"escape", `"note":""`, `"note":"\u0041"`, "CONTRACT_ENCODING"},
		{"note", `"note":""`, `"note":"` + strings.Repeat("a", 281) + `"`, "CONTRACT_NOTE"},
		{"parent", `"ordinal":0`, `"ordinal":1`, "CONTRACT_PARENT"},
		{"delegateorder", `"depth":1,"actions":["instruct"]`, `"actions":["instruct"],"depth":1`, "CONTRACT_DELEGATE"},
		{"duplicaterow", `"cap":0,`, `"cap":0,"cap":0,`, "CONTRACT_DELEGATE"},
		{"vout", `"vout":0`, `"vout":4294967296`, "CONTRACT_DELEGATE"},
		{"point", `"owner":"02`, `"owner":"04`, "CONTRACT_DELEGATE"},
		{"spend", `"depth":1,"actions":["instruct"]`, `"depth":1,"actions":["spend"]`, "CONTRACT_DELEGATE"},
	}
	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			b := strings.Replace(root, v.from, v.to, 1)
			if b == root {
				t.Fatal("unapplied case")
			}
			if _, c := parseJ7ProfileContract([]byte(b)); c != v.code {
				t.Fatalf("got %s want %s", c, v.code)
			}
		})
	}
	for _, b := range []string{root + "\n", " " + root, strings.Replace(root, `"profile":`, `"extra":0,"profile":`, 1)} {
		if _, c := parseJ7ProfileContract([]byte(b)); c != "CONTRACT_ENCODING" {
			t.Fatal(c)
		}
	}
	start := strings.Index(root, `"notaries":[`)
	end := strings.Index(root[start:], `,"checkpoint":`) + start
	noNotary := root[:start] + `"notaries":[]` + root[end:]
	if _, c := parseJ7ProfileContract([]byte(strings.Replace(noNotary, `"cap":0`, `"cap":1`, 1))); c != "DELEGATE_NO_NOTARY" {
		t.Fatal("no-notary priority", c)
	}
	if _, c := parseJ7ProfileContract([]byte(strings.Replace(noNotary, `"ordinal":0`, `"ordinal":1`, 1))); c != "CONTRACT_PARENT" {
		t.Fatal("parent before delegate", c)
	}
}
