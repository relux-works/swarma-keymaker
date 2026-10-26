package keymaker

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
)

// The dependency's added currency APIs must not opt the local legacy adapter
// into /2. Original /1 controls still accept; profile probes and oversize input
// refuse without a plan, receipt or changed protected facts. These are pure
// verifier calls, not qualification of a signed /2 proof or serving factory.
func TestMsgEnvelopeLegacyCurrencyBoundary(t *testing.T) {
	journal := k3Vector(t, filepath.Join("..", "..", "vectors", "waggle-s4", "P-JRN-publish-reissue.json"))
	freshness := k3ReceiptVector(t, "P-RC-current")
	mint := freshness["input"].(map[string]any)["mint"].(map[string]any)
	for _, row := range []struct {
		name    string
		fixture map[string]any
		input   map[string]any
	}{
		{"journal", journal["fixture"].(map[string]any), journal["input"].(map[string]any)},
		{"freshness", freshness["fixture"].(map[string]any), mint["input"].(map[string]any)},
	} {
		t.Run(row.name, func(t *testing.T) {
			p := k3Context(t, k3Facts(t, row.fixture))
			if p.facts.RegistryCurrencyVersion != 0 || p.facts.SnapshotJournal.IsAvailable() {
				t.Fatal("legacy context acquired successor premises")
			}
			before, err := json.Marshal(p.encoded)
			if err != nil {
				t.Fatal(err)
			}
			in := k3Input(t, row.input)
			if row.name == "journal" {
				r := p.verifyJournal(in)
				if r.Code != "accept" || r.Plan.SnapshotJournal != nil {
					t.Fatal("legacy journal control", r)
				}
			} else {
				r := p.verifyFreshness(in, false)
				if r.Code != "accept" || r.Plan.SnapshotJournal != nil || r.Audit == nil || r.Audit.Origin.RegistryCurrencyVersion != 0 {
					t.Fatal("legacy freshness control", r)
				}
			}
			for _, name := range []string{"registry_currency_version", "snapshot_journal"} {
				changed, err := p.updated(map[string]any{name: int64(2)})
				if changed != nil || err == nil || err.Error() != fmt.Sprintf("unsupported protected fact %q", name) {
					t.Fatal("unsupported fact must refuse at the local schema", name, changed, err)
				}
			}
			cp := pc2Object(t, in.Checkpoint)
			cp["body"].(map[string]any)["type"] = "checkpoint/2"
			in.Checkpoint = pc2Bytes(t, cp)
			if row.name == "journal" {
				k3Refusal(t, p.verifyJournal(in), "registry_currency_version_mismatch")
			} else {
				k3Refusal(t, p.verifyFreshness(in, false).Result, "registry_currency_version_mismatch")
			}
			in.Checkpoint = bytes.Repeat([]byte{' '}, 8193)
			if row.name == "journal" {
				k3Refusal(t, p.verifyJournal(in), "journal_malformed")
			} else {
				k3Refusal(t, p.verifyFreshness(in, false).Result, "freshness_malformed")
			}
			after, err := json.Marshal(p.encoded)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("refusal changed protected facts", err)
			}
		})
	}
}

// Recognizing a new library domain cannot widen the frozen local original
// grammar. The valid /1 original is the control; a /2 type with its recomputed
// content ID still refuses. This checks grammar, not signature authenticity.
func TestPC2EnvelopeCurrencyDomainBoundary(t *testing.T) {
	rule := authorityOriginalRule("checkpoint/1", false)
	encoded := pc2Original(t, "checkpoint/1")
	if err := rule(encoded); err != nil {
		t.Fatal("legacy original control", err)
	}
	raw, err := record.DecodeBase64(encoded, -1)
	if err != nil {
		t.Fatal(err)
	}
	o := pc2Object(t, raw)
	body := o["body"].(map[string]any)
	body["type"] = "checkpoint/2"
	o["id"], err = record.ContentID("checkpoint/2", body)
	if err != nil {
		t.Fatal("new library domain unavailable", err)
	}
	if err := rule(base64.RawURLEncoding.EncodeToString(pc2Bytes(t, o))); authorityCode(err) != "publication_original" {
		t.Fatal("successor domain widened local grammar", err)
	}
}
