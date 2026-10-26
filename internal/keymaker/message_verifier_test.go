package keymaker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
)

func k3Vector(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := record.Parse(raw, 1<<20, 16)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

// Fixture carriers use base64url; the production boundary accepts original bytes.
func k3Facts(t *testing.T, fixture map[string]any) map[string]any {
	t.Helper()
	f := map[string]any{}
	for k, v := range fixture {
		f[k] = v
	}
	// Upstream Authorize input is not a protected Context fact.
	delete(f, "request")
	if row, ok := f["delivery"].(map[string]any); ok {
		n := map[string]any{}
		for k, v := range row {
			n[k] = v
		}
		n["text"] = k3Bytes(t, row["text"])
		f["delivery"] = n
	}
	for _, name := range []string{"attestations", "operator_attestations", "service_attestations", "seen"} {
		if m, ok := f[name].(map[string]any); ok {
			n := map[string]any{}
			for k, v := range m {
				n[k] = k3Bytes(t, v)
			}
			f[name] = n
		}
	}
	if m, ok := f["revocations"].(map[string]any); ok {
		n := map[string]any{}
		for k, v := range m {
			row := map[string]any{}
			for name, value := range v.(map[string]any) {
				row[name] = value
			}
			row["snapshot"] = k3Bytes(t, row["snapshot"])
			n[k] = row
		}
		f["revocations"] = n
	}
	return f
}
func k3Bytes(t *testing.T, v any) []byte {
	t.Helper()
	b, err := record.DecodeBase64(v.(string), -1)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func k3Context(t *testing.T, values map[string]any) *messageProofContext {
	t.Helper()
	p, err := newMessageProofContext(values)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func k3Input(t *testing.T, in map[string]any) messageProofInput {
	t.Helper()
	p := messageProofInput{Route: messageFullProof}
	for name, dest := range map[string]*[]byte{"checkpoint": &p.Checkpoint, "conflict": &p.Conflict, "envelope": &p.Envelope} {
		if v, ok := in[name]; ok {
			*dest = k3Bytes(t, v)
		}
	}
	for _, name := range []string{"entries", "chain"} {
		if a, ok := in[name].([]any); ok {
			for _, v := range a {
				p.Chain = append(p.Chain, k3Bytes(t, v))
			}
		}
	}
	for name, dest := range map[string]*[]string{"ids": &p.IDs, "keys": &p.Keys} {
		if a, ok := in[name].([]any); ok {
			for _, v := range a {
				*dest = append(*dest, v.(string))
			}
		}
	}
	return p
}
func k3Refusal(t *testing.T, got verifier.Result, code string) {
	t.Helper()
	if got.Code != code || !reflect.DeepEqual(got.Plan, verifier.Plan{}) || got.FreshnessReceipt != nil {
		t.Fatalf("refusal must be %s with zero plan/no receipt: %+v", code, got)
	}
}

// MS-S12..15: exact imported signed bytes reject the six specific substitutions,
// including missing/wrong authenticated prior and backward time. Each negative
// has the unchanged publication/reissue positive; neither call advances facts.
func TestMsgS4ImportedJournal(t *testing.T) {
	base := filepath.Join("..", "..", "vectors", "waggle-s4")
	manifest := k3Vector(t, filepath.Join(base, "manifest.json"))
	positive := k3Vector(t, filepath.Join(base, "P-JRN-publish-reissue.json"))
	for _, entry := range manifest["files"].([]any) {
		row := entry.(map[string]any)
		t.Run(row["file"].(string), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(base, row["file"].(string)))
			if err != nil {
				t.Fatal(err)
			}
			h := sha256.Sum256(raw)
			if hex.EncodeToString(h[:]) != row["sha256"] || int64(len(raw)) != row["bytes"] {
				t.Fatal("imported bytes changed")
			}
			v := k3Vector(t, filepath.Join(base, row["file"].(string)))
			p := k3Context(t, k3Facts(t, v["fixture"].(map[string]any)))
			before, _ := json.Marshal(p.encoded)
			got := p.verifyJournal(k3Input(t, v["input"].(map[string]any)))
			want := v["expected"].(map[string]any)["code"].(string)
			if want != "accept" {
				k3Refusal(t, got, want)
			} else if got.Code != "accept" {
				t.Fatal(got)
			}
			after, _ := json.Marshal(p.encoded)
			if !bytes.Equal(before, after) {
				t.Fatal("journal verification mutated protected facts")
			}
			control := k3Context(t, k3Facts(t, positive["fixture"].(map[string]any)))
			accepted := control.verifyJournal(k3Input(t, positive["input"].(map[string]any)))
			var expected verifier.Plan
			b, _ := json.Marshal(positive["expected"].(map[string]any)["plan"])
			if err := json.Unmarshal(b, &expected); err != nil {
				t.Fatal(err)
			}
			if accepted.Code != "accept" || !reflect.DeepEqual(accepted.Plan, expected) {
				t.Fatal("publication positive plan", accepted, expected)
			}
		})
	}
	// The signed prior checkpoint cannot substitute for the distinct raw anchor.
	p := k3Context(t, k3Facts(t, positive["fixture"].(map[string]any)))
	in := k3Input(t, positive["input"].(map[string]any))
	in.Chain = in.Chain[1:]
	k3Refusal(t, p.verifyJournal(in), "journal_anchor_required")
}

// MS-S15: independently signed checkpoints may advance at equal time, while
// the raw prior checkpoint and anchor still match the protected witness.
func TestMsgS4EqualCheckpointTime(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x64}, 32))
	root := messageTestID(key[32:])
	at := "2026-01-01T00:01:20Z"
	snapshot := messageSigned(t, "revocation/1", map[string]any{"type": "revocation/1", "issuer": root, "issued_at": at, "complete": true, "entries": []any{}}, key)
	object := func(raw []byte) map[string]any {
		v, err := record.Parse(raw, 8192, 16)
		if err != nil {
			t.Fatal(err)
		}
		return v.(map[string]any)
	}
	entry := func(seq int64, prev any) []byte {
		body := map[string]any{"type": "journal-entry/1", "registry": root, "owner": "owner-a", "seq": seq, "prev": prev, "at": at, "op": "add", "record_type": "enrollment/1", "record": "sha256:" + strings.Repeat("1", 64)}
		id, err := record.ContentID("journal-entry/1", body)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := record.Canonical(map[string]any{"version": "swarm-envelope/2", "body": body, "id": id})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	anchor := entry(1, nil)
	next := entry(2, object(anchor)["id"])
	cp := func(seq int64, raw []byte) []byte {
		return messageSigned(t, "checkpoint/1", map[string]any{"type": "checkpoint/1", "registry": root, "owner": "owner-a", "seq": seq, "head": object(raw)["id"], "at": at, "snapshot": object(snapshot)["id"]}, key)
	}
	prior, candidate := cp(1, anchor), cp(2, next)
	p := k3Context(t, map[string]any{
		"service_root":   map[string]any{"key": messageTestID(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x65}, 32))[32:]), "purpose": int64(5)},
		"registry_owner": "owner-a", "agent_revocation_root": map[string]any{"key": root, "purpose": "registry-revocation", "attestation_root": messageTestID(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x65}, 32))[32:])},
		"journal_witness":      map[string]any{"registry_id": root, "owner": "owner-a", "registry_seq": int64(1), "registry_head": object(anchor)["id"], "checkpoint_id": object(prior)["id"], "previous_checkpoint_id": nil},
		"id_journal_available": true, "seen": map[string]any{object(prior)["id"].(string): prior},
		"now": at, "watermark": at, "watermark_available": true, "time": map[string]any{"trusted": true, "fresh": true, "authority_until": "2026-01-01T00:02:00Z"},
		"revocations": map[string]any{root: map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": true, "snapshot": snapshot}},
	})
	in := messageProofInput{Route: messageFullProof, Chain: [][]byte{anchor, next}, Checkpoint: candidate, Receipt: &verifier.FreshnessReceipt{}, RequireReceipt: true, MarginSeconds: -1}
	if got := p.verifyJournal(in); got.Code != "accept" {
		t.Fatal("equal checkpoint time/outside receipt mode", got)
	}
}

// MS-S23..25: exact complete encoded carrier sizes pass their individual gates;
// +1 refuses before the verifier, with no plan/receipt or context mutation.
// Padding exercises byte accounting only, not real WC1 or maximum-proof validity.
func TestMsgS45Caps(t *testing.T) {
	v := k3Vector(t, filepath.Join("..", "..", "vectors", "waggle-s4", "P-JRN-publish-reissue.json"))
	for _, row := range []struct {
		name  string
		route messageProofRoute
		limit int
	}{
		{"intake", messageIntakeProof, 524288}, {"full", messageFullProof, 2097152},
	} {
		t.Run(row.name, func(t *testing.T) {
			p := k3Context(t, k3Facts(t, v["fixture"].(map[string]any)))
			in := k3Input(t, v["input"].(map[string]any))
			in.Route = row.route
			in.Control = []string{""}
			n, err := p.proofSize(in)
			if err != nil {
				t.Fatal(err)
			}
			// Independent inventory oracle includes the original prior checkpoint
			// and all protected snapshot/control facts, plus their JSON encoding.
			carrier, err := json.Marshal(map[string]any{"Context": k3Facts(t, v["fixture"].(map[string]any)), "Input": in})
			if err != nil || n != len(carrier) {
				t.Fatal("complete carrier accounting", n, len(carrier), err)
			}
			in.Control[0] = strings.Repeat("x", row.limit-n+1)
			before, _ := json.Marshal(p.encoded)
			k3Refusal(t, p.verifyJournal(in), "message_proof_too_large")
			in.Control[0] = in.Control[0][:len(in.Control[0])-1]
			n, err = p.proofSize(in)
			if err != nil || n != row.limit {
				t.Fatal("exact full inventory size", n, err)
			}
			if got := p.verifyJournal(in); got.Code != "accept" {
				t.Fatal("exact cap positive", got)
			}
			after, _ := json.Marshal(p.encoded)
			if !bytes.Equal(before, after) {
				t.Fatal("cap check mutated facts")
			}
		})
	}
	p := k3Context(t, k3Facts(t, v["fixture"].(map[string]any)))
	in := k3Input(t, v["input"].(map[string]any))
	in.WitnessWrapper = append(bytes.Repeat([]byte{'x'}, 8192), '\n')
	k3Refusal(t, p.verifyJournal(in), "message_witness_too_large")
	in.WitnessWrapper = append(bytes.Repeat([]byte{'x'}, 8191), '\n')
	if code := p.check(in); code != "" {
		t.Fatal("8192 including LF must pass size gate", code)
	}
	// Full route does not bypass freshness/consumer caps, or permit unknown routes.
	in.Control = []string{strings.Repeat("x", 2097152)}
	k3Refusal(t, p.verifyFreshness(in, false).Result, "message_proof_too_large")
	k3Refusal(t, p.verifyMessage(in), "message_proof_too_large")
	if a, code := p.verifyAttestation(in); code != "message_proof_too_large" || a != (verifier.Attestation{}) {
		t.Fatal("attestation cap", a, code)
	}
	in.Route = 99
	k3Refusal(t, p.verifyJournal(in), "message_proof_invalid")
}

// Exact public S5 bytes from waggle 5f4e743, vectors/swarm-envelope-2/1-positive.
// These test inputs establish pure API behavior, not authenticated production facts.
func k3ReceiptVector(t *testing.T, name string) map[string]any {
	t.Helper()
	hashes := map[string]string{
		"P-RC-message":  "e7aa1028dae66853df125f0734116e2ad46f46143b6108b4bc933312e10e602b",
		"P-RC-current":  "032916c047a5689a0fe7eb9d783cfad999d6e9a0bfa24b79d3dcc4fbc9bb4821",
		"P-RC-reanchor": "316742f4bff6336ea94ac6da47cc051f61810672615771c0178be0ae6ded56cd",
	}
	path := filepath.Join("testdata", "waggle-s5", name+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != hashes[name] {
		t.Fatal("S5 import changed")
	}
	return k3Vector(t, path)
}
func k3Mint(t *testing.T, v map[string]any) (*messageProofContext, messageFreshnessResult, messageProofInput) {
	t.Helper()
	p := k3Context(t, k3Facts(t, v["fixture"].(map[string]any)))
	mint := v["input"].(map[string]any)["mint"].(map[string]any)
	in := k3Input(t, mint["input"].(map[string]any))
	r := p.verifyFreshness(in, mint["mode"] == "freshness-reanchor")
	if r.Code != "accept" || r.FreshnessReceipt == nil {
		t.Fatal("full freshness control", r)
	}
	tip, err := record.Parse(in.Chain[len(in.Chain)-1], 8192, 16)
	if err != nil {
		t.Fatal(err)
	}
	e := tip.(map[string]any)
	b := e["body"].(map[string]any)
	anchor := map[string]any{"registry_id": b["registry"], "owner": b["owner"], "publication_seq": b["publication_seq"], "freshness_id": e["id"], "issued_at": b["issued_at"], "snapshot": b["snapshot"], "registry_seq": b["registry_seq"], "checkpoint_id": b["checkpoint_id"]}
	updated, err := p.updated(map[string]any{"freshness_anchor": anchor})
	if err != nil {
		t.Fatal(err)
	}
	use := messageProofInput{Route: messageFullProof, Receipt: r.FreshnessReceipt, RequireReceipt: true}
	return updated, r, use
}

// MS-S17..20: no receipt means own snapshot age still applies to agent
// attestations/messages; current receipts renew only their bound registry.
// Identical rebuilt Evidence, missing required receipt and expiry refuse.
func TestMsgS5ReceiptConsumers(t *testing.T) {
	for _, name := range []string{"P-RC-message", "P-RC-current"} {
		t.Run(name, func(t *testing.T) {
			v := k3ReceiptVector(t, name)
			p, _, use := k3Mint(t, v)
			f := v["fixture"].(map[string]any)
			for key, reference := range f["agent_attestation_ids"].(map[string]any) {
				use.Key, use.Reference = key, reference.(string)
			}
			without := use
			without.Receipt = nil
			if _, code := p.verifyAttestation(without); code != "freshness_receipt_unavailable" {
				t.Fatal("required receipt", code)
			}
			without.RequireReceipt = false
			want := "key_binding_unavailable"
			if name == "P-RC-current" {
				want = "accept"
			}
			if _, code := p.verifyAttestation(without); code != want {
				t.Fatal("D41 own age", code, want)
			}
			if _, code := p.verifyAttestation(use); code != "accept" {
				t.Fatal("same Evidence control", code)
			}
			changed, err := p.updated(map[string]any{"revocations": k3Facts(t, f)["revocations"]})
			if err != nil {
				t.Fatal(err)
			}
			if _, code := changed.verifyAttestation(use); code != "freshness_receipt_binding_mismatch" {
				t.Fatal("rebuilt Evidence accepted", code)
			}
			if _, code := p.verifyAttestation(use); code != "accept" {
				t.Fatal("original lifetime mutated", code)
			}
			expired, err := p.updated(map[string]any{"now": "2026-01-01T00:04:00Z", "watermark": "2026-01-01T00:04:00Z"})
			if err != nil {
				t.Fatal(err)
			}
			if _, code := expired.verifyAttestation(use); code != "freshness_receipt_expired" {
				t.Fatal("exclusive expiry", code)
			}
			if name == "P-RC-message" {
				use.Envelope = k3Bytes(t, v["input"].(map[string]any)["consume"].(map[string]any)["input"].(map[string]any)["envelope"])
				without = use
				without.Receipt = nil
				without.RequireReceipt = false
				k3Refusal(t, p.verifyMessage(without), "key_binding_unavailable")
				if got := p.verifyMessage(use); got.Code != "accept" {
					t.Fatal("message receipt control", got)
				}
				k3Refusal(t, changed.verifyMessage(use), "freshness_receipt_binding_mismatch")
			}
		})
	}
}

// MS-S20/D41: a valid registry receipt cannot renew an aged operator snapshot.
// Re-minting after changing the complete snapshot Evidence avoids confusing
// the operator-age check with an unrelated old-receipt binding refusal.
func TestMsgS5OperatorOwnAge(t *testing.T) {
	v := k3ReceiptVector(t, "P-RC-current")
	for _, aged := range []bool{true, false} {
		t.Run(fmt.Sprint(aged), func(t *testing.T) {
			if aged {
				old := k3Vector(t, filepath.Join("..", "..", "vectors", "waggle-s4", "P-JRN-publish-reissue.json"))
				f := v["fixture"].(map[string]any)
				root := f["operator_root"].(string)
				f["revocations"].(map[string]any)[root] = old["fixture"].(map[string]any)["revocations"].(map[string]any)[root]
			}
			p, _, use := k3Mint(t, v)
			use.Device = true
			for key := range v["fixture"].(map[string]any)["operator_attestations"].(map[string]any) {
				use.Key = key
			}
			want := "accept"
			if aged {
				want = "key_binding_unavailable"
			}
			if _, code := p.verifyAttestation(use); code != want {
				t.Fatal("operator own age", code, want)
			}
		})
		v = k3ReceiptVector(t, "P-RC-current")
	}
}

// MS-S21/22 in-memory boundary: normal gaps never fall back to reanchor.
// Explicit recovery reports skipped positions and both exact endpoint IDs;
// this is origin metadata, not atomic audit/root persistence qualification.
func TestMsgS5ReanchorAudit(t *testing.T) {
	v := k3ReceiptVector(t, "P-RC-reanchor")
	p := k3Context(t, k3Facts(t, v["fixture"].(map[string]any)))
	in := k3Input(t, v["input"].(map[string]any)["mint"].(map[string]any)["input"].(map[string]any))
	r := p.verifyFreshness(in, false)
	k3Refusal(t, r.Result, "freshness_gap")
	if r.Audit != nil {
		t.Fatal("refused freshness returned audit")
	}
	r = p.verifyFreshness(in, true)
	if r.Code != "accept" || r.Audit == nil || r.Plan.Reanchor == nil {
		t.Fatal("explicit reanchor", r)
	}
	a, plan := r.Audit, r.Plan.Reanchor
	old := v["fixture"].(map[string]any)["freshness_anchor"].(map[string]any)
	if !a.Origin.Reanchored || a.SkippedPublications != plan.SkippedPublications || a.OldFreshnessID != old["freshness_id"] || a.OldCheckpointID != old["checkpoint_id"] || a.NewFreshnessID != plan.NewFreshnessID || a.NewCheckpointID != plan.NewCheckpointID {
		t.Fatal("reanchor endpoints/count", a, plan)
	}
	if _, err := json.Marshal(r); err == nil {
		t.Fatal("transient admission serialized")
	}
	p, _, _ = k3Mint(t, v)
	k3Refusal(t, p.verifyFreshness(in, true).Result, "freshness_rollback")
	// Ordinary admission also reports its retained and admitted endpoints.
	v = k3ReceiptVector(t, "P-RC-current")
	_, r, _ = k3Mint(t, v)
	if r.Audit == nil || r.Audit.Origin.Reanchored || r.Audit.SkippedPublications != 0 || r.Audit.OldFreshnessID == "" || r.Audit.OldCheckpointID == "" || r.Audit.NewFreshnessID != r.Audit.Origin.FreshnessID {
		t.Fatal("normal endpoints", r.Audit)
	}
	// A contiguous successor is also a valid explicit zero-skip reanchor.
	p = k3Context(t, k3Facts(t, v["fixture"].(map[string]any)))
	in = k3Input(t, v["input"].(map[string]any)["mint"].(map[string]any)["input"].(map[string]any))
	in.Receipt = &verifier.FreshnessReceipt{}
	in.RequireReceipt = true
	in.MarginSeconds = -1
	r = p.verifyFreshness(in, true)
	if r.Code != "accept" || r.Audit == nil || !r.Audit.Origin.Reanchored || r.Audit.SkippedPublications != 0 {
		t.Fatal("explicit zero skip/outside receipt mode", r)
	}
}

func k3PersistedReceiptPath(typ reflect.Type, seen map[reflect.Type]bool) string {
	if seen[typ] {
		return ""
	}
	seen[typ] = true
	if typ == reflect.TypeFor[verifier.FreshnessReceipt]() {
		return typ.String()
	}
	switch typ.Kind() {
	case reflect.Interface, reflect.UnsafePointer:
		return typ.String() + " can hold process authority"
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return k3PersistedReceiptPath(typ.Elem(), seen)
	case reflect.Map:
		if p := k3PersistedReceiptPath(typ.Key(), seen); p != "" {
			return p
		}
		return k3PersistedReceiptPath(typ.Elem(), seen)
	case reflect.Struct:
		for n := 0; n < typ.NumField(); n++ {
			f := typ.Field(n)
			if p := k3PersistedReceiptPath(f.Type, seen); p != "" {
				return f.Name + "." + p
			}
		}
	}
	return ""
}

// MS-S18: no schema-2/root/artifact type can hold a receipt, even behind a
// pointer, container, interface or json:"-" field. The nested positive plant
// proves this type-graph check detects custody, independently of JSON refusal.
// Raw JSON can hold bytes only; it cannot restore receipt identity on restart.
func TestMsgS5ReceiptNotPersistable(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeFor[bindingDisk](), reflect.TypeFor[messageInventory](), reflect.TypeFor[messageIntent](), reflect.TypeFor[messageCandidate](), reflect.TypeFor[messageResolution](), reflect.TypeFor[messageMigrationDecision](), reflect.TypeFor[AuditRecord](),
	} {
		if path := k3PersistedReceiptPath(typ, map[reflect.Type]bool{}); path != "" {
			t.Fatalf("persisted type %s can hold receipt: %s", typ, path)
		}
	}
	plant := reflect.TypeFor[struct {
		Hidden []*verifier.FreshnessReceipt `json:"-"`
	}]()
	if path := k3PersistedReceiptPath(plant, map[reflect.Type]bool{}); !strings.Contains(path, "Hidden") {
		t.Fatal("type guard missed known receipt plant", path)
	}
	_, r, _ := k3Mint(t, k3ReceiptVector(t, "P-RC-current"))
	for _, value := range []any{r.FreshnessReceipt, *r.FreshnessReceipt} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("receipt serialized", fmt.Sprintf("%T", value))
		}
	}
	var zero verifier.FreshnessReceipt
	if err := json.Unmarshal([]byte(`{}`), &zero); err == nil {
		t.Fatal("receipt deserialized")
	}
	if _, ok := zero.Audit(); ok {
		t.Fatal("restart manufactured receipt origin")
	}
}
