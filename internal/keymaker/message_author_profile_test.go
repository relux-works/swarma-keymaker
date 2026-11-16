package keymaker

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/tools/bip340check/oracle"
	"github.com/relux-works/swarma-envelope/verifier"
	"os"
	"reflect"
	"strings"
	"testing"
)

func maContextMap(t *testing.T, v maVectors) map[string]any {
	t.Helper()
	b, e := json.Marshal(v.Context)
	if e != nil {
		t.Fatal(e)
	}
	m, e := record.Parse(b, 65536, 16)
	if e != nil {
		t.Fatal(e)
	}
	return m.(map[string]any)
}

// Snapshot conversion is fixture transport only. It neither resolves nor
// authenticates live current facts; /1 historical fixtures do not opt into /2.
func maContext(t *testing.T, f map[string]any) verifier.Context {
	t.Helper()
	var c verifier.Context
	slots := map[string]*verifier.Evidence{"audience": &c.Audience, "required_roles": &c.RequiredRoles, "known_keys": &c.AdmittedKeys, "service_root": &c.ServiceRoot, "agent_revocation_root": &c.AgentRevocationRoot, "attestations": &c.Attestations, "agent_attestation_ids": &c.AgentAttestationIDs, "active_generations": &c.CurrentGenerations, "revocations": &c.SignedSnapshots, "time": &c.Time, "now": &c.Now, "watermark_available": &c.WatermarkAvailable, "watermark": &c.Watermark, "id_journal_available": &c.IDJournalAvailable, "seen": &c.IDJournal, "replay_available": &c.ReplayAvailable, "used_actions": &c.UsedActions, "signer_facts": &c.SignerFacts, "assurance": &c.Assurance, "delivery": &c.Delivery}
	for name, slot := range slots {
		v, ok := f[name]
		if !ok {
			continue
		}
		switch name {
		case "attestations", "seen":
			if m, ok := v.(map[string]any); ok {
				n := map[string]any{}
				for k, x := range m {
					n[k] = maBytes(t, x.(string))
				}
				v = n
			}
		case "revocations":
			n := map[string]any{}
			for k, x := range v.(map[string]any) {
				r := map[string]any{}
				for field, value := range x.(map[string]any) {
					r[field] = value
				}
				r["snapshot"] = maBytes(t, r["snapshot"].(string))
				n[k] = r
			}
			v = n
		case "delivery":
			n := map[string]any{}
			for k, x := range v.(map[string]any) {
				n[k] = x
			}
			n["text"] = maBytes(t, n["text"].(string))
			v = n
		}
		var e error
		*slot, e = verifier.Present(v)
		if e != nil {
			t.Fatal(e)
		}
	}
	return c
}
func maSignedRecord(t *testing.T, v maVectors, r map[string]any) []byte {
	t.Helper()
	k, s, b := maFixture(t)
	raw := maPre(t, r)
	p, c := prepareMessageAuthor(raw, v.Key, v.T)
	if c != "" {
		t.Fatal("provider rejected test premise", c)
	}
	sig, c := k.signSelected(s, b, p)
	if c != "" {
		t.Fatal(c)
	}
	h := sha256.Sum256(raw)
	if !oracle.Verify(maBytes(t, v.Key[7:]), h[:], sig) {
		t.Fatal("independent mutated signature")
	}
	body := r["body"].(map[string]any)
	id, e := record.ContentID(body["type"].(string), body)
	if e != nil {
		t.Fatal(e)
	}
	return maCanon(t, map[string]any{"version": r["version"], "body": body, "id": id, "signatures": []any{map[string]any{"key": v.Key, "role": r["role"], "sig": base64.RawURLEncoding.EncodeToString(sig)}}})
}
func maVerdict(t *testing.T, raw []byte, f map[string]any, want string) {
	t.Helper()
	before := maCanon(t, f)
	r := verifier.New(maContext(t, f)).VerifyMessage(raw)
	if r.Code != want {
		t.Fatalf("matched verdict %s want %s", r.Code, want)
	}
	if want != "accept" && (!reflect.DeepEqual(r.Plan, verifier.Plan{}) || r.FreshnessReceipt != nil) {
		t.Fatal("refusal partial plan")
	}
	if !bytes.Equal(before, maCanon(t, f)) {
		t.Fatal("receiver mutated fixture evidence")
	}
}

// Full matched verification preserves exact certificate provenance, current
// fixture binding, time and delivery beside valid source signatures. Contexts
// are historical /1 public fixtures, not a live current-authority provider.
func TestMessageAuthorMatchedVerifier(t *testing.T) {
	v := maData(t)
	raw := maBytes(t, v.Envelope)
	for _, tc := range []struct {
		name, want string
		change     func(map[string]any)
	}{
		{"valid", "accept", nil}, {"no-certificate", "key_binding_unavailable", func(f map[string]any) { f["attestations"] = map[string]any{} }}, {"no-generation", "key_binding_unavailable", func(f map[string]any) { f["active_generations"] = map[string]any{} }}, {"no-snapshot", "key_binding_unavailable", func(f map[string]any) { f["revocations"] = map[string]any{} }}, {"unknown-key", "signer_unknown", func(f map[string]any) { f["known_keys"] = []any{} }}, {"audience", "audience_mismatch", func(f map[string]any) { f["audience"] = "other" }}, {"room", "message_room_mismatch", func(f map[string]any) { f["delivery"].(map[string]any)["room"] = "!other:test.invalid" }}, {"recipient", "message_recipient_mismatch", func(f map[string]any) { f["delivery"].(map[string]any)["to"] = "@other:test.invalid" }}, {"text", "message_text_mismatch", func(f map[string]any) { f["delivery"].(map[string]any)["text"] = "b3RoZXI" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := maContextMap(t, v)
			if tc.change != nil {
				tc.change(f)
			}
			maVerdict(t, raw, f, tc.want)
		})
	}
	for _, field := range []string{"generation", "path", "uid", "registration_number", "master_epoch", "owner", "active"} {
		t.Run(field, func(t *testing.T) {
			f := maContextMap(t, v)
			g := f["active_generations"].(map[string]any)[v.Key].(map[string]any)
			switch field {
			case "uid", "registration_number":
				g[field] = int64(999)
			case "active":
				g[field] = false
			default:
				g[field] = "other"
			}
			maVerdict(t, raw, f, "key_binding_invalid")
		})
	}
	for _, fault := range []string{"algorithm", "class", "purpose", "subject", "expired", "wrong-reference", "signature", "issuer-pin"} {
		t.Run(fault, func(t *testing.T) {
			f := maContextMap(t, v)
			x, e := record.Parse(maBytes(t, v.Attestation), 8192, 16)
			if e != nil {
				t.Fatal(e)
			}
			a := x.(map[string]any)
			ab := a["body"].(map[string]any)
			want := "key_binding_invalid"
			switch fault {
			case "algorithm":
				ab["subject"].(map[string]any)["algorithm"] = "Ed25519"
			case "class":
				ab["key_class"] = "service"
			case "purpose":
				ab["purpose"] = "station-caller"
			case "subject":
				ab["subject"].(map[string]any)["key_id"] = "bip340:eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g"
			case "expired":
				ab["exp"] = "2026-01-01T00:01:00Z"
			case "wrong-reference":
				ab["iat"] = "2026-01-01T00:00:01Z"
				want = "author_attestation_mismatch"
			case "issuer-pin":
				f["service_root"].(map[string]any)["key"] = f["root"]
			}
			id, e := record.ContentID("attestation/1", ab)
			if e != nil {
				t.Fatal(e)
			}
			a["id"] = id
			seed, e := hex.DecodeString(v.IssuerSeed)
			if e != nil {
				t.Fatal(e)
			}
			issuer := ed25519.NewKeyFromSeed(seed)
			pre, e := record.SigningPreimage("attestation/1", ab["issuer"].(string), "author", ab)
			if e != nil {
				t.Fatal(e)
			}
			sig := ed25519.Sign(issuer, pre)
			if fault == "signature" {
				sig[0] ^= 1
			}
			a["signatures"] = []any{map[string]any{"key": ab["issuer"], "role": "author", "sig": base64.RawURLEncoding.EncodeToString(sig)}}
			recordWire := base64.RawURLEncoding.EncodeToString(maCanon(t, a))
			f["attestations"] = map[string]any{v.T: recordWire}
			maVerdict(t, raw, f, want)
		})
	}
	// A changed byte with the original signature fails crypto independently of
	// a payload ID mismatch; use a valid changed record and recompute its ID.
	r := maRecord(t, v)
	r["body"].(map[string]any)["nonce"] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{8}, 16))
	body := r["body"].(map[string]any)
	id, e := record.ContentID("message/1", body)
	if e != nil {
		t.Fatal(e)
	}
	bad := maCanon(t, map[string]any{"version": "swarm-envelope/2", "body": body, "id": id, "signatures": []any{map[string]any{"key": v.Key, "role": "author", "sig": v.Signature}}})
	maVerdict(t, bad, maContextMap(t, v), "envelope_signature_invalid")
}

// The exact opaque signer admits codec-only claims under its one fixed domain;
// the full receiver rejects those claims at the actual profile/schema gates.
func TestMessageAuthorProviderReceiverBoundary(t *testing.T) {
	v := maData(t)
	for _, tc := range []struct {
		name, want string
		change     func(map[string]any)
	}{{"author", "accept", nil}, {"approver", "envelope_role_invalid", func(r map[string]any) { r["role"] = "approver" }}, {"version", "envelope_version_unsupported", func(r map[string]any) { r["version"] = "swarm-envelope/3" }}, {"type", "envelope_type_mismatch", func(r map[string]any) { r["body"].(map[string]any)["type"] = "grant/1" }}, {"action", "envelope_malformed", func(r map[string]any) { r["body"].(map[string]any)["action"] = int64(1) }}} {
		t.Run(tc.name, func(t *testing.T) {
			r := maRecord(t, v)
			if tc.change != nil {
				tc.change(r)
			}
			raw := maSignedRecord(t, v, r)
			maVerdict(t, raw, maContextMap(t, v), tc.want)
		})
	}
	// Adding an otherwise valid author lets the forbidden BIP-340 approver
	// reach the algorithm/role gate rather than merely missing-required-author.
	r := maRecord(t, v)
	r["role"] = "approver"
	raw := maSignedRecord(t, v, r)
	parsed, e := record.Parse(raw, 65536, 16)
	if e != nil {
		t.Fatal(e)
	}
	env := parsed.(map[string]any)
	sigs := env["signatures"].([]any)
	env["signatures"] = append([]any{map[string]any{"key": v.Key, "role": "author", "sig": v.Signature}}, sigs...)
	maVerdict(t, maCanon(t, env), maContextMap(t, v), "signature_profile_invalid")
}

// Official fixed32 public vectors anchor strict scalar/field/point behavior.
// Valid high-s remains valid; variable-length BIP messages are out of the
// envelope's fixed32 hash profile, not declared invalid BIP-340.
func TestMessageAuthorStrictEncoding(t *testing.T) {
	raw, e := os.ReadFile("../../vectors/j7/bip340.csv")
	if e != nil {
		t.Fatal(e)
	}
	if fmtHash(raw) != "34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d" {
		t.Fatal("frozen official corpus")
	}
	rows, e := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if e != nil {
		t.Fatal(e)
	}
	checked, high := 0, 0
	for _, r := range rows[1:] {
		p, e := hex.DecodeString(r[2])
		if e != nil {
			t.Fatal(e)
		}
		m, e := hex.DecodeString(r[4])
		if e != nil {
			t.Fatal(e)
		}
		sig, e := hex.DecodeString(r[5])
		if e != nil {
			t.Fatal(e)
		}
		if len(m) != 32 {
			continue
		}
		checked++
		want := r[6] == "TRUE"
		if oracle.Verify(p, m, sig) != want || j7Verify(p, m, sig) != want {
			t.Fatal("official strict verdict", r[0])
		}
		if want && sig[32] >= 0x80 {
			high++
		}
	}
	if checked != 15 || high == 0 {
		t.Fatal("strict/high-s scope")
	}
	v := maData(t)
	p := maBytes(t, v.Key[7:])
	pre := maBytes(t, v.Preimage)
	sig := maBytes(t, v.Signature)
	for _, bad := range [][]byte{sig[:63], append(append([]byte{}, sig...), 0), append(bytes.Repeat([]byte{255}, 32), sig[32:]...), append(append([]byte{}, sig[:32]...), bytes.Repeat([]byte{255}, 32)...)} {
		if e := record.VerifySignature(v.Key, bad, pre); e == nil {
			t.Fatal("strict signature accepted")
		}
	}
	for _, bad := range []string{"bip340:" + base64.RawURLEncoding.EncodeToString(p[:31]), "bip340:" + base64.RawURLEncoding.EncodeToString(append([]byte{2}, p...)), "bip340:" + strings.Repeat("_", 43), v.Key + "=", "ed25519:" + v.Key[7:]} {
		if e := record.VerifySignature(bad, sig, pre); e == nil {
			t.Fatal("algorithm/encoding alias accepted")
		}
	}
	// Arbitrary bytes with the valid signature cannot acquire a registered domain.
	if e := record.CheckDomain(pre, "swarma-waggle grant/1", v.Key, sig); e == nil {
		t.Fatal("cross domain")
	}
}
func fmtHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// The independent fixture payload is immutable evidence identified by its
// manifest; it never turns synthetic public roots into enrolled custody.
func TestMessageAuthorFixtureManifest(t *testing.T) {
	b, e := os.ReadFile("testdata/message-author-v1/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	m, e := os.ReadFile("testdata/message-author-v1/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		SHA      string `json:"vectors_sha256"`
		TestOnly bool   `json:"test_only"`
		Commit   string `json:"envelope_commit"`
	}
	if json.Unmarshal(m, &v) != nil || !v.TestOnly || v.SHA != fmtHash(b) || v.Commit != "065e25f69da8b28cdf3ea35d9fcd7fc4aacc4d5e" {
		t.Fatal("fixture identity")
	}
}
