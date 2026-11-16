//go:build linux

package keymaker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keymaker/internal/keymaker/publicationhandoff"
)

const maLegacyBIP = "bip340:WowJ0rnekTFSPtivBWuoato06f_BXuc3w-BkTJspoPE"

// The authority-root Key grammar remains Ed25519 or P256 after the dependency
// repin. Valid BIP340 is a negative here, while it remains valid for purpose9.
// Anchor/witness exercise real field ownership, not only a prefix helper.
func TestMessageAuthorLegacyAuthorityAlgorithms(t *testing.T) {
	anchor := func(key any) map[string]any {
		return map[string]any{"registry_id": key, "owner": "owner", "publication_seq": int64(0), "freshness_id": nil, "issued_at": nil, "snapshot": "sha256:" + strings.Repeat("a", 64), "registry_seq": int64(1), "checkpoint_id": "sha256:" + strings.Repeat("b", 64)}
	}
	witness := func(key any) map[string]any {
		return map[string]any{"registry_id": key, "owner": "owner", "registry_seq": int64(1), "registry_head": "sha256:" + strings.Repeat("a", 64), "checkpoint_id": "sha256:" + strings.Repeat("b", 64), "previous_checkpoint_id": nil}
	}
	for _, tc := range []struct {
		name string
		key  any
		want string
	}{{"ed25519", pc2EdKey, ""}, {"p256", pc2P256Key, ""}, {"bip340", maLegacyBIP, "field_format"}, {"malformed-ed", "ed25519:x", "field_format"}, {"malformed-p256", "p256:x", "field_format"}, {"invalid-point", "ed25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "field_format"}, {"type", int64(7), "wrong_type"}} {
		t.Run(tc.name, func(t *testing.T) {
			for name, rule := range map[string]func(any) error{"key": arKey, "anchor": func(k any) error { return authorityAnchorRule()(anchor(k)) }, "witness": func(k any) error { return arWitness()(witness(k)) }} {
				if got := authorityCode(rule(tc.key)); got != tc.want {
					t.Errorf("legacy algorithm accepted: %s got %q want %q", name, got, tc.want)
				}
			}
		})
	}
	if record.ValidateKey(maLegacyBIP) != nil {
		t.Fatal("purpose9 positive point control")
	}
}

func maLegacyIntent(issuer string) messageIntent {
	b := Binding{UID: 1000, Generation: "generation-0", Path: "m/1'/1'/2'/3'", Owner: "owner-a", Number: 1, Lifetime: "persistent", Status: "active", Epoch: "epoch-1", RegistryRevision: "registry", Registrar: fixtureOperator}
	return messageIntent{Binding: b, Policy: messageIssuerPolicy{Path: "m/5'/1'/2'/3'", Key: issuer, Epoch: b.Epoch, RegistryRevision: b.RegistryRevision, LifetimeSeconds: 3600}, KeyID: pc2EdKey, IssuedAt: "2026-01-01T00:00:00Z"}
}

// A retained purpose5 issuer is Ed25519 only, independently of the subject
// KeyID's existing Ed25519 gate. P256/BIP340 are not issuer policy aliases.
func TestMessageAuthorPurpose5IntentIssuerAlgorithms(t *testing.T) {
	for _, tc := range []struct{ name, key, want string }{{"ed25519", pc2EdKey, ""}, {"bip340", maLegacyBIP, "keymaker: invalid issuance policy"}, {"p256", pc2P256Key, "keymaker: invalid issuance policy"}, {"malformed", "ed25519:x", "keymaker: invalid issuance policy"}, {"invalid-point", "ed25519:" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "keymaker: invalid issuance policy"}} {
		t.Run(tc.name, func(t *testing.T) {
			e := validateMessageIntent(maLegacyIntent(tc.key))
			got := ""
			if e != nil {
				got = e.Error()
			}
			if got != tc.want {
				t.Fatalf("purpose5 issuer algorithm accepted: got %q want %q", got, tc.want)
			}
		})
	}
}

// A mathematically valid BIP340 re-issuance of the historical Ed25519 subject
// cannot pass certificate recovery or the checked publication-handoff caller.
// All scalars are public test constants; this supplies no live issuer/provider.
func TestMessageAuthorPurpose5CertificateIssuerAlgorithms(t *testing.T) {
	c := preparedMessageControl(t)
	if e := validateMessageCertificate(c); e != nil {
		t.Fatal("Ed25519 certificate control", e)
	}
	if _, e := preparedMessagePublication(c); e != nil {
		t.Fatal("handoff positive", e)
	}
	raw, e := record.DecodeBase64(c.Envelope, -1)
	if e != nil {
		t.Fatal(e)
	}
	v, e := record.Parse(raw, 8192, 16)
	if e != nil {
		t.Fatal(e)
	}
	env := v.(map[string]any)
	body := env["body"].(map[string]any)
	key, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{3}, 32))
	defer key.Zero()
	kid := "bip340:" + base64.RawURLEncoding.EncodeToString(schnorr.SerializePubKey(key.PubKey()))
	c.IssuerPolicy.Key = kid
	body["issuer"] = kid
	c.ContentID, e = record.ContentID("attestation/1", body)
	if e != nil {
		t.Fatal(e)
	}
	env["id"] = c.ContentID
	pre, e := record.SigningPreimage("attestation/1", kid, "author", body)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(pre)
	var aux [32]byte
	sig, e := schnorr.Sign(key, h[:], schnorr.CustomNonce(aux))
	if e != nil || record.VerifySignature(kid, sig.Serialize(), pre) != nil {
		t.Fatal("BIP340 math premise", e)
	}
	env["signatures"] = []any{map[string]any{"key": kid, "role": "author", "sig": base64.RawURLEncoding.EncodeToString(sig.Serialize())}}
	wire, e := record.Canonical(env)
	if e != nil {
		t.Fatal(e)
	}
	c.Envelope = base64.RawURLEncoding.EncodeToString(wire)
	if e := validateMessageCertificate(c); e == nil || e.Error() != "keymaker: invalid certificate signature" {
		t.Fatal("purpose5 certificate issuer accepted", e)
	}
	if p, e := preparedMessagePublication(c); e != publicationhandoff.ErrInvalid || p != nil {
		t.Fatal("purpose5 handoff issuer accepted", e)
	}
}
