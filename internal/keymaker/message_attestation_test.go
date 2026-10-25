package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/waggle/record"
	"github.com/relux-works/waggle/verifier"
)

var messageTestNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

type messageTestClock struct {
	now         time.Time
	unavailable bool
}

type messageClockFunc func(context.Context) (timeconf.Sample, error)

func (f messageClockFunc) Sample(ctx context.Context) (timeconf.Sample, error) { return f(ctx) }

func (c *messageTestClock) Sample(context.Context) (timeconf.Sample, error) {
	if c.unavailable {
		return timeconf.Sample{}, timeconf.ErrUnavailable
	}
	return timeconf.Sample{Now: c.now, AuthorityUntil: c.now.Add(time.Second), Trusted: true, Fresh: true, Boot: "fixture", Uncertainty: time.Millisecond}, nil
}
func messageEvidence(t *testing.T, v any) verifier.Evidence {
	t.Helper()
	e, err := verifier.Present(v)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func messageTestID(public []byte) string {
	return "ed25519:" + base64.RawURLEncoding.EncodeToString(public)
}
func messageSigned(t *testing.T, kind string, body map[string]any, key ed25519.PrivateKey) []byte {
	t.Helper()
	id := messageTestID(key[32:])
	pre, err := record.SigningPreimage(kind, id, "author", body)
	if err != nil {
		t.Fatal(err)
	}
	content, err := record.ContentID(kind, body)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := record.Canonical(map[string]any{"version": "swarm-envelope/2", "body": body, "id": content, "signatures": []any{map[string]any{"role": "author", "key": id, "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, pre))}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func messageIssuerFixture(t *testing.T) (*messageIssuer, Binding, []byte, verifier.Context, ed25519.PrivateKey) {
	t.Helper()
	a, b := messageAdapterFixture(t, "m/1'/1'/1'/1'")
	public, _, c := a.public(b)
	if c != "" {
		t.Fatal(c)
	}
	// Root public pin is independently retained in the S1 golden's sibling table.
	v := messageFixtures(t).Vectors[0]
	root := messageTestID(fromHex(t, v.Siblings["5"]))
	i := &messageIssuer{master: a.master, policy: messageIssuerPolicy{Path: "m/5'/1'/1'/1'", Key: root, Epoch: b.Epoch, RegistryRevision: b.RegistryRevision, LifetimeSeconds: 3600}, clock: &messageTestClock{now: messageTestNow}}
	revoker := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, 32))
	rid := messageTestID(revoker[32:])
	binding := messageBindingOf(b)
	active := map[string]any{"uid": int64(binding.UID), "generation": binding.Generation, "registration_number": int64(binding.Number), "master_epoch": binding.Epoch, "owner": binding.Owner, "path": binding.Path, "active": true}
	snapshot := messageSigned(t, "revocation/1", map[string]any{"type": "revocation/1", "issuer": rid, "issued_at": messageStamp(messageTestNow), "complete": true, "entries": []any{}}, revoker)
	facts := verifier.Context{ServiceRoot: messageEvidence(t, map[string]any{"key": root, "purpose": int64(5)}), AgentRevocationRoot: messageEvidence(t, map[string]any{"key": rid, "purpose": "registry-revocation", "attestation_root": root}), CurrentGenerations: messageEvidence(t, map[string]any{messageTestID(public): active}), SignedSnapshots: messageEvidence(t, map[string]any{rid: map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": true, "snapshot": snapshot}}), Time: messageEvidence(t, map[string]any{"trusted": true, "fresh": true, "authority_until": messageStamp(messageTestNow.Add(time.Second))}), Now: messageEvidence(t, messageStamp(messageTestNow)), WatermarkAvailable: messageEvidence(t, true), Watermark: messageEvidence(t, messageStamp(messageTestNow))}
	return i, b, public, facts, revoker
}
func messageVerifyFixture(t *testing.T, c messageCertificate, f verifier.Context) string {
	t.Helper()
	raw, err := record.DecodeBase64(c.Envelope, -1)
	if err != nil {
		t.Fatal(err)
	}
	f.Attestations = messageEvidence(t, map[string]any{c.ContentID: raw})
	_, err = verifier.New(f).VerifyAttestation(c.KeyID, c.ContentID, false)
	return messageEvidenceCode(err)
}

// Purpose-5 attestation math uses the full tagged signed record and an independently
// pinned purpose-5 sibling; other sibling signatures do not verify under that pin.
func TestMsgV09CertificatePurpose(t *testing.T) {
	i, b, p, f, _ := messageIssuerFixture(t)
	c, code := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f)
	if code != "" {
		t.Fatal("valid issuer control", code)
	}
	raw, _ := record.DecodeBase64(c.Envelope, -1)
	v, err := record.Parse(raw, 8192, 16)
	if err != nil {
		t.Fatal(err)
	}
	obj := v.(map[string]any)
	body := obj["body"].(map[string]any)
	pre, _ := record.SigningPreimage("attestation/1", i.policy.Key, "author", body)
	sig, _ := record.DecodeBase64(obj["signatures"].([]any)[0].(map[string]any)["sig"].(string), 64)
	if record.VerifySignature(i.policy.Key, sig, pre) != nil {
		t.Fatal("full signed-record preimage failed")
	}
	bare, _ := record.Canonical(body)
	if record.VerifySignature(i.policy.Key, sig, bare) == nil || record.VerifySignature(i.policy.Key, sig, append([]byte("swarma-attestation attestation/1\x00"), bare...)) == nil {
		t.Fatal("bare/NUL preimage accepted")
	}
	if got := messageVerifyFixture(t, c, f); got != "accept" {
		t.Fatal(got)
	}
}

// Issuance uses trusted time, a half-open valid interval, and never stretches an
// invalid lifetime. Full verifier rejection of expired certificates is separate
// from S2's always-unenrolled local publication gate.
func TestMsgV12CertificationWindow(t *testing.T) {
	for _, bad := range []string{"clock", "zero", "negative", "overlong", "valid"} {
		t.Run(bad, func(t *testing.T) {
			i, b, p, f, _ := messageIssuerFixture(t)
			want := Code("key_not_valid_now")
			switch bad {
			case "clock":
				i.clock.(*messageTestClock).unavailable = true
				want = "clock_untrusted"
			case "zero":
				i.policy.LifetimeSeconds = 0
			case "negative":
				i.policy.LifetimeSeconds = -1
			case "overlong":
				i.policy.LifetimeSeconds = 86401
			case "valid":
				want = ""
			}
			c, got := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f)
			if got != want {
				t.Fatal("window guard", got, want)
			}
			if got != "" && c.Envelope != "" {
				t.Fatal("refusal returned certificate")
			}
			if got == "" {
				f.Now = messageEvidence(t, messageStamp(messageTestNow.Add(time.Hour)))
				f.Watermark = f.Now
				f.Time = messageEvidence(t, map[string]any{"trusted": true, "fresh": true, "authority_until": messageStamp(messageTestNow.Add(2 * time.Hour))})
				if v := messageVerifyFixture(t, c, f); v != "key_binding_invalid" {
					t.Fatal("expiry accepted", v)
				}
			}
		})
	}
}

// The issuer has no arbitrary Sign(bytes) capability; malformed/wrong-purpose
// protected tuple or pin refuses without producing a certificate. General APIs
// still reject purpose5; ordinary purpose1 and the fixed issuer remain controls.
func TestMsgV17RootIsolation(t *testing.T) {
	typ := reflect.TypeOf(&messageIssuer{})
	if _, ok := typ.MethodByName("Sign"); ok {
		t.Fatal("arbitrary issuer signing API")
	}
	for _, path := range []string{"m/1'/1'/1'/1'", "m/2'/1'/1'/1'", "m/3'/1'/1'/1'", "m/4'/1'/1'/1'", "m/5/1'/1'/1'"} {
		i, b, p, f, _ := messageIssuerFixture(t)
		i.policy.Path = path
		c, code := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f)
		if code == "" || c.Envelope != "" {
			t.Fatal("wrong-purpose issuer admitted", path)
		}
	}
	i, b, p, f, _ := messageIssuerFixture(t)
	if _, code := i.master.Sign(i.policy.Path, []byte("anything")); code != "purpose_unknown" {
		t.Fatal("general Sign exposed issuer", code)
	}
	if _, code := i.master.Sign(b.Path, []byte("fixture purpose1 control")); code != "" {
		t.Fatal(code)
	}
	i.policy.Key = messageTestID(p)
	if _, code := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f); code != "sign_key_mismatch" {
		t.Fatal("wrong root pin admitted", code)
	}
	i, b, p, f, _ = messageIssuerFixture(t)
	if _, code := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f); code != "" {
		t.Fatal("issuer control", code)
	}
}

// An attestation signed by each wrong sibling cannot substitute for the protected
// root; 86400 is accepted while 86401 refuses before signature creation.
func TestMsgV18IssuerAndLifetime(t *testing.T) {
	i, b, p, f, _ := messageIssuerFixture(t)
	i.policy.LifetimeSeconds = 86401
	if _, code := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f); code != "key_not_valid_now" {
		t.Fatal("24-hour bound bypassed", code)
	}
	i.policy.LifetimeSeconds = 86400
	c, code := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f)
	if code != "" {
		t.Fatal("86400 control", code)
	}
	raw, _ := record.DecodeBase64(c.Envelope, -1)
	parsed, _ := record.Parse(raw, 8192, 16)
	body := parsed.(map[string]any)["body"].(map[string]any)
	for purpose := 1; purpose <= 4; purpose++ {
		indices := []uint32{uint32(purpose) | 0x80000000, 0x80000001, 0x80000001, 0x80000001}
		node := deriveNode(i.master.seed, indices)
		key := ed25519.NewKeyFromSeed(node[:32])
		erase(node)
		forged := c
		forged.Envelope = base64.RawURLEncoding.EncodeToString(messageSigned(t, "attestation/1", body, key))
		erase(key)
		if v := messageVerifyFixture(t, forged, f); v != "key_binding_invalid" {
			t.Fatal("wrong sibling attestation accepted", purpose, v)
		}
	}
	if v := messageVerifyFixture(t, c, f); v != "accept" {
		t.Fatal(v)
	}
}

// Nonrepresentable binding values refuse rather than truncate or change base
// registration acceptance. Max valid UID/registration/strings are builder controls;
// full cryptographic admission is checked on the ordinary binding beside them.
func TestMsgV23AttestationProfile(t *testing.T) {
	for _, bad := range []string{"uid", "number", "generation", "owner", "epoch", "lineage", "public", "valid"} {
		t.Run(bad, func(t *testing.T) {
			i, b, p, f, _ := messageIssuerFixture(t)
			want := Code("binding_conflict")
			switch bad {
			case "uid":
				b.UID = 0xffffffff
			case "number":
				b.Number = 9007199254740992
			case "generation":
				b.Generation = strings.Repeat("x", 256)
			case "owner":
				b.Owner = strings.Repeat("x", 256)
			case "epoch":
				b.Epoch = "other"
			case "lineage":
				b.RegistryRevision = "other"
			case "public":
				p = make([]byte, 32)
				want = "sign_key_mismatch"
			case "valid":
				want = ""
			}
			c, got := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f)
			if got != want {
				t.Fatal("profile pre-sign bound", got, want)
			}
			if _, got := i.body(b, p, messageTestNow); got != want {
				t.Fatal("profile builder pre-sign bound", got, want)
			}
			if got != "" && c.Envelope != "" {
				t.Fatal("refusal returned certificate")
			}
		})
	}
	i, b, p, _, _ := messageIssuerFixture(t)
	b.UID = 4294967294
	b.Number = 9007199254740991
	b.Generation = strings.Repeat("g", 255)
	b.Owner = strings.Repeat("o", 255)
	b.Epoch = strings.Repeat("e", 255)
	i.policy.Epoch = b.Epoch
	if _, code := i.body(b, p, messageTestNow); code != "" {
		t.Fatal("representable boundary refused", code)
	}
}

// Current-use selfcheck uses real separately signed cumulative snapshots. Missing,
// stale, future, rollback-unsafe, revoked or wrong-scope evidence never acts as an
// empty revocation set. The complete independently signed control verifies.
func TestMsgV24RevocationSelfcheck(t *testing.T) {
	for _, mode := range []string{"missing", "stale", "age60", "max-age61", "future", "incomplete", "rollback", "revoked", "record", "cross-signature", "wrong-scope", "valid"} {
		t.Run(mode, func(t *testing.T) {
			i, b, p, f, r := messageIssuerFixture(t)
			rid := messageTestID(r[32:])
			at := messageTestNow
			complete, safe := true, true
			entries := []any{}
			want := Code("key_not_enrolled")
			maxAge := int64(60)
			switch mode {
			case "missing":
				f.SignedSnapshots = verifier.Evidence{}
			case "stale":
				at = at.Add(-61 * time.Second)
			case "age60":
				at = at.Add(-60 * time.Second)
				want = ""
			case "max-age61":
				maxAge = 61
				want = "binding_conflict"
			case "future":
				at = at.Add(time.Second)
			case "incomplete":
				complete = false
			case "rollback":
				safe = false
			case "revoked":
				entries = []any{map[string]any{"kind": "key", "id": messageTestID(p), "from": messageStamp(at)}}
				want = "identity_revoked"
			case "record":
				cert, code := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f)
				if code != "" {
					t.Fatal(code)
				}
				entries = []any{map[string]any{"kind": "record", "id": cert.ContentID, "from": messageStamp(at)}}
				want = "identity_revoked"
			case "cross-signature":
				want = "binding_conflict"
			case "wrong-scope":
				f.AgentRevocationRoot = messageEvidence(t, map[string]any{"key": rid, "purpose": "registry-revocation", "attestation_root": messageTestID(p)})
				want = "binding_conflict"
			case "valid":
				want = ""
			}
			if mode != "missing" {
				snapshot := messageSigned(t, "revocation/1", map[string]any{"type": "revocation/1", "issuer": rid, "issued_at": messageStamp(at), "complete": complete, "entries": entries}, r)
				if mode == "cross-signature" {
					root, code := i.master.withPurpose(i.policy.Path, "root-attestation", func(k ed25519.PrivateKey) []byte { return append([]byte(nil), k...) })
					if code != "" {
						t.Fatal(code)
					}
					snapshot = messageSigned(t, "revocation/1", map[string]any{"type": "revocation/1", "issuer": rid, "issued_at": messageStamp(at), "complete": true, "entries": entries}, ed25519.PrivateKey(root))
					erase(root)
				}
				f.SignedSnapshots = messageEvidence(t, map[string]any{rid: map[string]any{"availability": "available", "max_age": maxAge, "rollback_safe": safe, "snapshot": snapshot}})
			}
			_, code := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f)
			if code != want {
				t.Fatal("selfcheck guard", code, want)
			}
		})
	}
}

// A valid root signature cannot compensate for any missing certificate, subject
// or six-field binding member. Each omission reports the pinned unavailable
// evidence code; the complete independently active fixture verifies beside it.
func TestMsgMissingCertificateMembers(t *testing.T) {
	i, b, p, f, _ := messageIssuerFixture(t)
	cert, c := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f)
	if c != "" {
		t.Fatal(c)
	}
	raw, _ := record.DecodeBase64(cert.Envelope, -1)
	root, c := i.master.withPurpose(i.policy.Path, "root-attestation", func(k ed25519.PrivateKey) []byte { return append([]byte(nil), k...) })
	if c != "" {
		t.Fatal(c)
	}
	defer erase(root)
	for _, group := range []string{"body", "subject", "binding"} {
		value, e := record.Parse(raw, 8192, 16)
		if e != nil {
			t.Fatal(e)
		}
		body := value.(map[string]any)["body"].(map[string]any)
		members := body
		if group != "body" {
			members = body[group].(map[string]any)
		}
		for member := range members {
			t.Run(group+"/"+member, func(t *testing.T) {
				v, e := record.Parse(raw, 8192, 16)
				if e != nil {
					t.Fatal(e)
				}
				body := v.(map[string]any)["body"].(map[string]any)
				selected := body
				if group != "body" {
					selected = body[group].(map[string]any)
				}
				delete(selected, member)
				changed := cert
				content, e := record.ContentID("attestation/1", body)
				if e != nil {
					t.Fatal(e)
				}
				changed.ContentID = content
				changed.Envelope = base64.RawURLEncoding.EncodeToString(messageSigned(t, "attestation/1", body, ed25519.PrivateKey(root)))
				if c := messageVerifyFixture(t, changed, f); c != "key_binding_unavailable" {
					t.Fatal("missing certificate evidence", c)
				}
			})
		}
	}
	if c := messageVerifyFixture(t, cert, f); c != "accept" {
		t.Fatal("complete certificate control", c)
	}
}

// Exact-reference verifier lookup never substitutes a newer attestation for an
// absent/other ID. This is the certificate boundary, not VerifyMessage's later
// author_attestation equality check (owned by the signing/receiver slice).
func TestMsgV25ReceiverReference(t *testing.T) {
	i, b, p, f, _ := messageIssuerFixture(t)
	c, code := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f)
	if code != "" {
		t.Fatal(code)
	}
	raw, _ := record.DecodeBase64(c.Envelope, -1)
	f.Attestations = messageEvidence(t, map[string]any{c.ContentID: raw})
	lib := verifier.New(f)
	if _, err := lib.VerifyAttestation(c.KeyID, "sha256:"+strings.Repeat("0", 64), false); messageEvidenceCode(err) != "key_binding_unavailable" {
		t.Fatal("reference substituted", err)
	}
	if _, err := lib.VerifyAttestation(c.KeyID, c.ContentID, false); err != nil {
		t.Fatal(err)
	}
}

// Missing independently supplied authority refuses as unavailable; malformed or
// overlapping role pins refuse as invalid. The fully signed fresh fixture is
// accepted. Provider time is injected independently of these verifier facts.
func TestMsgAuthorityEvidence(t *testing.T) {
	for _, mode := range []string{"no-root", "no-binding", "no-watermark", "wrong-purpose", "overlap", "valid"} {
		t.Run(mode, func(t *testing.T) {
			i, b, p, f, _ := messageIssuerFixture(t)
			want := Code("key_not_enrolled")
			switch mode {
			case "no-root":
				f.ServiceRoot = verifier.Evidence{}
			case "no-binding":
				f.CurrentGenerations = verifier.Evidence{}
			case "no-watermark":
				f.Watermark = verifier.Evidence{}
			case "wrong-purpose":
				f.ServiceRoot = messageEvidence(t, map[string]any{"key": i.policy.Key, "purpose": int64(2)})
				want = "binding_conflict"
			case "overlap":
				f.AgentRevocationRoot = messageEvidence(t, map[string]any{"key": i.policy.Key, "purpose": "registry-revocation", "attestation_root": i.policy.Key})
				want = "binding_conflict"
			case "valid":
				want = ""
			}
			cert, c := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f)
			if c != want || c != "" && cert.Envelope != "" {
				t.Fatal("authority evidence refusal", c, want)
			}
		})
	}
}

// The pinned receiver rejects oversize/deep/extended certificate evidence. The
// issuer's fixed profile cannot fill 8192 legitimate bytes, so that exact-size
// number is a parser cap, not a claimed valid attestation fixture here.
func TestMsgCertificateEnvelopeBounds(t *testing.T) {
	i, b, p, f, _ := messageIssuerFixture(t)
	cert, c := i.prepare(t.Context(), strings.Repeat("1", 32), b, p, f)
	if c != "" {
		t.Fatal(c)
	}
	raw, _ := record.DecodeBase64(cert.Envelope, -1)
	for _, mode := range []string{"oversize", "deep", "extra", "valid"} {
		t.Run(mode, func(t *testing.T) {
			value, e := record.Parse(raw, 8192, 16)
			if e != nil {
				t.Fatal(e)
			}
			env := value.(map[string]any)
			switch mode {
			case "oversize":
				env["extra"] = strings.Repeat("x", 8192)
			case "deep":
				var x any = "x"
				for n := 0; n < 17; n++ {
					x = map[string]any{"x": x}
				}
				env["extra"] = x
			case "extra":
				env["body"].(map[string]any)["registry_revision"] = "unrecognized"
			}
			encoded, e := json.Marshal(env)
			if e != nil {
				t.Fatal(e)
			}
			altered := cert
			altered.Envelope = base64.RawURLEncoding.EncodeToString(encoded)
			want := "key_binding_invalid"
			if mode == "valid" {
				want = "accept"
			}
			if c := messageVerifyFixture(t, altered, f); c != want {
				t.Fatal("receiver envelope bound", c, want)
			}
		})
	}
}

// Losing authority or expiring the original lifetime after the durable intent
// leaves only the exact fenced intent, not a candidate or fallback. Cancelling
// after crypto likewise never writes a candidate; a fresh valid control issues.
func TestMsgIssuanceAuthorityLoss(t *testing.T) {
	for _, mode := range []string{"clock", "expired", "cancelled", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := messageStateSetup(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			clock := f.issuer.clock
			calls := 0
			f.issuer.clock = messageClockFunc(func(ctx context.Context) (timeconf.Sample, error) {
				calls++
				sample, e := clock.Sample(ctx)
				if calls == 2 {
					if mode == "clock" {
						return timeconf.Sample{}, timeconf.ErrUnavailable
					}
					if mode == "expired" {
						sample.Now = sample.Now.Add(time.Hour)
						sample.AuthorityUntil = sample.Now.Add(time.Second)
					}
				}
				return sample, e
			})
			f.store.messageFault = func(point string) Code {
				if point == "signed" && mode == "cancelled" {
					cancel()
				}
				return ""
			}
			_, code := f.service.issue(ctx, f.binding)
			want := map[string]Code{"clock": "clock_untrusted", "expired": "key_not_valid_now", "cancelled": "request_deadline_exceeded", "valid": ""}[mode]
			if code != want {
				t.Fatal("issuance time/deadline refusal", code, want)
			}
			if mode != "valid" {
				f.reopen(t)
				tx := f.store.messages.Transactions[0]
				if tx.Phase != "intent" || tx.Candidate != nil || len(f.store.messages.Certificates) != 0 || f.store.messages.Associations[0].Pending == nil {
					t.Fatal("authority loss escaped fence")
				}
			}
		})
	}
}
