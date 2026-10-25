package keymaker

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
	"github.com/relux-works/waggle/record"
	"github.com/relux-works/waggle/verifier"
)

// This capability is internal and has no daemon constructor, root-signing RPC or
// caller-supplied body/preimage. Publication/activation are deliberately absent.
type messageIssuerPolicy struct {
	Path             string `json:"path"`
	Key              string `json:"key"`
	Epoch            string `json:"master_epoch"`
	RegistryRevision string `json:"registry_revision"`
	LifetimeSeconds  int64  `json:"lifetime_seconds"`
}
type messageClock interface {
	Sample(context.Context) (timeconf.Sample, error)
}

var _ messageClock = (*timeconf.Provider)(nil)

type messageIssuer struct {
	master *Master
	policy messageIssuerPolicy
	clock  messageClock
}
type messageBinding struct {
	UID        uint32 `json:"uid"`
	Generation string `json:"generation"`
	Number     uint64 `json:"registration_number"`
	Epoch      string `json:"master_epoch"`
	Owner      string `json:"owner"`
	Path       string `json:"path"`
}
type messageCertificate struct {
	Transaction  string              `json:"transaction"`
	Binding      messageBinding      `json:"binding"`
	KeyID        string              `json:"key_id"`
	IssuerPolicy messageIssuerPolicy `json:"issuer_policy"`
	Envelope     string              `json:"envelope"`
	ContentID    string              `json:"content_id"`
}

func messageBindingOf(b Binding) messageBinding {
	return messageBinding{b.UID, b.Generation, b.Number, b.Epoch, b.Owner, "m/4'" + strings.TrimPrefix(b.Path, "m/1'")}
}
func messageStamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }
func messageText(s string) bool       { return s != "" && len(s) <= 255 && utf8.ValidString(s) }

func (i *messageIssuer) validateRoot() Code {
	if code := ValidatePath(i.policy.Path, "root-attestation"); code != "" {
		return code
	}
	root, code := i.master.withPurpose(i.policy.Path, "root-attestation", func(k ed25519.PrivateKey) []byte { return append([]byte(nil), k[32:]...) })
	if code != "" {
		return code
	}
	if i.policy.Key != "ed25519:"+base64.RawURLEncoding.EncodeToString(root) || record.ValidateKey(i.policy.Key) != nil {
		return "sign_key_mismatch"
	}
	return ""
}

func (i *messageIssuer) body(b Binding, public []byte, now time.Time) (map[string]any, Code) {
	if i == nil || ValidatePath(b.Path, "agent-identity") != "" || b.Status != "active" || b.UID == 0xffffffff || b.Number < 1 || b.Number > 9007199254740991 || !messageText(b.Generation) || !messageText(b.Owner) || !messageText(b.Epoch) || !messageText(b.RegistryRevision) || b.Epoch != i.policy.Epoch || b.RegistryRevision != i.policy.RegistryRevision {
		return nil, "binding_conflict"
	}
	if i.policy.LifetimeSeconds <= 0 || i.policy.LifetimeSeconds > 86400 || now.Year() < 1970 || now.Year() > 9999 {
		return nil, "key_not_valid_now"
	}
	at := now.UTC().Truncate(time.Second)
	exp := at.Add(time.Duration(i.policy.LifetimeSeconds) * time.Second)
	if exp.Year() > 9999 || !now.Before(exp) {
		return nil, "key_not_valid_now"
	}
	key := "ed25519:" + base64.RawURLEncoding.EncodeToString(public)
	if len(public) != ed25519.PublicKeySize || record.ValidateKey(key) != nil {
		return nil, "sign_key_mismatch"
	}
	mb := messageBindingOf(b)
	binding := map[string]any{"uid": int64(mb.UID), "generation": mb.Generation, "registration_number": int64(mb.Number), "master_epoch": mb.Epoch, "owner": mb.Owner, "path": mb.Path}
	return map[string]any{"type": "attestation/1", "issuer": i.policy.Key, "subject": map[string]any{"algorithm": "Ed25519", "key_id": key, "public_bytes": base64.RawURLEncoding.EncodeToString(public)}, "key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"}, "iat": messageStamp(at), "exp": messageStamp(exp), "binding": binding}, ""
}

// prepare may produce one candidate but never current authority. The shared
// provider implements messageClock in production; package fixtures inject it.
// PENDING: S4 conservative uncertainty/Now/W mapping and provider latency under
// generation windows must be qualified before a production constructor exists.
func (i *messageIssuer) prepare(ctx context.Context, id string, b Binding, public []byte, facts verifier.Context) (messageCertificate, Code) {
	return i.prepareAt(ctx, id, b, public, facts, time.Time{})
}
func (i *messageIssuer) prepareAt(ctx context.Context, id string, b Binding, public []byte, facts verifier.Context, issued time.Time) (messageCertificate, Code) {
	empty := messageCertificate{}
	if auditContextExpired(ctx) {
		return empty, "request_deadline_exceeded"
	}
	if i == nil || i.clock == nil {
		return empty, "clock_untrusted"
	}
	sample, err := i.clock.Sample(ctx)
	if err != nil || !timeconfidence.Valid(sample) {
		return empty, "clock_untrusted"
	}
	if issued.IsZero() {
		issued = sample.Now
	}
	if issued.After(sample.Now) {
		return empty, "key_not_valid_now"
	}
	if i.policy.LifetimeSeconds > 0 && i.policy.LifetimeSeconds <= 86400 && !sample.Now.Before(issued.Truncate(time.Second).Add(time.Duration(i.policy.LifetimeSeconds)*time.Second)) {
		return empty, "key_not_valid_now"
	}
	body, code := i.body(b, public, issued)
	if code != "" {
		return empty, code
	}
	if code = i.validateRoot(); code != "" {
		return empty, code
	}
	// Bounds and canonicality are checked on the exact final-size envelope before
	// signing; the all-zero signature is only a size placeholder, never retained.
	content, err := record.ContentID("attestation/1", body)
	if err != nil {
		return empty, "binding_conflict"
	}
	pre, err := record.SigningPreimage("attestation/1", i.policy.Key, "author", body)
	if err != nil {
		return empty, "binding_conflict"
	}
	envelope := func(sig []byte) ([]byte, error) {
		return record.Canonical(map[string]any{"version": "swarm-envelope/2", "body": body, "id": content, "signatures": []any{map[string]any{"role": "author", "key": i.policy.Key, "sig": base64.RawURLEncoding.EncodeToString(sig)}}})
	}
	placeholder, err := envelope(make([]byte, 64))
	if err != nil {
		return empty, "binding_conflict"
	}
	if _, err = record.Parse(placeholder, 8192, 16); err != nil {
		return empty, "binding_conflict"
	}
	if auditContextExpired(ctx) {
		return empty, "request_deadline_exceeded"
	}
	signature, code := i.master.withPurpose(i.policy.Path, "root-attestation", func(k ed25519.PrivateKey) []byte { return ed25519.Sign(k, pre) })
	if code != "" {
		return empty, code
	}
	raw, err := envelope(signature)
	erase(signature)
	if err != nil {
		return empty, "binding_conflict"
	}
	// Use the complete current-use verifier, not a crypto-only approximation.
	// The caller supplies independently qualified revocation/status/root/W facts.
	// Only candidate lookup and actual provider time are replaced locally.
	facts.Attestations, err = verifier.Present(map[string]any{content: raw})
	if err != nil {
		return empty, "binding_conflict"
	}
	facts.Now, err = verifier.Present(messageStamp(sample.Now))
	if err != nil {
		return empty, "clock_untrusted"
	}
	facts.Time, err = verifier.Present(map[string]any{"trusted": true, "fresh": true, "authority_until": messageStamp(sample.AuthorityUntil)})
	if err != nil {
		return empty, "clock_untrusted"
	}
	_, err = verifier.New(facts).VerifyAttestation("ed25519:"+base64.RawURLEncoding.EncodeToString(public), content, false)
	if code = messageVerifierCode(messageEvidenceCode(err)); code != "" {
		return empty, code
	}
	if auditContextExpired(ctx) {
		return empty, "request_deadline_exceeded"
	}
	return messageCertificate{id, messageBindingOf(b), "ed25519:" + base64.RawURLEncoding.EncodeToString(public), i.policy, base64.RawURLEncoding.EncodeToString(raw), content}, ""
}
func messageVerifierCode(code string) Code {
	switch code {
	case "accept":
		return ""
	case "time_unavailable":
		return "clock_untrusted"
	case "key_binding_unavailable", "watermark_unavailable", "revocation_unavailable":
		return "key_not_enrolled"
	case "revoked":
		return "identity_revoked"
	default:
		return "binding_conflict"
	}
}

func messageEvidenceCode(err error) string {
	if err == nil {
		return "accept"
	}
	if e, ok := err.(*record.Error); ok {
		return e.Code
	}
	return "key_binding_invalid"
}
