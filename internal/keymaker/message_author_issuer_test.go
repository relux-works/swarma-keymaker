//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/verifier"
	"github.com/relux-works/swarma-keymaker/messageauthor"
)

func newMAIssuerFixture(t *testing.T) (*maLiveFixture, *maIssuer) {
	t.Helper()
	f := newMALiveFixture(t)
	seed := bytes.Repeat([]byte{0xa5}, 32)
	k, c := newMAIssuerKey(seed)
	if c != "" {
		t.Fatal(c)
	}
	t.Cleanup(func() { k.close() })
	i := &maIssuer{store: f.h.store, subject: f.h.key, custody: k, generations: f.h.generations, clock: func(context.Context) (j7GateTime, Code) { return f.at, "" }}
	f.h.current = i
	return f, i
}
func maIssuerRead(t *testing.T, f *maLiveFixture, i *maIssuer, want Code) maLiveTuple {
	t.Helper()
	var out maLiveTuple
	calls := 0
	c := i.WithCurrent(t.Context(), f.b, f.at, func(v maLiveTuple) Code { calls++; out = v; return "" })
	if c != want || (want != "" && calls != 0) || (want == "" && calls != 1) {
		t.Fatalf("current gate got %q want %q callbacks=%d", c, want, calls)
	}
	return out
}

// The independently pinned verifier accepts the produced BIP-340 attestation
// under a purpose-5 service_root; tampering refuses beside that valid control.
func TestMAIssuerUpstream(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal("issue control", c)
	}
	v := maIssuerRead(t, f, i, "")
	pub, c := i.custody.public()
	if c != "" {
		t.Fatal(c)
	}
	facts := maContextMap(t, f.v)
	facts["service_root"] = map[string]any{"key": pub, "purpose": int64(5)}
	facts["attestations"] = map[string]any{v.T: base64Text(v.Attestation)}
	g := maIssuerWireBinding(f.b)
	g["active"] = true
	facts["active_generations"] = map[string]any{v.Key: g}
	revoker := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, 32))
	rid := messageTestID(revoker[32:])
	snapshot := messageSigned(t, "revocation/1", map[string]any{"type": "revocation/1", "issuer": rid, "issued_at": messageStamp(f.at.Now), "complete": true, "entries": []any{}}, revoker)
	facts["agent_revocation_root"] = map[string]any{"key": rid, "purpose": "registry-revocation", "attestation_root": pub}
	facts["revocations"] = map[string]any{rid: map[string]any{"availability": "available", "max_age": int64(60), "rollback_safe": true, "snapshot": base64Text(snapshot)}}
	facts["watermark"] = messageStamp(f.at.Now)
	facts["now"] = messageStamp(f.at.Now)
	facts["time"] = map[string]any{"trusted": true, "fresh": true, "authority_until": messageStamp(f.at.Now.Add(time.Minute))}
	_, e := verifier.New(maContext(t, facts)).VerifyAttestation(v.Key, v.T, false)
	if e != nil {
		t.Fatal("upstream positive", e)
	}
	// Each negative retains valid outer CCJ-1 framing, except the separately
	// labelled historical version flip. Expected refusal is key_binding_invalid.
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, 32))
	otherID := messageTestID(other[32:])
	for _, fault := range []string{"body", "signature", "other-signature", "other-root", "version"} {
		t.Run(fault, func(t *testing.T) {
			facts["service_root"] = map[string]any{"key": pub, "purpose": int64(5)}
			x, err := record.Parse(v.Attestation, 8192, 16)
			if err != nil {
				t.Fatal(err)
			}
			a := x.(map[string]any)
			sig := a["signatures"].([]any)[0].(map[string]any)
			switch fault {
			case "body":
				a["body"].(map[string]any)["binding"].(map[string]any)["owner"] = "different-owner"
			case "signature":
				b, err := base64.RawURLEncoding.DecodeString(sig["sig"].(string))
				if err != nil {
					t.Fatal(err)
				}
				b[0] ^= 1
				sig["sig"] = base64Text(b)
			case "other-signature":
				pre, err := record.SigningPreimage("attestation/1", otherID, "author", a["body"].(map[string]any))
				if err != nil {
					t.Fatal(err)
				}
				sig["key"], sig["sig"] = otherID, base64Text(ed25519.Sign(other, pre))
			case "other-root":
				facts["service_root"] = map[string]any{"key": otherID, "purpose": int64(5)}
			case "version":
				a["version"] = "swarm-envemope/2"
			}
			tampered, err := record.Canonical(a)
			if err != nil {
				t.Fatal(err)
			}
			facts["attestations"] = map[string]any{v.T: base64Text(tampered)}
			if _, err = verifier.New(maContext(t, facts)).VerifyAttestation(v.Key, v.T, false); err == nil || !strings.Contains(err.Error(), "key_binding_invalid") {
				t.Fatal("tampered A not refused by name", fault, err)
			}
			facts["service_root"] = map[string]any{"key": pub, "purpose": int64(5)}
			facts["attestations"] = map[string]any{v.T: base64Text(v.Attestation)}
			if _, err = verifier.New(maContext(t, facts)).VerifyAttestation(v.Key, v.T, false); err != nil {
				t.Fatal("adjacent valid A", err)
			}
		})
	}
	// The real issuer also composes with the unchanged holder wire/crypto path.
	obj := maRecord(t, f.v)
	obj["body"].(map[string]any)["author_attestation"] = v.T
	req := f.request()
	req.Preimage = maPre(t, obj)
	got := 0
	if c := f.h.handle(t.Context(), Principal{f.b.UID, f.b.Generation}, req, func(_ context.Context, r messageauthor.Response) Code {
		got++
		if r.Signature == nil {
			t.Fatal("no signature")
		}
		return ""
	}); c != "" || got != 1 {
		t.Fatal("holder positive", c, got)
	}
}
func base64Text(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Every one-field forbidden language/profile mutation refuses without a
// certificate; the same capability accepts the exact fixed internal body.
func TestMAIssuerProfile(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	key, _ := i.subject.publicSelected(i.store, f.b)
	body, c := i.body(f.b, key, f.at, 86400*time.Second)
	if c != "" {
		t.Fatal(c)
	}
	if _, c = i.custody.attest(body); c != "" {
		t.Fatal("profile positive", c)
	}
	for _, field := range []string{"algorithm", "roles", "actions", "purpose", "type", "issuer", "binding", "lifetime", "public_bytes"} {
		t.Run(field, func(t *testing.T) {
			b, _ := i.body(f.b, key, f.at, 86400*time.Second)
			switch field {
			case "algorithm":
				b["subject"].(map[string]any)["algorithm"] = "Ed25519"
			case "roles":
				b["roles"] = []any{"service_root"}
			case "actions":
				b["actions"] = []any{"message.verify"}
			case "purpose":
				b["purpose"] = 9
			case "type":
				b["type"] = "revocation/1"
			case "issuer":
				b["issuer"] = key
			case "binding":
				b["binding"].(map[string]any)["path"] = "m/4'/1'/2'/3'"
			case "lifetime":
				b["exp"] = messageStamp(f.at.Lower.Truncate(time.Second).Add(86401 * time.Second))
			case "public_bytes":
				b["subject"].(map[string]any)["public_bytes"] = "bad"
			}
			if raw, c := i.custody.attest(b); c != "binding_conflict" || raw != nil {
				t.Fatal("profile mutation issued", field, c)
			}
		})
	}
	for _, d := range []time.Duration{0, 86401 * time.Second} {
		if _, c = i.body(f.b, key, f.at, d); c != "key_not_valid_now" {
			t.Fatal("lifetime gate", c)
		}
	}
}

// Fencing begins at the durable pending marker. Only a durable pre-commit
// cancellation may restore a still-valid exact predecessor; a committed new T
// permanently retires the old T, including after restart.
func TestMAIssuerRenewal(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	old := maIssuerRead(t, f, i, "")
	f.at.Now = f.at.Now.Add(time.Hour)
	f.at.Lower = f.at.Lower.Add(time.Hour)
	f.at.Upper = f.at.Upper.Add(time.Hour)
	i.store.messageFault = func(p string) Code {
		if p == "mai-candidate" {
			return "request_deadline_exceeded"
		}
		return ""
	}
	if c := i.issue(t.Context(), f.b); c != "request_deadline_exceeded" {
		t.Fatal(c)
	}
	maIssuerRead(t, f, i, "message_author_unqualified")
	if c := f.restart(t); c != "" {
		t.Fatal("pending recovery", c)
	}
	i.store = f.h.store
	maIssuerRead(t, f, i, "message_author_unqualified")
	if c := i.cancel(t.Context(), f.b); c != "" {
		t.Fatal("proven cancel", c)
	}
	if maIssuerRead(t, f, i, "").T != old.T {
		t.Fatal("cancel did not restore")
	}
	i.store.messageFault = nil
	f.at.Now = f.at.Now.Add(time.Second)
	f.at.Lower = f.at.Lower.Add(time.Second)
	f.at.Upper = f.at.Upper.Add(time.Second)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal("renew", c)
	}
	next := maIssuerRead(t, f, i, "")
	if next.T == old.T || next.Key != old.Key {
		t.Fatal("renew identity")
	}
	beforeCancel := i.store.version
	beforeAudit := i.store.journal.seq
	if c := i.cancel(t.Context(), f.b); c != "message_author_unqualified" {
		t.Fatal("post-commit cancellation accepted", c)
	}
	if i.store.version != beforeCancel || i.store.journal.seq != beforeAudit {
		t.Fatal("post-commit cancellation changed evidence")
	}
	if c := f.restart(t); c != "" {
		t.Fatal(c)
	}
	i.store = f.h.store
	if maIssuerRead(t, f, i, "").T != next.T {
		t.Fatal("old T reopened")
	}
}

// Unknown issuance audit tails, pre-commit crashes and expired predecessor
// cancellation all remain fenced; a fully committed issuance survives recovery.
func TestMAIssuerCrash(t *testing.T) {
	for _, point := range []string{"mai-pending", "mai-candidate", "mai-success-audit", "mai-commit"} {
		t.Run(point, func(t *testing.T) {
			f, i := newMAIssuerFixture(t)
			i.store.messageFault = func(p string) Code {
				if p == point {
					return "request_deadline_exceeded"
				}
				return ""
			}
			if c := i.issue(t.Context(), f.b); c != "request_deadline_exceeded" {
				t.Fatal(c)
			}
			if c := maIssuerRestart(t, f); c != "" {
				t.Fatal(c)
			}
			i.store = f.h.store
			want := Code("message_author_unqualified")
			if point == "mai-commit" {
				want = ""
			}
			maIssuerRead(t, f, i, want)
			if point == "mai-success-audit" {
				if c := i.cancel(t.Context(), f.b); c != "message_author_unqualified" {
					t.Fatal("unknown cancellation restored", c)
				}
			}
		})
	}
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	i.store.messageFault = func(p string) Code {
		if p == "mai-pending" {
			return "request_deadline_exceeded"
		}
		return ""
	}
	f.at.Now = f.at.Now.Add(time.Hour)
	f.at.Lower = f.at.Lower.Add(time.Hour)
	f.at.Upper = f.at.Upper.Add(time.Hour)
	_ = i.issue(t.Context(), f.b)
	f.at.Now = f.at.Now.Add(24 * time.Hour)
	f.at.Lower = f.at.Lower.Add(24 * time.Hour)
	f.at.Upper = f.at.Upper.Add(24 * time.Hour)
	if c := i.cancel(t.Context(), f.b); c != "" || i.store.maLive.Issuers[0].Phase != "bound" || i.store.maLive.Issuers[0].Current != nil {
		t.Fatal("expired predecessor not tombstoned into bound", c)
	}
	maIssuerRead(t, f, i, "message_author_unqualified")
}

// Exact binding, generation, currentness and both time bounds remain mandatory;
// the same live issuer succeeds before each one-axis authority loss.
func TestMAIssuerAuthority(t *testing.T) {
	for _, kind := range []string{"unbound", "retire", "generation", "upper", "lower", "renew-due", "registry"} {
		t.Run(kind, func(t *testing.T) {
			f, i := newMAIssuerFixture(t)
			if c := i.issue(t.Context(), f.b); c != "" {
				t.Fatal(c)
			}
			maIssuerRead(t, f, i, "")
			switch kind {
			case "unbound":
				f.b.Number++
			case "retire":
				if c := i.store.retireMALive(t.Context(), fixtureOperator, f.b.Number); c != "" {
					t.Fatal(c)
				}
			case "generation":
				f.b.Generation = "other"
			case "registry":
				f.b.RegistryRevision = "other"
			case "lower":
				f.at.Lower = f.at.Now.Add(-2 * time.Second)
			case "upper":
				f.at.Upper = f.at.Now.Add(24 * time.Hour)
			case "renew-due":
				f.at.Upper = f.at.Now.Add(23 * time.Hour)
			}
			maIssuerRead(t, f, i, "message_author_unqualified")
		})
	}
}

// Pin printing is canonical public-only and audit-free. Strict parsing rejects
// unknown, malformed and mismatched documents; absence is distinct from an
// existing unsafe file. No test manufactures a root-owned file or live key.
func TestMAIssuerCustodyPin(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	pin, c := i.custody.pin()
	if c != "" {
		t.Fatal(c)
	}
	pub, _ := i.custody.public()
	if c = maIssuerCheckPin(pin, pub); c != "" {
		t.Fatal("pin positive", c)
	}
	for _, change := range []string{"format", "profile", "key", "extra", "noncanonical", "newline"} {
		t.Run(change, func(t *testing.T) {
			b := append([]byte(nil), pin...)
			switch change {
			case "format":
				b = bytes.Replace(b, []byte("pin/1"), []byte("pin/2"), 1)
			case "profile":
				b = bytes.Replace(b, []byte("attestation/1"), []byte("revocation/1"), 1)
			case "key":
				b = bytes.Replace(b, []byte(pub), []byte("ed25519:"+base64Text(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))[32:])), 1)
			case "extra":
				b = append([]byte(`{"unknown":0,`), b[1:]...)
			case "noncanonical":
				b = append([]byte(" "), b...)
			case "newline":
				b = b[:len(b)-1]
			}
			want := Code("message_author_issuer_pin_invalid")
			if change == "key" {
				want = "message_author_issuer_pin_mismatch"
			}
			if c := maIssuerCheckPin(b, pub); c != want {
				t.Fatal("pin mutation", change, c, want)
			}
		})
	}
	path := filepath.Join(t.TempDir(), "absent")
	if ok, c := maIssuerStartupPinOwner(path, nil, uint32(os.Getuid())); ok || c != "" {
		t.Fatal("absent", ok, c)
	}
	if err := os.WriteFile(path, pin, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if ok, c := maIssuerStartupPinOwner(path, i.custody, uint32(os.Getuid())); !ok || c != "" {
		t.Fatal("protected fixture pin", ok, c)
	}
	if _, c := maIssuerStartupPin(path, i.custody); c != "message_author_issuer_pin_invalid" {
		t.Fatal("unprotected pin accepted", c)
	}
	before := i.store.journal.seq
	if _, c = i.custody.pin(); c != "" || i.store.journal.seq != before {
		t.Fatal("pin print audited", c)
	}
	if bytes.Contains([]byte(fmt.Sprintf("%+v", i.custody)), i.custody.seed) {
		t.Fatal("issuer diagnostics disclose seed")
	}
	if bytes.Equal(i.custody.seed, i.subject.seed) {
		t.Fatal("shared seed")
	}
	if _, e := json.Marshal(i.custody); e == nil {
		t.Fatal("issuer exported")
	}
	if c = i.store.initMAIssuerSeed(t.Context(), fixtureOperator, bytes.NewReader(bytes.Repeat([]byte{0x42}, 32))); c != "" {
		t.Fatal("explicit init", c)
	}
	k, c := loadMAIssuerKey(f.dir, uint32(os.Getuid()))
	if c != "" {
		t.Fatal(c)
	}
	defer k.close()
	if _, c = k.pin(); c != "" {
		t.Fatal(c)
	}
	raw, _ := os.ReadFile(filepath.Join(f.dir.Name(), maIssuerSeedFile))
	defer erase(raw)
	if c = i.store.initMAIssuerSeed(t.Context(), fixtureOperator, bytes.NewReader(bytes.Repeat([]byte{0x43}, 32))); c != "custody_unavailable" {
		t.Fatal("seed replaced", c)
	}
	after, _ := os.ReadFile(filepath.Join(f.dir.Name(), maIssuerSeedFile))
	defer erase(after)
	if !bytes.Equal(raw, after) {
		t.Fatal("seed replacement effect")
	}
	i.custody.close()
	if _, c = i.custody.pin(); c != "custody_unavailable" {
		t.Fatal("closed custody", c)
	}
}

// Issuer admission must reserve its shared physical byte budget before a
// pending marker or signature. Existing attempts and retirement room survive.
func TestMAIssuerCapacity(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal("under cap", c)
	}
	target := (maLiveStateLimit-maLiveStateOverhead)/3 - maLiveRetireReserve
	_ = maLiveFillByteBound(t, f, target)
	before, _ := os.ReadFile(filepath.Join(f.dir.Name(), "bindings.json"))
	f.at.Now = f.at.Now.Add(time.Hour)
	f.at.Lower = f.at.Lower.Add(time.Hour)
	f.at.Upper = f.at.Upper.Add(time.Hour)
	if c := i.issue(t.Context(), f.b); c != "state_capacity_exceeded" {
		t.Fatal("issuer budget bypassed", c)
	}
	after, _ := os.ReadFile(filepath.Join(f.dir.Name(), "bindings.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("over-cap issue changed durable state")
	}
	if c := i.store.retireMALive(t.Context(), fixtureOperator, f.b.Number); c != "" {
		t.Fatal("retire at cap", c)
	}
}

// Schema 7 has no issuer evidence. It refuses by name; schema 8 loads exactly,
// and production never issues or selects a tuple even with valid fixture keys.
func TestMAIssuerSchemaProduction(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	maIssuerRead(t, f, i, "")
	prod := productionMALiveDeps()
	calls := 0
	if c := prod.current.WithCurrent(t.Context(), f.b, f.at, func(maLiveTuple) Code { calls++; return "" }); c != "message_author_unqualified" || calls != 0 {
		t.Fatal("production gate opened", c, calls)
	}
	path := filepath.Join(f.dir.Name(), "bindings.json")
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = loadStoreMessage(f.dir, i.store.uid, 8, false); e != nil {
		t.Fatal("schema8 control", e)
	}
	old := bytes.Replace(raw, []byte(`"schema_version":8`), []byte(`"schema_version":7`), 1)
	if bytes.Equal(old, raw) {
		t.Fatal("schema plant not applied")
	}
	if e = os.WriteFile(path, old, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = loadStoreMessage(f.dir, i.store.uid, 8, false); e != Code("message_author_state_schema_unsupported") {
		t.Fatal("old schema accepted or unnamed", e)
	}
}

func maIssuerRestart(t *testing.T, f *maLiveFixture) Code {
	t.Helper()
	s, e := loadStoreMessage(f.dir, f.h.store.uid, maLiveSchema, false)
	if e != nil {
		t.Fatal(e)
	}
	expected := maLiveExpected(t, s)
	f.h.store.Close()
	next, c := openMALive(f.dir, uint32(os.Getuid()), fixtureAuditClock{}, expected)
	if c == "" {
		f.h.store = next
		t.Cleanup(func() { next.Close() })
	}
	return c
}

// A persisted pre-commit cancellation is a recoverable proof, not an arbitrary
// rollback flag. Corrupting that proof or changing either bound cannot restore.
func TestMAIssuerCancelRecovery(t *testing.T) {
	for _, bad := range []bool{false, true} {
		t.Run(fmt.Sprint(bad), func(t *testing.T) {
			f, i := newMAIssuerFixture(t)
			if c := i.issue(t.Context(), f.b); c != "" {
				t.Fatal(c)
			}
			old := maIssuerRead(t, f, i, "")
			f.at.Now = f.at.Now.Add(time.Hour)
			f.at.Lower = f.at.Lower.Add(time.Hour)
			f.at.Upper = f.at.Upper.Add(time.Hour)
			i.store.messageFault = func(p string) Code {
				if p == "mai-pending" {
					return "request_deadline_exceeded"
				}
				return ""
			}
			_ = i.issue(t.Context(), f.b)
			i.store.messageFault = func(p string) Code {
				if p == "mai-cancel" {
					return "request_deadline_exceeded"
				}
				return ""
			}
			if c := i.cancel(t.Context(), f.b); c != "request_deadline_exceeded" {
				t.Fatal(c)
			}
			if c := maIssuerRestart(t, f); c != "" {
				t.Fatal(c)
			}
			i.store = f.h.store
			maIssuerRead(t, f, i, "message_author_unqualified")
			if bad {
				i.store.maLive.Issuers[0].CancelHash = strings.Repeat("a", 64)
			}
			c := i.cancel(t.Context(), f.b)
			if bad {
				if c != "message_author_unqualified" {
					t.Fatal("false cancellation proof accepted", c)
				}
			} else {
				if c != "" || maIssuerRead(t, f, i, "").T != old.T {
					t.Fatal("proven cancelled recovery", c)
				}
			}
		})
	}
}

// Superseded T never releases even a retained signature. A fresh request with
// the replacement T succeeds through the same real holder/custody barriers.
func TestMAIssuerOldTRelease(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	old := maIssuerRead(t, f, i, "")
	obj := maRecord(t, f.v)
	obj["body"].(map[string]any)["author_attestation"] = old.T
	r := f.request()
	r.Preimage = maPre(t, obj)
	if out, c := f.call(t.Context(), r); c != "" || out.Signature == nil {
		t.Fatal("old valid control", c)
	}
	f.at.Now = f.at.Now.Add(time.Hour)
	f.at.Lower = f.at.Lower.Add(time.Hour)
	f.at.Upper = f.at.Upper.Add(time.Hour)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	next := maIssuerRead(t, f, i, "")
	called := 0
	c := f.h.handle(t.Context(), Principal{f.b.UID, f.b.Generation}, r, func(context.Context, messageauthor.Response) Code { called++; return "" })
	if c != "signer_identity_mismatch" || called != 0 {
		t.Fatal("old T disclosed", c, called)
	}
	if i.store.maLive.Attempts[0].Status != "dead" {
		t.Fatal("old T not dead")
	}
	obj["body"].(map[string]any)["author_attestation"] = next.T
	r.ID = strings.Repeat("b", 32)
	r.Preimage = maPre(t, obj)
	if out, c := f.call(t.Context(), r); c != "" || out.Signature == nil {
		t.Fatal("replacement control", c)
	}
	if !slices.Contains(i.store.maLive.Issuers[0].Tombstones, old.T) {
		t.Fatal("old T tombstone lost")
	}
}

// Current readable bytes without their exact synced issuance receipt cannot
// establish currentness, and changing issuer custody cannot borrow that proof.
func TestMAIssuerCurrentProof(t *testing.T) {
	for _, fault := range []string{"audit", "root", "phase"} {
		t.Run(fault, func(t *testing.T) {
			f, i := newMAIssuerFixture(t)
			if c := i.issue(t.Context(), f.b); c != "" {
				t.Fatal(c)
			}
			maIssuerRead(t, f, i, "")
			switch fault {
			case "audit":
				i.store.maLive.Issuers[0].Current.Hash = strings.Repeat("a", 64)
			case "root":
				k, c := newMAIssuerKey(bytes.Repeat([]byte{0x44}, 32))
				if c != "" {
					t.Fatal(c)
				}
				defer k.close()
				i.custody = k
			case "phase":
				i.store.maLive.Issuers[0].Phase = "fenced"
			}
			maIssuerRead(t, f, i, "message_author_unqualified")
		})
	}
}

// Loader-side structural checks independently reject signed wider profiles;
// signatures here deliberately bypass the product builder using public test
// seed arithmetic so the reader gate cannot rely on the builder's correctness.
func TestMAIssuerEnvelopeClosed(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	current := i.store.maLive.Issuers[0].Current
	if !maIssuerEnvelope(current, f.b) {
		t.Fatal("envelope positive")
	}
	node := deriveNode(bytes.Repeat([]byte{0xa5}, 32), maIssuerPath)
	defer erase(node)
	root := ed25519.NewKeyFromSeed(node[:32])
	defer erase(root)
	for _, kind := range []string{"roles", "actions", "purpose", "algorithm", "binding", "lifetime", "timestamp"} {
		t.Run(kind, func(t *testing.T) {
			x, e := record.Parse(current.A, 8192, 16)
			if e != nil {
				t.Fatal(e)
			}
			a := x.(map[string]any)
			body := a["body"].(map[string]any)
			switch kind {
			case "roles":
				body["roles"] = []any{"service_root"}
			case "actions":
				body["actions"] = []any{"message.verify"}
			case "purpose":
				body["purpose"] = int64(9)
			case "algorithm":
				body["subject"].(map[string]any)["algorithm"] = "Ed25519"
			case "binding":
				body["binding"].(map[string]any)["owner"] = "other"
			case "timestamp":
				body["iat"] = strings.TrimSuffix(current.From, "Z") + ".000Z"
			case "lifetime":
				from, _ := time.Parse(time.RFC3339, current.From)
				body["exp"] = messageStamp(from.Add(86401 * time.Second))
			}
			raw := messageSigned(t, "attestation/1", body, root)
			id, _ := record.ContentID("attestation/1", body)
			changed := *current
			changed.A = raw
			changed.T = id
			if kind == "lifetime" {
				changed.Until = body["exp"].(string)
			}
			if kind == "timestamp" {
				changed.From = body["iat"].(string)
			}
			if maIssuerEnvelope(&changed, f.b) {
				t.Fatal("wider signed issuer record accepted", kind)
			}
		})
	}
}

// Internal maintenance issues only after enrollment and renews at exp-1h;
// issuance never runs from a current-T read or under the production gate.
func TestMAIssuerMaintain(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	bad := f.b
	bad.Number++
	if c := i.maintain(t.Context(), bad); c != "binding_conflict" || len(i.store.maLive.Issuers) != 0 {
		t.Fatal("unbound issue", c)
	}
	if c := i.maintain(t.Context(), f.b); c != "" {
		t.Fatal("enroll issue", c)
	}
	old := maIssuerRead(t, f, i, "")
	version := i.store.version
	if c := i.maintain(t.Context(), f.b); c != "" || i.store.version != version {
		t.Fatal("unneeded renewal", c)
	}
	f.at.Now = f.at.Now.Add(23 * time.Hour)
	f.at.Lower = f.at.Lower.Add(23 * time.Hour)
	f.at.Upper = f.at.Upper.Add(23 * time.Hour)
	maIssuerRead(t, f, i, "message_author_unqualified")
	if c := i.maintain(t.Context(), f.b); c != "" {
		t.Fatal("due renew", c)
	}
	next := maIssuerRead(t, f, i, "")
	if next.T == old.T || next.Key != old.Key {
		t.Fatal("maintenance renewal")
	}
}

// The exact signed-record ID is deterministic: a cancelled candidate's T cannot
// later become current at the same timestamp, nor can one renewal reuse old T.
func TestMAIssuerTombstoneNoResurrection(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	before := i.store.version
	if c := i.issue(t.Context(), f.b); c != "message_author_unqualified" || i.store.version != before {
		t.Fatal("same T renewal admitted", c)
	}
	f.at.Now = f.at.Now.Add(time.Hour)
	f.at.Lower = f.at.Lower.Add(time.Hour)
	f.at.Upper = f.at.Upper.Add(time.Hour)
	i.store.messageFault = func(p string) Code {
		if p == "mai-candidate" {
			return "request_deadline_exceeded"
		}
		return ""
	}
	_ = i.issue(t.Context(), f.b)
	if c := i.cancel(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	before = i.store.version
	i.store.messageFault = nil
	if c := i.issue(t.Context(), f.b); c != "message_author_unqualified" || i.store.version != before {
		t.Fatal("tombstoned candidate resurrected", c)
	}
	f.at.Now = f.at.Now.Add(time.Second)
	f.at.Lower = f.at.Lower.Add(time.Second)
	f.at.Upper = f.at.Upper.Add(time.Second)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal("fresh renewal control", c)
	}
	maIssuerRead(t, f, i, "")
}

// Time validity is the entire START interval; each individual bound loss
// refuses beside the same certificate's valid interval, without clock guessing.
func TestMAIssuerInterval(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	cert := i.store.maLive.Issuers[0].Current
	if !maIssuerTimes(cert, f.at) {
		t.Fatal("time positive")
	}
	from, _ := time.Parse(time.RFC3339, cert.From)
	until, _ := time.Parse(time.RFC3339, cert.Until)
	for _, kind := range []string{"lower", "upper"} {
		t.Run(kind, func(t *testing.T) {
			at := f.at
			if kind == "lower" {
				at.Lower = from.Add(-time.Second)
			} else {
				at.Upper = until
			}
			if maIssuerTimes(cert, at) {
				t.Fatal("issuer interval lost bound", kind)
			}
		})
	}
}

// Seed creation is explicit and exclusive. Failed audit leaves no custody file;
// no startup/read/currentness operation initializes it as a side effect.
func TestMAIssuerSeedAuditBeforeEffect(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	path := filepath.Join(f.dir.Name(), maIssuerSeedFile)
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("fixture implicitly provisioned")
	}
	i.store.journal.failed = true
	if c := i.store.initMAIssuerSeed(t.Context(), fixtureOperator, bytes.NewReader(bytes.Repeat([]byte{1}, 32))); c != "audit_unavailable" {
		t.Fatal("missing seed audit accepted", c)
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("unaudited seed effect")
	}
	f2, i2 := newMAIssuerFixture(t)
	if c := i2.store.initMAIssuerSeed(t.Context(), fixtureOperator, bytes.NewReader(bytes.Repeat([]byte{2}, 32))); c != "" {
		t.Fatal("audited seed positive", c)
	}
	k, c := loadMAIssuerKey(f2.dir, uint32(os.Getuid()))
	if c != "" {
		t.Fatal(c)
	}
	defer k.close()
}

// A selected current tuple keeps the local renewal exclusion through delivery;
// a concurrent internal renewal commits only after that callback releases it.
func TestMAIssuerRenewalExclusion(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	old := maIssuerRead(t, f, i, "")
	f.at.Now = f.at.Now.Add(time.Hour)
	f.at.Lower = f.at.Lower.Add(time.Hour)
	f.at.Upper = f.at.Upper.Add(time.Hour)
	selected := make(chan struct{})
	release := make(chan struct{})
	readDone := make(chan Code, 1)
	writeDone := make(chan Code, 1)
	started := make(chan struct{})
	go func() {
		readDone <- i.WithCurrent(t.Context(), f.b, f.at, func(v maLiveTuple) Code {
			if v.T != old.T {
				return "signer_identity_mismatch"
			}
			close(selected)
			<-release
			return ""
		})
	}()
	<-selected
	go func() { close(started); writeDone <- i.issue(t.Context(), f.b) }()
	<-started
	select {
	case c := <-writeDone:
		t.Fatal("renewal crossed held current callback", c)
	default:
	}
	close(release)
	if c := <-readDone; c != "" {
		t.Fatal(c)
	}
	if c := <-writeDone; c != "" {
		t.Fatal(c)
	}
	if maIssuerRead(t, f, i, "").T == old.T {
		t.Fatal("renewal did not commit")
	}
}

// Issuer receipts cannot consume the existing 2304 sign-proof slots. The
// actual issue is the positive control; isolated observer records probe only
// proof-map accounting, not additional signatures or live state qualification.
func TestMAIssuerAuditCapacityIsolation(t *testing.T) {
	f, i := newMAIssuerFixture(t)
	if c := i.issue(t.Context(), f.b); c != "" {
		t.Fatal(c)
	}
	j := i.store.journal
	if len(j.maLiveEvents) != 0 || len(j.maIssuerEvents) != 1 {
		t.Fatal("issuer consumed sign-proof slots")
	}
	domain := "swarma-msg"
	digest := maLiveHash([]byte("test proof accounting"))
	id := strings.Repeat("a", 32)
	for n := 1; n <= maLiveAttemptLimit; n++ {
		r := AuditRecord{Seq: uint64(n), Operation: "sign_message_author", Surface: "control", Domain: &domain, Result: "success", PayloadDigest: &digest, RequestID: &id, PeerUID: &f.b.UID, Generation: &f.b.Generation}
		if e := j.observeMALive(r); e != nil {
			t.Fatal("sign-proof capacity reduced", n, e)
		}
	}
	r := AuditRecord{Seq: maLiveAttemptLimit + 1, Operation: "sign_message_author", Surface: "control", Domain: &domain, Result: "success", PayloadDigest: &digest, RequestID: &id, PeerUID: &f.b.UID, Generation: &f.b.Generation}
	if e := j.observeMALive(r); e == nil {
		t.Fatal("sign-proof cap widened")
	}
}

// Expiry suppresses both pending/current evidence before a fresh issuance, only
// when both trusted bounds prove expiry. An unknown commit never takes this path.
func TestMAIssuerExpiry(t *testing.T) {
	for _, phase := range []string{"current", "pending", "unknown", "fenced"} {
		t.Run(phase, func(t *testing.T) {
			f, i := newMAIssuerFixture(t)
			if c := i.issue(t.Context(), f.b); c != "" {
				t.Fatal(c)
			}
			old := maIssuerRead(t, f, i, "")
			if phase == "fenced" {
				i.store.maLive.Issuers[0].Phase = "fenced"
			}
			if phase == "pending" || phase == "unknown" {
				f.at.Now = f.at.Now.Add(time.Hour)
				f.at.Lower = f.at.Lower.Add(time.Hour)
				f.at.Upper = f.at.Upper.Add(time.Hour)
				point := "mai-candidate"
				if phase == "unknown" {
					point = "mai-success-audit"
				}
				i.store.messageFault = func(p string) Code {
					if p == point {
						return "request_deadline_exceeded"
					}
					return ""
				}
				if c := i.issue(t.Context(), f.b); c != "request_deadline_exceeded" {
					t.Fatal(c)
				}
			}
			// A straddling interval is not proof that the selected candidate expired.
			selected := i.store.maLive.Issuers[0].Current
			if phase == "pending" || phase == "unknown" {
				selected = i.store.maLive.Issuers[0].Pending
			}
			until, _ := time.Parse(time.RFC3339, selected.Until)
			version := i.store.version
			i.store.messageFault = nil
			straddled := f.at
			straddled.Now = until
			straddled.Lower = until.Add(-time.Second)
			straddled.Upper = until.Add(time.Second)
			if c := i.active(t.Context(), f.b, func(s *Store, _ j7GateTime) Code {
				return s.maIssuerExpire(t.Context(), &s.maLive.Issuers[0], straddled)
			}); c != "key_not_valid_now" || i.store.version != version {
				t.Fatal("unproven expiry changed evidence", c)
			}
			f.at.Now = until.Add(time.Second)
			f.at.Lower = f.at.Now
			f.at.Upper = f.at.Now
			i.store.messageFault = func(p string) Code {
				if p == "mai-expired" {
					return "request_deadline_exceeded"
				}
				return ""
			}
			var c Code
			if phase == "fenced" {
				c = i.resolve(t.Context(), f.b)
			} else {
				c = i.maintain(t.Context(), f.b)
			}
			if phase == "unknown" {
				if c != "message_author_unqualified" || i.store.version != version {
					t.Fatal("unknown commit erased by expiry", c)
				}
				maIssuerRead(t, f, i, "message_author_unqualified")
				return
			}
			if c != "request_deadline_exceeded" {
				t.Fatal("no durable expiry transition", c)
			}
			r := i.store.maLive.Issuers[0]
			if r.Phase != "bound" || r.Current != nil || r.Pending != nil || !slices.Contains(r.Tombstones, old.T) {
				t.Fatal("expiry retained selectable evidence")
			}
			maIssuerRead(t, f, i, "message_author_unqualified")
			i.store.messageFault = nil
			if c := i.maintain(t.Context(), f.b); c != "" {
				t.Fatal("fresh issuance", c)
			}
			next := maIssuerRead(t, f, i, "")
			if next.T == old.T || next.Key != old.Key {
				t.Fatal("expiry resurrected old T or changed K")
			}
		})
	}
}

// State/event boundary controls use real enrollment, durable pending/commit,
// recovery and retirement. S5 resolution requires the original proven receipt;
// it never signs or chooses another T. A successor cannot resurrect this instance.
func TestMAIssuerStateBoundaries(t *testing.T) {
	for _, state := range []string{"unbound", "bound", "pending", "current", "withdrawn", "fenced"} {
		t.Run(state, func(t *testing.T) {
			f, i := newMAIssuerFixture(t)
			switch state {
			case "unbound":
				f.b.Number++
			case "bound":
			default:
				if state == "pending" {
					i.store.messageFault = func(p string) Code {
						if p == "mai-candidate" {
							return "request_deadline_exceeded"
						}
						return ""
					}
				}
				c := i.issue(t.Context(), f.b)
				if c != "" && (state != "pending" || c != "request_deadline_exceeded") {
					t.Fatal(c)
				}
				i.store.messageFault = nil
				if state == "withdrawn" {
					if c := i.store.retireMALive(t.Context(), fixtureOperator, f.b.Number); c != "" {
						t.Fatal(c)
					}
				}
				if state == "fenced" {
					real := i.store.maLive.Issuers[0].Current.Hash
					i.store.maLive.Issuers[0].Current.Hash = strings.Repeat("f", 64)
					if !i.store.recoverMAIssuers() {
						t.Fatal("unproven current not fenced")
					}
					version := i.store.version
					if c := i.resolve(t.Context(), f.b); c != "message_author_unqualified" || i.store.version != version {
						t.Fatal("unknown resolution changed evidence", c)
					}
					maIssuerRead(t, f, i, "message_author_unqualified")
					i.store.maLive.Issuers[0].Current.Hash = real
					original := *i.store.maLive.Issuers[0].Current
					if c := i.resolve(t.Context(), f.b); c != "" {
						t.Fatal("proven resolution", c)
					}
					if got := maIssuerRead(t, f, i, ""); got.T != original.T || !bytes.Equal(got.Attestation, original.A) {
						t.Fatal("resolve invented a T")
					}
					i.store.maLive.Issuers[0].Phase = "fenced"
				}
			}
			want := Code("message_author_unqualified")
			if state == "current" {
				want = ""
			}
			maIssuerRead(t, f, i, want)
			// All clean BAD refusals preserve the exact durable phase/evidence.
			version := i.store.version
			audit := i.store.journal.seq
			savedClock := i.clock
			i.clock = func(context.Context) (j7GateTime, Code) { return j7GateTime{}, "clock_untrusted" }
			c := i.issue(t.Context(), f.b)
			if state == "unbound" {
				if c != "binding_conflict" {
					t.Fatal(c)
				}
			} else if state == "withdrawn" {
				if c != "binding_conflict" {
					t.Fatal(c)
				}
			} else if c != "clock_untrusted" {
				t.Fatal("BAD not refused", c)
			}
			if i.store.version != version || i.store.journal.seq != audit {
				t.Fatal("BAD changed evidence")
			}
			i.clock = savedClock
			if state == "pending" {
				if c := i.issue(t.Context(), f.b); c != "message_author_unqualified" {
					t.Fatal("duplicate pending issue", c)
				}
				if c := i.cancel(t.Context(), f.b); c != "" {
					t.Fatal("cancel without predecessor", c)
				}
				if r := i.store.maLive.Issuers[0]; r.Phase != "bound" || r.Current != nil || r.Pending != nil {
					t.Fatal("cancel invented predecessor")
				}
			}
			if state == "fenced" || state == "current" || state == "pending" || state == "bound" {
				if c := i.store.retireMALive(t.Context(), fixtureOperator, f.b.Number); c != "" {
					t.Fatal("withdraw", c)
				}
				if state == "fenced" && i.store.maLive.Issuers[0].Phase != "fenced" {
					t.Fatal("withdraw cleared fence")
				}
				maIssuerRead(t, f, i, "message_author_unqualified")
				version = i.store.version
				if c := i.issue(t.Context(), f.b); c != "binding_conflict" || i.store.version != version {
					t.Fatal("withdrawn issue effect", c)
				}
				successor := f.b
				successor.Number++
				successor.Generation = "successor"
				if c := i.store.enrollMALive(t.Context(), fixtureOperator, successor); c != "binding_conflict" {
					t.Fatal("successor reused predecessor path", c)
				}
			}
			if state == "withdrawn" {
				if c := i.store.retireMALive(t.Context(), fixtureOperator, f.b.Number); c != "identity_revoked" || i.store.version != version {
					t.Fatal("withdraw not terminal", c)
				}
			}
		})
	}
}
