package keymaker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-envelope/tools/bip340check/oracle"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

type maVectors struct {
	Format      string         `json:"format"`
	TestOnly    bool           `json:"test_only"`
	Seed        string         `json:"seed_hex"`
	IssuerSeed  string         `json:"issuer_seed_hex"`
	Key         string         `json:"key_id"`
	T           string         `json:"attestation_id"`
	Attestation string         `json:"attestation"`
	Preimage    string         `json:"preimage"`
	Hash        string         `json:"hash_hex"`
	Signature   string         `json:"signature"`
	Envelope    string         `json:"envelope"`
	Context     map[string]any `json:"context"`
	Cases       []struct {
		Path   string `json:"path"`
		Public string `json:"public_x_hex"`
	} `json:"cases"`
}

func maData(t *testing.T) maVectors {
	t.Helper()
	raw, e := os.ReadFile("testdata/message-author-v1/vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var v maVectors
	if json.Unmarshal(raw, &v) != nil || !v.TestOnly || v.Format != "message-author-fixtures/1" {
		t.Fatal("fixture")
	}
	return v
}
func maBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, e := record.DecodeBase64(s, -1)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func maFixture(t *testing.T) (*messageAuthorKey, *Store, Binding) {
	t.Helper()
	v := maData(t)
	seed, e := hex.DecodeString(v.Seed)
	if e != nil {
		t.Fatal(e)
	}
	b := Binding{UID: 1000, Generation: "generation-0", Path: "m/1'/1'/2'/3'", Owner: "owner-a", Number: 1, Lifetime: "persistent", Status: "active", Epoch: "epoch-1", RegistryRevision: "registry", Registrar: fixtureOperator}
	s := NewStore()
	s.records = []Binding{b}
	s.next = 2
	if c := s.validate(); c != "" {
		t.Fatal("invalid fixture Store", c)
	}
	k := &messageAuthorKey{seed: seed, role: messageAuthorRole, instance: strings.Repeat("9", 32), epoch: b.Epoch, registry: b.RegistryRevision, entropy: bytes.NewReader(make([]byte, 128))}
	t.Cleanup(func() { _ = k.close() })
	return k, s, b
}
func maPrepare(t *testing.T, v maVectors) *messageAuthorPlan {
	t.Helper()
	p, c := prepareMessageAuthor(maBytes(t, v.Preimage), v.Key, v.T)
	if c != "" {
		t.Fatal(c)
	}
	return p
}
func maCanon(t *testing.T, v any) []byte {
	t.Helper()
	b, e := record.Canonical(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func maRecord(t *testing.T, v maVectors) map[string]any {
	t.Helper()
	p := maBytes(t, v.Preimage)
	x, e := record.Parse(p[len("swarma-msg/2\n"):], 24576, 12)
	if e != nil {
		t.Fatal(e)
	}
	return x.(map[string]any)
}
func maPre(t *testing.T, r map[string]any) []byte {
	return append([]byte("swarma-msg/2\n"), maCanon(t, r)...)
}

// Independent hardened-HMAC fixture nodes pin purpose9 paths and namespace7/8
// separation. This cannot detect a malicious operator copying root material.
func TestMessageAuthorBindingSelection(t *testing.T) {
	v := maData(t)
	k, s, b := maFixture(t)
	for _, row := range v.Cases {
		if !strings.HasPrefix(row.Path, "m/9'") {
			if _, e := validateMessageAuthorPath(row.Path); e != errMessageAuthorKey {
				t.Fatal("foreign purpose accepted")
			}
			continue
		}
		own := b
		own.Path = "m/1'" + strings.TrimPrefix(row.Path, "m/9'")
		st := NewStore()
		st.records = []Binding{own}
		id, c := k.publicSelected(st, own)
		pub, e := hex.DecodeString(row.Public)
		if e != nil || c != "" || id != "bip340:"+base64.RawURLEncoding.EncodeToString(pub) {
			t.Fatal("purpose9 oracle", row.Path, c)
		}
		for _, other := range v.Cases {
			if !strings.HasPrefix(other.Path, "m/9'") && row.Public == other.Public {
				t.Fatal("purpose collision")
			}
		}
	}
	for _, path := range []string{"m/9'/1'/2'/3", "m/9'/0'/2'/3'", "m/9'/1'/2'", "m/9'/1'/2'/3'/4'", "m/9'/2147483648'/2'/3'", "m/4'/1'/2'/3'", "m/7'/1'/2'/3'", "m/8'/1'/2'/3'"} {
		if _, e := validateMessageAuthorPath(path); e != errMessageAuthorKey {
			t.Fatal("foreign path accepted", path)
		}
	}
	plan := maPrepare(t, v)
	changes := []struct {
		name   string
		change func(*Binding)
		want   Code
	}{{"registration", func(x *Binding) { x.Number++ }, "binding_conflict"}, {"path", func(x *Binding) { x.Path = "m/1'/1'/2'/4'" }, "binding_conflict"}, {"owner", func(x *Binding) { x.Owner = "other" }, "binding_conflict"}, {"epoch", func(x *Binding) { x.Epoch = "other" }, "binding_conflict"}, {"registry", func(x *Binding) { x.RegistryRevision = "other" }, "binding_conflict"}, {"uid", func(x *Binding) { x.UID++ }, "binding_not_found"}, {"generation", func(x *Binding) { x.Generation = "other" }, "binding_not_found"}, {"status", func(x *Binding) { x.Status = "revoked" }, "binding_conflict"}}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			before := s.Snapshot()
			bad := b
			tc.change(&bad)
			if id, c := k.publicSelected(s, bad); c != tc.want || id != "" {
				t.Fatal("binding substitution public", c)
			}
			if sig, c := k.signSelected(s, bad, plan); c != tc.want || sig != nil {
				t.Fatal("binding substitution signed", c)
			}
			if !reflect.DeepEqual(before, s.Snapshot()) {
				t.Fatal("binding changed")
			}
		})
	}
	for _, fault := range []string{"epoch", "registry", "revoked", "unbound", "failed"} {
		t.Run(fault, func(t *testing.T) {
			k, s, b := maFixture(t)
			want := Code("binding_conflict")
			switch fault {
			case "epoch":
				k.epoch = "other"
			case "registry":
				k.registry = "other"
			case "revoked":
				s.records[0].Status = "revoked"
				want = "identity_revoked"
			case "unbound":
				s.records[0].Status = "unbound"
				want = "binding_not_found"
			case "failed":
				s.failed = true
				want = "audit_unavailable"
			}
			before := s.Snapshot()
			if out, c := k.signSelected(s, b, plan); c != want || out != nil {
				t.Fatal("withdrawn binding signed", c)
			}
			if !reflect.DeepEqual(before, s.Snapshot()) {
				t.Fatal("withdrawal state changed")
			}
		})
	}
	if got, c := k.publicSelected(s, b); c != "" || got != v.Key {
		t.Fatal("positive binding", c)
	}
}

// Fresh aux changes signatures for the same original P, while deterministic
// public aux0 matches the frozen corpus and independent public-math oracle.
// These are private fixture results, not durable/native/retry release evidence.
func TestMessageAuthorEnvelopeProfile(t *testing.T) {
	v := maData(t)
	k, s, b := maFixture(t)
	p := maPrepare(t, v)
	raw := maBytes(t, v.Preimage)
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != v.Hash {
		t.Fatal("literal hash")
	}
	key, c := k.publicSelected(s, b)
	if c != "" || key != v.Key {
		t.Fatal("key", c)
	}
	sig, c := k.signSelected(s, b, p)
	pub := maBytes(t, key[7:])
	if c != "" || !bytes.Equal(sig, maBytes(t, v.Signature)) || !oracle.Verify(pub, h[:], sig) || record.VerifySignature(key, sig, raw) != nil {
		t.Fatal("independent original preimage signature", c)
	}
	for _, bad := range [][]byte{raw, []byte(record.Digest(raw)), []byte("swarma-msg/2\n" + string(raw))} {
		if oracle.Verify(pub, bad, sig) {
			t.Fatal("wrong message hash accepted")
		}
	}
	double := sha256.Sum256(h[:])
	if oracle.Verify(pub, double[:], sig) {
		t.Fatal("double hash accepted")
	}
	k.entropy = bytes.NewReader(append(make([]byte, 32), bytes.Repeat([]byte{1}, 32)...))
	s1, c := k.signSelected(s, b, p)
	if c != "" {
		t.Fatal(c)
	}
	s2, c := k.signSelected(s, b, p)
	if c != "" || bytes.Equal(s1, s2) || !oracle.Verify(pub, h[:], s2) {
		t.Fatal("fresh aux invariant", c)
	}
	// Original input is copied before caller mutation.
	input := append([]byte{}, raw...)
	copyPlan, c := prepareMessageAuthor(input, key, v.T)
	if c != "" {
		t.Fatal(c)
	}
	input[0] = 'x'
	k.entropy = bytes.NewReader(make([]byte, 32))
	out, c := k.signSelected(s, b, copyPlan)
	if c != "" || !bytes.Equal(out, sig) {
		t.Fatal("preimage alias", c)
	}
}

type maCountReader struct {
	calls  int
	source io.Reader
}

func (r *maCountReader) Read(b []byte) (int, error) { r.calls++; return r.source.Read(b) }

// Custody/entropy faults return no bytes and leave Store state unchanged;
// pre-entropy refusals consume no entropy. Diagnostics/serialization expose no
// root, and nil custody is distinct from an unavailable selected binding.
func TestMessageAuthorCustodyNoRelease(t *testing.T) {
	v := maData(t)
	plan := maPrepare(t, v)
	for _, fault := range []string{"closed", "nil-seed", "short-seed", "wrong-role", "instance", "nil-entropy", "short-entropy", "nil-key", "nil-store", "foreign-plan", "nil-plan"} {
		t.Run(fault, func(t *testing.T) {
			k, s, b := maFixture(t)
			before := s.Snapshot()
			reader := &maCountReader{source: bytes.NewReader(make([]byte, 64))}
			k.entropy = reader
			want := Code("custody_unavailable")
			p := plan
			switch fault {
			case "closed":
				_ = k.close()
			case "nil-seed":
				k.seed = nil
			case "short-seed":
				k.seed = []byte{1}
			case "wrong-role":
				k.role = j7RequestRole
			case "instance":
				k.instance = strings.Repeat("0", 32)
			case "nil-entropy":
				k.entropy = nil
				want = "entropy_unavailable"
			case "short-entropy":
				k.entropy = bytes.NewReader([]byte{1})
				want = "entropy_unavailable"
			case "nil-key":
				k = nil
			case "nil-store":
				s = nil
				want = "binding_not_found"
			case "foreign-plan":
				p = &messageAuthorPlan{original: plan.original, key: "other", attestation: v.T}
				want = "sign_key_mismatch"
			case "nil-plan":
				p = nil
				want = "signer_payload_invalid"
			}
			if out, c := k.signSelected(s, b, p); c != want || out != nil {
				t.Fatal("custody failure output", c, want)
			}
			if reader.calls != 0 {
				t.Fatal("refusal consumed entropy")
			}
			if s != nil && !reflect.DeepEqual(before, s.Snapshot()) {
				t.Fatal("custody refusal changed state")
			}
		})
	}
	k, _, _ := maFixture(t)
	for _, f := range []string{"%v", "%+v", "%#v", "%x"} {
		if fmt.Sprintf(f, k) != "[message-author custody]" {
			t.Fatal("secret diagnostic")
		}
	}
	if b, e := json.Marshal(k); !errors.Is(e, errMessageAuthorKey) || b != nil {
		t.Fatal("secret serialized")
	}
	if b, e := k.MarshalText(); e != errMessageAuthorKey || b != nil {
		t.Fatal("secret text")
	}
	typ := reflect.TypeOf(k)
	for i := 0; i < typ.Elem().NumField(); i++ {
		if typ.Elem().Field(i).PkgPath == "" {
			t.Fatal("exported custody field")
		}
	}
	allowed := map[string]bool{"Format": true, "MarshalJSON": true, "MarshalText": true}
	for i := 0; i < typ.NumMethod(); i++ {
		if !allowed[typ.Method(i).Name] {
			t.Fatal("exported custody method")
		}
	}
}

// Original-byte admission is upstream ordered/canonical/bounded; the provider
// intentionally permits codec-only roles/types after three-path equality.
func TestMessageAuthorPreimageAdmission(t *testing.T) {
	v := maData(t)
	raw := maBytes(t, v.Preimage)
	cases := []struct {
		name string
		raw  []byte
		want Code
	}{{"oversize", make([]byte, 24577), "signer_preimage_too_large"}, {"no-LF", []byte("swarma-msg/2"), "signer_tag_malformed"}, {"empty-tag", []byte("\n{}"), "signer_tag_malformed"}, {"tag-cap", []byte(strings.Repeat("x", 97) + "\n{}"), "signer_tag_malformed"}, {"space", bytes.Replace(raw, []byte("\n{"), []byte("\n {"), 1), "signer_payload_invalid"}, {"trailingLF", append(append([]byte{}, raw...), '\n'), "signer_payload_invalid"}, {"duplicate", []byte("swarma-msg/2\n{\"a\":0,\"a\":1}"), "signer_payload_invalid"}, {"depth", []byte("swarma-msg/2\n" + strings.Repeat("[", 13) + "0" + strings.Repeat("]", 13)), "signer_payload_invalid"}}
	for _, tag := range []string{"swarma-msg/2extra", "swarma-msg/2 ", "Swarma-msg/2", "swarma-waggle grant/1", "swarma-attestation attestation/1", "keymaker-witness-record/1\x00"} {
		want := Code("signer_domain_refused")
		if strings.ContainsRune(tag, 0) {
			want = "signer_tag_malformed"
		}
		cases = append(cases, struct {
			name string
			raw  []byte
			want Code
		}{tag, append([]byte(tag+"\n"), raw[len("swarma-msg/2\n"):]...), want})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if p, c := prepareMessageAuthor(tc.raw, v.Key, v.T); p != nil || c != tc.want {
				t.Fatal("preimage refusal", c, tc.want)
			}
		})
	}
	for _, limit := range []int{8192, 8193} {
		r := maRecord(t, v)
		r["padding"] = strings.Repeat("x", limit)
		p, c := prepareMessageAuthor(maPre(t, r), v.Key, v.T)
		if limit == 8192 {
			if c != "" || p == nil {
				t.Fatal("string max control", c)
			}
		} else if p != nil || c != "signer_payload_invalid" {
			t.Fatal("string cap", c)
		}
	}
	for _, limit := range []int{64, 65} {
		r := maRecord(t, v)
		r["array"] = make([]any, limit)
		p, c := prepareMessageAuthor(maPre(t, r), v.Key, v.T)
		if limit == 64 {
			if c != "" || p == nil {
				t.Fatal("array max control", c)
			}
		} else if p != nil || c != "signer_payload_invalid" {
			t.Fatal("array cap", c)
		}
	}
	r := maRecord(t, v)
	r["a"] = ""
	r["b"] = ""
	r["c"] = ""
	need := 24576 - len(maPre(t, r))
	for _, f := range []string{"a", "b", "c"} {
		n := need
		if n > 8192 {
			n = 8192
		}
		r[f] = strings.Repeat("x", n)
		need -= n
	}
	boundary := maPre(t, r)
	if len(boundary) != 24576 {
		t.Fatal("cap fixture")
	}
	if p, c := prepareMessageAuthor(boundary, v.Key, v.T); c != "" || p == nil {
		t.Fatal("preimage max control", c)
	}
}

// Independently resolved K/T must match all three paths. Equal foreign K pairs,
// old T and internally forged plans never become purpose9 signatures.
func TestMessageAuthorCallerIdentity(t *testing.T) {
	v := maData(t)
	k, s, b := maFixture(t)
	for _, field := range []string{"key", "author", "attestation", "foreign-pair", "missing", "wrong-type"} {
		t.Run(field, func(t *testing.T) {
			r := maRecord(t, v)
			body := r["body"].(map[string]any)
			want := Code("signer_identity_mismatch")
			foreign := "bip340:eb5mfvncu6xVoGKVzocLBwKb_NstzijZWfKBWxb4F5g"
			switch field {
			case "key":
				r["key"] = foreign
			case "author":
				body["author"] = foreign
			case "foreign-pair":
				r["key"] = foreign
				body["author"] = foreign
			case "attestation":
				body["author_attestation"] = "sha256:" + strings.Repeat("b", 64)
			case "missing":
				delete(body, "author_attestation")
				want = "signer_identity_malformed"
			case "wrong-type":
				body["author"] = int64(1)
				want = "signer_identity_malformed"
			}
			raw := maPre(t, r)
			if p, c := prepareMessageAuthor(raw, v.Key, v.T); c != want || p != nil {
				t.Fatal("identity path accepted", c, want)
			}
			forged := &messageAuthorPlan{original: raw, key: v.Key, attestation: v.T}
			if out, c := k.signSelected(s, b, forged); c != want || out != nil {
				t.Fatal("forged admission plan", c)
			}
		})
	}
	for _, pair := range [][2]string{{"", v.T}, {v.Key, ""}, {"bip340:" + strings.Repeat("_", 43), v.T}} {
		if p, c := prepareMessageAuthor(maBytes(t, v.Preimage), pair[0], pair[1]); c != "signer_identity_unavailable" || p != nil {
			t.Fatal("unavailable identity", c)
		}
	}
	if p, c := prepareMessageAuthor(maBytes(t, v.Preimage), v.Key, v.T); c != "" || p == nil {
		t.Fatal("own paths control", c)
	}
}

// Persistent explicit re-registration keeps K within one independent root but
// retires the exact old selection; new fixture-current T rejects the old P.
// No publication/currentness provider is supplied by this source-only control.
func TestMessageAuthorRegistrationLease(t *testing.T) {
	v := maData(t)
	k, s, b := maFixture(t)
	key, c := k.publicSelected(s, b)
	if c != "" || key != v.Key {
		t.Fatal("stable key control", c)
	}
	if c := s.Unbind(fixtureOperator, fixtureOperator, b.UID, b.Generation); c != "" {
		t.Fatal(c)
	}
	if sig, c := k.signSelected(s, b, maPrepare(t, v)); c != "binding_not_found" || sig != nil {
		t.Fatal("retired selection signed", c)
	}
	next := b
	next.Generation = "generation-1"
	next, c = s.Register(fixtureOperator, fixtureOperator, next)
	if c != "" || next.Number == b.Number {
		t.Fatal("persistent explicit registration", c)
	}
	again, c := k.publicSelected(s, next)
	if c != "" || again != key {
		t.Fatal("persistent key changed", c)
	}
	newT := "sha256:" + strings.Repeat("c", 64)
	if plan, c := prepareMessageAuthor(maBytes(t, v.Preimage), key, newT); c != "signer_identity_mismatch" || plan != nil {
		t.Fatal("old certificate reference admitted", c)
	}
	r := maRecord(t, v)
	r["body"].(map[string]any)["author_attestation"] = newT
	plan, c := prepareMessageAuthor(maPre(t, r), key, newT)
	if c != "" || plan == nil {
		t.Fatal("new explicit fixture reference control", c)
	}
	// An independently supplied public test root has different key bytes even
	// for the same purpose/path. This is not proof about operator provisioning.
	other, st, own := maFixture(t)
	other.seed = bytes.Repeat([]byte{0x43}, 32)
	different, c := other.publicSelected(st, own)
	if c != "" || different == key {
		t.Fatal("independent root bytes collision", c)
	}
	if sig, c := other.signSelected(st, own, maPrepare(t, v)); c != "sign_key_mismatch" || sig != nil {
		t.Fatal("foreign root signed old selected key", c)
	}
}
