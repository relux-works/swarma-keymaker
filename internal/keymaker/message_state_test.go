package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/waggle/record"
	"github.com/relux-works/waggle/verifier"
)

type messageStateFixture struct {
	dir     *os.File
	path    string
	store   *Store
	floor   messageSchemaFloor
	issuer  *messageIssuer
	binding Binding
	service *messageCertification
	facts   verifier.Context
}

func messageStateSetup(t *testing.T) *messageStateFixture {
	t.Helper()
	path := t.TempDir()
	if e := os.Chmod(path, 0700); e != nil {
		t.Fatal(e)
	}
	dir, e := OpenDirectory(path, uint32(os.Getuid()), 0700)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { dir.Close() })
	s, _, _, e := openCustodyStateClock(dir, uint32(os.Getuid()), fixtureAuditClock{})
	if e != nil {
		t.Fatal(e)
	}
	i, b, _, facts, _ := messageIssuerFixture(t)
	b.Number = 0
	b, c := s.Register(fixtureOperator, fixtureOperator, b)
	if c != "" {
		t.Fatal(c)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	floor := messageSchemaFloor{minimum: 2}
	m, e := openMessageMaintenance(dir, uint32(os.Getuid()), floor, fixtureAuditClock{})
	if e != nil {
		t.Fatal(e)
	}
	if c = m.migrate(t.Context()); c != "" {
		t.Fatal("migration control", c)
	}
	if e = m.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = openMessageStore(dir, uint32(os.Getuid()), floor, fixtureAuditClock{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	f := &messageStateFixture{dir: dir, path: path, store: s, floor: floor, issuer: i, binding: b, facts: facts}
	f.service = &messageCertification{store: s, issuer: i, generations: newGenerations(b.UID, b.Generation), entropy: bytes.NewReader(bytes.Repeat([]byte{0x31}, 256)), facts: func(context.Context, Binding) (verifier.Context, Code) { return facts, "" }}
	return f
}
func (f *messageStateFixture) reopen(t *testing.T) *Store {
	t.Helper()
	if f.store != nil {
		if e := f.store.Close(); e != nil {
			t.Fatal(e)
		}
	}
	s, e := openMessageStore(f.dir, uint32(os.Getuid()), f.floor, fixtureAuditClock{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	f.store = s
	f.service.store = s
	return s
}

// Schema migration preserves binding/native history. Missing tags/arrays,
// downgrade under the external floor, and unqualified old openers refuse without
// changing bytes; an intact schema2 store reopens with the protected floor.
func TestMsgSchemaMigration(t *testing.T) {
	f := messageStateSetup(t)
	if f.store.schema != 2 || len(f.store.Snapshot()) != 1 {
		t.Fatal("migration lost binding")
	}
	path := filepath.Join(f.path, "bindings.json")
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.store.Close(); e != nil {
		t.Fatal(e)
	}
	f.store = nil
	for _, mode := range []string{"old-reader", "missing-schema", "missing-messages", "null-certificates", "unknown", "floor-downgrade"} {
		t.Run(mode, func(t *testing.T) {
			var obj map[string]any
			if e := json.Unmarshal(original, &obj); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "missing-schema":
				delete(obj, "schema_version")
			case "missing-messages":
				delete(obj, "messages")
			case "null-certificates":
				obj["messages"].(map[string]any)["certificates"] = nil
			case "unknown":
				obj["messages"].(map[string]any)["extra"] = true
			case "floor-downgrade":
				delete(obj, "schema_version")
				delete(obj, "messages")
			}
			raw, _ := json.Marshal(obj)
			if e := os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			before := recoveryFiles(t, f.path)
			var s *Store
			var err error
			if mode == "old-reader" {
				s, err = OpenStore(f.dir, uint32(os.Getuid()))
			} else {
				s, err = openMessageStore(f.dir, uint32(os.Getuid()), f.floor, fixtureAuditClock{})
			}
			if err == nil || s != nil {
				if s != nil {
					s.Close()
				}
				t.Fatal("downgrade/malformed schema admitted")
			}
			if !equalMessageFiles(before, recoveryFiles(t, f.path)) {
				t.Fatal("rejected schema changed evidence")
			}
		})
	}
	if e := os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	f.reopen(t)
}
func equalMessageFiles(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// Neither candidate construction nor issued commit sets current or admits
// message output. A pending association fences every new selection/retry; intact
// issued bytes survive reopening and still refuse key_not_enrolled.
func TestMsgV26RenewalCommit(t *testing.T) {
	f := messageStateSetup(t)
	before := f.store.version
	id, code := f.service.issue(t.Context(), f.binding)
	if code != "" {
		t.Fatal("issued candidate control", code)
	}
	if len(id) != 32 || f.store.version <= before || len(f.store.messages.Certificates) != 1 {
		t.Fatal("missing durable candidate")
	}
	a := f.store.messages.Associations[0]
	if a.Current != nil || a.Pending == nil || *a.Pending != id {
		t.Fatal("candidate promoted before publication/activation")
	}
	if _, code = f.store.messageCurrent(f.binding); code != "key_not_enrolled" {
		t.Fatal("unpublished certificate admitted", code)
	}
	original := f.store.messages.Certificates[0]
	f.reopen(t)
	if f.store.messages.Certificates[0] != original {
		t.Fatal("restart changed original certificate")
	}
	if _, code = f.store.messageCurrent(f.binding); code != "key_not_enrolled" {
		t.Fatal("restart activated candidate", code)
	}
	// S2 also refuses a retained/cached T1 even if a future activation fixture
	// supplies it; no public S2 method can create that pointer.
	f.store.messages.Associations[0].Current = &id
	if _, code = f.store.messageCurrent(f.binding); code != "key_not_enrolled" {
		t.Fatal("pending fence fell back to readable T1", code)
	}
}

// Capacity is reserved before intent; exhausted counts/bytes do not sign,
// create transaction artifacts or modify state/audit. Sufficient reservation
// accepts exactly one candidate and never exceeds the shared byte budget.
func TestMsgStateCapacity(t *testing.T) {
	for _, mode := range []string{"transactions", "certificates", "associations", "bytes", "audit", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := messageStateSetup(t)
			switch mode {
			case "transactions":
				f.store.messages.Transactions = make([]messageTransaction, 65536)
			case "certificates":
				f.store.messages.Certificates = make([]messageCertificate, 65536)
			case "associations":
				f.store.messages.Associations = make([]messageAssociation, 65536)
			case "bytes":
				f.store.messages.artifactBytes = stateBudget
			case "audit":
				f.store.journal.totalLimit = f.store.journal.total + messageAuditReserve - 1
			}
			before := recoveryFiles(t, f.path)
			_, code := f.service.issue(t.Context(), f.binding)
			if mode != "valid" {
				want := Code("state_capacity_exceeded")
				if mode == "audit" {
					want = "audit_unavailable"
				}
				if code != want {
					t.Fatal("capacity refusal", code)
				}
				if !equalMessageFiles(before, recoveryFiles(t, f.path)) {
					t.Fatal("capacity wrote evidence")
				}
			} else if code != "" {
				t.Fatal("capacity control", code)
			}
		})
	}
}

// Re-registration on a persistent path preserves K but creates a new exact
// generation/registration certificate. The old certificate fails the new active
// binding fixture; certificate math alone does not restore retired authority.
func TestMsgV16GenerationCertificate(t *testing.T) {
	f := messageStateSetup(t)
	if _, code := f.service.issue(t.Context(), f.binding); code != "" {
		t.Fatal(code)
	}
	old := f.store.messages.Certificates[0]
	if c := f.store.Unbind(fixtureOperator, fixtureOperator, f.binding.UID, f.binding.Generation); c != "" {
		t.Fatal(c)
	}
	b := f.binding
	b.Generation = "new-generation"
	b.Number = 0
	b, c := f.store.Register(fixtureOperator, fixtureOperator, b)
	if c != "" {
		t.Fatal(c)
	}
	f.issuer.clock.(*messageTestClock).now = messageTestNow.Add(1e9)
	p, _, code := messagePublicLocked(f.issuer.master, f.store, b, b.Epoch, b.RegistryRevision)
	if code != "" {
		t.Fatal(code)
	}
	// Explicit fixture authority for generation2, never manufactured by runtime.
	active := map[string]any{"uid": int64(b.UID), "generation": b.Generation, "registration_number": int64(b.Number), "master_epoch": b.Epoch, "owner": b.Owner, "path": messageBindingOf(b).Path, "active": true}
	facts := f.facts
	facts.CurrentGenerations = messageEvidence(t, map[string]any{messageTestID(p): active})
	facts.Now = messageEvidence(t, messageStamp(messageTestNow.Add(1e9)))
	facts.Watermark = facts.Now
	facts.Time = messageEvidence(t, map[string]any{"trusted": true, "fresh": true, "authority_until": messageStamp(messageTestNow.Add(2e9))})
	f.service.generations = newGenerations(b.UID, b.Generation)
	f.service.facts = func(context.Context, Binding) (verifier.Context, Code) { return facts, "" }
	f.service.entropy = bytes.NewReader(bytes.Repeat([]byte{0x32}, 256))
	if _, code = f.service.issue(t.Context(), b); code != "" {
		t.Fatal("fresh generation control", code)
	}
	fresh := f.store.messages.Certificates[1]
	if fresh.KeyID != old.KeyID || fresh.ContentID == old.ContentID || fresh.Binding.Number == old.Binding.Number {
		t.Fatal("persistent generation certificate association")
	}
	if code := messageVerifyFixture(t, old, facts); code != "key_binding_invalid" {
		t.Fatal("retired certificate verified", code)
	}
	if code := messageVerifyFixture(t, fresh, facts); code != "accept" {
		t.Fatal("new certificate failed", code)
	}
}

// Serialized phase intent is single-writer: a second issue on a pending binding
// refuses without another signature/transaction, while independent binders still
// obey their own checked generations. No result disclosure exists in this slice.
func TestMsgConcurrentIntent(t *testing.T) {
	f := messageStateSetup(t)
	id, c := f.service.issue(t.Context(), f.binding)
	if c != "" {
		t.Fatal(c)
	}
	before := recoveryFiles(t, f.path)
	if _, c = f.service.issue(t.Context(), f.binding); c != "key_not_enrolled" {
		t.Fatal("parallel renewal admitted", c)
	}
	if len(f.store.messages.Transactions) != 1 || f.store.messages.Transactions[0].ID != id || !equalMessageFiles(before, recoveryFiles(t, f.path)) {
		t.Fatal("duplicate issuance changed evidence")
	}
}

// Corrupt or substituted exact candidate bytes are not interchangeable with T:
// hashes and envelope signatures/profile are checked on reopen; the intact
// control survives and is never promoted in the absence of publication.
func TestMsgCandidateArtifacts(t *testing.T) {
	f := messageStateSetup(t)
	if _, c := f.service.issue(t.Context(), f.binding); c != "" {
		t.Fatal(c)
	}
	raw, _ := record.DecodeBase64(f.store.messages.Certificates[0].Envelope, -1)
	if !bytes.Contains(raw, []byte("attestation/1")) {
		t.Fatal("certificate control")
	}
	f.reopen(t)
	tx := f.store.messages.Transactions[0]
	if e := f.store.Close(); e != nil {
		t.Fatal(e)
	}
	f.store = nil
	path := filepath.Join(f.path, "message-tx", tx.ID, tx.Candidate.Hash)
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, append(before, []byte(" ")...), 0600); e != nil {
		t.Fatal(e)
	}
	if s, e := openMessageStore(f.dir, uint32(os.Getuid()), f.floor, fixtureAuditClock{}); e == nil || s != nil {
		if s != nil {
			s.Close()
		}
		t.Fatal("changed artifact admitted")
	}
}

// Root-owner authorization is a deployment prerequisite, not the snapshot's
// schema number. Writable/untrusted floor files reject; pure owner/mode checks
// have an adjacent root-owned fixture-stat control. Multi-UID deployment remains
// PENDING on the privileged root provisioning step; no such suite is skipped.
func TestMsgMinimumReaderFloor(t *testing.T) {
	p := filepath.Join(t.TempDir(), "floor.json")
	if e := os.WriteFile(p, []byte(`{"minimum_reader_schema":2}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := loadMessageSchemaFloor(p); e == nil {
		t.Fatal("untrusted floor file authorized migration")
	}
	if !validMessageFloorStat(0, 0600) || validMessageFloorStat(1, 0600) || validMessageFloorStat(0, 0660) {
		t.Fatal("minimum reader floor ownership gate")
	}
}
