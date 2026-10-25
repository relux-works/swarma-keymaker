package keymaker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every issued certificate belongs to exactly its committed transaction and
// association. In-memory corruptions isolate graph validation from the outer
// snapshot hash gate; a complete graph is the paired positive control.
func TestMsgStateGraph(t *testing.T) {
	for _, mode := range []string{"premature-certificate", "wrong-kind", "foreign-association", "lost-fence", "missing-event", "published", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := messageStateSetup(t)
			if _, c := f.service.issue(t.Context(), f.binding); c != "" {
				t.Fatal(c)
			}
			switch mode {
			case "premature-certificate":
				f.store.messages.Transactions[0].Phase = "prepared"
			case "wrong-kind":
				f.store.messages.Transactions[0].Kind = "renew"
			case "foreign-association":
				a := f.store.messages.Associations[0]
				a.Binding.Owner = "foreign"
				f.store.messages.Associations = append(f.store.messages.Associations, a)
			case "lost-fence":
				f.store.messages.Associations[0].Pending = nil
			case "missing-event":
				f.store.journal.messageEvents = nil
			case "published":
				f.store.messages.Publications = append(f.store.messages.Publications, messagePublication{})
			}
			before := recoveryFiles(t, f.path)
			e := f.store.validateMessages()
			if mode == "valid" {
				if e != nil {
					t.Fatal("complete graph control", e)
				}
			} else if e == nil {
				t.Fatal("inconsistent message graph accepted", mode)
			}
			if !equalMessageFiles(before, recoveryFiles(t, f.path)) {
				t.Fatal("graph validation wrote evidence")
			}
		})
	}
}

// A retained candidate declares only the exact issued, still-pending effect
// against its intent's base. Neither foreign references nor an activation or
// publication effect can be smuggled into the recovery manifest.
func TestMsgCandidateEffect(t *testing.T) {
	f := messageStateSetup(t)
	if _, c := f.service.issue(t.Context(), f.binding); c != "" {
		t.Fatal(c)
	}
	tx := f.store.messages.Transactions[0]
	intent, c := f.store.readMessageIntent(&tx)
	if c != "" {
		t.Fatal(c)
	}
	var candidate messageCandidate
	if c = f.store.readMessageArtifact(tx.ID, *tx.Candidate, &candidate); c != "" {
		t.Fatal(c)
	}
	for _, mode := range []string{"current", "pending", "base", "binding", "phase", "publication", "valid"} {
		t.Run(mode, func(t *testing.T) {
			effect := candidate.Effect
			switch mode {
			case "current":
				effect.Current = &tx.ID
			case "pending":
				effect.Pending = strings.Repeat("f", 32)
			case "base":
				effect.BaseDigest = strings.Repeat("f", 64)
			case "binding":
				effect.Binding.Owner = "foreign"
			case "phase":
				effect.Phase = "active"
			case "publication":
				effect.Publication = tx.Candidate
			}
			if messageEffectMatches(effect, tx, intent) != (mode == "valid") {
				t.Fatal("candidate effect escaped its exact intent", mode)
			}
		})
	}
}

// Admission refusals happen before any transaction artifact; every row has a
// healthy fixture control. These exact codes come from the existing generation,
// selection, custody, entropy and deadline contracts, not new wire vocabulary.
func TestMsgCertificationRefusals(t *testing.T) {
	for _, mode := range []string{"selection", "lineage", "custody", "root-path", "root-pin", "entropy", "inactive", "generation", "source", "deadline", "valid"} {
		t.Run(mode, func(t *testing.T) {
			f := messageStateSetup(t)
			selected := f.binding
			ctx := t.Context()
			want := Code("binding_conflict")
			switch mode {
			case "selection":
				selected.Owner = "changed"
			case "lineage":
				f.issuer.policy.RegistryRevision = "changed"
			case "custody":
				f.issuer.master = nil
				want = "custody_unavailable"
			case "root-path":
				f.issuer.policy.Path = "m/2'/1'/1'/1'"
				want = "purpose_unknown"
			case "root-pin":
				f.issuer.policy.Key = "unusable"
				want = "sign_key_mismatch"
			case "entropy":
				f.service.entropy = bytes.NewReader(nil)
				want = "key_not_enrolled"
			case "inactive":
				f.service.generations.(*fakeGenerations).set(selected.UID, "removed", selected.Generation)
				want = "generation_inactive"
			case "generation":
				selected.Generation = "changed"
				want = "generation_mismatch"
			case "source":
				f.service.generations.(*fakeGenerations).unavailable = true
				want = "generation_source_unavailable"
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = "request_deadline_exceeded"
			case "valid":
				want = ""
			}
			before := recoveryFiles(t, f.path)
			_, c := f.service.issue(ctx, selected)
			if c != want {
				t.Fatal("certification refusal", c, want)
			}
			if mode != "valid" && !equalMessageFiles(before, recoveryFiles(t, f.path)) {
				t.Fatal("admission refusal wrote evidence")
			}
		})
	}
}

// Earmarked audit bytes cannot be consumed by unrelated appends; the matching
// ticket can use them and is charged exactly once. Migration attribution stays
// null and issuance uses the resolved binding and exact artifact digest, with
// the unchanged closed audit record and a separate snapshot commit.
func TestMsgAuditReservation(t *testing.T) {
	t.Run("unrelated-append", func(t *testing.T) {
		f := messageStateSetup(t)
		j := f.store.journal
		j.totalLimit = j.total + messageAuditReserve
		_, release, c := j.reserveMessageAudit(t.Context())
		if c != "" {
			t.Fatal(c)
		}
		defer release()
		before := recoveryFiles(t, f.path)
		if c = j.Append(AuditRecord{Surface: "control", Operation: "fixture-unrelated", Result: "success"}); c != "audit_unavailable" {
			t.Fatal("unrelated append consumed reserved bytes", c)
		}
		if !equalMessageFiles(before, recoveryFiles(t, f.path)) {
			t.Fatal("exhausted audit append wrote bytes")
		}
	})
	f := messageStateSetup(t)
	j := f.store.journal
	j.totalLimit = j.total + messageAuditReserve
	ctx, release, c := j.reserveMessageAudit(t.Context())
	if c != "" {
		t.Fatal(c)
	}
	if _, _, c = j.reserveMessageAudit(t.Context()); c != "audit_unavailable" {
		t.Fatal("audit reservation oversubscribed", c)
	}
	if c = j.AppendContext(ctx, AuditRecord{Surface: "control", Operation: "fixture-ticket", Result: "success"}); c != "" {
		t.Fatal("ticket control", c)
	}
	if j.messageReserved >= messageAuditReserve || j.messageReserved <= 0 {
		t.Fatal("audit ticket not charged")
	}
	release()
	if j.messageReserved != 0 {
		t.Fatal("audit reservation leaked")
	}
	if c = j.AppendContext(context.Background(), AuditRecord{Surface: "control", Operation: "fixture-after-ticket", Result: "success"}); c != "" {
		t.Fatal("released budget unavailable", c)
	}
	f = messageStateSetup(t)
	if _, c = f.service.issue(t.Context(), f.binding); c != "" {
		t.Fatal(c)
	}
	tx := f.store.messages.Transactions[0]
	rows := nativeAudit(t, f.store.journal)
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Operation == "message_state_migrate" {
			seen[r.Operation] = true
			if r.PeerUID != nil || r.Generation != nil || r.Path != nil || r.Epoch != nil {
				t.Fatal("invented migration attribution")
			}
		}
		if r.Operation == "message_certification_fence" || r.Operation == "message_attestation_issue" {
			seen[r.Operation] = true
			if r.Surface != "control" || r.Domain == nil || *r.Domain != "control" || r.RequestID == nil || !strings.HasPrefix(*r.RequestID, "msg:"+tx.ID+":") || r.PeerUID == nil || *r.PeerUID != f.binding.UID || r.Generation == nil || *r.Generation != f.binding.Generation || r.Path == nil || *r.Path != f.binding.Path || r.Epoch == nil || *r.Epoch != f.binding.Epoch {
				t.Fatal("issuance audit mapping")
			}
			want := tx.Intent.Hash
			if r.Operation == "message_attestation_issue" {
				want = tx.Candidate.Hash
			}
			if r.PayloadDigest == nil || *r.PayloadDigest != want {
				t.Fatal("audit artifact digest")
			}
		}
	}
	for _, op := range []string{"message_state_migrate", "message_certification_fence", "message_attestation_issue"} {
		if !seen[op] {
			t.Fatal("missing issuance audit", op)
		}
	}
}

// Offline migration rejects all uncertain legacy staging without creating or
// changing artifacts. The exact original base bytes, bindings and audit anchor
// survive the clean migration control; another maintainer cannot share the lock.
func TestMsgMigrationEligibility(t *testing.T) {
	t.Run("empty-is-not-migration", func(t *testing.T) {
		path := t.TempDir()
		if e := os.Chmod(path, 0700); e != nil {
			t.Fatal(e)
		}
		dir, e := OpenDirectory(path, uint32(os.Getuid()), 0700)
		if e != nil {
			t.Fatal(e)
		}
		defer dir.Close()
		if m, e := openMessageMaintenance(dir, uint32(os.Getuid()), messageSchemaFloor{2}, fixtureAuditClock{}); e == nil {
			m.Close()
			t.Fatal("empty store bootstrapped under migration floor")
		}
		entries, e := os.ReadDir(path)
		if e != nil || len(entries) != 0 {
			t.Fatal("refused empty migration created evidence", e)
		}
	})
	for _, mode := range []string{"bindings.next", "message-tx", "valid"} {
		t.Run(mode, func(t *testing.T) {
			path := t.TempDir()
			if e := os.Chmod(path, 0700); e != nil {
				t.Fatal(e)
			}
			dir, e := OpenDirectory(path, uint32(os.Getuid()), 0700)
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			s, _, _, e := openCustodyStateClock(dir, uint32(os.Getuid()), fixtureAuditClock{})
			if e != nil {
				t.Fatal(e)
			}
			b := fixtureBinding(30001)
			if _, c := s.Register(fixtureOperator, fixtureOperator, b); c != "" {
				t.Fatal(c)
			}
			if e = s.Close(); e != nil {
				t.Fatal(e)
			}
			original, e := os.ReadFile(filepath.Join(path, "bindings.json"))
			if e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "bindings.next":
				if e = os.WriteFile(filepath.Join(path, mode), []byte("uncertain original bytes"), 0600); e != nil {
					t.Fatal(e)
				}
			case "message-tx":
				if e = os.Mkdir(filepath.Join(path, mode), 0700); e != nil {
					t.Fatal(e)
				}
			}
			before := recoveryFiles(t, path)
			m, e := openMessageMaintenance(dir, uint32(os.Getuid()), messageSchemaFloor{2}, fixtureAuditClock{})
			if e != nil {
				t.Fatal(e)
			}
			defer m.Close()
			if other, e := openMessageMaintenance(dir, uint32(os.Getuid()), messageSchemaFloor{2}, fixtureAuditClock{}); e == nil {
				other.Close()
				t.Fatal("concurrent maintenance acquired exclusive state")
			}
			c := m.migrate(t.Context())
			if mode != "valid" {
				if c != "audit_unavailable" || !equalMessageFiles(before, recoveryFiles(t, path)) {
					t.Fatal("uncertain migration wrote evidence", c)
				}
				return
			}
			if c != "" {
				t.Fatal("clean migration control", c)
			}
			retained, e := os.ReadFile(filepath.Join(path, "message-tx", "migration", "base"))
			if e != nil || string(retained) != string(original) {
				t.Fatal("migration changed exact legacy base", e)
			}
		})
	}
}

// Aborted internal IDs remain permanently consumed. Repeating entropy refuses
// the exact collision without writing; independent fresh entropy admits a new
// candidate after the fully evidenced pre-issuance abort.
func TestMsgCertificationIDReuse(t *testing.T) {
	f := messageStateSetup(t)
	f.store.messageFault = func(point string) Code {
		if point == "signed" {
			return "audit_unavailable"
		}
		return ""
	}
	if _, c := f.service.issue(t.Context(), f.binding); c != "audit_unavailable" {
		t.Fatal("intent interruption", c)
	}
	tx := f.store.messages.Transactions[0]
	m := messageMaintenanceFixture(t, f)
	if c := m.reconcile(t.Context(), messageExpected(tx, "abort")); c != "" {
		t.Fatal("known abort control", c)
	}
	if e := m.Close(); e != nil {
		t.Fatal(e)
	}
	f.reopen(t)
	before := recoveryFiles(t, f.path)
	if _, c := f.service.issue(t.Context(), f.binding); c != "request_conflict" {
		t.Fatal("consumed certification ID reused", c)
	}
	if !equalMessageFiles(before, recoveryFiles(t, f.path)) {
		t.Fatal("ID collision changed evidence")
	}
	f.service.entropy = bytes.NewReader(bytes.Repeat([]byte{0x33}, 32))
	if id, c := f.service.issue(t.Context(), f.binding); c != "" || id == tx.ID {
		t.Fatal("fresh internal ID control", id, c)
	}
	if len(f.store.messages.Transactions) != 2 || len(f.store.messages.Certificates) != 1 {
		t.Fatal("ID history lost or duplicate candidate")
	}
}
