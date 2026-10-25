package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Real schema2 history must apply capacity backpressure before an unmatched
// journal commit. This uses ordinary accepted bindings and retained snapshots,
// not a fabricated artifact-byte counter or a reduced production budget.
func TestMsgCapacityCommitAfterRefusal(t *testing.T) {
	f := messageStateSetup(t)
	for n := 0; n < 2000; n++ {
		b := fixtureBinding(uint32(100000 + n))
		b.Path = fmt.Sprintf("m/1'/1'/%d'/1'", 100000+n)
		b.Owner = strings.Repeat("o", 512)
		priorCommit := f.store.journal.binding
		priorBytes := f.store.messages.artifactBytes
		priorSnapshot, e := os.ReadFile(filepath.Join(f.path, "bindings.json"))
		if e != nil {
			t.Fatal(e)
		}
		proposed := b
		proposed.Number = f.store.next
		proposed.Status = "active"
		proposed.Registrar = fixtureOperator
		records := append(append([]Binding(nil), f.store.records...), proposed)
		nativePreflight := f.store.fitsState(records, f.store.next+1, f.store.requests)
		_, c := f.store.Register(fixtureOperator, fixtureOperator, b)
		if c == "" {
			installed, e := os.ReadFile(filepath.Join(f.path, "bindings.json"))
			if e != nil {
				t.Fatal(e)
			}
			// Independent peak: prior installed snapshot + newly retained recovery body
			// (the artifact delta) + new install staging snapshot coexist before rename.
			peak := priorBytes + int64(len(priorSnapshot)) + (f.store.messages.artifactBytes - priorBytes) + int64(len(installed))
			if peak > stateBudget {
				t.Fatalf("capacity admitted simultaneous snapshot copies: %d > %d", peak, stateBudget)
			}
			continue
		}
		if c != "state_capacity_exceeded" {
			t.Fatal("unexpected boundary", n, c)
		}
		t.Logf("accepted_bindings=%d artifact_bytes_before=%d snapshot_bytes=%d before_version=%d after_commit_version=%d", n, priorBytes, len(priorSnapshot), priorCommit.Version, f.store.journal.binding.Version)
		if f.store.journal.binding != priorCommit {
			t.Logf("native-style fitsState accepted=%t", nativePreflight)
			installed, e := os.ReadFile(filepath.Join(f.path, "bindings.json"))
			if e != nil {
				t.Fatal(e)
			}
			t.Logf("installed_snapshot_unchanged=%t", string(installed) == string(priorSnapshot))
			afterVersion := f.store.journal.binding.Version
			if e = f.store.Close(); e != nil {
				t.Fatal(e)
			}
			f.store = nil
			reopened, err := openMessageStore(f.dir, uint32(os.Getuid()), f.floor, fixtureAuditClock{})
			if reopened != nil {
				reopened.Close()
			}
			t.Logf("serving_restart_error=%v", err)
			t.Fatalf("capacity refusal appended an unmatched binding_commit: %d -> %d", priorCommit.Version, afterVersion)
		}
		if n == 0 {
			t.Fatal("last-fitting positive control never ran")
		}
		if f.store.failed || len(f.store.records) != n+1 || f.store.next != proposed.Number {
			t.Fatal("capacity refusal changed live binding state")
		}
		if _, retry := f.store.Register(fixtureOperator, fixtureOperator, b); retry != "state_capacity_exceeded" || f.store.journal.binding != priorCommit {
			t.Fatal("clean capacity refusal could not repeat", retry)
		}
		if f.store.messages.artifactBytes != priorBytes {
			t.Fatal("refusal wrote recovery artifact")
		}
		installed, e := os.ReadFile(filepath.Join(f.path, "bindings.json"))
		if e != nil || string(installed) != string(priorSnapshot) {
			t.Fatal("refusal changed installed snapshot", e)
		}
		s := f.reopen(t)
		if s.journal.binding != priorCommit || len(s.records) != n+1 {
			t.Fatal("clean restart lost last fitting transition")
		}
		return
	}
	t.Fatal("capacity boundary not reached")
}

// The same real 256 MiB history exercises fitsState and the native mutation's
// pending/effect pair, with retained result growth. This is the native accounting
// primitive and persistence sequence, not a production message RPC or wire test.
// The last admitted pair must survive restart; the next refusal adds no intent,
// effect, recovery file or journal version, even when one commit alone fits.
func TestMsgNativeCapacityCommitAfterRefusal(t *testing.T) {
	f := messageStateSetup(t)
	accepted := 0
	for n := 0; n < 2000; n++ {
		s := f.store
		b := fixtureBinding(uint32(200000 + n))
		b.Path = fmt.Sprintf("m/1'/1'/%d'/1'", 200000+n)
		b.Owner = strings.Repeat("n", 512)
		b.Number = s.next
		b.Status = "active"
		b.Registrar = fixtureOperator
		records := append(append([]Binding(nil), s.records...), b)
		encoded, e := json.Marshal(map[string]any{"public_key": "fixture-public", "path": b.Path, "registration_number": b.Number, "master_epoch": b.Epoch})
		if e != nil {
			t.Fatal(e)
		}
		entry := retainedRequest{Caller: fixtureOperator, ID: fmt.Sprintf("%032x", n+1), Method: "register", Arguments: "{}", Status: "committed", Result: encoded}
		prospective := append(append([]retainedRequest(nil), s.requests...), entry)
		prior := s.journal.binding
		artifacts := s.messages.artifactBytes
		before, e := os.ReadFile(filepath.Join(f.path, "bindings.json"))
		if e != nil {
			t.Fatal(e)
		}
		if !s.fitsState(records, s.next+1, prospective) {
			if accepted == 0 {
				t.Fatal("no native pair positive control")
			}
			// The single-snapshot bound cannot stand in for this two-commit admission.
			preview := s.messagePreview()
			preview.records, preview.next, preview.requests = records, s.next+1, prospective
			one, e := preview.messageSnapshotBound(s.version + 1)
			if e != nil {
				t.Fatal(e)
			}
			if !s.messageFits(len(one)) {
				t.Fatal("neighbour did not isolate native two-commit reservation")
			}
			if s.journal.binding != prior || s.messages.artifactBytes != artifacts || len(s.requests) != accepted {
				t.Fatal("native refusal changed state")
			}
			after, e := os.ReadFile(filepath.Join(f.path, "bindings.json"))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("native refusal changed snapshot", e)
			}
			s = f.reopen(t)
			if s.journal.binding != prior || len(s.requests) != accepted || len(s.records) != accepted+1 {
				t.Fatal("native last-fitting pair did not reopen cleanly")
			}
			t.Logf("native_pairs=%d version=%d artifact_bytes=%d; next one-commit fits but pair refuses", accepted, prior.Version, artifacts)
			return
		}
		pending := entry
		pending.Status = "pending"
		pending.Result = json.RawMessage("null")
		s.appendRequest(pending)
		if c := s.persist(); c != "" {
			t.Fatal("native admitted intent failed", c)
		}
		installed, e := os.ReadFile(filepath.Join(f.path, "bindings.json"))
		if e != nil {
			t.Fatal(e)
		}
		if peak := int64(len(before)) + s.messages.artifactBytes + int64(len(installed)); peak > stateBudget {
			t.Fatalf("native intent peak exceeded: %d", peak)
		}
		before = installed
		s.records, s.next = records, s.next+1
		s.requests[len(s.requests)-1] = entry
		if c := s.persist(); c != "" {
			t.Fatal("native admitted effect failed", c)
		}
		installed, e = os.ReadFile(filepath.Join(f.path, "bindings.json"))
		if e != nil {
			t.Fatal(e)
		}
		if peak := int64(len(before)) + s.messages.artifactBytes + int64(len(installed)); peak > stateBudget {
			t.Fatalf("native effect peak exceeded: %d", peak)
		}
		if s.journal.binding.Version != prior.Version+2 {
			t.Fatal("native pair did not retain two commits")
		}
		accepted++
	}
	t.Fatal("native capacity boundary not reached")
}

// Capacity-only controls isolate the installed-copy term and preflight ordering;
// the two boundary tests above independently exercise the real encoded history.
// Sparse temporary bytes below only enlarge the installed file for sizing, and
// are restored before any serving validation. No reduced production budget.
func TestMsgCapacityInstalledCopy(t *testing.T) {
	f := messageStateSetup(t)
	s := f.store
	file := filepath.Join(f.path, "bindings.json")
	raw, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Truncate(file, 1<<20); e != nil {
		t.Fatal(e)
	}
	defer os.WriteFile(file, raw, 0600)
	// With exactly one free MiB, a tiny proposed snapshot still needs room for
	// the larger installed predecessor, its recovery body and install staging.
	s.messages.artifactBytes = stateBudget - (1 << 20)
	if s.messageFits(1) {
		t.Fatal("shrinking transition forgot installed predecessor")
	}
	s.messages.artifactBytes -= 2
	if !s.messageFits(1) {
		t.Fatal("exact-fit installed-copy control refused")
	}
	if s.messageFitsTransitions(1, 2, 0) {
		t.Fatal("second recovery copy not reserved")
	}
	for _, tc := range []struct {
		raw, phases int
		extra       int64
	}{{-1, 1, 0}, {stateBudget + 1, 1, 0}, {1, 0, 0}, {1, 4, 0}, {1, 1, -1}, {1, 1, stateBudget}} {
		if s.messageFitsTransitions(tc.raw, tc.phases, tc.extra) {
			t.Fatal("invalid capacity input admitted", tc)
		}
	}
}

// Resolution capacity refuses before the new artifact/audit, preserving the
// pending fence and allowing exact same-evidence retry after capacity returns.
// A sparse installed-file sizing fixture isolates this preflight; its original
// bytes are restored before serving/retry. Real valid history is covered above.
// Both abort and issued-commit have valid controls.
func TestMsgResolutionCapacityPreflight(t *testing.T) {
	for _, outcome := range []string{"abort", "commit"} {
		t.Run(outcome, func(t *testing.T) {
			f := messageStateSetup(t)
			if outcome == "abort" {
				f.store.messageFault = func(p string) Code {
					if p == "signed" {
						return "audit_unavailable"
					}
					return ""
				}
			}
			_, code := f.service.issue(t.Context(), f.binding)
			if outcome == "abort" && code != "audit_unavailable" || outcome == "commit" && code != "" {
				t.Fatal("issuance control", code)
			}
			tx := f.store.messages.Transactions[0]
			m := messageMaintenanceFixture(t, f)
			if e := m.store.validateMessages(); e != nil {
				t.Fatal("resolution history control", e)
			}
			installed := filepath.Join(f.path, "bindings.json")
			original, e := os.ReadFile(installed)
			if e != nil {
				t.Fatal(e)
			}
			defer os.WriteFile(installed, original, 0600)
			// Leave a single byte after current inventory/reservations, insufficient
			// for any resolution artifact plus recovery/staging copies.
			if e = os.Truncate(installed, stateBudget-m.store.messages.artifactBytes-m.store.messages.reservation()-1); e != nil {
				t.Fatal(e)
			}
			inventory := func() map[string]string {
				out := map[string]string{}
				if e := filepath.Walk(f.path, func(path string, info os.FileInfo, e error) error {
					if e != nil {
						return e
					}
					out[path] = fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
					return nil
				}); e != nil {
					t.Fatal(e)
				}
				return out
			}
			before := inventory()
			version := m.store.journal.binding
			if c := m.reconcile(t.Context(), messageExpected(tx, outcome)); c != "state_capacity_exceeded" {
				t.Fatal("resolution capacity refusal", c)
			}
			if m.store.journal.binding != version || !reflect.DeepEqual(before, inventory()) || m.store.messageTx(tx.ID).Resolution != nil || m.store.messages.Associations[0].Pending == nil {
				t.Fatal("resolution capacity changed evidence/fence")
			}
			if e = os.WriteFile(installed, original, 0600); e != nil {
				t.Fatal(e)
			}
			if c := m.reconcile(t.Context(), messageExpected(tx, outcome)); c != "" {
				t.Fatal("resolution capacity positive retry", c)
			}
		})
	}
}

// A schema-2 capacity refusal rolls back the trusted lifecycle proposal without
// fencing the healthy Store or notifying watchers. Restored accounting admits
// the same revoke/unbind. This injects only the byte counter, not durable state;
// the named boundary regressions cover the real budget and restart separately.
func TestMsgTrustedTransitionCapacity(t *testing.T) {
	for _, operation := range []string{"revoke", "unbind"} {
		t.Run(operation, func(t *testing.T) {
			f := messageStateSetup(t)
			s := f.store
			b := fixtureBinding(41001)
			b.Path = "m/1'/1'/2'/1'"
			b, c := s.Register(fixtureOperator, fixtureOperator, b)
			if c != "" {
				t.Fatal(c)
			}
			watch, release := s.Watch(b.Number)
			defer release()
			before := recoveryFiles(t, f.path)
			prior := s.journal.binding
			actual := s.messages.artifactBytes
			transition := func() Code {
				if operation == "revoke" {
					return s.Revoke(context.Background(), fixtureOperator, fixtureOperator, b.Number, approvedAct{})
				}
				return s.Unbind(fixtureOperator, fixtureOperator, b.UID, b.Generation)
			}
			s.messages.artifactBytes = stateBudget
			if c := transition(); c != "state_capacity_exceeded" {
				t.Fatal("trusted capacity refusal", c)
			}
			if got, c := s.lookup(b.UID, b.Generation); c != "" || got != b || s.failed || s.journal.binding != prior || !equalMessageFiles(before, recoveryFiles(t, f.path)) {
				t.Fatal("trusted refusal changed live/durable state", c)
			}
			select {
			case <-watch:
				t.Fatal("capacity refusal notified retirement")
			default:
			}
			s.messages.artifactBytes = actual
			if c := transition(); c != "" {
				t.Fatal("trusted capacity positive retry", c)
			}
			select {
			case <-watch:
			default:
				t.Fatal("accepted transition did not notify retirement")
			}
			f.reopen(t)
		})
	}
}

// Valid legacy JSON may have a large original whitespace encoding. Migration
// must charge both that installed original and the immutable retained base,
// even though the canonical schema-2 body is small. This real 256 MiB control
// refuses before creating message-tx or appending an audit event, then the same
// validated legacy state migrates after restoring its compact encoding.
func TestMsgMigrationCapacityPreflight(t *testing.T) {
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
	if _, c := s.Register(fixtureOperator, fixtureOperator, fixtureBinding(30001)); c != "" {
		t.Fatal(c)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	installed := filepath.Join(path, "bindings.json")
	original, e := os.ReadFile(installed)
	if e != nil {
		t.Fatal(e)
	}
	file, e := os.OpenFile(installed, os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		t.Fatal(e)
	}
	chunk := bytes.Repeat([]byte(" "), 1<<20)
	for n := 0; n < 128; n++ {
		if _, e = file.Write(chunk); e != nil {
			file.Close()
			t.Fatal(e)
		}
	}
	if e = file.Sync(); e != nil {
		file.Close()
		t.Fatal(e)
	}
	if e = file.Close(); e != nil {
		t.Fatal(e)
	}
	floor := messageSchemaFloor{minimum: 2}
	m, e := openMessageMaintenance(dir, uint32(os.Getuid()), floor, fixtureAuditClock{})
	if e != nil {
		t.Fatal("valid large legacy control", e)
	}
	defer m.Close()
	prior := m.store.journal.binding
	auditBytes := m.store.journal.total
	if c := m.migrate(t.Context()); c != "state_capacity_exceeded" {
		t.Fatal("migration capacity refusal", c)
	}
	if m.store.journal.binding != prior || m.store.journal.total != auditBytes || m.store.schema != 0 || m.store.messages != nil || m.store.failed {
		t.Fatal("migration capacity changed legacy state/journal")
	}
	if _, e = os.Stat(filepath.Join(path, "message-tx")); !os.IsNotExist(e) {
		t.Fatal("migration capacity retained partial artifacts", e)
	}
	if _, e = os.Stat(filepath.Join(path, "bindings.next")); !os.IsNotExist(e) {
		t.Fatal("migration capacity created staging", e)
	}
	st, e := os.Stat(installed)
	if e != nil || st.Size() != int64(len(original))+(128<<20) {
		t.Fatal("migration changed original legacy encoding", e)
	}
	if e = os.WriteFile(installed, original, 0600); e != nil {
		t.Fatal(e)
	}
	if c := m.migrate(t.Context()); c != "" {
		t.Fatal("migration compact positive control", c)
	}
	if e = m.Close(); e != nil {
		t.Fatal(e)
	}
	opened, e := openMessageStore(dir, uint32(os.Getuid()), floor, fixtureAuditClock{})
	if e != nil {
		t.Fatal("migrated positive control reopen", e)
	}
	defer opened.Close()
	if opened.schema != 2 || len(opened.records) != 1 {
		t.Fatal("migration lost legacy binding")
	}
}
