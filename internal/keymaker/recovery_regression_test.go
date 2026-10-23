package keymaker

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Snapshot loss must fence recovery without rewriting retained evidence; intact
// recovery keeps tombstones and issued numbers. A truly empty directory works.
func TestMissingSnapshotRecovery(t *testing.T) {
	for _, damage := range []string{"intact", "missing", "unreadable"} {
		t.Run(damage, func(t *testing.T) {
			d := t.TempDir()
			if err := os.Chmod(d, 0700); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Getuid())
			dir, err := OpenDirectory(d, uid, 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			s, err := OpenStore(dir, uid)
			if err != nil {
				t.Fatal("empty control", err)
			}
			b, c := s.Register(fixtureOperator, fixtureOperator, fixtureBinding(31001))
			if c != "" {
				t.Fatal(c)
			}
			if c = s.Revoke(context.Background(), fixtureOperator, fixtureOperator, b.Number, approvedAct{}); c != "" {
				t.Fatal(c)
			}
			auditPath := filepath.Join(d, "audit")
			if err = os.Mkdir(auditPath, 0700); err != nil {
				t.Fatal(err)
			}
			adir, err := OpenDirectory(auditPath, uid, 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer adir.Close()
			j, err := OpenJournal(adir, uid)
			if err != nil {
				t.Fatal(err)
			}
			code := Code("identity_revoked")
			if c = j.Append(AuditRecord{Surface: "agent", Operation: "sign", Result: "refused", RefusalCode: &code, PeerUID: &b.UID, Generation: &b.Generation, Path: &b.Path, Epoch: &b.Epoch}); c != "" {
				t.Fatal(c)
			}
			j.Close()
			snapshot := filepath.Join(d, "bindings.json")
			if damage == "missing" {
				if err = os.Remove(snapshot); err != nil {
					t.Fatal(err)
				}
			}
			if damage == "unreadable" {
				if err = os.Chmod(snapshot, 0644); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(filepath.Join(auditPath, auditName(1)))
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := OpenStore(dir, uid)
			if damage != "intact" {
				if err == nil || recovered != nil {
					t.Fatal("incomplete recovery admitted a store")
				}
				if damage == "missing" {
					if _, err = os.Lstat(snapshot); !os.IsNotExist(err) {
						t.Fatal("snapshot recreated")
					}
				}
			} else {
				if err != nil {
					t.Fatal("intact control", err)
				}
				if _, c = recovered.Register(fixtureOperator, fixtureOperator, b); c != "identity_revoked" {
					t.Fatal("tombstone lost", c)
				}
				b.Path = "m/1'/1'/1'/2'"
				b.Generation = "next"
				if next, c := recovered.Register(fixtureOperator, fixtureOperator, b); c != "" || next.Number != 2 {
					t.Fatal("issued number reused", next.Number, c)
				}
			}
			after, err := os.ReadFile(filepath.Join(auditPath, auditName(1)))
			if err != nil || string(before) != string(after) {
				t.Fatal("recovery changed audit evidence", err)
			}
		})
	}
}

// All retained predecessors constrain the active path. A middle unbound record
// cannot hide an active/revoked predecessor or an illegal owner/lifetime change.
func TestBindingHistoryUniqueness(t *testing.T) {
	for _, scenario := range []string{"valid", "hidden-active", "active-then-unbound", "revoked", "owner-change", "ephemeral-reuse", "out-of-order"} {
		t.Run(scenario, func(t *testing.T) {
			rows := make([]Binding, 3)
			for i := range rows {
				rows[i] = fixtureBinding(uint32(31001 + i))
				rows[i].Lifetime, rows[i].Status = "persistent", "unbound"
				rows[i].Number, rows[i].Registrar = uint64(i+1), fixtureOperator
			}
			rows[2].Status = "active"
			switch scenario {
			case "hidden-active":
				rows[0].Status = "active"
			case "active-then-unbound":
				rows[0].Status, rows[2].Status = "active", "unbound"
			case "revoked":
				rows[0].Status = "revoked"
			case "owner-change":
				rows[0].Owner = "other-owner"
			case "ephemeral-reuse":
				rows[0].Lifetime = "ephemeral"
			case "out-of-order":
				rows[0].Number, rows[1].Number = rows[1].Number, rows[0].Number
			}
			d := t.TempDir()
			if err := os.Chmod(d, 0700); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(bindingDisk{Next: 4, Records: rows})
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(d, "bindings.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			dir, err := OpenDirectory(d, uint32(os.Getuid()), 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			s, err := OpenStore(dir, uint32(os.Getuid()))
			if scenario != "valid" {
				if err != Code("binding_conflict") || s != nil {
					t.Fatalf("history admitted: store=%v code=%v, want binding_conflict", s != nil, err)
				}
				return
			}
			if err != nil {
				t.Fatal("valid history control", err)
			}
			// The valid recovered owner actually signs; older principals cannot admit.
			_, _, signer, audit, _ := fixtureEngine(t)
			g := newGenerations(rows[2].UID, rows[2].Generation)
			e := NewEngine(s, g, signer, audit)
			session := e.OpenSession(context.Background(), Peer{UID: rows[2].UID})
			body := validBody(signer.key[32:], "git")
			if c := e.Handle(context.Background(), session, body, func(response []byte) error { checkResponse(t, response, signer.key[32:], body); return nil }); c != "" {
				t.Fatal("valid signing control", c)
			}
			for _, b := range rows[:2] {
				g.set(b.UID, "active", b.Generation)
				if got := e.OpenSession(context.Background(), Peer{UID: b.UID}); got.Admission != "binding_not_found" {
					t.Fatal("retired owner admitted", got.Admission)
				}
			}
		})
	}
}

// Startup admits an intact pair, but missing/unsafe snapshots or missing, empty,
// or corrupt journals never trigger reconstruction. An interrupted first start
// and a directory containing only unrelated/old evidence also require recovery.
func TestCustodyStartupReconciliation(t *testing.T) {
	for _, damage := range []string{"intact", "missing-snapshot", "unsafe-snapshot", "missing-audit", "empty-audit", "corrupt-audit", "interrupted-bootstrap", "old-lock", "empty-audit-only"} {
		t.Run(damage, func(t *testing.T) {
			d := t.TempDir()
			if err := os.Chmod(d, 0700); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Getuid())
			dir, err := OpenDirectory(d, uid, 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			lock, err := LockState(dir, uid)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			if damage == "old-lock" {
				err = os.WriteFile(filepath.Join(d, "keymaker.lock"), nil, 0600)
			} else if damage == "empty-audit-only" {
				err = os.Mkdir(filepath.Join(d, "audit"), 0700)
			} else if damage == "interrupted-bootstrap" {
				_, err = OpenStore(dir, uid)
			} else {
				s, j, adir, e := openCustodyState(dir, uid)
				if e != nil {
					t.Fatal("empty startup control", e)
				}
				b, code := s.Register(fixtureOperator, fixtureOperator, fixtureBinding(31001))
				if code != "" {
					t.Fatal(code)
				}
				if code = s.Revoke(context.Background(), fixtureOperator, fixtureOperator, b.Number, approvedAct{}); code != "" {
					t.Fatal(code)
				}
				code = "identity_revoked"
				if c := j.Append(AuditRecord{Surface: "agent", Operation: "sign", Result: "refused", RefusalCode: &code, Path: &b.Path, Epoch: &b.Epoch}); c != "" {
					t.Fatal(c)
				}
				j.Close()
				adir.Close()
				switch damage {
				case "missing-snapshot":
					err = os.Remove(filepath.Join(d, "bindings.json"))
				case "unsafe-snapshot":
					err = os.Chmod(filepath.Join(d, "bindings.json"), 0644)
				case "missing-audit":
					err = os.RemoveAll(filepath.Join(d, "audit"))
				case "empty-audit":
					err = os.Remove(filepath.Join(d, "audit", auditName(1)))
				case "corrupt-audit":
					err = os.WriteFile(filepath.Join(d, "audit", auditName(1)), []byte("incomplete"), 0600)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			s, j, adir, err := openCustodyState(dir, uid)
			if err == nil {
				defer j.Close()
				defer adir.Close()
			}
			if damage != "intact" {
				if err == nil || s != nil || j != nil || adir != nil {
					t.Fatal("incomplete custody evidence admitted startup")
				}
				return
			}
			if err != nil {
				t.Fatal("intact startup control", err)
			}
			if j.seq != 1 {
				t.Fatal("audit history lost", j.seq)
			}
			if _, code := s.Register(fixtureOperator, fixtureOperator, fixtureBinding(31001)); code != "identity_revoked" {
				t.Fatal("revoked startup path resurrected", code)
			}
		})
	}
}
