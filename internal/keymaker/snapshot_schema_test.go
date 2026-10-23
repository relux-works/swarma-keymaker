package keymaker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Construct complete, journal-committed fixtures, including intentionally illegal
// histories. The real opener must reject their binding semantics independently.
func writeHistoryFixture(t *testing.T, d string, rows []Binding, next uint64) {
	t.Helper()
	dir, err := OpenDirectory(d, uint32(os.Getuid()), 0700)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	s, err := OpenStore(dir, uint32(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.records, s.next = rows, next
	if c := s.persist(); c != "" {
		t.Fatal(c)
	}
}

// Presence is a separate gate from history and cross-binding. Every omitted,
// null or unknown member rejects at the snapshot decoder before reconciliation;
// the adjacent complete empty/revoked controls load and retain their records.
func TestSnapshotSchemaRequired(t *testing.T) {
	for _, populated := range []bool{true, false} {
		name := "empty"
		if populated {
			name = "revoked"
		}
		t.Run(name, func(t *testing.T) {
			d := t.TempDir()
			if err := os.Chmod(d, 0700); err != nil {
				t.Fatal(err)
			}
			dir, err := OpenDirectory(d, uint32(os.Getuid()), 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			s, err := OpenStore(dir, uint32(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			if populated {
				b, c := s.Register(fixtureOperator, fixtureOperator, fixtureBinding(31001))
				if c != "" {
					t.Fatal(c)
				}
				if c = s.Revoke(t.Context(), fixtureOperator, fixtureOperator, b.Number, approvedAct{}); c != "" {
					t.Fatal(c)
				}
			}
			s.Close()
			path := filepath.Join(d, "bindings.json")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"records", "next_registration_number", "version", "audit_seq", "audit_hash", "requests"} {
				t.Run("missing-"+key, func(t *testing.T) {
					var changed map[string]json.RawMessage
					json.Unmarshal(original, &changed)
					delete(changed, key)
					data, _ := json.Marshal(changed)
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
					got, err := loadStore(dir, uint32(os.Getuid()))
					if err == nil || got != nil {
						t.Fatal("missing snapshot member admitted")
					}
				})
			}
			for _, mode := range []string{"null-records", "unknown", "case-alias", "unknown-row", "unknown-registrar"} {
				if !populated && (mode == "unknown-row" || mode == "unknown-registrar") {
					continue
				}
				t.Run(mode, func(t *testing.T) {
					var changed map[string]any
					json.Unmarshal(original, &changed)
					switch mode {
					case "null-records":
						changed["records"] = nil
					case "unknown":
						changed["extra"] = true
					case "case-alias":
						changed["VERSION"] = 1
					case "unknown-row":
						changed["records"].([]any)[0].(map[string]any)["extra"] = true
					case "unknown-registrar":
						changed["records"].([]any)[0].(map[string]any)["registrar_principal"].(map[string]any)["extra"] = true
					}
					data, _ := json.Marshal(changed)
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
					if got, err := loadStore(dir, uint32(os.Getuid())); err == nil || got != nil {
						t.Fatal("incomplete snapshot admitted")
					}
				})
			}
			if populated {
				for _, key := range []string{"uid", "generation", "path", "owner", "registration_number", "lifetime", "registrar_principal", "status", "master_epoch", "registry_revision", "registrar.generation", "registrar.uid"} {
					t.Run("nested-"+key, func(t *testing.T) {
						var disk map[string]json.RawMessage
						if err := json.Unmarshal(original, &disk); err != nil {
							t.Fatal(err)
						}
						var rows []map[string]json.RawMessage
						if err := json.Unmarshal(disk["records"], &rows); err != nil {
							t.Fatal(err)
						}
						if key == "registrar.generation" || key == "registrar.uid" {
							var principal map[string]json.RawMessage
							if err := json.Unmarshal(rows[0]["registrar_principal"], &principal); err != nil {
								t.Fatal(err)
							}
							delete(principal, key[len("registrar."):])
							rows[0]["registrar_principal"], err = json.Marshal(principal)
						} else {
							delete(rows[0], key)
						}
						if err != nil {
							t.Fatal(err)
						}
						disk["records"], err = json.Marshal(rows)
						if err != nil {
							t.Fatal(err)
						}
						data, err := json.Marshal(disk)
						if err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(path, data, 0600); err != nil {
							t.Fatal(err)
						}
						if got, err := loadStore(dir, uint32(os.Getuid())); err == nil || got != nil {
							t.Fatal("nested snapshot member admitted")
						}
					})
				}
			}
			t.Run("intact", func(t *testing.T) {
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
				got, err := OpenStore(dir, uint32(os.Getuid()))
				if err != nil {
					t.Fatal(err)
				}
				defer got.Close()
				if populated && (len(got.records) != 1 || got.records[0].Status != "revoked") {
					t.Fatal("lost tombstone")
				}
				if !populated && len(got.records) != 0 {
					t.Fatal("nonempty virgin store")
				}
			})
		})
	}
}
