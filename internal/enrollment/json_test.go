package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Removed first_use and all case aliases refuse as unknown members. An explicit
// operator publication with the current schema is the nearby positive control.
func TestConfigBootstrapCaseAlias(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	f.writeConfig()
	original, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"first_use", "First_Use", "FIRST_USE"} {
		for _, value := range []string{"true", "false"} {
			t.Run(alias+"/"+value, func(t *testing.T) {
				bad := append([]byte(nil), original[:len(original)-1]...)
				bad = append(bad, []byte(`,"`+alias+`":`+value+`}`)...)
				if err := os.WriteFile(f.configPath, bad, 0600); err != nil {
					t.Fatal(err)
				}
				a := New(f.configPath, f.files, nil)
				expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
				result, code := authorize(a)
				expectCode(t, EnrollmentUnverified, code)
				if result != (EnrolledKey{}) {
					t.Fatal("alias released admission data")
				}
				if _, err := os.Stat(filepath.Join(f.config.StateDir, "accepted")); !os.IsNotExist(err) {
					t.Fatal("invalid config consumed bootstrap")
				}
			})
		}
	}
	if err := os.WriteFile(f.configPath, original, 0600); err != nil {
		t.Fatal(err)
	}
	expectCode(t, EnrollmentUnverified, New(f.configPath, f.files, nil).Reload(context.Background()))
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, OK, code)
}

// Every config field uses exact spelling; aliases alone or alongside canonical
// members, unknown names, and duplicate decoded names refuse before any write.
func TestConfigExactMembers(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	f.writeConfig()
	original, err := os.ReadFile(f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(original, &members); err != nil {
		t.Fatal(err)
	}
	for key, value := range members {
		for _, shape := range []string{"alias-only", "alias-before", "alias-after", "duplicate"} {
			t.Run(key+"/"+shape, func(t *testing.T) {
				alias := string(bytes.ToUpper([]byte(key[:1]))) + key[1:]
				canonical := []byte(`"` + key + `":` + string(value))
				other := []byte(`"` + alias + `":` + string(value))
				var bad []byte
				switch shape {
				case "alias-only":
					bad = bytes.Replace(original, []byte(`"`+key+`":`), []byte(`"`+alias+`":`), 1)
				case "alias-before":
					bad = append(append([]byte{'{'}, append(other, ',')...), original[1:]...)
				case "alias-after":
					bad = append(append(append([]byte(nil), original[:len(original)-1]...), ','), append(other, '}')...)
				case "duplicate":
					bad = append(append([]byte{'{'}, append(canonical, ',')...), original[1:]...)
				}
				var c PinConfig
				if strictJSON(bad, &c) == nil {
					t.Fatal("non-exact config member accepted")
				}
				if strictJSON(original, &c) != nil {
					t.Fatal("canonical config refused")
				}
			})
		}
	}
	for _, bad := range [][]byte{append([]byte(`{"unknown":0,`), original[1:]...), append([]byte(`{"first_\u0075se":true,`), original[1:]...)} {
		var c PinConfig
		if strictJSON(bad, &c) == nil {
			t.Fatal("unknown or escaped duplicate member accepted")
		}
	}
}

// Persisted wrapper, high-water and nested host/history fields share the exact
// member contract. Refusal preserves evidence; restoring exact bytes plus an
// independently matching reconciler is the positive control.
func TestStoredStateExactMembers(t *testing.T) {
	for _, tc := range []struct{ name, from, to string }{
		{"wrapper-alias", `"version":`, `"Version":`},
		{"high-water-alias", `"high_water":`, `"High_Water":`},
		{"revision-alias", `"Revision":`, `"revision":`},
		{"hosts-alias", `"Hosts":`, `"hosts":`},
		{"seq-alias", `"Seq":`, `"seq":`},
		{"id-alias", `"ID":`, `"id":`},
		{"revoked-alias", `"Revoked":`, `"revoked":`},
		{"history-alias", `"History":`, `"history":`},
		{"key-owners-alias", `"KeyOwners":`, `"keyowners":`},
		{"name-owners-alias", `"NameOwners":`, `"nameowners":`},
		{"integer-key-alias", `"History":{"1":`, `"History":{"01":`},
		{"nested-unknown", `"Seq":`, `"unknown":0,"Seq":`},
		{"nested-duplicate", `"Seq":1`, `"Seq":1,"Seq":1`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.config.Revision = f.commit(f.valid(), "", true)
			a := f.authority()
			expectCode(t, OK, a.Reload(context.Background()))
			path := filepath.Join(f.config.StateDir, "high-water.json")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			bad := bytes.Replace(original, []byte(tc.from), []byte(tc.to), 1)
			if bytes.Equal(bad, original) {
				t.Fatal("negative case was not applied")
			}
			if err := os.WriteFile(path, bad, 0600); err != nil {
				t.Fatal(err)
			}
			restart := New(f.configPath, f.files, exactReconciler{a.retained.Clone()})
			expectCode(t, EnrollmentUnverified, restart.Reload(context.Background()))
			result, code := authorize(restart)
			expectCode(t, EnrollmentUnverified, code)
			if result != (EnrolledKey{}) {
				t.Fatal("invalid state released data")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, bad) {
				t.Fatal("invalid state was rewritten")
			}
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			expectCode(t, OK, restart.Reload(context.Background()))
			_, code = authorize(restart)
			expectCode(t, OK, code)
		})
	}
}

// Approval aliases, duplicates and unknown members cannot act as operator
// consent. Exact startup/digest spelling still admits the same reconciled state.
func TestOperatorApprovalExactMembers(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	path := filepath.Join(f.base, "approval.json")
	r, err := NewOperatorReconciler(path, f.files)
	if err != nil {
		t.Fatal(err)
	}
	good, err := json.Marshal(map[string]string{"startup_id": r.Challenge(), "state_sha256": StateDigest(a.retained)})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"startup_id", "state_sha256"} {
		t.Run(key, func(t *testing.T) {
			alias := string(bytes.ToUpper([]byte(key[:1]))) + key[1:]
			bad := bytes.Replace(good, []byte(`"`+key+`":`), []byte(`"`+alias+`":`), 1)
			if err := os.WriteFile(path, bad, 0600); err != nil {
				t.Fatal(err)
			}
			if r.Check(context.Background(), a.retained) == nil {
				t.Fatal("approval case alias accepted")
			}
			if err := os.WriteFile(path, good, 0600); err != nil {
				t.Fatal(err)
			}
			if err := r.Check(context.Background(), a.retained); err != nil {
				t.Fatal("canonical approval refused")
			}
		})
	}
	for _, bad := range [][]byte{append([]byte(`{"unknown":"x",`), good[1:]...), append([]byte(`{"startup_id":"bad",`), good[1:]...)} {
		if err := os.WriteFile(path, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if r.Check(context.Background(), a.retained) == nil {
			t.Fatal("unknown/duplicate approval accepted")
		}
	}
}
