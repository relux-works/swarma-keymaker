package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/registry"
)

// Protected configuration requires an explicit exact enum, and the revision
// must match that enum. Each refusal is paired with a valid pin for that format.
func TestEnrollmentProtectedObjectFormat(t *testing.T) {
	f := newFixture(t)
	for _, profile := range []struct {
		name  string
		width int
	}{{"sha1", 40}, {"sha256", 64}} {
		for _, tc := range []struct {
			name   string
			value  any
			absent bool
		}{
			{"absent", nil, true}, {"empty", "", false}, {"unknown", "sha512", false},
			{"uppercase", "SHA1", false}, {"whitespace", " sha1", false},
			{"null", nil, false}, {"nonstring", 40, false},
		} {
			t.Run(profile.name+"/"+tc.name, func(t *testing.T) {
				raw, _ := json.Marshal(f.config)
				var document map[string]any
				if err := json.Unmarshal(raw, &document); err != nil {
					t.Fatal(err)
				}
				document["revision"] = strings.Repeat("a", profile.width)
				if tc.absent {
					delete(document, "object_format")
				} else {
					document["object_format"] = tc.value
				}
				raw, _ = json.Marshal(document)
				if _, err := ParseConfig(raw); !errors.Is(err, errTrust) {
					t.Fatalf("invalid format must refuse as unverified local trust: %v", err)
				}
				document["object_format"] = profile.name
				raw, _ = json.Marshal(document)
				if _, err := ParseConfig(raw); err != nil {
					t.Fatalf("explicit format control: %v", err)
				}
			})
		}
		for _, width := range []int{profile.width - 1, profile.width + 1, 7, 104 - profile.width} {
			t.Run(fmt.Sprintf("%s/revision-width-%d", profile.name, width), func(t *testing.T) {
				raw, _ := json.Marshal(f.config)
				var document map[string]any
				_ = json.Unmarshal(raw, &document)
				document["object_format"] = profile.name
				document["revision"] = strings.Repeat("a", width)
				raw, _ = json.Marshal(document)
				if _, err := ParseConfig(raw); !errors.Is(err, errTrust) {
					t.Fatalf("wrong-width revision accepted: %v", err)
				}
				document["revision"] = strings.Repeat("a", profile.width)
				raw, _ = json.Marshal(document)
				if _, err := ParseConfig(raw); err != nil {
					t.Fatalf("exact-width control: %v", err)
				}
			})
		}
	}
}

// Both repository formats verify real signed commits. Cross-format or malformed
// commit/tree/blob/ancestor IDs refuse; their matching IDs remain usable.
func TestEnrollmentGitObjectFormat(t *testing.T) {
	for _, profile := range []string{"sha1", "sha256"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithFormat(t, profile)
			f.config.Revision = f.commit(f.valid(), "", true)
			v := newGitVerifier(context.Background(), f.repo, f.config.Revision, profile, f.config.Maintainers)
			entries, err := v.entries()
			if err != nil || v.Verify(f.config.Revision, entries) != nil {
				t.Fatalf("signed format control: %v", err)
			}
			root, _, _, err := commitParts(v.commit, profile)
			if err != nil {
				t.Fatal(err)
			}
			blob := strings.TrimSpace(string(f.git(entries[0].Bytes, "hash-object", "--stdin")))
			for _, kindID := range []struct{ kind, id string }{{"commit", f.config.Revision}, {"tree", root}, {"blob", blob}} {
				for _, bad := range []string{strings.Repeat("a", 104-len(kindID.id)), strings.ToUpper(kindID.id), kindID.id[:7], kindID.id[:len(kindID.id)-1], kindID.id + "a", "main"} {
					if _, err := v.object(kindID.kind, bad, 1<<20); !errors.Is(err, errTrust) {
						t.Fatalf("invalid %s ID accepted: %v", kindID.kind, err)
					}
					if _, err := v.object(kindID.kind, kindID.id, 1<<20); err != nil {
						t.Fatalf("valid %s ID control: %v", kindID.kind, err)
					}
				}
			}
			// Matching the candidate to a malformed predecessor must not make it an ancestor.
			good := v.revision
			for _, bad := range []string{strings.Repeat("a", 104-len(good)), strings.ToUpper(good), good[:7], good[:len(good)-1], good + "a"} {
				v.revision = bad
				if ok, err := v.Descends(bad, bad); ok || !errors.Is(err, errTrust) {
					t.Fatalf("invalid equal ancestor accepted: ok=%v err=%v", ok, err)
				}
				if _, err := v.entries(); !errors.Is(err, errTrust) {
					t.Fatalf("invalid revision accepted: %v", err)
				}
				v.revision = good
				if ok, err := v.Descends(good, good); !ok || err != nil {
					t.Fatalf("equal ancestor control: %v", err)
				}
			}
		})
	}
}

// The upstream Loader has no implicit format. Omitting it refuses before
// verifier/store effects; the explicit protected format loads the same entries.
func TestEnrollmentLoaderRequiresObjectFormat(t *testing.T) {
	for _, profile := range []string{"sha1", "sha256"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithFormat(t, profile)
			f.config.Revision = f.commit(f.valid(), "", true)
			f.writeConfig()
			_, policy, err := loadConfig(f.configPath, f.files)
			if err != nil {
				t.Fatal(err)
			}
			v := newGitVerifier(context.Background(), f.repo, f.config.Revision, profile, f.config.Maintainers)
			entries, err := v.entries()
			if err != nil {
				t.Fatal(err)
			}
			store := &previewStore{}
			observed := &objectFormatVerifier{Verifier: v}
			loader := registry.Loader{Policy: policy, Verifier: observed, Store: store}
			input := registry.Input{Revision: f.config.Revision, Entries: entries, FirstUse: true}
			for _, bad := range []string{"", "sha512"} {
				loader.ObjectFormat = bad
				snapshot, high, err := loader.Load(input)
				if registrarCode(t, err) != "registry_unavailable" || snapshot != nil || high != nil || store.after != nil || observed.calls != 0 {
					t.Fatalf("missing/unknown Loader format did not refuse without commit: %v", err)
				}
			}
			loader.ObjectFormat = profile
			snapshot, high, err := loader.Load(input)
			if err != nil || snapshot == nil || high == nil || store.after == nil || observed.calls == 0 {
				t.Fatalf("explicit Loader control: %v", err)
			}
		})
	}
}

// Count verifier calls so a missing Loader format cannot pass by reaching a
// later rejection. The explicit-format control must actually verify the commit.
type objectFormatVerifier struct {
	registry.Verifier
	calls int
}

func (v *objectFormatVerifier) Verify(revision string, entries []registry.Entry) error {
	v.calls++
	return v.Verifier.Verify(revision, entries)
}
func (v *objectFormatVerifier) Descends(candidate, previous string) (bool, error) {
	v.calls++
	return v.Verifier.Descends(candidate, previous)
}

// Failed reloads revoke admission and preserve accepted high-water bytes. A
// restored explicit pin re-admits the same signed snapshot under either format.
func TestEnrollmentObjectFormatReload(t *testing.T) {
	for _, profile := range []string{"sha1", "sha256"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithFormat(t, profile)
			f.config.Revision = f.commit(f.valid(), "", true)
			a := f.authority()
			defer a.Close()
			if code := a.Reload(context.Background()); code != OK {
				t.Fatalf("explicit protected format did not reach authority Loader: %s", code)
			}
			original, err := os.ReadFile(f.configPath)
			if err != nil {
				t.Fatal(err)
			}
			statePath := filepath.Join(f.config.StateDir, "high-water.json")
			before, err := os.ReadFile(statePath)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"absent", "empty", "unknown", "cross-format", "uppercase", "abbreviated", "short", "long"} {
				t.Run(name, func(t *testing.T) {
					var document map[string]any
					if err := json.Unmarshal(original, &document); err != nil {
						t.Fatal(err)
					}
					switch name {
					case "absent":
						delete(document, "object_format")
					case "empty":
						document["object_format"] = ""
					case "unknown":
						document["object_format"] = "sha512"
					case "cross-format":
						document["revision"] = strings.Repeat("a", 104-len(f.config.Revision))
					case "uppercase":
						document["revision"] = strings.ToUpper(f.config.Revision)
					case "abbreviated":
						document["revision"] = f.config.Revision[:7]
					case "short":
						document["revision"] = f.config.Revision[:len(f.config.Revision)-1]
					case "long":
						document["revision"] = f.config.Revision + "a"
					}
					bad, err := json.Marshal(document)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(f.configPath, bad, 0600); err != nil {
						t.Fatal(err)
					}
					expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
					key, code := authorize(a)
					if code != EnrollmentUnverified || key != (EnrolledKey{}) {
						t.Fatalf("bad pin released authority: %s", code)
					}
					after, err := os.ReadFile(statePath)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("bad pin changed accepted state")
					}
					if err := os.WriteFile(f.configPath, original, 0600); err != nil {
						t.Fatal(err)
					}
					expectCode(t, OK, a.Reload(context.Background()))
					_, code = authorize(a)
					expectCode(t, OK, code)
				})
			}
		})
	}
}

// Tree and parent headers are checked against the protected format before use;
// an opposite-width header cannot select another algorithm.
func TestEnrollmentCommitPartsObjectFormat(t *testing.T) {
	for _, profile := range []string{"sha1", "sha256"} {
		width := objectIDBytes(profile) * 2
		good := strings.Repeat("a", width)
		for _, bad := range []string{strings.Repeat("b", 104-width), strings.ToUpper(good), good[:7], good[:width-1], good + "a", "main"} {
			for _, header := range []string{"tree", "parent"} {
				tree, parent := good, good
				if header == "tree" {
					tree = bad
				} else {
					parent = bad
				}
				raw := []byte("tree " + tree + "\nparent " + parent + "\nauthor fixture\n\nfixture\n")
				if _, _, _, err := commitParts(raw, profile); !errors.Is(err, errTrust) {
					t.Fatalf("%s invalid %s accepted: %v", profile, header, err)
				}
				raw = []byte("tree " + good + "\nparent " + good + "\nauthor fixture\n\nfixture\n")
				if tree, _, _, err := commitParts(raw, profile); err != nil || tree != good {
					t.Fatalf("valid commit header control: %v", err)
				}
			}
		}
	}
}

// Persisted revisions use the same protected width. A rejected state read never
// rewrites the evidence; restoring the valid bytes permits the read again.
func TestEnrollmentStoredRevisionObjectFormat(t *testing.T) {
	for _, profile := range []string{"sha1", "sha256"} {
		t.Run(profile, func(t *testing.T) {
			f := newFixtureWithFormat(t, profile)
			f.config.Revision = f.commit(f.valid(), "", true)
			if _, err := f.operatorBootstrap(diskOps{}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.config.StateDir, "high-water.json")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, bad := range []string{strings.Repeat("a", 104-len(f.config.Revision)), strings.ToUpper(f.config.Revision), f.config.Revision[:7], f.config.Revision[:len(f.config.Revision)-1], f.config.Revision + "a"} {
				var state stateRecord
				if err := json.Unmarshal(original, &state); err != nil {
					t.Fatal(err)
				}
				state.High.Revision = bad
				raw, err := json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				store := newFileStore(context.Background(), f.config.StateDir, f.files, profile)
				if high, err := store.read(); high != nil || !errors.Is(err, errTrust) {
					t.Fatalf("bad persisted revision accepted: %v", err)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(raw, after) {
					t.Fatal("refused state read changed evidence")
				}
				if err := os.WriteFile(path, original, 0600); err != nil {
					t.Fatal(err)
				}
				if high, err := store.read(); err != nil || high == nil || high.Revision != f.config.Revision {
					t.Fatalf("valid persisted revision control: %v", err)
				}
			}
		})
	}
}
