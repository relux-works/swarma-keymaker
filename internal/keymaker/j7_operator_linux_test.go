//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

const j7OperatorJournalPath = "/protected/generations"

var j7OperatorInstance = strings.Repeat("1", 32)

// The fixture is an owned scratch tree: a reconciled legacy store holding one
// active station binding and a published generation anchor, plus empty key,
// policy and input directories. Stages advance it with the code under test's
// neighbours (migrateJ7) or with the operator command itself.
type j7OperatorFixture struct {
	uid                                   uint32
	root, state, keyDir, policyDir, input string
	identity                              uint64
	head                                  j7Expectation
	schema                                int
}

func j7OperatorSetup(t *testing.T, stage string) *j7OperatorFixture {
	t.Helper()
	if os.Getuid() == 0 {
		t.Fatal("test requires an unprivileged runner")
	}
	uid := uint32(os.Getuid())
	root := t.TempDir()
	f := &j7OperatorFixture{uid: uid, root: root, state: filepath.Join(root, "state"), keyDir: filepath.Join(root, "key"), policyDir: filepath.Join(root, "policy"), input: filepath.Join(root, "input", "table.json")}
	if os.Chmod(root, 0700) != nil {
		t.Fatal("fixture root")
	}
	for _, d := range []string{f.state, f.keyDir, f.policyDir, filepath.Dir(f.input)} {
		if os.Mkdir(d, 0700) != nil {
			t.Fatal("fixture directory")
		}
	}
	if stage == "empty" {
		return f
	}
	dir, e := OpenDirectory(f.state, uid, 0700)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	lock, e := LockState(dir, uid)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	s, e := fixtureOpenStore(dir, uid)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	b, c := s.Register(fixtureOperator, fixtureOperator, fixtureBinding(uid+100))
	if c != "" {
		t.Fatal(c)
	}
	f.identity = b.Number
	if c := persistGenerationAnchor(t.Context(), s, generationAnchor{Path: j7OperatorJournalPath, Floor: gj.Floor{Hash: gj.ZeroHash}}); c != "" {
		t.Fatal("fixture anchor", c)
	}
	if stage == "schema4" || stage == "schema5" {
		if c := s.migrateJ7(t.Context(), j7Head(t, s), j7OperatorInstance, f.identity); c != "" {
			t.Fatal("fixture schema 4", c)
		}
		f.schema = j7Schema
	}
	if stage == "schema5" {
		if c := s.migrateJ7Signing(t.Context(), j7Head(t, s)); c != "" {
			t.Fatal("fixture schema 5", c)
		}
		f.schema = j7SigningSchema
	}
	f.head = j7Head(t, s)
	raw := j7PolicyRaw(t, f.table(1))
	if os.WriteFile(f.input, raw, 0600) != nil {
		t.Fatal("fixture policy input")
	}
	return f
}

func (f *j7OperatorFixture) table(version uint64) *j7PolicyTable {
	origin := j7OriginKey{Kind: "admission", Event: strings.Repeat("a", 64), Grant: strings.Repeat("b", 64)}
	return &j7PolicyTable{Format: "keymaker-j7-policy/1", Instance: j7OperatorInstance, Identity: f.identity, Version: version, Rows: []j7PolicyRow{{Origin: origin, Use: []string{strings.Repeat("d", 64)}, Delegate: []string{}, Consent: []j7ConsentPermission{}, Deny: []string{}}}}
}

// request returns the complete valid request of one command for this fixture.
func (f *j7OperatorFixture) request(command string) J7OperatorRequest {
	r := J7OperatorRequest{Command: command, ServiceUID: f.uid, StateDir: f.state}
	expected := func() {
		r.Schema, r.Expected, r.ExpectedVersion, r.ExpectedDigest = f.schema, true, f.head.Version, f.head.Digest
	}
	switch command {
	case J7OperatorSeedInit:
		r.KeyFile, r.Instance = filepath.Join(f.keyDir, "root"), j7OperatorInstance
	case J7OperatorMigrate:
		expected()
		r.Instance, r.Identity, r.GenerationJournal = j7OperatorInstance, f.identity, j7OperatorJournalPath
	case J7OperatorPolicyPublish:
		expected()
		r.Instance, r.Identity, r.PolicyFile, r.PolicyInput = j7OperatorInstance, f.identity, filepath.Join(f.policyDir, "table.json"), f.input
	case J7OperatorHead:
		expected()
	}
	return r
}

// j7OperatorTree is the complete observable content of a scratch tree: every
// entry name, type, permission and file digest.
func j7OperatorTree(t *testing.T, root string) string {
	t.Helper()
	var rows []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		row := fmt.Sprintf("%s %v", path, info.Mode())
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			row += fmt.Sprintf(" %x", sha256.Sum256(b))
		}
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}

func j7OperatorFixtureDeps() j7OperatorDeps { return j7OperatorDeps{clock: fixtureAuditClock{}} }

// Claim: every listed misuse of every stopped-operator command is refused with
// its exact code and detail and changes nothing on disk, and the unmodified
// request on the very same fixture then succeeds (the positive control).
func TestJ7OperatorRefusals(t *testing.T) {
	type row struct {
		name, command, stage string
		// plant turns the valid request or fixture into the negative and returns
		// the step that restores the fixture for the positive control.
		plant        func(*testing.T, *j7OperatorFixture, *J7OperatorRequest) func()
		code, detail string
	}
	none := func() {}
	request := func(change func(*j7OperatorFixture, *J7OperatorRequest)) func(*testing.T, *j7OperatorFixture, *J7OperatorRequest) func() {
		return func(_ *testing.T, f *j7OperatorFixture, r *J7OperatorRequest) func() { change(f, r); return none }
	}
	wrongUser := request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.ServiceUID++ })
	relativeState := request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.StateDir = "state" })
	// The lock is held exactly as a running service holds it: LockState on the
	// state directory, from another open file description.
	serviceLock := func(t *testing.T, f *j7OperatorFixture, _ *J7OperatorRequest) func() {
		dir, e := OpenDirectory(f.state, f.uid, 0700)
		if e != nil {
			t.Fatal(e)
		}
		lock, e := LockState(dir, f.uid)
		if e != nil {
			t.Fatal(e)
		}
		return func() { lock.Close(); dir.Close() }
	}
	wrongVersion := request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.ExpectedVersion++ })
	wrongDigest := request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.ExpectedDigest = strings.Repeat("f", 64) })
	schema := func(n int) func(*testing.T, *j7OperatorFixture, *J7OperatorRequest) func() {
		return request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.Schema = n })
	}
	const (
		user, userDetail = "role_not_permitted", "command runs only as the service user"
		locked           = "state_locked"
		lockedDetail     = "state already locked"
		malformed        = "request_malformed"
		pathDetail       = "path must be absolute and clean"
		fenced           = "j7_state_fenced"
		headDetail       = "J7 expected head mismatch"
		floorDetail      = "message schema floor mismatch"
		anchorCode       = "generation_source_fenced"
		anchorDetail     = "generation anchor unavailable"
	)
	seed, migrate, publish, head := J7OperatorSeedInit, J7OperatorMigrate, J7OperatorPolicyPublish, J7OperatorHead
	rows := []row{
		{"seed-init/wrong-user", seed, "legacy", wrongUser, user, userDetail},
		{"seed-init/service-lock", seed, "legacy", serviceLock, locked, lockedDetail},
		{"seed-init/relative-state", seed, "legacy", relativeState, malformed, pathDetail},
		{"seed-init/relative-key", seed, "legacy", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.KeyFile = "key/root" }), malformed, pathDetail},
		{"seed-init/unclean-key", seed, "legacy", request(func(f *j7OperatorFixture, r *J7OperatorRequest) { r.KeyFile = f.keyDir + "/../key/root" }), malformed, pathDetail},
		{"seed-init/key-inside-state", seed, "legacy", request(func(f *j7OperatorFixture, r *J7OperatorRequest) { r.KeyFile = filepath.Join(f.state, "root") }), malformed, "path must be outside the state directory"},
		{"seed-init/nested-key-inside-state", seed, "legacy", request(func(f *j7OperatorFixture, r *J7OperatorRequest) { r.KeyFile = filepath.Join(f.state, "nested", "root") }), malformed, "path must be outside the state directory"},
		{"seed-init/bad-instance", seed, "legacy", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.Instance = strings.Repeat("0", 32) }), malformed, "invalid seed arguments"},
		{"seed-init/existing-seed", seed, "legacy", func(t *testing.T, _ *j7OperatorFixture, r *J7OperatorRequest) func() {
			if os.WriteFile(r.KeyFile, []byte("planted existing record"), 0600) != nil {
				t.Fatal("plant seed")
			}
			return func() { os.Remove(r.KeyFile) }
		}, "j7_seed_exists", "existing seed is never replaced"},
		{"seed-init/existing-symlink", seed, "legacy", func(t *testing.T, _ *j7OperatorFixture, r *J7OperatorRequest) func() {
			if os.Symlink("/nonexistent", r.KeyFile) != nil {
				t.Fatal("plant link")
			}
			return func() { os.Remove(r.KeyFile) }
		}, "j7_seed_exists", "existing seed is never replaced"},
		{"seed-init/unsafe-key-directory", seed, "legacy", func(t *testing.T, f *j7OperatorFixture, _ *J7OperatorRequest) func() {
			if os.Chmod(f.keyDir, 0750) != nil {
				t.Fatal("plant mode")
			}
			return func() { os.Chmod(f.keyDir, 0700) }
		}, "j7_key_unavailable", "key custody unavailable"},

		{"migrate/wrong-user", migrate, "legacy", wrongUser, user, userDetail},
		{"migrate/service-lock", migrate, "legacy", serviceLock, locked, lockedDetail},
		{"migrate/relative-state", migrate, "legacy", relativeState, malformed, pathDetail},
		{"migrate/relative-journal", migrate, "legacy", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.GenerationJournal = "generations" }), malformed, pathDetail},
		{"migrate/missing-head", migrate, "legacy", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) {
			r.Expected, r.ExpectedVersion, r.ExpectedDigest = false, 0, ""
		}), malformed, "expected head required"},
		{"migrate/wrong-head-version", migrate, "legacy", wrongVersion, fenced, headDetail},
		{"migrate/wrong-head-digest", migrate, "legacy", wrongDigest, fenced, headDetail},
		{"migrate/wrong-source-schema-2", migrate, "legacy", schema(2), fenced, floorDetail},
		{"migrate/wrong-source-schema-4", migrate, "legacy", schema(4), fenced, floorDetail},
		{"migrate/unsupported-source-schema-5", migrate, "legacy", schema(5), malformed, "unsupported schema"},
		{"migrate/missing-anchor", migrate, "legacy", func(t *testing.T, f *j7OperatorFixture, _ *J7OperatorRequest) func() {
			from, to := filepath.Join(f.state, "generation.anchor"), filepath.Join(f.root, "anchor.aside")
			if os.Rename(from, to) != nil {
				t.Fatal("plant missing anchor")
			}
			return func() { os.Rename(to, from) }
		}, anchorCode, anchorDetail},
		{"migrate/interrupted-anchor", migrate, "legacy", func(t *testing.T, f *j7OperatorFixture, _ *J7OperatorRequest) func() {
			staged := filepath.Join(f.state, "generation.next")
			if os.WriteFile(staged, []byte("{}"), 0600) != nil {
				t.Fatal("plant staged anchor")
			}
			return func() { os.Remove(staged) }
		}, anchorCode, anchorDetail},
		{"migrate/anchor-names-other-journal", migrate, "legacy", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.GenerationJournal = "/protected/other" }), anchorCode, anchorDetail},
		{"migrate/unknown-identity", migrate, "legacy", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.Identity += 7 }), "binding_not_found", "migration to schema 4 refused"},
		{"migrate/bad-instance", migrate, "legacy", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.Instance = "not-hex" }), malformed, "invalid instance or identity"},
		{"migrate/unresolved-intent", migrate, "legacy", func(t *testing.T, f *j7OperatorFixture, _ *J7OperatorRequest) func() {
			staged := filepath.Join(f.state, "bindings.next")
			if os.WriteFile(staged, []byte("{}"), 0600) != nil {
				t.Fatal("plant intent")
			}
			return func() { os.Remove(staged) }
		}, fenced, "unresolved binding intent"},

		{"migrate-from-4/wrong-head", migrate, "schema4", wrongVersion, fenced, headDetail},
		{"migrate-from-4/wrong-source-schema-0", migrate, "schema4", schema(0), fenced, floorDetail},
		{"migrate-from-4/other-instance", migrate, "schema4", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.Instance = strings.Repeat("2", 32) }), fenced, "J7 pins mismatch"},
		{"migrate-from-4/other-identity", migrate, "schema4", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.Identity++ }), fenced, "J7 pins mismatch"},
		{"migrate-from-4/missing-anchor", migrate, "schema4", func(t *testing.T, f *j7OperatorFixture, _ *J7OperatorRequest) func() {
			from, to := filepath.Join(f.state, "generation.anchor"), filepath.Join(f.root, "anchor.aside")
			if os.Rename(from, to) != nil {
				t.Fatal("plant missing anchor")
			}
			return func() { os.Rename(to, from) }
		}, anchorCode, anchorDetail},

		{"policy-publish/non-holder", publish, "schema5", wrongUser, user, userDetail},
		{"policy-publish/service-lock", publish, "schema5", serviceLock, locked, lockedDetail},
		{"policy-publish/relative-state", publish, "schema5", relativeState, malformed, pathDetail},
		{"policy-publish/relative-policy-file", publish, "schema5", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.PolicyFile = "policy/table.json" }), malformed, pathDetail},
		{"policy-publish/relative-input", publish, "schema5", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.PolicyInput = "input/table.json" }), malformed, pathDetail},
		{"policy-publish/input-is-table", publish, "schema5", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.PolicyFile = r.PolicyInput }), malformed, "unexpected argument"},
		{"policy-publish/table-inside-state", publish, "schema5", request(func(f *j7OperatorFixture, r *J7OperatorRequest) { r.PolicyFile = filepath.Join(f.state, "table.json") }), malformed, "path must be outside the state directory"},
		{"policy-publish/missing-head", publish, "schema5", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) {
			r.Expected, r.ExpectedVersion, r.ExpectedDigest = false, 0, ""
		}), malformed, "expected head required"},
		{"policy-publish/wrong-head-version", publish, "schema5", wrongVersion, fenced, headDetail},
		{"policy-publish/wrong-head-digest", publish, "schema5", wrongDigest, fenced, headDetail},
		{"policy-publish/wrong-schema", publish, "schema5", schema(4), fenced, floorDetail},
		{"policy-publish/legacy-schema", publish, "schema5", schema(0), malformed, "unsupported schema"},
		{"policy-publish/unclosed-file", publish, "schema5", func(t *testing.T, f *j7OperatorFixture, _ *J7OperatorRequest) func() {
			good, _ := os.ReadFile(f.input)
			bad := bytes.Replace(good, []byte(`{"format"`), []byte(`{"extra":true,"format"`), 1)
			if bytes.Equal(good, bad) || os.WriteFile(f.input, bad, 0600) != nil {
				t.Fatal("plant member")
			}
			return func() { os.WriteFile(f.input, good, 0600) }
		}, malformed, "invalid policy file"},
		{"policy-publish/foreign-instance-file", publish, "schema5", func(t *testing.T, f *j7OperatorFixture, _ *J7OperatorRequest) func() {
			good, _ := os.ReadFile(f.input)
			table := f.table(1)
			table.Instance = strings.Repeat("2", 32)
			if os.WriteFile(f.input, j7PolicyRaw(t, table), 0600) != nil {
				t.Fatal("plant instance")
			}
			return func() { os.WriteFile(f.input, good, 0600) }
		}, malformed, "invalid policy file"},
		{"policy-publish/peer-writable-input", publish, "schema5", func(t *testing.T, f *j7OperatorFixture, _ *J7OperatorRequest) func() {
			if os.Chmod(f.input, 0660) != nil {
				t.Fatal("plant mode")
			}
			return func() { os.Chmod(f.input, 0600) }
		}, malformed, "policy input unavailable"},
		{"policy-publish/hardlinked-input", publish, "schema5", func(t *testing.T, f *j7OperatorFixture, r *J7OperatorRequest) func() {
			link := filepath.Join(filepath.Dir(f.input), "other.json")
			if os.Link(f.input, link) != nil {
				t.Fatal("plant hardlink")
			}
			return func() { os.Remove(link) }
		}, malformed, "policy input unavailable"},
		{"policy-publish/writable-input-ancestry", publish, "schema5", func(t *testing.T, f *j7OperatorFixture, r *J7OperatorRequest) func() {
			dir := filepath.Dir(f.input)
			if os.Chmod(dir, 0770) != nil {
				t.Fatal("plant ancestry")
			}
			return func() { os.Chmod(dir, 0700) }
		}, malformed, "policy input unavailable"},
		{"policy-publish/symlink-input", publish, "schema5", func(t *testing.T, f *j7OperatorFixture, r *J7OperatorRequest) func() {
			link := filepath.Join(filepath.Dir(f.input), "link.json")
			if os.Symlink(f.input, link) != nil {
				t.Fatal("plant link")
			}
			r.PolicyInput = link
			return func() { os.Remove(link) }
		}, malformed, "policy input unavailable"},
		{"policy-publish/other-identity", publish, "schema5", func(t *testing.T, f *j7OperatorFixture, r *J7OperatorRequest) func() {
			good, _ := os.ReadFile(f.input)
			table := f.table(1)
			table.Identity++
			r.Identity++
			if os.WriteFile(f.input, j7PolicyRaw(t, table), 0600) != nil {
				t.Fatal("plant identity")
			}
			return func() { os.WriteFile(f.input, good, 0600) }
		}, "j7_policy_unavailable", "J7 policy pins unavailable"},
		{"policy-publish/unsafe-policy-directory", publish, "schema5", func(t *testing.T, f *j7OperatorFixture, _ *J7OperatorRequest) func() {
			if os.Chmod(f.policyDir, 0750) != nil {
				t.Fatal("plant mode")
			}
			return func() { os.Chmod(f.policyDir, 0700) }
		}, "j7_policy_unavailable", "unsafe policy holder"},

		{"head/wrong-user", head, "schema5", wrongUser, user, userDetail},
		{"head/service-lock", head, "schema5", serviceLock, locked, lockedDetail},
		{"head/relative-state", head, "schema5", relativeState, malformed, pathDetail},
		{"head/wrong-head-version", head, "schema5", wrongVersion, fenced, headDetail},
		{"head/wrong-head-digest", head, "schema5", wrongDigest, fenced, headDetail},
		{"head/half-head", head, "schema5", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.Expected = false }), malformed, "invalid expected head"},
		{"head/wrong-schema-4", head, "schema5", schema(4), fenced, floorDetail},
		{"head/wrong-schema-0", head, "schema5", schema(0), fenced, floorDetail},
		{"head/unsupported-schema-6", head, "schema5", schema(6), malformed, "unsupported schema"},
		{"head/unsafe-state-mode", head, "schema5", func(t *testing.T, f *j7OperatorFixture, _ *J7OperatorRequest) func() {
			if os.Chmod(f.state, 0750) != nil {
				t.Fatal("plant mode")
			}
			return func() { os.Chmod(f.state, 0700) }
		}, "state_unavailable", "unsafe directory ownership or mode"},
		{"head/extra-argument", head, "schema5", request(func(_ *j7OperatorFixture, r *J7OperatorRequest) { r.Instance = j7OperatorInstance }), malformed, "unexpected argument"},
		{"head-legacy/wrong-schema-2", head, "legacy", schema(2), fenced, floorDetail},
		{"unknown-command", "j7 export-seed", "legacy", request(func(*j7OperatorFixture, *J7OperatorRequest) {}), malformed, "unknown command"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			f := j7OperatorSetup(t, row.stage)
			control := row.command
			if row.name == "unknown-command" {
				control = J7OperatorHead
			}
			negative := f.request(row.command)
			if row.name == "unknown-command" {
				negative = f.request(control)
				negative.Command = row.command
			}
			restore := row.plant(t, f, &negative)
			before := j7OperatorTree(t, f.root)
			got := runJ7Operator(t.Context(), negative, j7OperatorFixtureDeps())
			if got.Outcome != "refused" || got.Refusal != row.code || got.Detail != row.detail {
				t.Fatalf("negative: want %s/%q, got %+v", row.code, row.detail, got)
			}
			if after := j7OperatorTree(t, f.root); after != before {
				t.Fatalf("refusal had an effect:\n%s\n--- after ---\n%s", before, after)
			}
			// A refusal reports either no head or exactly the unchanged one.
			if got.Version != 0 && (got.Version != f.head.Version || got.Digest != f.head.Digest) {
				t.Fatalf("refusal reported a foreign head %+v", got)
			}
			restore()
			positive := runJ7Operator(t.Context(), f.request(control), j7OperatorFixtureDeps())
			if positive.Outcome != "ok" || positive.Refusal != "" || positive.Detail != "" {
				t.Fatalf("positive control refused: %+v", positive)
			}
			if after := j7OperatorTree(t, f.root); control != J7OperatorHead && after == before {
				t.Fatal("positive control had no effect")
			}
		})
	}
}

// Claim: no operator command initializes binding state: on an empty state
// directory head and migrate refuse and create nothing, while the same requests
// on a reconciled legacy store succeed (the positive control).
func TestJ7OperatorNeverInitializes(t *testing.T) {
	for _, command := range []string{J7OperatorHead, J7OperatorMigrate} {
		empty, legacy := j7OperatorSetup(t, "empty"), j7OperatorSetup(t, "legacy")
		r := legacy.request(command)
		r.StateDir = empty.state
		before := j7OperatorTree(t, empty.root)
		got := runJ7Operator(t.Context(), r, j7OperatorFixtureDeps())
		if got.Outcome != "refused" || got.Refusal != "j7_state_fenced" || got.Detail != "binding snapshot unavailable" || got.Version != 0 || got.Digest != "" {
			t.Fatalf("%s: empty directory was not refused: %+v", command, got)
		}
		if j7OperatorTree(t, empty.root) != before {
			t.Fatal(command, "refusal created state")
		}
		if got := runJ7Operator(t.Context(), legacy.request(command), j7OperatorFixtureDeps()); got.Outcome != "ok" {
			t.Fatalf("%s: positive control refused: %+v", command, got)
		}
	}
}

// Claim: `j7 head` is a read-only export: it reports exactly the independently
// computed version and digest for every supported schema, with and without an
// expectation, and leaves every byte of the tree unchanged.
func TestJ7OperatorHeadExport(t *testing.T) {
	for _, stage := range []string{"legacy", "schema4", "schema5"} {
		f := j7OperatorSetup(t, stage)
		before := j7OperatorTree(t, f.root)
		for _, expected := range []bool{true, false} {
			r := f.request(J7OperatorHead)
			if !expected {
				r.Expected, r.ExpectedVersion, r.ExpectedDigest = false, 0, ""
			}
			got := runJ7Operator(t.Context(), r, j7OperatorFixtureDeps())
			want := J7OperatorResult{Command: J7OperatorHead, Outcome: "ok", Schema: f.schema, Version: f.head.Version, Digest: f.head.Digest}
			if got != want {
				t.Fatalf("%s: head export differs: %+v", stage, got)
			}
		}
		if j7OperatorTree(t, f.root) != before {
			t.Fatal(stage, "head export changed the tree")
		}
	}
}

// Claim: migrate takes a reconciled schema-0 store (or resumes from schema 4)
// to schema 5 in place: the binding and the generation.anchor bytes are carried
// unchanged, the anchor still loads for the named journal, and the reported
// head is exactly the one the service's own opener then requires; a head one
// version off is refused by that opener (the negative beside the positive).
func TestJ7OperatorMigrateCarriesAnchor(t *testing.T) {
	for _, stage := range []string{"legacy", "schema4"} {
		f := j7OperatorSetup(t, stage)
		anchor, e := os.ReadFile(filepath.Join(f.state, "generation.anchor"))
		if e != nil {
			t.Fatal(e)
		}
		got := runJ7Operator(t.Context(), f.request(J7OperatorMigrate), j7OperatorFixtureDeps())
		steps := uint64(2)
		if stage == "schema4" {
			steps = 1
		}
		if got.Outcome != "ok" || got.Schema != j7SigningSchema || got.Version != f.head.Version+steps || !validDigest(got.Digest) {
			t.Fatalf("%s: migration result: %+v", stage, got)
		}
		if after, e := os.ReadFile(filepath.Join(f.state, "generation.anchor")); e != nil || !bytes.Equal(after, anchor) {
			t.Fatal(stage, "anchor was not carried byte-for-byte")
		}
		dir, e := OpenDirectory(f.state, f.uid, 0700)
		if e != nil {
			t.Fatal(e)
		}
		defer dir.Close()
		lock, e := LockState(dir, f.uid)
		if e != nil {
			t.Fatal("operator command kept the state lock", e)
		}
		defer lock.Close()
		if s, e := openJ7SigningStore(dir, f.uid, fixtureAuditClock{}, j7Expectation{got.Version - 1, got.Digest}); e == nil {
			s.Close()
			t.Fatal(stage, "stale head opened the migrated store")
		}
		s, e := openJ7SigningStore(dir, f.uid, fixtureAuditClock{}, j7Expectation{got.Version, got.Digest})
		if e != nil {
			t.Fatal(stage, "reported head does not open the migrated store", e)
		}
		defer s.Close()
		loaded, damaged := loadGenerationAnchor(s, j7OperatorJournalPath, gj.Floor{})
		if damaged || loaded.Path != j7OperatorJournalPath {
			t.Fatal(stage, "migrated store is fenced from its generation journal")
		}
		if s.j7.Instance != j7OperatorInstance || s.j7.Identity != f.identity || s.j7.BaseSchema != 0 || len(s.records) != 1 || s.records[0].Number != f.identity || s.records[0].Status != "active" {
			t.Fatal(stage, "migration changed the carried binding or pins")
		}
		// A second migration of the migrated store refuses and changes nothing.
		before := j7OperatorTree(t, f.root)
		s.Close()
		lock.Close()
		again := f.request(J7OperatorMigrate)
		again.ExpectedVersion, again.ExpectedDigest = got.Version, got.Digest
		if r := runJ7Operator(t.Context(), again, j7OperatorFixtureDeps()); r.Outcome != "refused" || r.Refusal != "j7_state_fenced" || j7OperatorTree(t, f.root) != before {
			t.Fatalf("%s: repeated migration: %+v", stage, r)
		}
	}
}

// Claim: policy-publish installs exactly the input bytes as the table the
// service reads and advances the head it reports; an older table is then
// refused without changing the table or the head, while republishing the
// current bytes is the idempotent positive.
func TestJ7OperatorPolicyPublish(t *testing.T) {
	for _, stage := range []string{"schema4", "schema5"} {
		f := j7OperatorSetup(t, stage)
		r := f.request(J7OperatorPolicyPublish)
		for version := uint64(2); version >= 1; version-- {
			// Version 2 first, so that version 1 is the rollback negative.
			if os.WriteFile(f.input, j7PolicyRaw(t, f.table(version)), 0600) != nil {
				t.Fatal("policy input")
			}
			before, _ := os.ReadFile(r.PolicyFile)
			got := runJ7Operator(t.Context(), r, j7OperatorFixtureDeps())
			if version == 2 {
				table, e := os.ReadFile(r.PolicyFile)
				if got.Outcome != "ok" || got.Schema != f.schema || got.Version != f.head.Version+2 || e != nil || !bytes.Equal(table, j7PolicyRaw(t, f.table(2))) {
					t.Fatalf("%s: publication: %+v", stage, got)
				}
				same := r
				same.ExpectedVersion, same.ExpectedDigest = got.Version, got.Digest
				if again := runJ7Operator(t.Context(), same, j7OperatorFixtureDeps()); again.Outcome != "ok" || again.Version != got.Version || again.Digest != got.Digest {
					t.Fatalf("%s: idempotent publication: %+v", stage, again)
				}
				// The pre-publication head is now stale for the next command.
				if stale := runJ7Operator(t.Context(), r, j7OperatorFixtureDeps()); stale.Refusal != "j7_state_fenced" || stale.Detail != "J7 expected head mismatch" {
					t.Fatalf("%s: stale head after publication: %+v", stage, stale)
				}
				r = same
				continue
			}
			after, _ := os.ReadFile(r.PolicyFile)
			if got.Outcome != "refused" || got.Refusal != "GRANT_NOT_FOR_RUN" || got.Version != r.ExpectedVersion || got.Digest != r.ExpectedDigest || !bytes.Equal(before, after) {
				t.Fatalf("%s: rollback publication: %+v", stage, got)
			}
		}
	}
}

// Claim: the whole procedure works through the production entry (no time
// source, so commits are untimed), every result has exactly the closed member
// set, and neither the results nor their JSON contain the generated seed in
// raw, hex or base64 form; the seed itself is a loadable request-role record
// (the positive control that the searched-for secret really exists).
func TestJ7OperatorProductionFlowNoSecret(t *testing.T) {
	f := j7OperatorSetup(t, "legacy")
	var transcript bytes.Buffer
	run := func(r J7OperatorRequest) J7OperatorResult {
		t.Helper()
		got := RunJ7Operator(context.Background(), r)
		line, e := json.Marshal(got)
		if e != nil {
			t.Fatal(e)
		}
		var members map[string]json.RawMessage
		if json.Unmarshal(line, &members) != nil || len(members) != 7 {
			t.Fatalf("result is not the closed member set: %s", line)
		}
		for _, name := range []string{"command", "outcome", "refusal", "detail", "state_schema", "head_version", "head_digest"} {
			if _, ok := members[name]; !ok {
				t.Fatalf("result lacks %s: %s", name, line)
			}
		}
		transcript.Write(line)
		transcript.WriteString(fmt.Sprintf("%v %+v %#v\n", got, got, got))
		if got.Outcome != "ok" {
			t.Fatalf("production flow refused: %s", line)
		}
		return got
	}
	seedRequest := f.request(J7OperatorSeedInit)
	if got := run(seedRequest); got.Schema != 0 || got.Version != 0 || got.Digest != "" {
		t.Fatal("seed-init reported state", got)
	}
	// A second initialization refuses and leaves the record untouched.
	record, e := os.ReadFile(seedRequest.KeyFile)
	if e != nil || len(record) < 32 {
		t.Fatal("seed record", e)
	}
	again := RunJ7Operator(context.Background(), seedRequest)
	if now, _ := os.ReadFile(seedRequest.KeyFile); again.Refusal != "j7_seed_exists" || !bytes.Equal(now, record) {
		t.Fatalf("existing seed: %+v", again)
	}
	line, _ := json.Marshal(again)
	transcript.Write(line)
	migrated := run(f.request(J7OperatorMigrate))
	f.schema, f.head = migrated.Schema, j7Expectation{migrated.Version, migrated.Digest}
	published := run(f.request(J7OperatorPolicyPublish))
	f.head = j7Expectation{published.Version, published.Digest}
	if exported := run(f.request(J7OperatorHead)); exported.Version != published.Version || exported.Digest != published.Digest || exported.Schema != j7SigningSchema {
		t.Fatal("exported head differs from the published head", exported)
	}
	key, e := loadJ7Key(seedRequest.KeyFile, f.uid, j7RequestRole, j7OperatorInstance, "fixture-epoch", "fixture-revision")
	if e != nil {
		t.Fatal("initialized seed does not load", e)
	}
	key.close()
	seed := record[len(record)-32:]
	header := []byte(j7SeedMagic + j7RequestRole + "\n" + j7OperatorInstance + "\n")
	if !bytes.Equal(record[:len(record)-32], header) || bytes.Equal(seed, make([]byte, 32)) {
		t.Fatal("seed record is not the closed request-role record")
	}
	for name, needle := range map[string][]byte{
		"raw":       seed,
		"hex":       []byte(hex.EncodeToString(seed)),
		"base64":    []byte(base64.StdEncoding.EncodeToString(seed)),
		"base64url": []byte(base64.RawURLEncoding.EncodeToString(seed)),
		"half":      []byte(hex.EncodeToString(seed[:16])),
	} {
		if bytes.Contains(transcript.Bytes(), needle) {
			t.Fatal("operator output contains the seed as", name)
		}
	}
	// Control for the search itself: the same needles are found where the
	// seed really is.
	if !bytes.Contains(record, seed) || !bytes.Contains([]byte(hex.EncodeToString(record)), []byte(hex.EncodeToString(seed))) {
		t.Fatal("secret search control failed")
	}
}

// Claim: a schema-2 source keeps its message participant through the operator
// migration (base schema 2, same message inventory bytes), and the same store
// declared as schema 0 is refused first with no effect (the negative beside it).
func TestJ7OperatorMigrateFromMessageSchema(t *testing.T) {
	m := messageStateSetup(t)
	if c := persistGenerationAnchor(t.Context(), m.store, generationAnchor{Path: j7OperatorJournalPath, Floor: gj.Floor{Hash: gj.ZeroHash}}); c != "" {
		t.Fatal("fixture anchor", c)
	}
	head := j7Head(t, m.store)
	messages, e := canonical(m.store.messages)
	if e != nil {
		t.Fatal(e)
	}
	if e := m.store.Close(); e != nil {
		t.Fatal(e)
	}
	uid := uint32(os.Getuid())
	r := J7OperatorRequest{Command: J7OperatorMigrate, ServiceUID: uid, StateDir: m.path, Schema: 0, Expected: true, ExpectedVersion: head.Version, ExpectedDigest: head.Digest, Instance: j7OperatorInstance, Identity: m.binding.Number, GenerationJournal: j7OperatorJournalPath}
	before := j7OperatorTree(t, m.path)
	if got := runJ7Operator(t.Context(), r, j7OperatorFixtureDeps()); got.Refusal != "j7_state_fenced" || got.Detail != "message schema floor mismatch" || j7OperatorTree(t, m.path) != before {
		t.Fatalf("schema-2 store migrated as schema 0: %+v", got)
	}
	r.Schema = 2
	got := runJ7Operator(t.Context(), r, j7OperatorFixtureDeps())
	if got.Outcome != "ok" || got.Schema != j7SigningSchema || got.Version != head.Version+2 {
		t.Fatalf("schema-2 migration: %+v", got)
	}
	lock, e := LockState(m.dir, uid)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	s, e := openJ7SigningStore(m.dir, uid, fixtureAuditClock{}, j7Expectation{got.Version, got.Digest})
	if e != nil {
		t.Fatal("reported head does not open the migrated store", e)
	}
	defer s.Close()
	after, e := canonical(s.messages)
	if e != nil || s.j7.BaseSchema != 2 || !bytes.Equal(after, messages) {
		t.Fatal("migration lost the message participant")
	}
}

// Claim: a sealed audit tail is read without creating the next segment, even
// when migration is refused for a missing anchor; a valid migration then opens
// a new segment only when it commits. All fixtures are stopped and reconciled.
func TestJ7OperatorSealedTail(t *testing.T) {
	f := j7OperatorSetup(t, "legacy")
	dir, err := OpenDirectory(f.state, f.uid, 0700)
	if err != nil {
		t.Fatal(err)
	}
	s, _, _, err := openCustodyStateMessage(dir, f.uid, fixtureAuditClock{}, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	seal, err := canonical(auditSeal{s.journal.first, s.journal.seq, s.journal.previous})
	name := filepath.Join(f.state, "audit", auditName(s.journal.segment)+".seal")
	if err != nil || s.Close() != nil || dir.Close() != nil || os.WriteFile(name, seal, 0600) != nil {
		t.Fatal("seal fixture")
	}
	before := j7OperatorTree(t, f.root)
	if got := RunJ7Operator(t.Context(), f.request(J7OperatorHead)); got.Outcome != "ok" || got.Version != f.head.Version || got.Digest != f.head.Digest {
		t.Fatalf("sealed head: %+v", got)
	}
	if j7OperatorTree(t, f.root) != before {
		t.Fatal("head export created or changed audit evidence")
	}
	anchor := filepath.Join(f.state, "generation.anchor")
	aside := filepath.Join(f.root, "anchor.aside")
	if os.Rename(anchor, aside) != nil {
		t.Fatal("plant missing anchor")
	}
	before = j7OperatorTree(t, f.root)
	if got := RunJ7Operator(t.Context(), f.request(J7OperatorMigrate)); got.Refusal != "generation_source_fenced" {
		t.Fatalf("anchor refusal: %+v", got)
	}
	if j7OperatorTree(t, f.root) != before {
		t.Fatal("anchor refusal created or changed audit evidence")
	}
	if os.Rename(aside, anchor) != nil {
		t.Fatal("restore anchor")
	}
	if got := RunJ7Operator(t.Context(), f.request(J7OperatorMigrate)); got.Outcome != "ok" || got.Schema != 5 {
		t.Fatalf("sealed migration control: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(f.state, "audit", auditName(2))); err != nil {
		t.Fatal("valid commit did not open the next audit segment", err)
	}
}

// Claim: the service opener keeps its eager writer at a sealed tail; only
// stopped-operator replay defers creation. This is not a service lifecycle test.
func TestJ7OperatorServiceOpenStaysEager(t *testing.T) {
	f := j7OperatorSetup(t, "legacy")
	dir, err := OpenDirectory(f.state, f.uid, 0700)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	s, _, _, err := openCustodyStateMessage(dir, f.uid, fixtureAuditClock{}, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	seal, err := canonical(auditSeal{s.journal.first, s.journal.seq, s.journal.previous})
	name := filepath.Join(f.state, "audit", auditName(s.journal.segment)+".seal")
	if err != nil || s.Close() != nil || os.WriteFile(name, seal, 0600) != nil {
		t.Fatal("seal fixture")
	}
	next := filepath.Join(f.state, "audit", auditName(2))
	if _, err := os.Stat(next); !os.IsNotExist(err) {
		t.Fatal("next segment already present")
	}
	s, _, _, err = openCustodyStateMessage(dir, f.uid, fixtureAuditClock{}, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.journal.file == nil || s.journal.writer == nil || s.journal.deferredWriter {
		t.Fatal("service writer was deferred")
	}
	if _, err := os.Stat(next); err != nil {
		t.Fatal("service open did not create the next segment", err)
	}
}

// Claim: no arbitrary command, error string or Code can be reflected as secret
// diagnostic text, beside a recognized fixed diagnostic and command control.
func TestJ7OperatorOpaqueDiagnostics(t *testing.T) {
	const payload = "fixture-private-payload"
	for _, err := range []error{errors.New("keymaker: " + payload), Code(payload), errors.New(payload)} {
		if got := j7OperatorDetail(err); got != "unavailable" {
			t.Fatal("error payload reflected")
		}
	}
	if got := j7OperatorDetail(failure("state already locked")); got != "state already locked" {
		t.Fatal("fixed diagnostic lost")
	}
	f := j7OperatorSetup(t, "legacy")
	r := f.request(J7OperatorHead)
	r.Command = payload
	got := RunJ7Operator(t.Context(), r)
	raw, _ := json.Marshal(got)
	if got.Refusal != "request_malformed" || got.Command != "" || bytes.Contains(raw, []byte(payload)) {
		t.Fatal("unknown command reflected")
	}
	if got := RunJ7Operator(t.Context(), f.request(J7OperatorHead)); got.Outcome != "ok" {
		t.Fatalf("head control: %+v", got)
	}
}

// Claim: unknown signing handoff fences read-only export and policy publication
// despite matching snapshot/journal heads. The released neighbor remains usable.
// Fixture signing is local, not a native or distinct-UID qualification.
func TestJ7OperatorUnknownHandoff(t *testing.T) {
	for _, release := range []string{"handoff_unknown", "released"} {
		t.Run(release, func(t *testing.T) {
			f := j7SigningSetup(t)
			c := f.dial(t, 1)
			f.bind(t, c, 2, f.f.origin, f.f.uid+200)
			j7ResultEvent(t, j7Call(t, c, 3, "j7_sign", f.consent(t), ""))
			// The release callback may have delivered bytes before its final
			// commit; acquire the Store gate before stopping the fixture.
			f.f.store.mu.Lock()
			rec := f.f.store.j7SigningRecord(f.a.launcher, nativeID(3))
			if rec == nil {
				t.Fatal("missing actual signing record")
			}
			rec.Release = release
			code := f.f.store.commitJ7(t.Context())
			expected := j7Head(t, f.f.store)
			f.f.store.mu.Unlock()
			if code != "" {
				t.Fatal("fixture commit", code)
			}
			c.Close()
			f.stop()
			<-f.done
			if f.f.store.Close() != nil {
				t.Fatal("fixture close")
			}
			f.f.store = nil
			if err := f.f.lock.Close(); err != nil {
				t.Fatal(err)
			}
			root := filepath.Dir(f.f.path)
			input := filepath.Join(root, "operator-input.json")
			raw, err := f.f.policy.read()
			if err != nil || os.WriteFile(input, raw, 0600) != nil {
				t.Fatal("policy input fixture", err)
			}
			for _, command := range []string{J7OperatorHead, J7OperatorPolicyPublish} {
				r := J7OperatorRequest{Command: command, ServiceUID: f.f.uid, StateDir: f.f.path, Schema: 5, Expected: true, ExpectedVersion: expected.Version, ExpectedDigest: expected.Digest}
				if command == J7OperatorPolicyPublish {
					r.Instance, r.Identity = j7OperatorInstance, f.f.binding.Number
					r.PolicyInput, r.PolicyFile = input, filepath.Join(root, "policy", "table.json")
				}
				before := j7OperatorTree(t, root)
				got := RunJ7Operator(t.Context(), r)
				if release == "handoff_unknown" {
					if got.Refusal != "j7_state_fenced" || got.Detail != "unknown signing handoff" || got.Version != 0 || got.Digest != "" {
						t.Fatalf("unknown handoff exported: %+v", got)
					}
				} else if got.Outcome != "ok" || got.Version != expected.Version || got.Digest != expected.Digest {
					t.Fatalf("released control: %+v", got)
				}
				if j7OperatorTree(t, root) != before {
					t.Fatal("operator command changed evidence")
				}
			}
		})
	}
}

// Claim: both migration entry schemas require the station's binding to remain
// active. Real revoke/unbind transitions are refused without migration effects;
// a fresh active binding at the same source schema migrates successfully.
func TestJ7OperatorRetiredStation(t *testing.T) {
	for _, stage := range []string{"legacy", "schema4"} {
		for _, status := range []string{"revoked", "unbound", "active"} {
			t.Run(stage+"/"+status, func(t *testing.T) {
				f := j7OperatorSetup(t, stage)
				dir, err := OpenDirectory(f.state, f.uid, 0700)
				if err != nil {
					t.Fatal(err)
				}
				lock, err := LockState(dir, f.uid)
				if err != nil {
					t.Fatal(err)
				}
				s, _, _, err := openCustodyStateMessage(dir, f.uid, fixtureAuditClock{}, f.schema, false, f.head)
				if err != nil {
					t.Fatal(err)
				}
				var code Code
				if status == "revoked" {
					code = s.Revoke(t.Context(), fixtureOperator, fixtureOperator, f.identity, approvedAct{})
				}
				if status == "unbound" {
					code = s.Unbind(fixtureOperator, fixtureOperator, s.records[0].UID, s.records[0].Generation)
				}
				if code != "" {
					t.Fatal("fixture transition", code)
				}
				f.head = j7Head(t, s)
				if s.Close() != nil || lock.Close() != nil || dir.Close() != nil {
					t.Fatal("fixture close")
				}
				before := j7OperatorTree(t, f.root)
				got := RunJ7Operator(t.Context(), f.request(J7OperatorMigrate))
				if status != "active" {
					if got.Refusal != "binding_not_found" || got.Outcome != "refused" {
						t.Fatalf("retired station migrated: %+v", got)
					}
					if j7OperatorTree(t, f.root) != before {
						t.Fatal("retired-station refusal changed evidence")
					}
				} else if got.Outcome != "ok" || got.Schema != 5 {
					t.Fatalf("active station control: %+v", got)
				}
			})
		}
	}
}
