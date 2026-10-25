package enrollment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/registry"
)

// An external fixture decision admits one EXACT high-water value, never any
// readable local file. This models the reconciler boundary, not production
// qualification of backup freshness or an external revocation source.
type exactReconciler struct{ expected *registry.HighWater }

func (r exactReconciler) Check(_ context.Context, h *registry.HighWater) error {
	if !reflect.DeepEqual(h, r.expected) {
		return errTrust
	}
	return nil
}

type failingOps struct {
	diskOps
	stage string
}

func (o failingOps) Sync(f *os.File) error {
	if o.stage == "file-sync" && strings.HasPrefix(filepath.Base(f.Name()), ".high-water-") {
		return errors.New("injected file sync failure")
	}
	return o.diskOps.Sync(f)
}
func (o failingOps) Rename(old, next string) error {
	if o.stage == "rename" {
		return errors.New("injected rename failure")
	}
	return o.diskOps.Rename(old, next)
}
func (o failingOps) SyncDir(path string) error {
	if o.stage == "directory-sync" {
		return errors.New("injected directory sync failure")
	}
	return o.diskOps.SyncDir(path)
}

// Every monotonicity refusal goes through signed descendant Git objects and the
// registrar loader. No separate Keymaker sequence/tombstone validator exists.
func TestRegistryRollbackRefusals(t *testing.T) {
	for _, name := range []string{"lower-sequence", "equal-sequence-different-id", "vanished-host", "resurrected-tombstone"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			initial := f.valid()
			if name == "lower-sequence" {
				body := baseBody()
				body["seq"] = int64(2)
				initial = append(initial, registry.Entry{Path: "enrollments/2.json", Bytes: signedRecord(t, body, 1)})
			}
			if name == "vanished-host" {
				f.config.Stations["other"] = true
				body := baseBody()
				body["host"] = "other"
				body["names"] = map[string]any{"prefix": "other_", "explicit": []any{}}
				body["keys"].([]any)[0].(map[string]any)["key"] = public(3)
				body["uid_map"] = []any{map[string]any{"uid": int64(30002), "names": []any{"other_core_worker"}}}
				initial = append(initial, registry.Entry{Path: "enrollments/other.json", Bytes: signedRecord(t, body, 1)})
			}
			if name == "resurrected-tombstone" {
				body := baseBody()
				body["state"] = "revoked"
				initial[0].Bytes = signedRecord(t, body, 1)
			}
			first := f.commit(initial, "", true)
			f.config.Revision = first
			a := f.authority()
			expectCode(t, OK, a.Reload(context.Background()))
			before := a.retained.Clone()
			candidate := append([]registry.Entry{}, initial...)
			switch name {
			case "lower-sequence", "vanished-host":
				candidate = candidate[:1]
			case "equal-sequence-different-id":
				body := baseBody()
				body["keys"].([]any)[0].(map[string]any)["key"] = public(3)
				candidate[0].Bytes = signedRecord(t, body, 1)
			case "resurrected-tombstone":
				body := baseBody()
				body["seq"] = int64(2)
				candidate = append(candidate, registry.Entry{Path: "enrollments/2.json", Bytes: signedRecord(t, body, 1)})
			}
			f.config.Revision = f.commit(candidate, first, true)
			f.writeConfig()
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			result, code := authorize(a)
			expectCode(t, EnrollmentUnverified, code)
			if result.Key != "" {
				t.Fatal("rollback returned authority")
			}
			store := newFileStore(context.Background(), f.config.StateDir, f.files, f.config.ObjectFormat)
			after, err := store.read()
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("rollback modified high-water state")
			}
			// Same valid history, new descendant commit is a positive reload control.
			f.config.Revision = f.commit(initial, first, true)
			f.writeConfig()
			expectCode(t, OK, a.Reload(context.Background()))
			_, code = authorize(a)
			if name == "resurrected-tombstone" {
				expectCode(t, HostRevoked, code)
			} else {
				expectCode(t, OK, code)
			}
		})
	}
}

// Empty state always refuses in the service; explicit operator publication and
// exact reconciliation admit. Missing accepted state remains fenced on restart.
func TestExplicitFirstUseAndMissingState(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	f.writeConfig()
	a := New(f.configPath, f.files, nil)
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	a = f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, OK, code)
	high := a.retained.Clone()
	statePath := filepath.Join(f.config.StateDir, "high-water.json")
	saved, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	_, code = authorize(a)
	expectCode(t, EnrollmentUnverified, code)
	restarted := New(f.configPath, f.files, exactReconciler{high})
	expectCode(t, EnrollmentUnverified, restarted.Reload(context.Background()))
	if err = os.WriteFile(statePath, saved, 0600); err != nil {
		t.Fatal(err)
	}
	expectCode(t, OK, restarted.Reload(context.Background()))
}

// Readability and a valid local digest do not attest restart freshness. A fixture
// external decision matching the complete retained state is the positive control.
func TestRestartRequiresReconciliation(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	missing := New(f.configPath, f.files, nil)
	expectCode(t, EnrollmentUnverified, missing.Reload(context.Background()))
	_, code := authorize(missing)
	expectCode(t, EnrollmentUnverified, code)
	wrong := a.retained.Clone()
	wrong.Revision = strings.Repeat("f", 40)
	restarted := New(f.configPath, f.files, exactReconciler{wrong})
	expectCode(t, EnrollmentUnverified, restarted.Reload(context.Background()))
	restarted = New(f.configPath, f.files, exactReconciler{a.retained.Clone()})
	expectCode(t, OK, restarted.Reload(context.Background()))
	_, code = authorize(restarted)
	expectCode(t, OK, code)
}

// Corrupt, missing-marker and restored older high-water files fence admission;
// replacing exact known state is a positive control, not an inferred bootstrap.
func TestCorruptAndRestoredHighWater(t *testing.T) {
	for _, name := range []string{"corrupt", "missing-marker", "restored-old"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			entries := f.valid()
			first := f.commit(entries, "", true)
			f.config.Revision = first
			a := f.authority()
			expectCode(t, OK, a.Reload(context.Background()))
			path := filepath.Join(f.config.StateDir, "high-water.json")
			old, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			body := baseBody()
			body["seq"] = int64(2)
			entries = append(entries, registry.Entry{Path: "enrollments/2.json", Bytes: signedRecord(t, body, 1)})
			f.config.Revision = f.commit(entries, first, true)
			f.writeConfig()
			expectCode(t, OK, a.Reload(context.Background()))
			current, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "corrupt":
				err = os.WriteFile(path, []byte(`{"version":1,"high_water":null}`), 0600)
			case "missing-marker":
				err = os.Remove(filepath.Join(f.config.StateDir, "accepted"))
			case "restored-old":
				err = os.WriteFile(path, old, 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			_, code := authorize(a)
			expectCode(t, EnrollmentUnverified, code)
			if name == "restored-old" {
				restarted := New(f.configPath, f.files, exactReconciler{a.retained.Clone()})
				expectCode(t, EnrollmentUnverified, restarted.Reload(context.Background()))
			}
			if err = os.WriteFile(path, current, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(f.config.StateDir, "accepted"), []byte(acceptedMarker), 0600); err != nil {
				t.Fatal(err)
			}
			expectCode(t, OK, a.Reload(context.Background()))
			_, code = authorize(a)
			expectCode(t, OK, code)
		})
	}
}

// A stale CAS cannot overwrite accepted state; a matching previous value commits
// durably. This checks cross-instance locking/CAS, not hostile filesystem writes.
func TestStoreCompareAndSwap(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	before := a.retained.Clone()
	next := before.Clone()
	next.Revision = strings.Repeat("f", 40)
	stale := newFileStore(context.Background(), f.config.StateDir, f.files, f.config.ObjectFormat)
	if stale.Commit(nil, *next) == nil {
		t.Fatal("stale CAS succeeded")
	}
	current, err := newFileStore(context.Background(), f.config.StateDir, f.files, f.config.ObjectFormat).read()
	if err != nil || !reflect.DeepEqual(before, current) {
		t.Fatal("stale CAS changed state")
	}
	store := newFileStore(context.Background(), f.config.StateDir, f.files, f.config.ObjectFormat)
	if err = store.Commit(before, *next); err != nil {
		t.Fatal(err)
	}
	current, err = store.read()
	if err != nil || !reflect.DeepEqual(next, current) {
		t.Fatal("matching CAS failed to publish next")
	}
}

// Pre-rename failures preserve prior bytes; post-rename directory-sync failure
// has an explicitly indeterminate durable outcome. All Commit failures poison
// live authority until a new instance receives trusted startup reconciliation.
func TestInterruptedWriteFencesUntilRestart(t *testing.T) {
	for _, stage := range []string{"file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t)
			entries := f.valid()
			first := f.commit(entries, "", true)
			f.config.Revision = first
			a := f.authority()
			expectCode(t, OK, a.Reload(context.Background()))
			path := filepath.Join(f.config.StateDir, "high-water.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			body := baseBody()
			body["seq"] = int64(2)
			entries = append(entries, registry.Entry{Path: "enrollments/2.json", Bytes: signedRecord(t, body, 1)})
			f.config.Revision = f.commit(entries, first, true)
			f.writeConfig()
			a.storeOps = failingOps{stage: stage}
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			_, code := authorize(a)
			expectCode(t, EnrollmentUnverified, code)
			if !a.commitFault {
				t.Fatal("commit failure did not poison authority")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if stage != "directory-sync" && string(after) != string(before) {
				t.Fatal("pre-rename failure modified prior state")
			}
			if stage == "directory-sync" && string(after) == string(before) {
				t.Fatal("control did not reach post-rename failure")
			}
			a.storeOps = nil
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			noEvidence := New(f.configPath, f.files, nil)
			expectCode(t, EnrollmentUnverified, noEvidence.Reload(context.Background()))
			disk, err := newFileStore(context.Background(), f.config.StateDir, f.files, f.config.ObjectFormat).read()
			if err != nil {
				t.Fatal(err)
			}
			restarted := New(f.configPath, f.files, exactReconciler{disk})
			expectCode(t, OK, restarted.Reload(context.Background()))
			_, code = authorize(restarted)
			expectCode(t, OK, code)
			matches, err := filepath.Glob(filepath.Join(f.config.StateDir, ".high-water-*"))
			if err != nil || len(matches) != 0 {
				t.Fatal("interrupted write left live temporary files")
			}
		})
	}
}

// A bootstrap interrupted after durable acceptance evidence is written cannot
// reclassify missing state as first use on restart.
func TestInterruptedBootstrapIsNotFirstUse(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	if _, err := f.operatorBootstrap(failingOps{stage: "rename"}); err == nil {
		t.Fatal("operator publication unexpectedly succeeded")
	}
	if _, err := os.Stat(filepath.Join(f.config.StateDir, "accepted")); err != nil {
		t.Fatal("missing retained acceptance evidence")
	}
	restarted := New(f.configPath, f.files, nil)
	expectCode(t, EnrollmentUnverified, restarted.Reload(context.Background()))
}
