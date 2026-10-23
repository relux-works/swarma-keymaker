//go:build linux

package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/relux-works/swarma-registrar/registry"
)

// Ownership substitution is confined to tests. Actual fd identity, nlink,
// no-follow opens, writes, Git signatures, loader and flock operations are real.
func (f fixtureFiles) openedMetadata(file *os.File) (Metadata, error) {
	info, err := file.Stat()
	if err != nil {
		return Metadata{}, err
	}
	m, err := metadata(info)
	m.UID = 0
	if override, ok := f.override[file.Name()]; ok {
		m = override
	}
	return m, err
}
func reconciliationFixture(t *testing.T) (*fixture, *registry.HighWater) {
	t.Helper()
	f := newFixture(t)
	uid := uint32(os.Geteuid())
	f.config.ServiceUID = &uid
	f.files.override[f.config.StateDir] = Metadata{Mode: os.ModeDir | 0700, UID: uid}
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	high := a.retained.Clone()
	a.Close()
	f.writeConfig()
	return f, high
}
func runFixtureReconcile(f *fixture, confirm string, input io.Reader, ops durableOps) ([]ReconciliationReport, error) {
	var out, summary bytes.Buffer
	err := reconcileCommand(context.Background(), f.configPath, confirm, input, &out, &summary, f.files, ops)
	dec := json.NewDecoder(&out)
	var reports []ReconciliationReport
	for {
		var r ReconciliationReport
		if e := dec.Decode(&r); e != nil {
			break
		}
		reports = append(reports, r)
	}
	return reports, err
}
func directoryImage(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	image := map[string]string{}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		info, e := os.Lstat(path)
		if e != nil {
			t.Fatal(e)
		}
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		image[entry.Name()] = fmt.Sprintf("%s:%s", info.Mode(), b)
	}
	return image
}
func reconciliationImage(t *testing.T, f *fixture) map[string]string {
	t.Helper()
	image := directoryImage(t, f.config.StateDir)
	for _, path := range []string{f.configPath, pendingPath(f.configPath)} {
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			image[path] = "absent"
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		image[path] = string(b)
	}
	return image
}
func assertUnchanged(t *testing.T, f *fixture, before map[string]string) {
	t.Helper()
	if got := reconciliationImage(t, f); !reflect.DeepEqual(got, before) {
		t.Fatalf("refusal mutated state\nbefore=%v\nafter=%v", before, got)
	}
}
func expectCommandApproval(t *testing.T, f *fixture, high *registry.HighWater) {
	t.Helper()
	reports, err := runFixtureReconcile(f, StateDigest(high), nil, diskOps{})
	if err != nil || len(reports) != 2 || !reports[0].Match || !reports[1].Approved {
		t.Fatalf("control refused: %v %#v", err, reports)
	}
}
func startApproved(t *testing.T, f *fixture) *Authority {
	t.Helper()
	a := New(f.configPath, f.files, nil)
	t.Cleanup(func() { a.Close() })
	expectCode(t, OK, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, OK, code)
	return a
}

// The exact command receipt admits ONE restart, preserves the high-water bytes,
// and reports every host plus a digest including invisible ownership/history.
func TestReconcileCommandOneStartup(t *testing.T) {
	f, high := reconciliationFixture(t)
	before, _ := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
	reports, err := runFixtureReconcile(f, "", strings.NewReader(StateDigest(high)+"\n"), diskOps{})
	if err != nil || len(reports) != 2 {
		t.Fatalf("%v %#v", err, reports)
	}
	r := reports[0]
	if !r.Match || r.Approved || r.StateSHA256 != StateDigest(high) || r.SnapshotSHA256 != r.StateSHA256 || r.PinRevision != f.config.Revision || r.PinSHA256 != pinDigest(f.config) || r.Audience != testAudience || len(r.Hosts) != 1 || r.Hosts[0].Host != "sample" || r.Hosts[0].Seq != high.Hosts["sample"].Seq || r.Hosts[0].ID != high.Hosts["sample"].ID || r.Hosts[0].Revoked != high.Hosts["sample"].Revoked || r.PublisherFingerprint != "SHA256:34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e" || !reflect.DeepEqual(r.Evidence, []string{"bootstrap_marker_present"}) {
		t.Fatalf("incomplete report: %#v", r)
	}
	if !reports[1].Approved {
		t.Fatal("missing approval result")
	}
	a := startApproved(t, f)
	a.Close()
	after, _ := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("changed high water")
	}
	beforeDir := reconciliationImage(t, f)
	again := New(f.configPath, f.files, nil)
	defer again.Close()
	expectCode(t, EnrollmentUnverified, again.Reload(context.Background()))
	assertUnchanged(t, f, beforeDir)
	again.Close()
	expectCommandApproval(t, f, high)
}

// Wrong confirmations and changed-state digests refuse without creating any
// files; each adjacent exact-digest control publishes a usable startup receipt.
func TestReconcileCommandDigestRefusals(t *testing.T) {
	for _, name := range []string{"wrong", "stale", "empty", "whitespace"} {
		t.Run(name, func(t *testing.T) {
			f, high := reconciliationFixture(t)
			confirm := StateDigest(high)
			var input io.Reader
			switch name {
			case "wrong":
				confirm = strings.Repeat("0", 64)
			case "stale":
				body := baseBody()
				body["seq"] = int64(2)
				f.config.Revision = f.commit(append(f.valid(), registry.Entry{Path: "enrollments/2.json", Bytes: signedRecord(t, body, 1)}), f.config.Revision, true)
				f.writeConfig()
				a := New(f.configPath, f.files, exactReconciler{high})
				expectCode(t, OK, a.Reload(context.Background()))
				high = a.retained.Clone()
				a.Close()
			case "empty":
				confirm = ""
				input = strings.NewReader("\n")
			case "whitespace":
				confirm = " " + confirm
			}
			before := reconciliationImage(t, f)
			_, err := runFixtureReconcile(f, confirm, input, diskOps{})
			if err == nil || err.Error() != "confirmation_digest_mismatch" {
				t.Fatalf("wrong refusal: %v", err)
			}
			assertUnchanged(t, f, before)
			expectCommandApproval(t, f, high)
			startApproved(t, f)
		})
	}
}

// The pinned snapshot is actually recomputed, not inferred from a readable
// local digest: a different pin, missing local host/history and rollback reject.
func TestReconcileCommandSnapshotMismatch(t *testing.T) {
	for _, name := range []string{"new-pin", "rollback", "missing-host", "different-id", "ownership", "extra-key-owner"} {
		t.Run(name, func(t *testing.T) {
			f, high := reconciliationFixture(t)
			switch name {
			case "new-pin":
				f.config.Revision = f.commit(f.valid(), f.config.Revision, true)
				f.writeConfig()
			case "rollback":
				entries := f.valid()
				entries[0].Path = "enrollments/alternate.json"
				f.config.Revision = f.commit(entries, "", true)
				f.writeConfig()
			case "missing-host":
				delete(high.Hosts, "sample")
			case "different-id":
				h := high.Hosts["sample"]
				h.ID = "enrollment:sha256:" + strings.Repeat("0", 64)
				high.Hosts["sample"] = h
			case "ownership":
				high.NameOwners["unexpected_name"] = "missing"
			case "extra-key-owner":
				high.KeyOwners[public(4)] = "sample"
			}
			if name == "missing-host" || name == "different-id" || name == "ownership" || name == "extra-key-owner" {
				b, _ := json.Marshal(stateRecord{1, high})
				if err := os.WriteFile(filepath.Join(f.config.StateDir, "high-water.json"), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := reconciliationImage(t, f)
			reports, err := runFixtureReconcile(f, StateDigest(high), nil, diskOps{})
			if err == nil || len(reports) != 1 || reports[0].Match || reports[0].Reason == "matching_state" {
				t.Fatalf("mismatch admitted: %v %#v", err, reports)
			}
			if name == "missing-host" && !strings.Contains(reports[0].Reason, "local_missing_host: sample") {
				t.Fatalf("missing-host reason lost: %s", reports[0].Reason)
			}
			if name == "different-id" && !strings.Contains(reports[0].Reason, "snapshot_different_id_or_revocation: sample") {
				t.Fatalf("different-ID reason lost: %s", reports[0].Reason)
			}
			if name == "rollback" && !strings.Contains(reports[0].Reason, "registry_rollback") {
				t.Fatalf("rollback reason lost: %s", reports[0].Reason)
			}
			assertUnchanged(t, f, before)
			// A separate untouched fixture is the independent matching-state control.
			control, h := reconciliationFixture(t)
			expectCommandApproval(t, control, h)
			startApproved(t, control)
		})
	}
}

// Existing crash evidence, or a never-used directory, is never repaired or
// bootstrapped. An independent intact fixture is the exact positive control.
func TestReconcileCommandInterruptedState(t *testing.T) {
	for _, name := range []string{"partial-marker", "orphan", "pending-approval", "operator-fence", "missing-high-water", "fresh"} {
		t.Run(name, func(t *testing.T) {
			f, high := reconciliationFixture(t)
			switch name {
			case "partial-marker":
				os.WriteFile(filepath.Join(f.config.StateDir, "accepted"), nil, 0600)
			case "orphan":
				os.WriteFile(filepath.Join(f.config.StateDir, ".high-water-orphan"), []byte("partial"), 0600)
			case "operator-fence":
				os.WriteFile(pendingPath(f.configPath), nil, 0644)
			case "pending-approval":
				os.WriteFile(filepath.Join(f.config.StateDir, pendingName), nil, 0644)
			case "missing-high-water":
				os.Remove(filepath.Join(f.config.StateDir, "high-water.json"))
			case "fresh":
				os.Remove(filepath.Join(f.config.StateDir, "accepted"))
				os.Remove(filepath.Join(f.config.StateDir, "high-water.json"))
				os.Remove(filepath.Join(f.config.StateDir, "high-water.lock"))
			}
			before := reconciliationImage(t, f)
			_, err := runFixtureReconcile(f, StateDigest(high), nil, diskOps{})
			if err == nil {
				t.Fatal("interrupted state admitted")
			}
			assertUnchanged(t, f, before)
			control, h := reconciliationFixture(t)
			expectCommandApproval(t, control, h)
			startApproved(t, control)
		})
	}
}

// A missing, service-forged, other-pin, wrong-digest, aliased, hard-linked or
// old-format receipt cannot be consumed; every refusal preserves all bytes.
func TestReconcileCommandRecordRefusals(t *testing.T) {
	for _, name := range []string{"missing", "forged", "other-pin", "other-config", "wrong-digest", "case-alias", "hard-link", "old-format"} {
		t.Run(name, func(t *testing.T) {
			f, high := reconciliationFixture(t)
			path := filepath.Join(f.config.StateDir, approvalName)
			expectCommandApproval(t, f, high)
			switch name {
			case "missing":
				os.Remove(path)
			case "forged":
				f.files.override[path] = Metadata{Mode: 0644, UID: uint32(os.Geteuid()), Links: 1}
			case "other-pin":
				c := f.config
				c.Audience = "another.example.invalid"
				f.config = c
				f.writeConfig()
			case "other-config":
				f.configPath = filepath.Join(f.base, "another-pins.json")
				f.writeConfig()
			case "wrong-digest":
				b, _ := json.Marshal(commandApproval{Version: 1, ConfigPathSHA256: digestBytes([]byte(f.configPath)), PinSHA256: pinDigest(f.config), StateSHA256: strings.Repeat("0", 64)})
				os.WriteFile(path, b, 0644)
			case "case-alias":
				b, _ := os.ReadFile(path)
				b = bytes.Replace(b, []byte("state_sha256"), []byte("State_SHA256"), 1)
				os.WriteFile(path, b, 0644)
			case "hard-link":
				if err := os.Link(path, filepath.Join(f.base, "retained-receipt")); err != nil {
					t.Fatal(err)
				}
			case "old-format":
				os.WriteFile(path, []byte(`{"startup_id":"old","state_sha256":"`+StateDigest(high)+`"}`), 0644)
			}
			before := reconciliationImage(t, f)
			a := New(f.configPath, f.files, nil)
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			a.Close()
			assertUnchanged(t, f, before)
			control, h := reconciliationFixture(t)
			expectCommandApproval(t, control, h)
			startApproved(t, control)
		})
	}
}

// An actual live Authority lease (including failed startup) and a direct Store
// writer exclude the command. After stop/unlock it succeeds. Closing fences
// Authorize and Reload permanently, so it cannot rejoin after releasing lease.
func TestReconcileCommandLiveAuthority(t *testing.T) {
	f, high := reconciliationFixture(t)
	a := New(f.configPath, f.files, exactReconciler{high})
	expectCode(t, OK, a.Reload(context.Background()))
	before := reconciliationImage(t, f)
	_, err := runFixtureReconcile(f, StateDigest(high), nil, diskOps{})
	if err == nil || !strings.Contains(err.Error(), "enrollment_authority_live") {
		t.Fatalf("wrong live refusal: %v", err)
	}
	assertUnchanged(t, f, before)
	a.Close()
	_, code := authorize(a)
	expectCode(t, EnrollmentUnverified, code)
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	store := newFileStore(context.Background(), f.config.StateDir, f.files)
	lock, err := store.lock()
	if err != nil {
		t.Fatal(err)
	}
	_, err = runFixtureReconcile(f, StateDigest(high), nil, diskOps{})
	if err == nil || !strings.Contains(err.Error(), "store_writer_live") {
		t.Fatalf("writer live: %v", err)
	}
	assertUnchanged(t, f, before)
	unlock(lock)
	expectCommandApproval(t, f, high)
	startApproved(t, f)
}

type readCallback struct {
	run  func()
	line string
}

func (r *readCallback) Read(b []byte) (int, error) {
	if r.run != nil {
		r.run()
		r.run = nil
	}
	if r.line == "" {
		return 0, io.EOF
	}
	n := copy(b, r.line)
	r.line = r.line[n:]
	return n, nil
}

// Protected pins and the entire state are read again after confirmation;
// direct fixture changes while the operator waits cannot approve stale data.
func TestReconcileCommandConfirmationRace(t *testing.T) {
	for _, change := range []string{"pin", "state"} {
		t.Run(change, func(t *testing.T) {
			f, high := reconciliationFixture(t)
			var after map[string]string
			input := &readCallback{line: StateDigest(high) + "\n", run: func() {
				if change == "pin" {
					f.config.Generations["30001"] = strings.Repeat("2", 32)
					f.writeConfig()
				} else {
					altered := high.Clone()
					altered.NameOwners["unapproved"] = "another"
					b, _ := json.Marshal(stateRecord{1, altered})
					os.WriteFile(filepath.Join(f.config.StateDir, "high-water.json"), b, 0600)
				}
				after = reconciliationImage(t, f)
			}}
			_, err := runFixtureReconcile(f, "", input, diskOps{})
			if err == nil || !strings.Contains(err.Error(), "changed_during_confirmation") {
				t.Fatalf("race admitted: %v", err)
			}
			assertUnchanged(t, f, after)
			control, h := reconciliationFixture(t)
			expectCommandApproval(t, control, h)
			startApproved(t, control)
		})
	}
}

type approvalFaultOps struct {
	diskOps
	stage   string
	reached bool
}

func (o *approvalFaultOps) Write(f *os.File, b []byte) (int, error) {
	if o.stage == "write" && strings.HasPrefix(filepath.Base(f.Name()), ".reconciliation-") && !strings.HasPrefix(filepath.Base(f.Name()), pendingName) {
		o.reached = true
		return 0, errors.New("injected write failure")
	}
	return o.diskOps.Write(f, b)
}
func (o *approvalFaultOps) Sync(f *os.File) error {
	if o.stage == "file-sync" && strings.Contains(filepath.Base(f.Name()), ".reconciliation-") && !strings.HasPrefix(filepath.Base(f.Name()), pendingName) {
		o.reached = true
		return errors.New("injected file sync failure")
	}
	return o.diskOps.Sync(f)
}
func (o *approvalFaultOps) Rename(a, b string) error {
	if o.stage == "rename" {
		o.reached = true
		return errors.New("injected rename failure")
	}
	return o.diskOps.Rename(a, b)
}
func (o *approvalFaultOps) SyncDir(path string) error {
	if o.stage == "directory-sync" {
		if _, err := os.Stat(filepath.Join(path, approvalName)); err == nil {
			o.reached = true
			return errors.New("injected directory sync failure")
		}
	}
	return o.diskOps.SyncDir(path)
}

// Write/file-sync/rename/post-rename-directory-sync failures retain a durable
// fence, even if the candidate approval is visible. No high-water byte changes.
func TestReconcileCommandWriteFailureFences(t *testing.T) {
	for _, stage := range []string{"write", "file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			f, high := reconciliationFixture(t)
			before, _ := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
			ops := &approvalFaultOps{stage: stage}
			_, err := runFixtureReconcile(f, StateDigest(high), nil, ops)
			if err == nil || !ops.reached || !strings.Contains(err.Error(), "approval_write_failed_fenced") {
				t.Fatalf("fault missed: %v", err)
			}
			if stage == "directory-sync" {
				if _, err := os.Stat(filepath.Join(f.config.StateDir, approvalName)); err != nil {
					t.Fatal("post-rename fault missed visible receipt", err)
				}
			}
			if _, err = os.Stat(pendingPath(f.configPath)); err != nil {
				t.Fatal("lost failure fence")
			}
			after, _ := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
			if !bytes.Equal(before, after) {
				t.Fatal("high water changed")
			}
			a := New(f.configPath, f.files, nil)
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			a.Close()
			control, h := reconciliationFixture(t)
			expectCommandApproval(t, control, h)
			startApproved(t, control)
		})
	}
}

// Two operators cannot both pass confirmation concurrently; startup cannot run
// while confirmation holds the exclusive lease. The winning command is usable.
func TestReconcileCommandConcurrentLifecycle(t *testing.T) {
	f, high := reconciliationFixture(t)
	entered := make(chan struct{})
	proceed := make(chan struct{})
	result := make(chan error, 1)
	input := &readCallback{line: StateDigest(high) + "\n", run: func() { close(entered); <-proceed }}
	go func() { _, err := runFixtureReconcile(f, "", input, diskOps{}); result <- err }()
	<-entered
	before := reconciliationImage(t, f)
	_, err := runFixtureReconcile(f, StateDigest(high), nil, diskOps{})
	if err == nil {
		t.Fatal("second operator entered")
	}
	a := New(f.configPath, f.files, nil)
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	a.Close()
	assertUnchanged(t, f, before)
	close(proceed)
	if err = <-result; err != nil {
		t.Fatal(err)
	}
	startApproved(t, f)
}

// Two startup attempts racing for one receipt admit at most one process; the
// receipt removal is fsynced before the successful Check returns.
func TestReconcileCommandConcurrentStartup(t *testing.T) {
	f, high := reconciliationFixture(t)
	expectCommandApproval(t, f, high)
	var wg sync.WaitGroup
	codes := make(chan Code, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := New(f.configPath, f.files, nil)
			defer a.Close()
			codes <- a.Reload(context.Background())
		}()
	}
	wg.Wait()
	close(codes)
	accepted := 0
	for code := range codes {
		if code == OK {
			accepted++
		} else if code != EnrollmentUnverified {
			t.Fatal(code)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d starts", accepted)
	}
}

// Confirmation covers invisible history and permanent ownership as well as
// current host positions; cloning leaves the digest unchanged.
func TestReconcileCommandDigestCoverage(t *testing.T) {
	f, high := reconciliationFixture(t)
	baseline := StateDigest(high)
	for _, field := range []string{"revision", "seq", "id", "revoked", "history", "key-owner", "name-owner"} {
		t.Run(field, func(t *testing.T) {
			changed := high.Clone()
			h := changed.Hosts["sample"]
			switch field {
			case "revision":
				changed.Revision = strings.Repeat("0", 40)
			case "seq":
				h.Seq++
			case "id":
				h.ID = "changed"
			case "revoked":
				h.Revoked = !h.Revoked
			case "history":
				h.History[100] = "changed"
			case "key-owner":
				changed.KeyOwners[public(4)] = "sample"
			case "name-owner":
				changed.NameOwners["sample_old"] = "sample"
			}
			changed.Hosts["sample"] = h
			if StateDigest(changed) == baseline {
				t.Fatal("digest omitted " + field)
			}
			if StateDigest(high.Clone()) != baseline {
				t.Fatal("clone changed canonical digest")
			}
		})
	}
	expectCommandApproval(t, f, high)
	startApproved(t, f)
}

// A pre-existing receipt is never overwritten by a second approval attempt,
// preserving one-use semantics even when a later attempt hits early I/O faults.
func TestReconcileCommandExistingApproval(t *testing.T) {
	f, high := reconciliationFixture(t)
	expectCommandApproval(t, f, high)
	before := reconciliationImage(t, f)
	_, err := runFixtureReconcile(f, StateDigest(high), nil, diskOps{})
	if err == nil || !strings.HasPrefix(err.Error(), "approval_already_present:") {
		t.Fatalf("existing receipt overwritten: %v", err)
	}
	assertUnchanged(t, f, before)
	startApproved(t, f)
}

// Missing service identity and service-owned ancestors cannot weaken the root
// operator fence. Protected canonical configuration remains the positive case.
func TestReconcileCommandOwnership(t *testing.T) {
	for _, bad := range []string{"missing-uid", "root-state-owner", "unsafe-state-parent"} {
		t.Run(bad, func(t *testing.T) {
			f, high := reconciliationFixture(t)
			if bad == "missing-uid" {
				f.config.ServiceUID = nil
				f.writeConfig()
			} else if bad == "root-state-owner" {
				delete(f.files.override, f.config.StateDir)
			} else {
				parent := filepath.Join(f.base, "service-owned")
				if err := os.Mkdir(parent, 0700); err != nil {
					t.Fatal(err)
				}
				moved := filepath.Join(parent, "state")
				if err := os.Rename(f.config.StateDir, moved); err != nil {
					t.Fatal(err)
				}
				f.config.StateDir = moved
				f.files.override[moved] = Metadata{Mode: os.ModeDir | 0700, UID: uint32(os.Geteuid())}
				f.writeConfig()
				f.files.override[parent] = Metadata{Mode: os.ModeDir | 0700, UID: uint32(os.Geteuid())}
			}
			before := reconciliationImage(t, f)
			_, err := runFixtureReconcile(f, StateDigest(high), nil, diskOps{})
			if err == nil {
				t.Fatal("unsafe ownership admitted")
			}
			if bad == "missing-uid" && err.Error() != "service_uid_required" {
				t.Fatalf("wrong uid refusal: %v", err)
			}
			if bad != "missing-uid" && !errors.Is(err, errTrust) {
				t.Fatalf("wrong parent refusal: %v", err)
			}
			assertUnchanged(t, f, before)
			control, h := reconciliationFixture(t)
			expectCommandApproval(t, control, h)
			startApproved(t, control)
		})
	}
}

type consumeFaultOps struct{ diskOps }

func (consumeFaultOps) SyncDir(string) error {
	return errors.New("injected approval-consumption sync failure")
}

// A failed consumption-directory fsync cannot install authority; the renamed
// receipt stays unusable. A fresh fixture consumes its own approval successfully.
func TestReconcileCommandConsumptionFailure(t *testing.T) {
	f, high := reconciliationFixture(t)
	expectCommandApproval(t, f, high)
	before, _ := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
	r := &commandReconciler{configPath: f.configPath, files: f.files, consumeOps: consumeFaultOps{}}
	a := New(f.configPath, f.files, r)
	defer a.Close()
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, EnrollmentUnverified, code)
	after, _ := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("consumption failure changed high water")
	}
	control, h := reconciliationFixture(t)
	expectCommandApproval(t, control, h)
	startApproved(t, control)
}

type observedPipe struct {
	*io.PipeReader
	reading chan struct{}
	once    sync.Once
}

func (p *observedPipe) Read(b []byte) (int, error) {
	p.once.Do(func() { close(p.reading) })
	return p.PipeReader.Read(b)
}

// Canceling a waiting operator closes its owned input and releases leases with
// no approval or state changes. The same stopped state can then be approved.
func TestReconcileCommandCanceledConfirmation(t *testing.T) {
	f, high := reconciliationFixture(t)
	before := reconciliationImage(t, f)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	input := &observedPipe{PipeReader: reader, reading: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		var out, summary bytes.Buffer
		result <- reconcileCommand(ctx, f.configPath, "", input, &out, &summary, f.files, diskOps{})
	}()
	<-input.reading
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("wrong cancellation: %v", err)
	}
	assertUnchanged(t, f, before)
	expectCommandApproval(t, f, high)
	startApproved(t, f)
}
