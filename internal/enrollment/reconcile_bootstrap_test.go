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
	"strings"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-registrar/registry"
)

func cleanBootstrapFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	uid := uint32(os.Geteuid())
	f.config.ServiceUID = &uid
	f.files.override[f.config.StateDir] = Metadata{Mode: os.ModeDir | 0700, UID: uid}
	f.config.Revision = f.commit(f.valid(), "", true)
	f.writeConfig()
	return f
}
func runFixtureBootstrap(f *fixture, confirm string, input io.Reader, ops durableOps) ([]ReconciliationReport, error) {
	var out, summary bytes.Buffer
	err := reconcileCommandMode(context.Background(), f.configPath, confirm, input, &out, &summary, f.files, ops, true)
	var reports []ReconciliationReport
	d := json.NewDecoder(&out)
	for {
		var r ReconciliationReport
		if e := d.Decode(&r); e != nil {
			break
		}
		reports = append(reports, r)
	}
	return reports, err
}
func bootstrapPreview(t *testing.T, f *fixture) ReconciliationReport {
	t.Helper()
	before := reconciliationImage(t, f)
	reports, err := runFixtureBootstrap(f, "", nil, diskOps{})
	if err == nil || err.Error() != "confirmation_required" || len(reports) != 1 || !reports[0].Bootstrap || !reports[0].Match || reports[0].Approved || len(reports[0].StateSHA256) != 64 {
		t.Fatalf("read-only bootstrap preview: %v %#v", err, reports)
	}
	assertUnchanged(t, f, before)
	return reports[0]
}
func approveBootstrap(t *testing.T, f *fixture) {
	t.Helper()
	r := bootstrapPreview(t, f)
	reports, err := runFixtureBootstrap(f, r.StateSHA256, nil, diskOps{})
	if err != nil || len(reports) != 2 || !reports[1].Approved || !reports[1].Bootstrap {
		t.Fatalf("valid bootstrap refused: %v %#v", err, reports)
	}
}
func assertBootstrapFenced(t *testing.T, f *fixture) {
	t.Helper()
	a := New(f.configPath, f.files, nil)
	defer a.Close()
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	result, code := authorize(a)
	expectCode(t, EnrollmentUnverified, code)
	if result != (EnrolledKey{}) {
		t.Fatal("failed bootstrap released admission")
	}
}

// Wrong/stale digests leave the empty state unchanged. The current exact digest
// is a paired control and admits only after the explicit operator command.
func TestReconcileBootstrapDigestRefusals(t *testing.T) {
	for _, kind := range []string{"wrong", "stale", "empty", "whitespace"} {
		t.Run(kind, func(t *testing.T) {
			f := cleanBootstrapFixture(t)
			old := bootstrapPreview(t, f)
			digest := strings.Repeat("0", 64)
			switch kind {
			case "stale":
				body := baseBody()
				body["seq"] = int64(2)
				entries := append(f.valid(), registry.Entry{Path: "enrollments/2.json", Bytes: signedRecord(t, body, 1)})
				f.config.Revision = f.commit(entries, f.config.Revision, true)
				f.writeConfig()
				digest = old.StateSHA256
			case "empty":
				digest = ""
			case "whitespace":
				digest = old.StateSHA256 + " "
			}
			before := reconciliationImage(t, f)
			reports, err := runFixtureBootstrap(f, digest, strings.NewReader("\n"), diskOps{})
			if err == nil || !strings.Contains(err.Error(), "confirmation_digest_mismatch") || len(reports) != 1 || reports[0].Approved {
				t.Fatalf("bad digest accepted: %v %#v", err, reports)
			}
			assertUnchanged(t, f, before)
			assertBootstrapFenced(t, f)
			approveBootstrap(t, f)
			startApproved(t, f).Close()
		})
	}
}

// Every pre-existing entry, including the former inert lock, prevents bootstrap
// without writes. A separate clean fixture is the explicit positive control.
func TestReconcileBootstrapEvidence(t *testing.T) {
	for _, shape := range []string{"lock-only", "empty-marker", "partial-marker", "complete-marker", "orphan", "high-water-only", "approval-only", "pending", "previous-state"} {
		t.Run(shape, func(t *testing.T) {
			f := cleanBootstrapFixture(t)
			baseline := bootstrapPreview(t, f)
			path := filepath.Join(f.config.StateDir, "accepted")
			data := []byte(acceptedMarker)
			switch shape {
			case "lock-only":
				path = filepath.Join(f.config.StateDir, "high-water.lock")
				data = nil
			case "empty-marker":
				data = nil
			case "partial-marker":
				data = []byte("accept")
			case "orphan":
				path = filepath.Join(f.config.StateDir, ".high-water-orphan")
			case "high-water-only":
				path = filepath.Join(f.config.StateDir, "high-water.json")
				data = []byte(`{"version":1}`)
			case "approval-only":
				path = filepath.Join(f.config.StateDir, approvalName)
			case "pending":
				path = pendingPath(f.configPath)
			case "previous-state":
				approveBootstrap(t, f)
				startApproved(t, f).Close()
				path = ""
			}
			if path != "" {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := reconciliationImage(t, f)
			reports, err := runFixtureBootstrap(f, baseline.StateSHA256, nil, diskOps{})
			if err == nil || len(reports) != 1 || !strings.Contains(reports[0].Reason, "bootstrap_requires_empty_state") || len(reports[0].Evidence) == 0 {
				t.Fatalf("prior evidence allowed: %v %#v", err, reports)
			}
			assertUnchanged(t, f, before)
		})
	}
	f := cleanBootstrapFixture(t)
	approveBootstrap(t, f)
	startApproved(t, f).Close()
}

// A live helper, even one fenced by empty state, holds its lifecycle lease.
// Closing it enables explicit bootstrap; normal reconciliation works afterwards.
func TestReconcileBootstrapLiveHelper(t *testing.T) {
	f := cleanBootstrapFixture(t)
	r := bootstrapPreview(t, f)
	a := New(f.configPath, f.files, nil)
	defer a.Close()
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	before := reconciliationImage(t, f)
	if _, err := runFixtureBootstrap(f, r.StateSHA256, nil, diskOps{}); err == nil || !strings.Contains(err.Error(), "enrollment_authority_live") {
		t.Fatalf("live helper allowed: %v", err)
	}
	assertUnchanged(t, f, before)
	a.Close()
	approveBootstrap(t, f)
	a = startApproved(t, f)
	high := a.retained.Clone()
	a.Close()
	reports, err := runFixtureReconcile(f, StateDigest(high), nil, diskOps{})
	if err != nil || len(reports) != 2 || reports[0].Bootstrap || !reports[1].Approved {
		t.Fatalf("normal reconcile regressed: %v %#v", err, reports)
	}
	startApproved(t, f).Close()
}

// The v1 bootstrap report binds the complete pin/snapshot and all host fields.
// Confirmation publishes exactly those bytes plus one consumed startup receipt.
func TestReconcileBootstrapOneStartup(t *testing.T) {
	f := cleanBootstrapFixture(t)
	r := bootstrapPreview(t, f)
	if r.Version != 1 || r.PinRevision != f.config.Revision || r.PinSHA256 != pinDigest(f.config) || r.LocalRevision != "" || r.StateSHA256 != r.SnapshotSHA256 || len(r.Hosts) != 1 || r.Hosts[0].Host != "sample" || r.Hosts[0].Seq != 1 || r.Hosts[0].ID == "" || r.Hosts[0].Revoked || r.Audience != testAudience || len(r.Evidence) != 0 || r.Reason != "bootstrap_ready" {
		t.Fatalf("incomplete report %#v", r)
	}
	reports, err := runFixtureBootstrap(f, "", strings.NewReader(r.StateSHA256+"\n"), diskOps{})
	if err != nil || len(reports) != 2 || !reports[1].Approved {
		t.Fatalf("interactive bootstrap refused: %v %#v", err, reports)
	}
	high, err := newFileStore(context.Background(), f.config.StateDir, f.files).read()
	if err != nil || StateDigest(high) != r.StateSHA256 {
		t.Fatal("published a different state", err)
	}
	a := startApproved(t, f)
	a.Close()
	assertBootstrapFenced(t, f)
	expectCommandApproval(t, f, high)
	startApproved(t, f).Close()
}

// The pin and prior evidence are rechecked after interactive confirmation.
// These fixture changes are operator actions; rejection adds no further writes.
func TestReconcileBootstrapConfirmationRace(t *testing.T) {
	for _, kind := range []string{"pin", "evidence"} {
		t.Run(kind, func(t *testing.T) {
			f := cleanBootstrapFixture(t)
			r := bootstrapPreview(t, f)
			var after map[string]string
			input := &readCallback{run: func() {
				if kind == "pin" {
					f.config.Generations["30001"] = strings.Repeat("a", 32)
					f.writeConfig()
				} else {
					if err := os.WriteFile(filepath.Join(f.config.StateDir, "high-water.lock"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
				after = reconciliationImage(t, f)
			}, line: r.StateSHA256 + "\n"}
			_, err := runFixtureBootstrap(f, "", input, diskOps{})
			want := "state_changed_during_confirmation"
			if kind == "pin" {
				want = "pin_changed_during_confirmation"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("confirmation race allowed: %v", err)
			}
			assertUnchanged(t, f, after)
			assertBootstrapFenced(t, f)
		})
	}
	f := cleanBootstrapFixture(t)
	approveBootstrap(t, f)
	startApproved(t, f).Close()
}

type bootstrapReceiptOps struct {
	diskOps
	stage, state string
	reached      bool
}

func (o *bootstrapReceiptOps) fail(stage string) error {
	if stage == o.stage {
		o.reached = true
		return fmt.Errorf("injected receipt %s", stage)
	}
	return nil
}
func (o *bootstrapReceiptOps) Write(f *os.File, b []byte) (int, error) {
	if strings.HasPrefix(filepath.Base(f.Name()), ".reconciliation-") {
		if err := o.fail("receipt-write"); err != nil {
			return 0, err
		}
	}
	return o.diskOps.Write(f, b)
}
func (o *bootstrapReceiptOps) Sync(f *os.File) error {
	stage := ""
	if strings.HasPrefix(filepath.Base(f.Name()), pendingName) {
		stage = "fence-sync"
	} else if strings.HasPrefix(filepath.Base(f.Name()), ".reconciliation-") {
		stage = "receipt-sync"
	}
	if stage != "" {
		if err := o.fail(stage); err != nil {
			return err
		}
	}
	return o.diskOps.Sync(f)
}
func (o *bootstrapReceiptOps) Close(f *os.File) error {
	if err := o.diskOps.Close(f); err != nil {
		return err
	}
	if strings.HasPrefix(filepath.Base(f.Name()), pendingName) {
		return o.fail("fence-close")
	}
	if strings.HasPrefix(filepath.Base(f.Name()), ".reconciliation-") {
		return o.fail("receipt-close")
	}
	return nil
}
func (o *bootstrapReceiptOps) Rename(old, next string) error {
	if filepath.Base(next) == approvalName {
		if err := o.fail("receipt-rename"); err != nil {
			return err
		}
	}
	return o.diskOps.Rename(old, next)
}
func (o *bootstrapReceiptOps) SyncDir(path string) error {
	if path == filepath.Dir(o.state) {
		if err := o.fail("fence-directory-sync"); err != nil {
			return err
		}
	}
	if _, err := os.Stat(filepath.Join(o.state, approvalName)); err == nil && path == o.state {
		if err := o.fail("receipt-directory-sync"); err != nil {
			return err
		}
	}
	return o.diskOps.SyncDir(path)
}

// Initial-state and receipt I/O errors, including visible post-rename receipts,
// always fence default startup. All faults run against isolated real files.
func TestReconcileBootstrapWriteFailures(t *testing.T) {
	stages := []string{"marker-create-dir-sync", "marker-write", "marker-partial-write", "marker-short-write", "marker-sync", "marker-close", "marker-directory-sync", "temp-write", "temp-partial-write", "temp-short-write", "temp-sync", "temp-close", "rename", "directory-sync", "fence-sync", "fence-close", "fence-directory-sync", "receipt-write", "receipt-sync", "receipt-close", "receipt-rename", "receipt-directory-sync"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			f := cleanBootstrapFixture(t)
			r := bootstrapPreview(t, f)
			initial := &bootstrapOps{stage: stage}
			receipt := &bootstrapReceiptOps{stage: stage, state: f.config.StateDir}
			var ops durableOps = initial
			if strings.HasPrefix(stage, "receipt-") || strings.HasPrefix(stage, "fence-") {
				ops = receipt
			}
			_, err := runFixtureBootstrap(f, r.StateSHA256, nil, ops)
			if err == nil || !strings.Contains(err.Error(), "bootstrap_write_failed_fenced") || (!initial.visited && !receipt.reached) {
				t.Fatalf("fault not reached and refused: %v", err)
			}
			assertBootstrapFenced(t, f)
			before := reconciliationImage(t, f)
			reports, err := runFixtureBootstrap(f, r.StateSHA256, nil, diskOps{})
			if err == nil || len(reports) != 1 || !strings.Contains(reports[0].Reason, "bootstrap_requires_empty_state") {
				t.Fatalf("failed attempt retried implicitly: %v", err)
			}
			assertUnchanged(t, f, before)
		})
	}
	f := cleanBootstrapFixture(t)
	approveBootstrap(t, f)
	startApproved(t, f).Close()
}

type bootstrapOutputFailure struct{ calls int }

func (w *bootstrapOutputFailure) Write(b []byte) (int, error) {
	w.calls++
	if w.calls == 2 {
		return 0, errors.New("injected final output failure")
	}
	return len(b), nil
}

// Even final stdout failure leaves the durable root fence over the receipt.
// Both directory and Store locks remain held until receipt output finishes.
func TestReconcileBootstrapPublicationLocksAndOutput(t *testing.T) {
	f := cleanBootstrapFixture(t)
	r := bootstrapPreview(t, f)
	w := &bootstrapOutputFailure{}
	err := reconcileCommandMode(context.Background(), f.configPath, r.StateSHA256, nil, w, io.Discard, f.files, diskOps{}, true)
	if err == nil || !strings.Contains(err.Error(), "injected final output failure") {
		t.Fatal("output fault not reached", err)
	}
	if _, err := os.Stat(pendingPath(f.configPath)); err != nil {
		t.Fatal("lost durable startup fence", err)
	}
	assertBootstrapFenced(t, f)
	// A receipt sync hook probes the existing Store lock during publication.
	f = cleanBootstrapFixture(t)
	r = bootstrapPreview(t, f)
	probe := &bootstrapLockProbe{state: f.config.StateDir}
	if _, err := runFixtureBootstrap(f, r.StateSHA256, nil, probe); err != nil || !probe.reached {
		t.Fatal("publication lock probe", err)
	}
	startApproved(t, f).Close()
}

type bootstrapLockProbe struct {
	diskOps
	state   string
	reached bool
}

func (o *bootstrapLockProbe) Sync(f *os.File) error {
	if strings.HasPrefix(filepath.Base(f.Name()), ".reconciliation-") {
		lock, err := os.Open(filepath.Join(o.state, "high-water.lock"))
		if err != nil {
			return err
		}
		defer lock.Close()
		err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			if err == nil {
				_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			}
			return fmt.Errorf("Store lock not held during approval: %v", err)
		}
		dir, err := os.Open(o.state)
		if err != nil {
			return err
		}
		defer dir.Close()
		err = syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			if err == nil {
				_ = syscall.Flock(int(dir.Fd()), syscall.LOCK_UN)
			}
			return fmt.Errorf("directory lease not held during approval: %v", err)
		}
		o.reached = true
	}
	return o.diskOps.Sync(f)
}

// Invalid Git signatures, maintainer pins and publisher records cannot prepare
// initial state. Restoring the exact approved pin is each case's positive control.
func TestReconcileBootstrapSnapshotRefusals(t *testing.T) {
	for _, kind := range []string{"unsigned", "maintainer", "publisher"} {
		t.Run(kind, func(t *testing.T) {
			f := cleanBootstrapFixture(t)
			saved := f.config
			switch kind {
			case "unsigned":
				f.config.Revision = f.commit(f.valid(), "", false)
			case "maintainer":
				f.config.Maintainers = []string{newFixture(t).public}
			case "publisher":
				f.config.Publisher = public(3)
			}
			f.writeConfig()
			before := reconciliationImage(t, f)
			reports, err := runFixtureBootstrap(f, strings.Repeat("0", 64), nil, diskOps{})
			if err == nil || len(reports) != 1 || !strings.HasPrefix(reports[0].Reason, "snapshot_rejected:") || reports[0].Match {
				t.Fatalf("unverified bootstrap not refused by loader: %v %#v", err, reports)
			}
			assertUnchanged(t, f, before)
			assertBootstrapFenced(t, f)
			f.config = saved
			f.writeConfig()
			approveBootstrap(t, f)
			startApproved(t, f).Close()
		})
	}
}

// Real pre-marker syscall failures cannot turn a service restart into consent.
// With no evidence left, a new explicit command can retry; lock leftovers refuse.
func TestReconcileBootstrapPreMarkerFailuresThenRetry(t *testing.T) {
	for _, stage := range []string{"commit-lock", "state-read", "marker-create"} {
		t.Run(stage, func(t *testing.T) {
			f := cleanBootstrapFixture(t)
			r := bootstrapPreview(t, f)
			files := &earlyBootstrapFiles{fixtureFiles: f.files, state: f.config.StateDir, stage: stage}
			t.Cleanup(func() { _ = os.Chmod(f.config.StateDir, 0700) })
			var input io.Reader
			digest := r.StateSHA256
			if stage == "commit-lock" {
				digest = ""
				input = &readCallback{line: r.StateSHA256 + "\n", run: func() {
					if err := os.Chmod(f.config.StateDir, 0500); err != nil {
						t.Fatal(err)
					}
					files.reached = true
				}}
			}
			err := reconcileCommandMode(context.Background(), f.configPath, digest, input, io.Discard, io.Discard, files, diskOps{}, true)
			if err == nil || !strings.Contains(err.Error(), "bootstrap_write_failed_fenced") || !files.reached || !errors.Is(err, os.ErrPermission) {
				t.Fatalf("pre-marker syscall not reached: %v reached=%t", err, files.reached)
			}
			if err := os.Chmod(f.config.StateDir, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(f.config.StateDir, "accepted")); !os.IsNotExist(err) {
				t.Fatal("failure was not pre-marker", err)
			}
			assertBootstrapFenced(t, f)
			if stage == "commit-lock" {
				approveBootstrap(t, f)
				startApproved(t, f).Close()
			} else {
				before := reconciliationImage(t, f)
				reports, err := runFixtureBootstrap(f, r.StateSHA256, nil, diskOps{})
				if err == nil || len(reports) != 1 || !strings.Contains(reports[0].Reason, "bootstrap_requires_empty_state") {
					t.Fatal("lock-only failure silently retried", err)
				}
				assertUnchanged(t, f, before)
			}
		})
	}
	f := cleanBootstrapFixture(t)
	approveBootstrap(t, f)
	startApproved(t, f).Close()
}
