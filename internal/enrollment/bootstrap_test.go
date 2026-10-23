package enrollment

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Explicit operator publication failures retain evidence and service restarts
// refuse. A successful operator publication plus reconciliation is the control.
func TestBootstrapCommitRequiresReconciliation(t *testing.T) {
	for _, stage := range []string{"file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t)
			f.config.Revision = f.commit(f.valid(), "", true)
			if _, err := f.operatorBootstrap(failingOps{stage: stage}); err == nil {
				t.Fatal("failed operator publication succeeded")
			}
			if _, err := f.operatorBootstrap(diskOps{}); err == nil {
				t.Fatal("operator publication retried over evidence")
			}
			if _, err := os.Stat(filepath.Join(f.config.StateDir, "accepted")); err != nil {
				t.Fatal("bootstrap evidence missing after Commit error")
			}
			restart := New(f.configPath, f.files, nil)
			expectCode(t, EnrollmentUnverified, restart.Reload(context.Background()))
			result, code := authorize(restart)
			expectCode(t, EnrollmentUnverified, code)
			if result != (EnrolledKey{}) {
				t.Fatal("failed bootstrap released admission data")
			}
		})
	}
	t.Run("fresh-control", func(t *testing.T) {
		f := newFixture(t)
		f.config.Revision = f.commit(f.valid(), "", true)
		a := f.authority()
		expectCode(t, OK, a.Reload(context.Background()))
		_, code := authorize(a)
		expectCode(t, OK, code)
		restart := New(f.configPath, f.files, exactReconciler{a.retained.Clone()})
		expectCode(t, OK, restart.Reload(context.Background()))
	})
}

// These injected operations exercise real files; errors are bounded to one
// publication step. Crash controls exit only the owned test subprocess.
type bootstrapOps struct {
	diskOps
	stage   string
	crash   bool
	dirs    int
	visited bool
	events  []string
}

func (o *bootstrapOps) step(name string) error {
	o.events = append(o.events, name)
	if name != o.stage {
		return nil
	}
	o.visited = true
	if o.crash {
		os.Exit(73)
	}
	return errors.New("injected bootstrap " + name)
}
func bootstrapFile(f *os.File) string {
	if filepath.Base(f.Name()) == "accepted" {
		return "marker"
	}
	return "temp"
}
func (o *bootstrapOps) Write(f *os.File, b []byte) (int, error) {
	kind := bootstrapFile(f)
	if !o.crash && o.stage == kind+"-write" {
		return 0, o.step(kind + "-write")
	}
	if o.stage == kind+"-partial-write" || o.stage == kind+"-short-write" {
		n, err := o.diskOps.Write(f, b[:len(b)/2])
		if err != nil {
			return n, err
		}
		o.visited = true
		if o.stage == kind+"-partial-write" {
			return n, errors.New("injected partial write")
		}
		return n, nil
	}
	n, err := o.diskOps.Write(f, b)
	if err == nil {
		err = o.step(kind + "-write")
	}
	return n, err
}
func (o *bootstrapOps) Sync(f *os.File) error {
	name := bootstrapFile(f) + "-sync"
	if !o.crash && o.stage == name {
		return o.step(name)
	}
	if err := o.diskOps.Sync(f); err != nil {
		return err
	}
	return o.step(name)
}
func (o *bootstrapOps) Close(f *os.File) error {
	if err := o.diskOps.Close(f); err != nil {
		return err
	}
	return o.step(bootstrapFile(f) + "-close")
}
func (o *bootstrapOps) Rename(old, next string) error {
	if !o.crash && o.stage == "rename" {
		return o.step("rename")
	}
	if err := o.diskOps.Rename(old, next); err != nil {
		return err
	}
	return o.step("rename")
}
func (o *bootstrapOps) SyncDir(path string) error {
	o.dirs++
	name := "directory-sync"
	if o.dirs == 1 {
		name = "marker-create-dir-sync"
	}
	if o.dirs == 2 {
		name = "marker-directory-sync"
	}
	if !o.crash && o.stage == name {
		return o.step(name)
	}
	if err := o.diskOps.SyncDir(path); err != nil {
		return err
	}
	return o.step(name)
}

// Each operator publication failure leaves attempt evidence and refuses retry
// over it. Service restart never infers consent. The control checks durable order.
func TestBootstrapFailureBoundaries(t *testing.T) {
	stages := []string{"marker-create-dir-sync", "marker-write", "marker-partial-write", "marker-short-write", "marker-sync", "marker-close", "marker-directory-sync", "temp-write", "temp-partial-write", "temp-short-write", "temp-sync", "temp-close", "rename", "directory-sync"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t)
			f.config.Revision = f.commit(f.valid(), "", true)
			ops := &bootstrapOps{stage: stage}
			if _, err := f.operatorBootstrap(ops); err == nil || !ops.visited {
				t.Fatal("operator fault was not reached and refused", err)
			}
			marker := filepath.Join(f.config.StateDir, "accepted")
			before, err := os.ReadFile(marker)
			if err != nil {
				t.Fatal("attempt evidence missing", err)
			}
			if strings.HasPrefix(stage, "marker") || stage != "directory-sync" {
				if _, err := os.Stat(filepath.Join(f.config.StateDir, "high-water.json")); !os.IsNotExist(err) {
					t.Fatal("failure published a high-water file")
				}
			}
			if _, err := f.operatorBootstrap(diskOps{}); err == nil {
				t.Fatal("operator publication retried over evidence")
			}
			restart := New(f.configPath, f.files, nil)
			expectCode(t, EnrollmentUnverified, restart.Reload(context.Background()))
			result, code := authorize(restart)
			expectCode(t, EnrollmentUnverified, code)
			if result != (EnrolledKey{}) {
				t.Fatal("failure returned authority")
			}
			after, err := os.ReadFile(marker)
			if err != nil || string(after) != string(before) {
				t.Fatal("restart rewrote intent evidence")
			}
		})
	}
	t.Run("durable-order-control", func(t *testing.T) {
		f := newFixture(t)
		f.config.Revision = f.commit(f.valid(), "", true)
		ops := &bootstrapOps{}
		high, err := f.operatorBootstrap(ops)
		if err != nil {
			t.Fatal(err)
		}
		a := New(f.configPath, f.files, exactReconciler{high})
		expectCode(t, OK, a.Reload(context.Background()))
		want := []string{"marker-create-dir-sync", "marker-write", "marker-sync", "marker-close", "marker-directory-sync", "temp-write", "temp-sync", "temp-close", "rename", "directory-sync"}
		if !reflect.DeepEqual(ops.events, want) {
			t.Fatalf("publication order=%v want=%v", ops.events, want)
		}
		_, code := authorize(a)
		expectCode(t, OK, code)
		restart := New(f.configPath, f.files, exactReconciler{a.retained.Clone()})
		expectCode(t, OK, restart.Reload(context.Background()))
	})
}

// Abrupt owned-process exits after each real publication operation bypass all
// defers. Restarts refuse even a crash after durable publication without an
// operator decision. These are process-crash controls, not a disk power-loss rig.
func TestBootstrapCrashRequiresReconciliation(t *testing.T) {
	for _, stage := range []string{"marker-create-dir-sync", "marker-write", "marker-sync", "marker-close", "marker-directory-sync", "temp-write", "temp-sync", "temp-close", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t)
			f.config.Revision = f.commit(f.valid(), "", true)
			f.writeConfig()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestBootstrapCrashChild$")
			cmd.Env = append(os.Environ(), "KEYMAKER_BOOTSTRAP_CRASH="+stage, "KEYMAKER_BOOTSTRAP_FIXTURE="+f.base)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Logf("owned crash child pid=%d stage=%s", cmd.Process.Pid, stage)
			err = cmd.Wait()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("child did not reach crash point: %v", err)
			}
			if _, err := os.Stat(filepath.Join(f.config.StateDir, "accepted")); err != nil {
				t.Fatal("crash lost bootstrap evidence")
			}
			restart := New(f.configPath, f.files, nil)
			expectCode(t, EnrollmentUnverified, restart.Reload(context.Background()))
			result, code := authorize(restart)
			expectCode(t, EnrollmentUnverified, code)
			if result != (EnrolledKey{}) {
				t.Fatal("crash restart returned authority")
			}
		})
	}
}

// Helper for the parent's isolated crash cases; ordinary invocations do no I/O.
func TestBootstrapCrashChild(t *testing.T) {
	stage := os.Getenv("KEYMAKER_BOOTSTRAP_CRASH")
	if stage == "" {
		return
	}
	base := os.Getenv("KEYMAKER_BOOTSTRAP_FIXTURE")
	files := fixtureFiles{base: base, override: map[string]Metadata{}}
	_, err := bootstrapFixture(context.Background(), filepath.Join(base, "pins.json"), files, &bootstrapOps{stage: stage, crash: true})
	t.Fatalf("crash point not reached: %v", err)
}

// An orphaned temporary file is attempted-bootstrap evidence even with no
// marker. Only an explicit operator publication can establish the control.
func TestBootstrapOrphanIsNotFirstUse(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	f.writeConfig()
	path := filepath.Join(f.config.StateDir, ".high-water-orphan")
	if err := os.WriteFile(path, []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	expectCode(t, EnrollmentUnverified, New(f.configPath, f.files, nil).Reload(context.Background()))
	// Only this isolated fixture is reset to establish the empty-directory control.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, OK, code)
}
