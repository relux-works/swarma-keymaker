package enrollment

import (
	"context"
	"errors"
	"github.com/relux-works/swarma-registrar/registry"
	"os"
	"path/filepath"
	"testing"
)

// No local state shape supplies operator consent. Service reads and commits do
// not create lock/marker/state files, including a genuinely empty directory.
func TestServiceNeverBootstraps(t *testing.T) {
	for _, shape := range []string{"empty", "lock-only", "marker-only", "orphan-only"} {
		t.Run(shape, func(t *testing.T) {
			f := newFixture(t)
			f.config.Revision = f.commit(f.valid(), "", true)
			f.writeConfig()
			names := map[string]string{"lock-only": "high-water.lock", "marker-only": "accepted", "orphan-only": ".high-water-orphan"}
			if name := names[shape]; name != "" {
				if err := os.WriteFile(filepath.Join(f.config.StateDir, name), []byte(acceptedMarker), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadDir(f.config.StateDir)
			a := New(f.configPath, f.files, nil)
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			result, code := authorize(a)
			expectCode(t, EnrollmentUnverified, code)
			if result != (EnrolledKey{}) {
				t.Fatal("empty state released authority")
			}
			store := newFileStore(context.Background(), f.config.StateDir, f.files, f.config.ObjectFormat)
			if store.Commit(nil, registry.HighWater{}) == nil {
				t.Fatal("service Store bootstrapped")
			}
			after, _ := os.ReadDir(f.config.StateDir)
			if len(before) != len(after) {
				t.Fatal("service created bootstrap evidence")
			}
		})
	}
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, OK, code)
}

// Real permission failures at the three former pre-marker boundaries no longer
// permit a restart. Ownership substitution stays confined to this fixture.
type earlyBootstrapFiles struct {
	fixtureFiles
	state, stage string
	reached      bool
}

func (f *earlyBootstrapFiles) Lstat(path string) (Metadata, error) {
	m, err := f.fixtureFiles.Lstat(path)
	trigger := (f.stage == "state-read" && path == filepath.Join(f.state, "high-water.lock")) || (f.stage == "marker-create" && path == filepath.Join(f.state, "accepted"))
	if trigger && !f.reached {
		mode := os.FileMode(0000)
		if f.stage == "marker-create" {
			mode = 0500
		}
		if e := os.Chmod(f.state, mode); e != nil {
			return m, e
		}
		f.reached = true
	}
	return m, err
}
func TestBootstrapPreIntentCommitFailureRequiresReconciliation(t *testing.T) {
	for _, stage := range []string{"commit-lock", "state-read", "marker-create"} {
		t.Run(stage, func(t *testing.T) {
			f := newFixture(t)
			f.config.Revision = f.commit(f.valid(), "", true)
			f.writeConfig()
			files := &earlyBootstrapFiles{fixtureFiles: f.files, state: f.config.StateDir, stage: stage}
			if stage == "commit-lock" {
				if err := os.Chmod(f.config.StateDir, 0500); err != nil {
					t.Fatal(err)
				}
				files.reached = true
			}
			t.Cleanup(func() { _ = os.Chmod(f.config.StateDir, 0700) })
			err := (initialPublisher{newFileStore(context.Background(), f.config.StateDir, files, f.config.ObjectFormat)}).Commit(nil, registry.HighWater{})
			if err == nil || !files.reached || !errors.Is(err, os.ErrPermission) {
				t.Fatalf("intended pre-marker permission failure not reached: %v reached=%t", err, files.reached)
			}
			if err := os.Chmod(f.config.StateDir, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(f.config.StateDir, "accepted")); !os.IsNotExist(err) {
				t.Fatal("failure did not precede marker", err)
			}
			a := New(f.configPath, f.files, nil)
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			result, code := authorize(a)
			expectCode(t, EnrollmentUnverified, code)
			if result != (EnrolledKey{}) {
				t.Fatal("pre-marker failure released authority")
			}
		})
	}
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
}
