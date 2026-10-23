package enrollment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// An operator approval is scoped to a fresh startup challenge and exact state.
// Old-start, wrong-state and unsafe-owner records fail; an explicit matching
// root input is the control. Fixture metadata does not attest a live operator.
func TestOperatorStartupReconciliation(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	path := filepath.Join(f.base, "operator-approval.json")
	current, err := NewOperatorReconciler(path, f.files)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewOperatorReconciler(path, f.files)
	if err != nil {
		t.Fatal(err)
	}
	write := func(startup, digest string) {
		b, err := json.Marshal(map[string]string{"startup_id": startup, "state_sha256": digest})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"missing", "earlier-start", "wrong-state", "unsafe-owner"} {
		t.Run(name, func(t *testing.T) {
			switch name {
			case "missing":
				_ = os.Remove(path)
			case "earlier-start":
				write(other.Challenge(), StateDigest(a.retained))
			case "wrong-state":
				write(current.Challenge(), "wrong")
			case "unsafe-owner":
				write(current.Challenge(), StateDigest(a.retained))
				f.files.override[path] = Metadata{Mode: 0600, UID: 42}
			}
			restarted := New(f.configPath, f.files, current)
			expectCode(t, EnrollmentUnverified, restarted.Reload(context.Background()))
			delete(f.files.override, path)
			write(current.Challenge(), StateDigest(a.retained))
			expectCode(t, OK, restarted.Reload(context.Background()))
			_, code := authorize(restarted)
			expectCode(t, OK, code)
		})
	}
	// Even a correct approval cannot be reused by the next process-start instance.
	next, err := NewOperatorReconciler(path, f.files)
	if err != nil {
		t.Fatal(err)
	}
	restarted := New(f.configPath, f.files, next)
	expectCode(t, EnrollmentUnverified, restarted.Reload(context.Background()))
	write(next.Challenge(), StateDigest(a.retained))
	expectCode(t, OK, restarted.Reload(context.Background()))
}
