//go:build linux && multiuid

package keymaker

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/testwindow"
)

// This runs in the existing keymaker-window runner (whose ^TestMultiUID filter
// includes it). It is PENDING without the provisioned window, never silently
// skipped. A real distinct UID creates/owns the object: the runner-owner pin
// refuses, that UID's valid identity admits, and a changed actual mode refuses.
// These fixtures do not qualify deployment of the root-owned protected fence.
func TestMultiUIDPC2FenceIdentity(t *testing.T) {
	if os.Getenv("KEYMAKER_PC2_FOREIGN_FENCE") == "1" {
		expected, e := strconv.ParseUint(os.Getenv("KEYMAKER_PC2_EXPECT_OWNER"), 10, 32)
		if e != nil || uint32(expected) == uint32(os.Getuid()) {
			t.Fatal("foreign owner fixture not distinct")
		}
		f := pc2FenceSetup(t)
		own := f.policy.Authority.UID
		f.policy.Authority.UID = uint32(expected)
		pc2FenceRefusal(t, f, "foreign_actual_owner", "fence_identity")
		f.policy.Authority.UID = own
		c, e := openAuthorityFence(f.dir, f.policy)
		if e != nil {
			t.Fatal(e)
		}
		l, e := c.TryLock()
		if e != nil {
			c.Close()
			t.Fatal(e)
		}
		l.Close()
		if e = os.Chmod(filepath.Join(f.path, "authority.lock"), 0600); e != nil {
			t.Fatal(e)
		}
		pc2FenceRefusal(t, f, "foreign_actual_mode", "fence_identity")
		return
	}
	cfg, status, e := testwindow.Load(os.Getenv("KEYMAKER_WINDOW_CONFIG"))
	if e != nil {
		t.Fatalf("PENDING: test window not provisioned (runner status %d): %v", status, e)
	}
	w, status, e := testwindow.Verify(cfg, uint32(os.Getuid()), testwindow.CommandOutput)
	if e != nil {
		t.Fatalf("PENDING: window status %d: %v", status, e)
	}
	// Existing runner scratch is traversable by its provisioned clients. Give the
	// foreign process its own writable temp root without changing shared services.
	parent := os.Getenv("KEYMAKER_WINDOW_SCRATCH")
	if parent == "" {
		t.Fatal("PENDING: run through keymaker-window for client-traversable scratch")
	}
	scratch, e := os.MkdirTemp(parent, "pc2-fence-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := os.RemoveAll(scratch); e != nil {
			t.Errorf("retained window fixture %s: %v", scratch, e)
		}
	})
	if e = os.Chmod(scratch, 0777); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "-n", "-u", w.A, "--", "/usr/bin/env", "KEYMAKER_PC2_FOREIGN_FENCE=1", "KEYMAKER_PC2_EXPECT_OWNER="+strconv.FormatUint(uint64(w.UID), 10), "TMPDIR="+scratch, os.Args[0], "-test.run=^TestMultiUIDPC2FenceIdentity$", "-test.timeout=8s", "-keymaker-window-token="+*windowToken)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Logf("foreign owner child pid=%d", cmd.Process.Pid)
	if e = cmd.Wait(); e != nil {
		t.Fatalf("foreign owner/mode qualification: %v %s", e, output.Bytes())
	}
}
