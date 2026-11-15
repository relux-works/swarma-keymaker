//go:build linux && multiuid

package keymaker

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/testwindow"
)

// PENDING until the operator supplies the reviewed multi-UID window, a protected
// scratch root and a readable test binary. This is a real different-UID client:
// mode checks under a fabricated peer never satisfy it. No accounts or policies
// are provisioned by this test. Missing inputs fail explicitly, not as a pass.
func TestMultiUIDJ7PolicyProtection(t *testing.T) {
	if os.Getenv("KEYMAKER_J7_POLICY_CLIENT") == "1" {
		want, e := strconv.ParseUint(os.Getenv("KEYMAKER_J7_EXPECTED_UID"), 10, 32)
		if e != nil || want == 0 || uint32(want) != uint32(os.Getuid()) {
			t.Fatal("foreign UID not established")
		}
		path := os.Getenv("KEYMAKER_J7_POLICY_PATH")
		if !filepath.IsAbs(path) {
			t.Fatal("client fixture path")
		}
		for _, effect := range []func() error{func() error { return os.WriteFile(path, []byte("forbidden fixture policy"), 0600) }, func() error { return os.WriteFile(path+".replace", []byte("forbidden replacement"), 0600) }, func() error { return os.Rename(path, path+".moved") }} {
			e := effect()
			if !errors.Is(e, syscall.EACCES) && !errors.Is(e, syscall.EPERM) {
				t.Fatal("distinct UID was not specifically denied policy mutation", e)
			}
		}
		return
	}
	config := os.Getenv("KEYMAKER_WINDOW_CONFIG")
	root := os.Getenv("KEYMAKER_J7_PROTECTED_TEST_ROOT")
	if config == "" || root == "" || !messageID(*windowToken) {
		t.Fatal("PENDING: reviewed window configuration, non-secret window token and holder-owned protected scratch root required")
	}
	cfg, status, e := testwindow.Load(config)
	if e != nil || status != 0 {
		t.Fatalf("PENDING: window configuration status=%d error=%v", status, e)
	}
	window, status, e := testwindow.Verify(cfg, uint32(os.Getuid()), testwindow.CommandOutput)
	if e != nil || status != 0 {
		t.Fatalf("PENDING: current authorized window verification status=%d error=%v", status, e)
	}
	protected, e := j7PolicyDirectory(root, uint32(os.Getuid()))
	if e != nil {
		t.Fatal("PENDING: scratch ancestry is not protected", e)
	}
	protected.Close()
	dir := filepath.Join(root, "j7-policy-"+*windowToken)
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal("fresh exact-token fixture required", e)
	}
	defer os.RemoveAll(dir)
	f := j7StateSetup(t)
	path := filepath.Join(dir, "table.json")
	p, e := newJ7Policy(path, f.uid, f.store, f.store.j7.Instance, f.binding.Number)
	if e != nil {
		t.Fatal("protected path positive", e)
	}
	defer p.close()
	raw := j7PolicyRaw(t, f.table(1))
	if c := p.publish(t.Context(), raw); c != "" {
		t.Fatal("holder positive", c)
	}
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	for _, client := range []struct {
		name string
		uid  uint32
	}{{window.A, window.AID}, {window.B, window.BID}} {
		cmd := exec.Command("sudo", windowPolicyArguments(window, client.name, client.uid, path, exe, *windowToken)...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C"}
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		if e := cmd.Start(); e != nil {
			t.Fatal("PENDING: reviewed foreign-UID invocation unavailable", e)
		}
		t.Logf("foreign policy client pid=%d uid=%d", cmd.Process.Pid, client.uid)
		if e := cmd.Wait(); e != nil {
			t.Fatalf("foreign policy client failed: %v %s", e, output.String())
		}
	}
	actual, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(raw, actual) {
		t.Fatal("agent changed table", e)
	}
	next := f.table(2)
	if c := p.publish(t.Context(), j7PolicyRaw(t, next)); c != "" {
		t.Fatal("holder publication after refusals", c)
	}
}

func windowPolicyArguments(w testwindow.Window, user string, uid uint32, path, executable, token string) []string {
	return w.ClientArgs(user, "", "KEYMAKER_J7_POLICY_CLIENT=1", "KEYMAKER_J7_EXPECTED_UID="+strconv.FormatUint(uint64(uid), 10), "KEYMAKER_J7_POLICY_PATH="+path, executable, "-test.run=^TestMultiUIDJ7PolicyProtection$", "-test.timeout=10s", "-keymaker-window-token="+token)
}
