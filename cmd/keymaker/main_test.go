package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Version and malformed dispatch do not start a service or expose a signing path.
func TestCommandDispatch(t *testing.T) {
	for _, sample := range []struct {
		args   []string
		status int
	}{{[]string{"version"}, 0}, {nil, 2}, {[]string{"decrypt"}, 2}, {[]string{"serve", "--unknown"}, 2}} {
		var out bytes.Buffer
		if code := run(context.Background(), sample.args, &out, &out); code != sample.status {
			t.Fatal(code)
		}
	}
}

// The real production entry rejects an unsafe configuration parent before
// journal readiness or service startup. TestProductionConfigGenerationGate in
// the core separately covers a parsed configuration with no journal configured.
func TestProductionBinaryGenerationGate(t *testing.T) {
	if os.Getuid() == 0 {
		t.Fatal("test requires an unprivileged runner")
	}
	d := t.TempDir()
	binary := filepath.Join(d, "keymaker")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", binary, ".")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build failed: %v %s", e, b)
	}
	cmd := exec.Command(binary, "serve", "--config", filepath.Join(d, "unused.json"))
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + d, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "SSH_AUTH_SOCK=" + filepath.Join(d, "absent.sock")}
	out, e := cmd.CombinedOutput()
	exit, failed := e.(*exec.ExitError)
	if !failed || exit.ExitCode() != 1 || strings.TrimSpace(string(out)) != "keymaker: unsafe configuration parent" {
		t.Fatalf("production configuration must refuse before readiness: %v %s", e, out)
	}
}

// Reconciliation dispatch validates flags and requires the privileged operator;
// version is the nearby nonprivileged positive command. No system path is read.
func TestReconcileCommandDispatch(t *testing.T) {
	for _, sample := range []struct {
		args   []string
		status int
	}{
		{[]string{"enrollment", "reconcile"}, 2},
		{[]string{"enrollment", "reconcile", "--unknown"}, 2},
		{[]string{"enrollment", "reconcile", "--config", filepath.Join(t.TempDir(), "pins.json"), "extra"}, 2},
		{[]string{"enrollment", "reconcile", "--config", filepath.Join(t.TempDir(), "pins.json")}, 1},
		{[]string{"enrollment", "reconcile", "--bootstrap"}, 2},
		{[]string{"enrollment", "reconcile", "--bootstrap=invalid", "--config", filepath.Join(t.TempDir(), "pins.json")}, 2},
		{[]string{"enrollment", "reconcile", "--bootstrap", "--config", filepath.Join(t.TempDir(), "pins.json")}, 1},
		{[]string{"version"}, 0},
	} {
		var out bytes.Buffer
		if status := run(context.Background(), sample.args, &out, &out); status != sample.status {
			t.Fatalf("%v: %d %s", sample.args, status, &out)
		}
	}
}
