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

// A real production binary has no fixture-generation switch and cannot serve or
// sign before the journal format exists. A fake-backed positive is kept in the
// core's TestProductionGenerationRefuses and TestRealClients.
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
	if !failed || exit.ExitCode() != 1 || strings.TrimSpace(string(out)) != "generation_source_unavailable" {
		t.Fatalf("production admission must refuse: %v %s", e, out)
	}
}
