//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"testing"
)

// A dedicated child proves actual role startup replaces a larger runtime limit
// before state load; an unselected role is the paired no-global-side-effect case.
func TestMALiveRuntimeMemoryLimit(t *testing.T) {
	if root := os.Getenv("KEYMAKER_MA_MEMORY_CHILD"); root == "" {
		root = t.TempDir()
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "-test.run=^TestMALiveRuntimeMemoryLimit$", "-test.v")
		cmd.Env = append(os.Environ(), "KEYMAKER_MA_MEMORY_CHILD="+root, "GOTMPDIR="+root)
		var log bytes.Buffer
		cmd.Stdout = &log
		cmd.Stderr = &log
		err = cmd.Run()
		t.Log(log.String())
		if err != nil {
			t.Fatal("memory policy child", err)
		}
		return
	} else if !filepath.IsAbs(root) || root != os.Getenv("GOTMPDIR") {
		t.Fatal("memory child outside isolated scratch")
	}
	previous := debug.SetMemoryLimit(384 << 20)
	defer debug.SetMemoryLimit(previous)
	if err := serveMALive(context.Background(), Config{}, nil, maLiveServiceDeps{}); err == nil {
		t.Fatal("unselected role accepted")
	}
	if got := debug.SetMemoryLimit(-1); got != 384<<20 {
		t.Fatal("unselected role changed runtime limit", got)
	}
	cfg := Config{maLive: &maLiveConfiguration{}}
	if err := serveMALive(context.Background(), cfg, nil, maLiveServiceDeps{}); err != Code("generation_source_unavailable") {
		t.Fatal("startup refusal changed", err)
	}
	if got := debug.SetMemoryLimit(-1); got != 192<<20 {
		t.Fatal("startup runtime memory limit missing", got)
	}
}
