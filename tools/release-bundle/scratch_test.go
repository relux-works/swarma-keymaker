package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// MkdirTemp creates no intermediate directory whose mode could be masked by
// the caller's umask. Explicit chmod establishes the final mode before use;
// neither the caller's TMPDIR nor any pre-existing object is chmodded.
func privateTestScratch(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "release-test-")
	if err != nil {
		t.Fatal("create private test scratch", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error("remove test scratch", err)
		}
	})
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("chmod test scratch", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal("stat test scratch", err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		t.Fatal("test scratch must be an owned mode-0700 directory")
	}
	return dir
}

// The helper establishes exact ownership/mode even under an independently
// restrictive umask; the caller's TMPDIR permissions are left unchanged.
func TestReleasePrivateScratch(t *testing.T) {
	caller := os.TempDir()
	before, err := os.Stat(caller)
	if err != nil {
		t.Fatal(err)
	}
	dir := privateTestScratch(t)
	t.Setenv("TMPDIR", dir)
	if os.TempDir() != dir {
		t.Fatal("test scratch not passed as TMPDIR")
	}
	after, err := os.Stat(caller)
	if err != nil || after.Mode() != before.Mode() {
		t.Fatal("caller TMPDIR mode changed", err)
	}
}

// Explicitly unsafe scratch parents refuse with errTarget and create nothing;
// a fresh private helper root is a paired successful production scratch control.
func TestReleaseScratchPermissions(t *testing.T) {
	t.Setenv("TMPDIR", privateTestScratch(t))
	for _, mode := range []os.FileMode{0775, 0707} {
		t.Run(mode.String(), func(t *testing.T) {
			dir := privateTestScratch(t)
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TMPDIR", dir)
			root, name, cleanup, err := privateScratch("refusal-")
			if cleanup != nil {
				cleanup()
			}
			if root != nil || name != "" || !errors.Is(err, errTarget) {
				t.Fatal("unsafe scratch parent admitted", err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatal("unsafe scratch refusal created entries", err)
			}
			safe := privateTestScratch(t)
			t.Setenv("TMPDIR", safe)
			root, name, cleanup, err = privateScratch("control-")
			if err != nil {
				t.Fatal("private scratch control refused", err)
			}
			defer cleanup()
			if filepath.Dir(name) != safe {
				t.Fatal("scratch escaped selected private parent")
			}
			info, err := root.Stat(".")
			if err != nil {
				t.Fatal(err)
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) {
				t.Fatal("production scratch control permissions differ")
			}
		})
	}
}
