package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The delayed real mkdirat return exposes the producer's mkdir/open window.
// Substitution must refuse before adopting unrelated contents; no-swap opens.
func TestReleaseConcurrentTargetCreation(t *testing.T) {
	for _, attack := range []bool{false, true} {
		t.Run(fmt.Sprint(attack), func(t *testing.T) {
			base := t.TempDir()
			if err := os.Chmod(base, 0700); err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(base, "foreign")
			target := filepath.Join(base, "target")
			if err := os.Mkdir(foreign, 0700); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, filepath.Join(foreign, "sentinel"), []byte("preserve"))
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "strace", "-f", "-e", "trace=mkdirat,openat2", "-e", "inject=mkdirat:delay_exit=500ms:when=1", "-o", filepath.Join(base, "trace"), exe, "-test.run=^TestReleaseCreationHelper$")
			cmd.Env = append(os.Environ(), "RELEASE_CREATION_HELPER="+base)
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Logf("creation probe pid=%d", cmd.Process.Pid)
			waitFile(t, target)
			if attack {
				if err := os.Rename(target, filepath.Join(base, "moved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(foreign, target); err != nil {
					t.Fatal(err)
				}
			}
			err = cmd.Wait()
			witness := foreign
			if attack {
				witness = target
				if err == nil || !strings.Contains(out.String(), "root-refused") {
					t.Fatal("concurrent nonempty root admitted", err, out.String())
				}
			} else if err != nil {
				t.Fatal("creation control refused", err, out.String())
			}
			raw, err := os.ReadFile(filepath.Join(witness, "sentinel"))
			if err != nil || string(raw) != "preserve" {
				t.Fatal("creation swap deleted unrelated sentinel", err)
			}
		})
	}
}

// Test subprocess only; no fixture Git operations or production child helpers.
func TestReleaseCreationHelper(t *testing.T) {
	base := os.Getenv("RELEASE_CREATION_HELPER")
	if base == "" {
		return
	}
	parent, err := openRootNoLinks(base)
	if err != nil {
		os.Exit(3)
	}
	root, err := createTarget(parent, "target")
	if err != nil {
		fmt.Fprintln(os.Stdout, "root-refused")
		os.Exit(1)
	}
	ledger := &createdObjects{}
	if ledger.writeFile(root, "ours", []byte("created"), 0600) != nil || ledger.cleanup(root) != nil {
		os.Exit(4)
	}
	ledger.close()
	root.Close()
	parent.Close()
	os.Exit(0)
}

// Real adoption refuses nonempty/wrong-mode roots unchanged; an empty 0700
// root opens. Foreign ownership is a stat-policy control, not a chown claim:
// this unprivileged suite has no authority to create another uid's directory.
func TestReleaseAdoptedRoot(t *testing.T) {
	for _, kind := range []string{"empty", "nonempty", "mode", "foreign-stat"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			name := filepath.Join(base, "root")
			if err := os.Mkdir(name, 0700); err != nil {
				t.Fatal(err)
			}
			if kind == "nonempty" {
				writeFixture(t, filepath.Join(name, "sentinel"), []byte("preserve"))
			}
			if kind == "mode" {
				if err := os.Chmod(name, 0755); err != nil {
					t.Fatal(err)
				}
			}
			parent, err := openRootNoLinks(base)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			if kind == "foreign-stat" {
				var st unix.Stat_t
				if unix.Stat(name, &st) != nil {
					t.Fatal("stat")
				}
				st.Uid = uint32(os.Geteuid() + 1)
				if validRootStat(st) {
					t.Fatal("foreign owner admitted")
				}
				return
			}
			root, err := adoptTarget(parent, "root")
			if kind == "empty" {
				if err != nil {
					t.Fatal("empty root control refused", err)
				}
				root.Close()
				return
			}
			if root != nil {
				root.Close()
			}
			if !errors.Is(err, errTarget) {
				t.Fatal("unsafe adopted root admitted", kind, err)
			}
			if kind == "nonempty" {
				raw, err := os.ReadFile(filepath.Join(name, "sentinel"))
				if err != nil || string(raw) != "preserve" {
					t.Fatal("adoption altered unrelated sentinel", err)
				}
			}
		})
	}
}

// Cleanup removes recorded creations but preserves unknown files, substituted
// inodes and unknown directory descendants. No recursive ownership inference.
func TestReleaseCleanupCreatedOnly(t *testing.T) {
	for _, kind := range []string{"control", "unrelated", "replacement", "descendant"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			root, err := openRootNoLinks(base)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			owned := &createdObjects{}
			defer owned.close()
			if err := owned.writeFile(root, "ours", []byte("ours"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := mkdirRootAll(root, "nested", owned); err != nil {
				t.Fatal(err)
			}
			if err := owned.writeFile(root, "nested/ours", []byte("ours"), 0600); err != nil {
				t.Fatal(err)
			}
			witness := ""
			switch kind {
			case "unrelated":
				witness = "foreign"
			case "replacement":
				if err := os.Remove(filepath.Join(base, "ours")); err != nil {
					t.Fatal(err)
				}
				witness = "ours"
			case "descendant":
				witness = "nested/foreign"
			}
			if witness != "" {
				writeFixture(t, filepath.Join(base, witness), []byte("preserve"))
			}
			if err := owned.cleanup(root); err != nil {
				t.Fatal(err)
			}
			if witness != "" {
				raw, err := os.ReadFile(filepath.Join(base, witness))
				if err != nil || string(raw) != "preserve" {
					t.Fatal("cleanup removed unrelated object", kind, err)
				}
			} else {
				emptyTarget(t, base)
			}
			absent(t, filepath.Join(base, "nested/ours"))
			if kind != "replacement" {
				absent(t, filepath.Join(base, "ours"))
			}
		})
	}
}

// Group/world writable nonsticky parents refuse before creating any entry.
// Private and self-owned sticky parents are the paired permitted controls.
func TestReleaseParentPermissions(t *testing.T) {
	for _, kind := range []string{"private", "group", "world", "sticky"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			mode := os.FileMode(0700)
			if kind == "group" {
				mode = 0770
			}
			if kind == "world" {
				mode = 0777
			}
			if kind == "sticky" {
				mode = 0777 | os.ModeSticky
			}
			if err := os.Chmod(base, mode); err != nil {
				t.Fatal(err)
			}
			parent, err := openRootNoLinks(base)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			root, err := createTarget(parent, "bundle")
			if kind == "group" || kind == "world" {
				if root != nil {
					root.Close()
				}
				if !errors.Is(err, errTarget) {
					t.Fatal("writable parent admitted", err)
				}
				absent(t, filepath.Join(base, "bundle"))
			} else {
				if err != nil {
					t.Fatal("safe parent refused", err)
				}
				root.Close()
			}
		})
	}
}

// A trusted Git executable wrapper is a bounded instrument for the write
// boundary itself: outside writes fail; scratch writes succeed. The parent
// retains its authority. Actual filter refusal is exercised separately below.
func TestReleaseGitPreflightBoundary(t *testing.T) {
	for _, attack := range []bool{false, true} {
		t.Run(fmt.Sprint(attack), func(t *testing.T) {
			f := newFixture(t)
			base := filepath.Dir(f.o.config)
			victim := filepath.Join(base, "victim")
			writeFixture(t, victim, []byte("preserve"))
			git, err := exec.LookPath("git")
			if err != nil {
				t.Fatal(err)
			}
			bin := wrapperDir(t, f)
			destination := "/proc/self/fd/3/inside"
			if attack {
				destination = victim
			}
			attempt := "printf changed > " + shellQuote(destination)
			if attack {
				attempt += " 2>/dev/null || :"
			}
			script(t, filepath.Join(bin, "git"), attempt+"\nexec "+shellQuote(git)+" \"$@\"\n")
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			if _, err := gitRead(context.Background(), f.o.repo, "rev-parse", "HEAD"); err != nil {
				t.Fatal("Git control refused", err)
			}
			raw, err := os.ReadFile(victim)
			if err != nil || string(raw) != "preserve" {
				t.Fatal("Git preflight escaped scratch boundary", err)
			}
			if !attack {
				markers, _ := filepath.Glob(filepath.Join(os.TempDir(), "release-git-*/inside"))
				if len(markers) != 1 {
					t.Fatal("scratch write control missing", markers)
				}
				raw, err := os.ReadFile(markers[0])
				if err != nil || string(raw) != "changed" {
					t.Fatal("scratch write control differs", err)
				}
			}
			writeFixture(t, filepath.Join(base, "parent-authorized"), nil)
		})
	}
}

func fixtureGitConfig(t *testing.T, f fixture, key, value string) {
	t.Helper()
	if err := runCommand(gitCommand(context.Background(), f.o.repo, "config", "--local", key, value)); err != nil {
		t.Fatal(err)
	}
}

// Filters selected via external attributes, info/attributes and .gitattributes
// refuse explicitly before any filter runs. Removing the selection restores
// valid preflight; scripts attempt outside mutation if actually executed.
func TestReleaseConfiguredFilters(t *testing.T) {
	for _, kind := range []string{"attributes-file", "local-config", "gitattributes"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			base := filepath.Dir(f.o.config)
			victim := filepath.Join(base, "sentinel")
			writeFixture(t, victim, []byte("preserve"))
			filter := filepath.Join(base, "filter")
			script(t, filter, ": > /proc/self/fd/3/filter-ran\n"+"printf changed > "+shellQuote(victim)+" 2>/dev/null || :\nexec /usr/bin/cat\n")
			fixtureGitConfig(t, f, "filter.fixture.clean", filter)
			fixtureGitConfig(t, f, "filter.fixture.smudge", filter)
			attrs := filepath.Join(f.o.repo, ".git/info/attributes")
			if kind == "attributes-file" {
				attrs = filepath.Join(base, "attributes")
				fixtureGitConfig(t, f, "core.attributesFile", attrs)
			}
			if kind == "gitattributes" {
				attrs = filepath.Join(f.o.repo, ".gitattributes")
			}
			writeFixture(t, attrs, []byte("cmd/keymaker/main.go filter=fixture\n"))
			stamp := time.Now().Add(5 * time.Second)
			if err := os.Chtimes(filepath.Join(f.o.repo, "cmd/keymaker/main.go"), stamp, stamp); err != nil {
				t.Fatal(err)
			}
			_, err := prepare(context.Background(), f.o)
			if !errors.Is(err, errFilter) {
				t.Fatal("configured filter admitted", err)
			}
			raw, e := os.ReadFile(victim)
			if e != nil || string(raw) != "preserve" {
				t.Fatal("filter wrote outside scratch", e)
			}
			absent(t, f.o.target)
			markers, _ := filepath.Glob(filepath.Join(os.TempDir(), "release-git-*/filter-ran"))
			if len(markers) != 0 {
				t.Fatal("configured filter ran", markers)
			}
			if err := os.Remove(attrs); err != nil {
				t.Fatal(err)
			}
			control(t, f)
		})
	}
}

// Hostile repository fsmonitor, hooks, textconv and external diff must never
// execute. Their selected programs are read-only test scripts with a sentinel;
// a plain clean clone is the positive control for the same raw-byte comparison.
func TestReleaseConfiguredPrograms(t *testing.T) {
	f := newFixture(t)
	base := filepath.Dir(f.o.config)
	marker := filepath.Join(base, "executed")
	program := filepath.Join(base, "program")
	script(t, program, ": > /proc/self/fd/3/configured-program-ran\n"+"printf executed > "+shellQuote(marker)+"\nexit 1\n")
	hooks := filepath.Join(base, "hooks")
	if err := os.Mkdir(hooks, 0700); err != nil {
		t.Fatal(err)
	}
	script(t, filepath.Join(hooks, "post-checkout"), "printf executed > "+shellQuote(marker)+"\n")
	fixtureGitConfig(t, f, "core.fsmonitor", program)
	fixtureGitConfig(t, f, "core.hooksPath", hooks)
	fixtureGitConfig(t, f, "diff.external", program)
	fixtureGitConfig(t, f, "diff.fixture.textconv", program)
	writeFixture(t, filepath.Join(f.o.repo, ".git/info/attributes"), []byte("cmd/keymaker/main.go diff=fixture\n"))
	control(t, f)
	absent(t, marker)
	markers, _ := filepath.Glob(filepath.Join(os.TempDir(), "release-git-*/configured-program-ran"))
	if len(markers) != 0 {
		t.Fatal("repository program ran", markers)
	}
	control(t, newFixture(t))
}

// The verified /dev/null control opens. Without privilege to create a real
// character device in the fixture, a regular-file substitution exercises the
// actual open/fstat refusal; synthetic fstat values also narrow the rdev guard.
func TestReleaseNullDeviceVerification(t *testing.T) {
	file, err := openNullDevice(os.DevNull)
	if err != nil {
		t.Fatal("real null device refused", err)
	}
	file.Close()
	base := t.TempDir()
	name := filepath.Join(base, "not-null")
	if err := unix.Mknod(name, unix.S_IFCHR|0600, int(unix.Mkdev(1, 5))); err != nil {
		if err != unix.EPERM && err != unix.EACCES {
			t.Fatal(err)
		}
		t.Log("unprivileged mknod refused; using real regular-file substitution and synthetic wrong-rdev stat")
		writeFixture(t, name, []byte("preserve"))
	}
	substitute, err := openNullDevice(name)
	if substitute != nil {
		substitute.Close()
	}
	if err == nil {
		t.Fatal("substituted null device admitted")
	}
	st := unix.Stat_t{Mode: unix.S_IFCHR | 0600, Rdev: unix.Mkdev(1, 5)}
	if validNullStat(st) {
		t.Fatal("wrong rdev admitted")
	}
	st.Rdev = unix.Mkdev(1, 3)
	if !validNullStat(st) {
		t.Fatal("null rdev control refused")
	}
}
