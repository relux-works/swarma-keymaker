package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func script(t *testing.T, name, body string) {
	t.Helper()
	if err := os.WriteFile(name, []byte("#!/bin/sh\nset -eu\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
}
func pause(ready, release string) string {
	return ": > " + shellQuote(ready) + "\ni=0\nwhile [ ! -e " + shellQuote(release) + " ]; do i=$((i+1)); [ \"$i\" -lt 3000 ] || exit 124; /bin/sleep 0.01; done\n"
}
func waitFile(t *testing.T, name string) {
	t.Helper()
	end := time.Now().Add(40 * time.Second)
	for time.Now().Before(end) {
		if _, err := os.Stat(name); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("fixture synchronization not reached", name)
}
func waitScratch(t *testing.T, pattern string) string {
	t.Helper()
	end := time.Now().Add(40 * time.Second)
	for time.Now().Before(end) {
		matches, _ := filepath.Glob(filepath.Join(os.TempDir(), pattern))
		if len(matches) == 1 {
			return matches[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("fixture scratch synchronization not reached", pattern)
	return ""
}
func runOptions(ctx context.Context, o options) (int, string) {
	args := []string{"-repo", o.repo, "-commit", o.commit, "-version", o.version, "-target", o.target, "-config", o.config, "-name-indices", o.registry}
	if o.moduleCache != "" {
		args = append(args, "-module-cache", o.moduleCache)
	}
	var out, diagnostic bytes.Buffer
	code := run(ctx, args, &out, &diagnostic)
	return code, diagnostic.String()
}
func wrapperDir(t *testing.T, f fixture) string {
	t.Helper()
	dir := filepath.Join(filepath.Dir(f.o.config), "wrappers")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Swapping the checked parent before target creation never redirects extraction.
// Both cases reach the extracted source and then intentionally fail the fake Go
// build, preserving the outside directory and retaining an empty pinned target.
func TestReleaseParentSwap(t *testing.T) {
	for _, attack := range []bool{false, true} {
		t.Run(fmt.Sprint(attack), func(t *testing.T) {
			f := newFixture(t)
			base := filepath.Dir(f.o.config)
			parent, outside := filepath.Join(base, "parent"), filepath.Join(base, "outside")
			for _, name := range []string{parent, outside} {
				if err := os.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
			}
			f.o.target = filepath.Join(parent, "bundle")
			git, err := exec.LookPath("git")
			if err != nil {
				t.Fatal(err)
			}
			bin := wrapperDir(t, f)
			ready, release := "/proc/self/fd/3/ready", "/proc/self/fd/3/release"
			script(t, filepath.Join(bin, "git"), "for a in \"$@\"; do last=$a; done\ncase \"$last\" in *:cmd/keymaker/main.go)\n"+pause(ready, release)+";; esac\nexec "+shellQuote(git)+" \"$@\"\n")
			script(t, filepath.Join(bin, "go"), pause("/proc/self/fd/3/.build/ready", "/proc/self/fd/3/.build/release")+"exit 77\n")
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
			defer cancel()
			type result struct {
				code       int
				diagnostic string
			}
			done := make(chan result, 1)
			go func() { code, diagnostic := runOptions(ctx, f.o); done <- result{code, diagnostic} }()
			readyFile := waitScratch(t, "release-git-*/ready")
			actual := parent
			if attack {
				actual = parent + "-moved"
				if err := os.Rename(parent, actual); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, parent); err != nil {
					t.Fatal(err)
				}
			}
			writeFixture(t, filepath.Join(filepath.Dir(readyFile), "release"), nil)
			selected := filepath.Join(actual, "bundle")
			buildReady := waitScratch(t, "release-build-*/.build/ready")
			_, sourceErr := os.Stat(filepath.Join(filepath.Dir(buildReady), "source/go.mod"))
			entries, outsideErr := os.ReadDir(outside)
			writeFixture(t, filepath.Join(filepath.Dir(buildReady), "release"), nil)
			got := <-done
			if got.code != 1 || !strings.Contains(got.diagnostic, "offline keymaker build failed") {
				t.Fatal("wrong controlled failure", got)
			}
			if sourceErr != nil {
				t.Fatal("pinned source extraction missing", sourceErr)
			}
			if outsideErr != nil || len(entries) != 0 {
				t.Fatal("parent swap redirected writes outside pinned target", outsideErr)
			}
			emptyTarget(t, selected)
		})
	}
}

// A link planted after real compilation must not overwrite a sibling victim.
// The unmodified control assembles a complete bundle through the same CLI.
func TestReleaseOutputSymlink(t *testing.T) {
	for _, attack := range []bool{false, true} {
		t.Run(fmt.Sprint(attack), func(t *testing.T) {
			f := newFixture(t)
			f.o.moduleCache = fixtureModuleCache(t)
			base := filepath.Dir(f.o.config)
			victim := filepath.Join(base, "victim")
			original := []byte("preserve sibling\n")
			writeFixture(t, victim, original)
			realGo, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			bin := wrapperDir(t, f)
			script(t, filepath.Join(bin, "go"), shellQuote(realGo)+" \"$@\" &\nchild=$!\nprintf '%s\\n' \"$child\" > /proc/self/fd/3/.build/go-child.pid\nwait \"$child\"\n"+pause("/proc/self/fd/3/.build/ready", "/proc/self/fd/3/.build/release"))
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			type result struct {
				code       int
				diagnostic string
			}
			done := make(chan result, 1)
			go func() { code, diagnostic := runOptions(ctx, f.o); done <- result{code, diagnostic} }()
			buildReady := waitScratch(t, "release-build-*/.build/ready")
			if attack {
				if err := os.Symlink(victim, filepath.Join(f.o.target, "config.json")); err != nil {
					t.Fatal(err)
				}
			}
			writeFixture(t, filepath.Join(filepath.Dir(buildReady), "release"), nil)
			got := <-done
			after, err := os.ReadFile(victim)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("output symlink overwrote sibling victim", err)
			}
			if attack {
				if got.code != 1 {
					t.Fatal("output link admitted", got)
				}
				st, err := os.Lstat(filepath.Join(f.o.target, "config.json"))
				if err != nil || st.Mode()&os.ModeSymlink == 0 {
					t.Fatal("cleanup deleted unrelated output link", err)
				}
			} else if got.code != 0 {
				t.Fatal("valid bundle refused", got)
			}
		})
	}
}

// A replace ref must not change the full commit's exported source or recorded
// tree. Both cases build the actual named tree; the pin is captured independently
// before the replacement plant, using existing commits and no signing key.
func TestReleaseReplacementCommit(t *testing.T) {
	for _, attack := range []bool{false, true} {
		t.Run(fmt.Sprint(attack), func(t *testing.T) {
			f := newFixture(t)
			f.o.moduleCache = fixtureModuleCache(t)
			expected, err := gitRead(context.Background(), f.o.repo, "rev-parse", f.o.commit+"^{tree}")
			if err != nil {
				t.Fatal(err)
			}
			if attack {
				older, err := gitRead(context.Background(), f.o.repo, "rev-parse", f.o.commit+"^")
				if err != nil {
					t.Fatal(err)
				}
				if err := runCommand(gitCommand(context.Background(), f.o.repo, "replace", f.o.commit, strings.TrimSpace(string(older)))); err != nil {
					t.Fatal(err)
				}
			}
			code, diagnostic := runOptions(context.Background(), f.o)
			if code != 0 {
				t.Fatal("replacement changed release provenance", code, diagnostic)
			}
			raw, err := os.ReadFile(filepath.Join(f.o.target, "VERSION.json"))
			if err != nil {
				t.Fatal(err)
			}
			var record versionRecord
			if err := json.Unmarshal(raw, &record); err != nil {
				t.Fatal(err)
			}
			if record.Commit != f.o.commit || record.Tree != strings.TrimSpace(string(expected)) {
				t.Fatal("replacement changed release provenance", record)
			}
		})
	}
}

// Local graft/shallow hints are ignored; object alternates are refused. Host
// GIT_* redirects never enter child environments. Each case restores the same
// clean source as a control; no registry/network or host keys participate.
func TestReleaseGitTrustMetadata(t *testing.T) {
	for _, kind := range []string{"grafts", "shallow", "alternates", "http-alternates", "object-link", "environment"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			ctx := context.Background()
			var planted string
			switch kind {
			case "grafts":
				planted = filepath.Join(f.o.repo, ".git/info/grafts")
				writeFixture(t, planted, []byte("not valid graft metadata\n"))
			case "shallow":
				planted = filepath.Join(f.o.repo, ".git/shallow")
				writeFixture(t, planted, []byte("not valid shallow metadata\n"))
			case "alternates", "http-alternates":
				planted = filepath.Join(f.o.repo, ".git/objects/info", kind)
				writeFixture(t, planted, []byte(filepath.Join(filepath.Dir(f.o.config), "foreign-objects")+"\n"))
			case "object-link":
				objects := filepath.Join(f.o.repo, ".git/objects")
				if err := os.Rename(objects, objects+"-original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(objects+"-original", objects); err != nil {
					t.Fatal(err)
				}
				planted = objects
			case "environment":
				for _, key := range []string{"GIT_DIR", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_INDEX_FILE", "GIT_WORK_TREE", "GIT_GRAFT_FILE", "GIT_SHALLOW_FILE"} {
					t.Setenv(key, filepath.Join(filepath.Dir(f.o.config), "untrusted"))
				}
				t.Setenv("GIT_NO_REPLACE_OBJECTS", "0")
			}
			_, err := prepare(ctx, f.o)
			if strings.Contains(kind, "alternates") || kind == "object-link" {
				if !errors.Is(err, errCommit) {
					t.Fatal("alternates not refused", err)
				}
			} else if err != nil {
				t.Fatal("local Git metadata redirected source", err)
			}
			absent(t, f.o.target)
			if planted != "" {
				if err := os.Remove(planted); err != nil {
					t.Fatal(err)
				}
				if kind == "object-link" {
					if err := os.Rename(planted+"-original", planted); err != nil {
						t.Fatal(err)
					}
				}
			}
			control(t, f)
		})
	}
}

// A different valid archive must fail the actual pre-build tree check, while the
// unaltered export builds successfully. The wrapper changes only archive bytes.
func TestReleaseExportTreeMismatch(t *testing.T) {
	for _, attack := range []bool{false, true} {
		t.Run(fmt.Sprint(attack), func(t *testing.T) {
			f := newFixture(t)
			f.o.moduleCache = fixtureModuleCache(t)
			if attack {
				git, err := exec.LookPath("git")
				if err != nil {
					t.Fatal(err)
				}
				bin := wrapperDir(t, f)
				script(t, filepath.Join(bin, "git"), "for a in \"$@\"; do if [ \"$a\" = archive ]; then exec "+shellQuote(git)+" --no-replace-objects -C "+shellQuote(f.o.repo)+" archive --format=tar "+shellQuote(f.o.commit+"^^{tree}")+"; fi; done\nexec "+shellQuote(git)+" \"$@\"\n")
				t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			}
			code, diagnostic := runOptions(context.Background(), f.o)
			if attack {
				if code != 1 || !strings.Contains(diagnostic, errTree.Error()) {
					t.Fatal("export tree mismatch admitted", code, diagnostic)
				}
				emptyTarget(t, f.o.target)
			} else if code != 0 {
				t.Fatal("exact tree control refused", code, diagnostic)
			}
		})
	}
}

// Go's descendants inherit the kernel write boundary: a symlink to a sibling
// refuses with EACCES, preserves its bytes, and the ordinary in-target write
// succeeds. The parent can still write its own fixture after the child exits.
func TestReleaseChildWriteBoundary(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := openRootNoLinks(target)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	anchor, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	defer anchor.Close()
	victim := filepath.Join(base, "victim")
	original := []byte("preserve")
	writeFixture(t, victim, original)
	if err := os.Symlink(victim, filepath.Join(target, "link")); err != nil {
		t.Fatal(err)
	}
	for _, attack := range []bool{false, true} {
		t.Run(fmt.Sprint(attack), func(t *testing.T) {
			name := "okay"
			if attack {
				name = "link"
			}
			cmd := exec.Command("/bin/sh", "-c", "printf 'child' > /proc/self/fd/3/"+name)
			cmd.ExtraFiles = []*os.File{anchor}
			var diagnostic bytes.Buffer
			cmd.Stderr = &diagnostic
			err := runConfined(cmd, anchor)
			if attack {
				exit, ok := err.(*exec.ExitError)
				if !ok || exit.ExitCode() == 0 || !strings.Contains(diagnostic.String(), "Permission denied") {
					t.Fatal("child escape not refused", err, diagnostic.String())
				}
			} else if err != nil {
				t.Fatal("confined write control refused", err)
			}
			after, e := os.ReadFile(victim)
			if e != nil || !bytes.Equal(after, original) {
				t.Fatal("child changed outside file", e)
			}
		})
	}
	writeFixture(t, filepath.Join(base, "parent-still-authorized"), nil)
}

func emptyTarget(t *testing.T, name string) {
	t.Helper()
	entries, err := os.ReadDir(name)
	if err != nil || len(entries) != 0 {
		t.Fatal("owned failed target not empty", err)
	}
}

// A substituted target entry belongs to the actor, never to failure cleanup.
// The original directory is emptied through its handle; both the moved-root
// and unchanged-root controls retain an empty directory without parent unlink.
func TestReleaseTargetSwapCleanup(t *testing.T) {
	for _, attack := range []bool{false, true} {
		t.Run(fmt.Sprint(attack), func(t *testing.T) {
			f := newFixture(t)
			bin := wrapperDir(t, f)
			script(t, filepath.Join(bin, "go"), pause("/proc/self/fd/3/.build/ready", "/proc/self/fd/3/.build/release")+"exit 77\n")
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
			defer cancel()
			done := make(chan int, 1)
			go func() { code, _ := runOptions(ctx, f.o); done <- code }()
			buildReady := waitScratch(t, "release-build-*/.build/ready")
			selected := f.o.target
			if attack {
				selected += "-moved"
				if err := os.Rename(f.o.target, selected); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(f.o.target, 0700); err != nil {
					t.Fatal(err)
				}
				writeFixture(t, filepath.Join(f.o.target, "foreign"), []byte("preserve"))
			}
			writeFixture(t, filepath.Join(filepath.Dir(buildReady), "release"), nil)
			if code := <-done; code != 1 {
				t.Fatal("controlled build did not refuse", code)
			}
			emptyTarget(t, selected)
			if attack {
				raw, err := os.ReadFile(filepath.Join(f.o.target, "foreign"))
				if err != nil || string(raw) != "preserve" {
					t.Fatal("cleanup changed replacement target", err)
				}
			}
		})
	}
}
