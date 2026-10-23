package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

type fixture struct {
	o                options
	config, registry []byte
}

// Clones retain existing signed objects; no test creates a commit or uses a
// signing key. Dirty working files in the developer checkout are not imported.
func newFixture(t *testing.T) fixture {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	head, err := gitRead(context.Background(), root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	repo := filepath.Join(dir, "source")
	if err := runCommand(gitCommand(context.Background(), root, "clone", "--local", "--no-hardlinks", "--quiet", "--no-checkout", "--", root, repo)); err != nil {
		t.Fatal("fixture clone", err)
	}
	commit := strings.TrimSpace(string(head))
	if err := runCommand(gitCommand(context.Background(), repo, "checkout", "--quiet", "--detach", commit)); err != nil {
		t.Fatal("fixture checkout", err)
	}
	config, err := os.ReadFile(filepath.Join(repo, "packaging/config.example.json"))
	if err != nil {
		t.Fatal("tests require committed packaging source", err)
	}
	registry := []byte(`{"products":[{"name":"example","index":1,"projects":[{"name":"project","index":1,"agents":[{"name":"agent","index":1}]}]}]}`)
	f := fixture{o: options{repo: repo, commit: commit, version: "0.1.0-dev", target: filepath.Join(dir, "bundle"), config: filepath.Join(dir, "operator.json"), registry: filepath.Join(dir, "indices.json")}, config: config, registry: registry}
	writeFixture(t, f.o.config, config)
	writeFixture(t, f.o.registry, registry)
	return f
}
func writeFixture(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}
func absent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("refusal wrote target", err)
	}
}
func control(t *testing.T, f fixture) {
	t.Helper()
	if _, err := prepare(context.Background(), f.o); err != nil {
		t.Fatal("valid preflight control refused", err)
	}
	absent(t, f.o.target)
}
func refused(t *testing.T, o options, want error) {
	t.Helper()
	_, err := prepare(context.Background(), o)
	if !errors.Is(err, want) {
		t.Fatalf("refusal=%v want=%v", err, want)
	}
	absent(t, o.target)
}

// Tracked, staged and untracked dirt each refuse before target creation. A
// separate clean clone is the paired control; immutable snapshots are not a
// reason to silently admit a dirty checkout.
func TestReleaseDirtyTree(t *testing.T) {
	for _, mode := range []string{"tracked", "staged", "untracked"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			name := filepath.Join(f.o.repo, "cmd/keymaker/main.go")
			if mode == "untracked" {
				name = filepath.Join(f.o.repo, "untracked-fixture.txt")
			}
			file, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = file.WriteString("\n// test-only dirt\n"); err != nil {
				t.Fatal(err)
			}
			if err = file.Close(); err != nil {
				t.Fatal(err)
			}
			if mode == "staged" {
				if err := runCommand(gitCommand(context.Background(), f.o.repo, "add", "--", "cmd/keymaker/main.go")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := prepare(context.Background(), f.o); !errors.Is(err, errDirty) {
				t.Fatalf("dirty source admitted: %v", err)
			}
			absent(t, f.o.target)
			control(t, newFixture(t))
		})
	}
}

// The full requested commit must equal HEAD and the source version must equal
// the operator pin. Neither refusal creates output; the real baseline passes.
func TestReleaseCommitAndVersion(t *testing.T) {
	f := newFixture(t)
	for _, mode := range []string{"short-commit", "other-commit", "wrong-version"} {
		t.Run(mode, func(t *testing.T) {
			o, want := f.o, errCommit
			switch mode {
			case "short-commit":
				o.commit = o.commit[:7]
			case "other-commit":
				o.commit = strings.Repeat("0", 40)
			case "wrong-version":
				o.version = "unexpected-version"
				want = errVersion
			}
			refused(t, o, want)
			control(t, f)
		})
	}
}

// Each operator input refuses symlinks (including ancestors), directories,
// FIFOs, missing files and over-budget files; ordinary complete files pass.
// All objects and FIFO operations are inside private temporary fixtures.
func TestReleaseInputFiles(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Dir(f.o.config)
	for _, which := range []string{"config", "registry"} {
		for _, mode := range []string{"symlink", "ancestor", "directory", "fifo", "missing", "large"} {
			t.Run(which+"-"+mode, func(t *testing.T) {
				o := f.o
				bad := filepath.Join(dir, which+"-"+mode)
				switch mode {
				case "symlink":
					if err := os.Symlink(f.o.config, bad); err != nil {
						t.Fatal(err)
					}
				case "ancestor":
					if err := os.Symlink(dir, bad); err != nil {
						t.Fatal(err)
					}
					bad = filepath.Join(bad, filepath.Base(f.o.config))
				case "directory":
					if err := os.Mkdir(bad, 0700); err != nil {
						t.Fatal(err)
					}
				case "fifo":
					if err := syscall.Mkfifo(bad, 0600); err != nil {
						t.Fatal(err)
					}
				case "large":
					writeFixture(t, bad, make([]byte, inputLimit+1))
				}
				if which == "config" {
					o.config = bad
				} else {
					o.registry = bad
				}
				refused(t, o, errInput)
				control(t, f)
			})
		}
	}
}

// Actual parser failures preserve operator bytes and never create output. The
// registry's allocation-history validator runs as well as JSON decoding.
func TestReleaseInputParsers(t *testing.T) {
	f := newFixture(t)
	for _, mode := range []string{"config-syntax", "config-unknown", "registry-syntax", "registry-unknown", "registry-history", "registry-duplicate"} {
		t.Run(mode, func(t *testing.T) {
			name, bad, want := f.o.config, []byte("{"), errConfig
			switch mode {
			case "config-unknown":
				bad = bytes.Replace(f.config, []byte("{\n"), []byte("{\n\"future\":true,"), 1)
			case "registry-syntax":
				name = f.o.registry
				want = errRegistry
			case "registry-unknown":
				name = f.o.registry
				want = errRegistry
				bad = []byte(`{"products":[],"future":true}`)
			case "registry-history":
				name = f.o.registry
				want = errRegistry
				bad = bytes.Replace(f.registry, []byte(`"index":1`), []byte(`"index":2`), 1)
			case "registry-duplicate":
				name = f.o.registry
				want = errRegistry
				bad = []byte(`{"products":[],"products":[]}`)
			}
			writeFixture(t, name, bad)
			refused(t, f.o, want)
			if after, err := os.ReadFile(name); err != nil || !bytes.Equal(after, bad) {
				t.Fatal("parser refusal changed input")
			}
			writeFixture(t, f.o.config, f.config)
			writeFixture(t, f.o.registry, f.registry)
			control(t, f)
		})
	}
}

// Every supplied enrollment path fails the explicit revision gate without
// opening or parsing it. Omission is the valid control; no substitute runs.
func TestReleaseEnrollmentGate(t *testing.T) {
	f := newFixture(t)
	o := f.o
	o.enrollment = filepath.Join(filepath.Dir(o.config), "enrollment.json")
	writeFixture(t, o.enrollment, []byte("not syntax-validated"))
	for _, mode := range []string{"regular", "missing", "symlink", "directory"} {
		t.Run(mode, func(t *testing.T) {
			gated := o
			if mode != "regular" {
				gated.enrollment += "-" + mode
				if mode == "symlink" {
					if err := os.Symlink(o.enrollment, gated.enrollment); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "directory" {
					if err := os.Mkdir(gated.enrollment, 0700); err != nil {
						t.Fatal(err)
					}
				}
			}
			refused(t, gated, errEnrollment)
			control(t, f)
		})
	}
	if errEnrollment.Error() != "enrollment validation unavailable at this revision" {
		t.Fatal("dependency gate message drift")
	}
	control(t, f)
}

// Existing files/directories/symlinks are preserved, and missing/symlinked
// parents refuse. A new target under the normal fixture parent remains valid.
func TestReleaseExistingTarget(t *testing.T) {
	f := newFixture(t)
	parent := filepath.Dir(f.o.target)
	for _, mode := range []string{"directory", "file", "symlink", "parent-link", "missing-parent"} {
		t.Run(mode, func(t *testing.T) {
			o := f.o
			o.target = filepath.Join(parent, "target-"+mode)
			switch mode {
			case "directory":
				if err := os.Mkdir(o.target, 0700); err != nil {
					t.Fatal(err)
				}
				writeFixture(t, filepath.Join(o.target, "keep"), []byte("preserve"))
			case "file":
				writeFixture(t, o.target, []byte("preserve"))
			case "symlink":
				if err := os.Symlink(f.o.config, o.target); err != nil {
					t.Fatal(err)
				}
			case "parent-link":
				if err := os.Symlink(parent, o.target); err != nil {
					t.Fatal(err)
				}
				o.target = filepath.Join(o.target, "absent-child")
			case "missing-parent":
				o.target = filepath.Join(o.target, "absent-child")
			}
			if err := assemble(context.Background(), o); !errors.Is(err, errTarget) {
				t.Fatal("existing/unsafe target admitted", err)
			}
			if mode == "directory" || mode == "file" {
				name := o.target
				if mode == "directory" {
					name = filepath.Join(name, "keep")
				}
				if b, e := os.ReadFile(name); e != nil || string(b) != "preserve" {
					t.Fatal("existing target changed")
				}
			}
			if mode == "symlink" {
				if link, e := os.Readlink(o.target); e != nil || link != f.o.config {
					t.Fatal("existing link changed")
				}
			}
			control(t, f)
		})
	}
}

// A real missing-Go dependency fails after target creation, and cleanup removes
// only that new target. This is not a mocked successful build or toolchain.
func TestReleaseBuildFailureCleanup(t *testing.T) {
	f := newFixture(t)
	control(t, f)
	git, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(filepath.Dir(f.o.target), "only-git")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(git, filepath.Join(bin, "git")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	if err := assemble(context.Background(), f.o); err == nil || err.Error() != "offline keymaker build failed" {
		t.Fatal("missing Go did not fail as intended", err)
	}
	absent(t, f.o.target)
	if raw, err := os.ReadFile(f.o.config); err != nil || !bytes.Equal(raw, f.config) {
		t.Fatal("build failure changed input")
	}
}

// Build configuration ignores inherited toolchain/workspace/SSH variables and
// confines every writable Go directory to the newly owned build work directory.
func TestReleaseBuildEnvironment(t *testing.T) {
	work := filepath.Join(t.TempDir(), "work")
	t.Setenv("GOFLAGS", "-toolexec=unwanted")
	t.Setenv("SSH_AUTH_SOCK", "test-only-unavailable")
	env := map[string]string{}
	for _, v := range buildEnv(work) {
		k, v, _ := strings.Cut(v, "=")
		env[k] = v
	}
	for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "TMPDIR", "GOTMPDIR", "GOCACHE", "GOPATH"} {
		if !inside(work, env[key]) {
			t.Fatal("writable directory escaped", key)
		}
	}
	for _, key := range []string{"GOFLAGS", "SSH_AUTH_SOCK", "GIT_SSH_COMMAND"} {
		if _, ok := env[key]; ok {
			t.Fatal("ambient authority inherited", key)
		}
	}
	if env["GOPROXY"] != "off" || env["GOSUMDB"] != "off" || env["GOWORK"] != "off" || env["GOTOOLCHAIN"] != "local" {
		t.Fatal("offline build configuration differs")
	}
}

// One real clean-commit offline build qualifies version, trimpath metadata,
// exact staged bytes and complete checksums. It creates no service or system
// files. Sibling inputs/source index remain unchanged and build scratch is gone.
func TestReleaseBundle(t *testing.T) {
	f := newFixture(t)
	index := filepath.Join(f.o.repo, ".git/index")
	before, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := []string{"-repo", f.o.repo, "-commit", f.o.commit, "-version", f.o.version, "-target", f.o.target, "-config", f.o.config, "-name-indices", f.o.registry}
	var out, diagnostic bytes.Buffer
	if code := run(ctx, args, &out, &diagnostic); code != 0 {
		t.Fatalf("actual bundle build exit=%d: %s", code, &diagnostic)
	}
	entries, err := os.ReadDir(f.o.target)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		if !e.Type().IsRegular() {
			t.Fatal("nonregular bundle entry", e.Name())
		}
	}
	want := []string{"SHA256SUMS", "VERSION.json", "config.json", "keymaker", "name-indices.json", "swarma-keymaker.service"}
	if !reflect.DeepEqual(names, want) {
		t.Fatal("bundle inventory differs", names)
	}
	var record versionRecord
	raw, err := os.ReadFile(filepath.Join(f.o.target, "VERSION.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &record); err != nil || record.Commit != f.o.commit || record.Version != f.o.version || !record.Trimpath || record.GoVersion == "" || record.GOOS != "linux" || record.GOARCH != runtime.GOARCH {
		t.Fatal("version metadata differs", err)
	}
	t.Logf("built source commit=%s version=%s go=%s target=%s/%s", record.Commit, record.Version, record.GoVersion, record.GOOS, record.GOARCH)
	if st, err := os.Stat(f.o.target); err != nil || st.Mode().Perm() != 0700 {
		t.Fatal("target privacy mode differs", err)
	}
	for _, name := range want {
		mode := os.FileMode(0600)
		if name == "keymaker" {
			mode = 0700
		}
		if st, err := os.Stat(filepath.Join(f.o.target, name)); err != nil || st.Mode().Perm() != mode {
			t.Fatal("release file mode differs", name, err)
		}
	}
	manifest, err := os.ReadFile(filepath.Join(f.o.target, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(manifest), "\n"), "\n")
	if len(lines) != len(want)-1 {
		t.Fatal("incomplete manifest")
	}
	seen := map[string]bool{}
	for _, line := range lines {
		digest, name, ok := strings.Cut(line, "  ")
		if !ok || seen[name] || name == "SHA256SUMS" || strings.ContainsAny(name, "/\\") {
			t.Fatal("invalid manifest entry")
		}
		seen[name] = true
		raw, err := os.ReadFile(filepath.Join(f.o.target, name))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(raw)
		if digest != hex.EncodeToString(hash[:]) {
			t.Fatal("incorrect checksum", name)
		}
	}
	for _, name := range want[1:] {
		if !seen[name] {
			t.Fatal("unhashed entry", name)
		}
	}
	check := exec.CommandContext(ctx, "sha256sum", "-c", "SHA256SUMS")
	check.Dir = f.o.target
	check.Env = gitEnv()
	var checksumOutput bytes.Buffer
	check.Stdout, check.Stderr = &checksumOutput, &checksumOutput
	if err := runCommand(check); err != nil {
		t.Fatal("owner checksum command failed", err)
	}
	t.Logf("sha256sum -c actual_exit=0: %s", &checksumOutput)
	for name, want := range map[string][]byte{"config.json": f.config, "name-indices.json": f.registry} {
		got, err := os.ReadFile(filepath.Join(f.o.target, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("copied input differs", name)
		}
	}
	unit, spec := shippedUnit(t)
	copied, err := os.ReadFile(filepath.Join(f.o.target, "swarma-keymaker.service"))
	if err != nil || !bytes.Equal(copied, unit) || unitMatchesSpec(copied, spec) != nil {
		t.Fatal("bundled unit drift")
	}
	for path, want := range map[string][]byte{f.o.config: f.config, f.o.registry: f.registry, index: before} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("build changed outside target", path)
		}
	}
	control(t, fixture{o: options{repo: f.o.repo, commit: f.o.commit, version: f.o.version, target: filepath.Join(filepath.Dir(f.o.target), "another-bundle"), config: f.o.config, registry: f.o.registry}, config: f.config, registry: f.registry})
	// The owner's actual checksum instrument must detect a bounded corruption,
	// with the intended named file failure rather than a setup error.
	writeFixture(t, filepath.Join(f.o.target, "config.json"), append(append([]byte(nil), f.config...), '\n'))
	badCheck := exec.CommandContext(ctx, "sha256sum", "-c", "SHA256SUMS")
	badCheck.Dir, badCheck.Env = f.o.target, gitEnv()
	checksumOutput.Reset()
	badCheck.Stdout, badCheck.Stderr = &checksumOutput, &checksumOutput
	err = runCommand(badCheck)
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(checksumOutput.String(), "config.json: FAILED") {
		t.Fatal("checksum corruption control did not fail as intended", err, &checksumOutput)
	}
	t.Logf("checksum corruption control actual_exit=1: %s", &checksumOutput)
	writeFixture(t, filepath.Join(f.o.target, "config.json"), f.config)
}

// Malformed flags and missing required inputs refuse without a build.
func TestReleaseCommandRefusals(t *testing.T) {
	for _, c := range []struct {
		args []string
		want int
	}{{[]string{"-unknown"}, 2}, {nil, 1}, {[]string{"extra"}, 2}} {
		var out bytes.Buffer
		if got := run(context.Background(), c.args, &out, &out); got != c.want {
			t.Fatal(got, c.want)
		}
	}
}
