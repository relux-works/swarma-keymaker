package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", dir)
	repo := filepath.Join(dir, "source")
	clone := gitCommand(context.Background(), root, "clone", "--local", "--no-hardlinks", "--quiet", "--no-checkout", "--", root, repo)
	clone.Env = append(clone.Env, "GIT_ALLOW_PROTOCOL=file") // Test-only local clone; production disallows all transports.
	if err := runCommand(clone); err != nil {
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
	for _, which := range []string{"config", "registry", "enrollment"} {
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
				} else if which == "registry" {
					o.registry = bad
				} else {
					o.enrollment = bad
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

// Supplied enrollment pins use the real policy parser. Malformed, unknown,
// aliased and invalid pins refuse without writes or input changes; valid pins
// are retained byte-for-byte. Omission remains valid and omits the file.
func TestReleaseEnrollmentGate(t *testing.T) {
	f := newFixture(t)
	o := f.o
	o.enrollment = filepath.Join(filepath.Dir(o.config), "enrollment.json")
	valid := enrollmentInput(t)
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"syntax", []byte("{")},
		{"oversized", append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), 1<<20)...)},
		{"unknown", bytes.Replace(valid, []byte(`"audience":`), []byte(`"unknown":true,"audience":`), 1)},
		{"alias", bytes.Replace(valid, []byte(`"audience":`), []byte(`"Audience":`), 1)},
		{"duplicate", bytes.Replace(valid, []byte(`"audience":`), []byte(`"audience":"other.invalid","audience":`), 1)},
		{"revision", bytes.Replace(valid, []byte(strings.Repeat("a", 40)), []byte("main"), 1)},
		{"generation-alias", bytes.Replace(valid, []byte(`"30001":`), []byte(`"030001":`), 1)},
		{"service-uid", bytes.Replace(valid, []byte(`"service_uid":30001`), []byte(`"service_uid":0`), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if bytes.Equal(tc.raw, valid) {
				t.Fatal("negative not applied")
			}
			writeFixture(t, o.enrollment, tc.raw)
			refused(t, o, errEnrollment)
			if got, err := os.ReadFile(o.enrollment); err != nil || !bytes.Equal(got, tc.raw) {
				t.Fatal("enrollment refusal changed input")
			}
			writeFixture(t, o.enrollment, valid)
			files, err := validateInputs(o)
			if err != nil || !bytes.Equal(files["enrollment.json"], valid) {
				t.Fatal("valid enrollment refused or changed", err)
			}
			absent(t, o.target)
		})
	}
	files, err := validateInputs(f.o)
	if err != nil || files["enrollment.json"] != nil {
		t.Fatal("omission differs", err)
	}
}
func enrollmentInput(t *testing.T) []byte {
	t.Helper()
	// Fixed public test seed; this creates no files or signatures and uses no host credentials.
	public := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	blob := make([]byte, 4)
	binary.BigEndian.PutUint32(blob, 11)
	blob = append(blob, []byte("ssh-ed25519")...)
	n := make([]byte, 4)
	binary.BigEndian.PutUint32(n, 32)
	blob = append(blob, n...)
	blob = append(blob, public...)
	raw, err := json.Marshal(map[string]any{
		"maintainers": []string{"ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)},
		"revision":    strings.Repeat("a", 40), "publisher": "ed25519:" + base64.RawURLEncoding.EncodeToString(public),
		"audience": "example.invalid", "registry": "/registry.git", "state_dir": "/enrollment-state",
		"stations": map[string]bool{"sample": true}, "generations": map[string]string{"30001": strings.Repeat("1", 32)}, "service_uid": 30001,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
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
// only its contents, retaining the directory without a parent-entry unlink.
// This is not a mocked successful build or toolchain.
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
	emptyTarget(t, f.o.target)
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
	for _, v := range buildEnv(work, "") {
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
	proxy := buildEnv(work, filepath.Join(work, "read-only cache"))
	found := false
	for _, v := range proxy {
		if strings.HasPrefix(v, "GOPROXY=") {
			found = v == "GOPROXY=file://"+strings.ReplaceAll(filepath.Join(work, "read-only cache", "cache", "download"), " ", "%20")
		}
	}
	if !found {
		t.Fatal("local proxy has network fallback or unsafe URL")
	}
	if env["GOPROXY"] != "off" || env["GOSUMDB"] != "off" || env["GOWORK"] != "off" || env["GOTOOLCHAIN"] != "local" {
		t.Fatal("offline build configuration differs")
	}
}

// One real clean-commit offline build qualifies version, trimpath metadata,
// exact staged bytes and complete checksums. It creates no service or system
// files. Sibling inputs/source index remain unchanged; target has no build
// scratch, while child-created files are retained in private TMPDIR scratch.
func TestReleaseBundle(t *testing.T) { testReleaseBundle(t, false) }

// A supplied valid pin configuration is copied and checksummed in a real
// offline build; this validates policy bytes, not installed Git trust or state.
func TestReleaseBundleWithEnrollment(t *testing.T) { testReleaseBundle(t, true) }
func testReleaseBundle(t *testing.T, withEnrollment bool) {
	f := newFixture(t)
	f.o.moduleCache = fixtureModuleCache(t)
	proxyBefore, err := snapshotFiles(f.o.moduleCache)
	if err != nil {
		t.Fatal(err)
	}
	var pins []byte
	if withEnrollment {
		pins = enrollmentInput(t)
		f.o.enrollment = filepath.Join(filepath.Dir(f.o.config), "enrollment.json")
		writeFixture(t, f.o.enrollment, pins)
	}
	index := filepath.Join(f.o.repo, ".git/index")
	before, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	args := []string{"-repo", f.o.repo, "-commit", f.o.commit, "-version", f.o.version, "-target", f.o.target, "-config", f.o.config, "-name-indices", f.o.registry, "-module-cache", f.o.moduleCache}
	if withEnrollment {
		args = append(args, "-enrollment", f.o.enrollment)
	}
	var out, diagnostic bytes.Buffer
	if code := run(ctx, args, &out, &diagnostic); code != 0 {
		t.Fatalf("actual bundle build exit=%d: %s", code, &diagnostic)
	}
	proxyAfter, err := snapshotFiles(f.o.moduleCache)
	if err != nil || !reflect.DeepEqual(proxyBefore, proxyAfter) {
		t.Fatal("build changed dependency cache", err)
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
	if withEnrollment {
		want = append(want[:3], append([]string{"enrollment.json"}, want[3:]...)...)
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatal("bundle inventory differs", names)
	}
	var record versionRecord
	raw, err := os.ReadFile(filepath.Join(f.o.target, "VERSION.json"))
	if err != nil {
		t.Fatal(err)
	}
	expectedTree, treeErr := commitTree(ctx, f.o.repo, f.o.commit)
	if treeErr != nil {
		t.Fatal(treeErr)
	}
	if err = json.Unmarshal(raw, &record); err != nil || record.Tree != expectedTree || record.Commit != f.o.commit || record.Version != f.o.version || !record.Trimpath || record.GoVersion == "" || record.GOOS != "linux" || record.GOARCH != runtime.GOARCH {
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
	copiedInputs := map[string][]byte{"config.json": f.config, "name-indices.json": f.registry}
	if withEnrollment {
		copiedInputs["enrollment.json"] = pins
	}
	for name, want := range copiedInputs {
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

// File-proxy dependencies come from an isolated copy of the exact committed
// go.sum entries. No tests modify the host's module cache or fetch the network.
func fixtureModuleCache(t *testing.T) string {
	t.Helper()
	cache := os.Getenv("GOMODCACHE")
	if cache == "" {
		cmd := exec.Command("go", "env", "GOMODCACHE")
		cmd.Env = append(os.Environ(), "GOTELEMETRY=off")
		out, err := cmd.Output()
		if err != nil {
			t.Fatal("module cache location", err)
		}
		cache = strings.TrimSpace(string(out))
	}
	sums, err := os.ReadFile("../../go.sum")
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || strings.HasSuffix(fields[1], "/go.mod") {
			continue
		}
		for _, ext := range []string{".mod", ".info", ".zip"} {
			rel := filepath.Join("cache", "download", fields[0], "@v", fields[1]+ext)
			raw, err := os.ReadFile(filepath.Join(cache, rel))
			if err != nil {
				t.Fatal("offline dependency must already be cached", err)
			}
			dest := filepath.Join(dst, rel)
			if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, dest, raw)
		}
	}
	return dst
}

// Missing local dependencies fail closed, clean only the owned target and
// preserve the empty proxy. Real offline builds above are positive controls.
func TestReleaseOfflineDependencies(t *testing.T) {
	f := newFixture(t)
	f.o.moduleCache = t.TempDir()
	before, err := snapshotFiles(f.o.moduleCache)
	if err != nil {
		t.Fatal(err)
	}
	if err := assemble(context.Background(), f.o); err == nil || err.Error() != "offline keymaker build failed" {
		t.Fatal("unavailable dependency admitted", err)
	}
	emptyTarget(t, f.o.target)
	after, err := snapshotFiles(f.o.moduleCache)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("build changed read-only dependency source", err)
	}
}
func snapshotFiles(root string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		out[path] = hex.EncodeToString(sum[:])
		return nil
	})
	return out, err
}

// Fixture-only commands may write their own clone; production Git always uses
// runGitConfined. Narrowing overlays can invoke this helper to remove that gate.
func runCommand(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "release child pid=%d\n", cmd.Process.Pid)
	return cmd.Wait()
}
