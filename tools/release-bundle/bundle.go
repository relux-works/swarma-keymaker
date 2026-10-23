package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type plan struct {
	repo, target string
	files        map[string][]byte
}

func prepare(ctx context.Context, o options) (plan, error) {
	if o.repo == "" || o.version == "" {
		return plan{}, fmt.Errorf("repo, commit, version, target, config and name-indices are required")
	}
	repo, err := pathWithoutLinks(o.repo, false)
	if err != nil {
		return plan{}, err
	}
	root, err := gitRead(ctx, repo, "rev-parse", "--show-toplevel")
	if err != nil || strings.TrimSpace(string(root)) != repo {
		return plan{}, errCommit
	}
	if err := cleanSource(ctx, repo, o.commit); err != nil {
		return plan{}, err
	}
	target, err := targetPath(repo, o.target)
	if err != nil {
		return plan{}, err
	}
	files, err := validateInputs(o)
	if err != nil {
		return plan{}, err
	}
	unit, err := gitRead(ctx, repo, "show", o.commit+":packaging/swarma-keymaker.service")
	if err != nil {
		return plan{}, errUnit
	}
	spec, err := gitRead(ctx, repo, "show", o.commit+":spec/keymaker.md")
	if err != nil {
		return plan{}, errUnit
	}
	if err := unitMatchesSpec(unit, spec); err != nil {
		return plan{}, err
	}
	main, err := gitRead(ctx, repo, "show", o.commit+":cmd/keymaker/main.go")
	if err != nil {
		return plan{}, errVersion
	}
	version, err := sourceVersion(main)
	if err != nil || version != o.version {
		return plan{}, errVersion
	}
	files["swarma-keymaker.service"] = unit
	return plan{repo: repo, target: target, files: files}, nil
}

func buildEnv(work string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "HOME=" + filepath.Join(work, "home"), "XDG_CONFIG_HOME=" + filepath.Join(work, "home"),
		"TMPDIR=" + filepath.Join(work, "tmp"), "GOTMPDIR=" + filepath.Join(work, "tmp"), "GOCACHE=" + filepath.Join(work, "cache"), "GOPATH=" + filepath.Join(work, "gopath"),
		"GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOTELEMETRY=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + runtime.GOARCH, "GOMAXPROCS=2",
	}
}
func runCommand(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "release child pid=%d\n", cmd.Process.Pid)
	return cmd.Wait()
}

type versionRecord struct {
	Commit    string `json:"commit"`
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	Trimpath  bool   `json:"trimpath"`
}

func assemble(ctx context.Context, o options) (err error) {
	p, err := prepare(ctx, o)
	if err != nil {
		return err
	}
	// Mkdir refuses races/existing targets. Cleanup is restricted to this exact
	// newly-created directory identity; it never removes a pre-existing target.
	if err = os.Mkdir(p.target, 0700); err != nil {
		return errTarget
	}
	owned, err := os.Lstat(p.target)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		if !success {
			current, statErr := os.Lstat(p.target)
			if statErr == nil && os.SameFile(owned, current) {
				if removeErr := os.RemoveAll(p.target); removeErr != nil {
					err = fmt.Errorf("bundle failed; owned target cleanup failed")
				}
			}
		}
	}()
	work := filepath.Join(p.target, ".build")
	for _, dir := range []string{"source", "home", "tmp", "cache", "gopath"} {
		if err = os.MkdirAll(filepath.Join(work, dir), 0700); err != nil {
			return err
		}
	}
	if err = extractSource(ctx, p.repo, o.commit, filepath.Join(work, "source")); err != nil {
		return fmt.Errorf("source snapshot refused")
	}
	binary := filepath.Join(p.target, "keymaker")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-p=2", "-ldflags=-buildid=", "-o", binary, "./cmd/keymaker")
	build.Dir = filepath.Join(work, "source")
	build.Env = buildEnv(work)
	if err = runCommand(build); err != nil {
		return fmt.Errorf("offline keymaker build failed")
	}
	versionCmd := exec.CommandContext(ctx, binary, "version")
	versionCmd.Dir = work
	versionCmd.Env = buildEnv(work)
	var version bytes.Buffer
	versionCmd.Stdout = &version
	if err = runCommand(versionCmd); err != nil || version.String() != o.version+"\n" {
		return errVersion
	}
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		return fmt.Errorf("binary build information unavailable")
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["-trimpath"] != "true" || settings["GOOS"] != "linux" || settings["GOARCH"] != runtime.GOARCH || settings["CGO_ENABLED"] != "0" {
		return fmt.Errorf("binary build settings refused")
	}
	record := versionRecord{Commit: o.commit, Version: o.version, GoVersion: info.GoVersion, GOOS: "linux", GOARCH: runtime.GOARCH, Trimpath: true}
	metadata, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	p.files["VERSION.json"] = append(metadata, '\n')
	for name, body := range p.files {
		if err = os.WriteFile(filepath.Join(p.target, name), body, 0600); err != nil {
			return err
		}
	}
	if err = os.Chmod(binary, 0700); err != nil {
		return err
	}
	if err = os.RemoveAll(work); err != nil {
		return err
	}
	if err = cleanSource(ctx, p.repo, o.commit); err != nil {
		return err
	}
	names := []string{"keymaker"}
	for name := range p.files {
		names = append(names, name)
	}
	sort.Strings(names)
	var manifest strings.Builder
	for _, name := range names {
		raw, readErr := readInput(filepath.Join(p.target, name))
		// The compiled binary can exceed the operator-input budget.
		if name == "keymaker" {
			raw, readErr = os.ReadFile(binary)
		}
		if readErr != nil {
			return readErr
		}
		digest := sha256.Sum256(raw)
		fmt.Fprintf(&manifest, "%s  %s\n", hex.EncodeToString(digest[:]), name)
	}
	if err = os.WriteFile(filepath.Join(p.target, "SHA256SUMS"), []byte(manifest.String()), 0600); err != nil {
		return err
	}
	success = true
	return nil
}
