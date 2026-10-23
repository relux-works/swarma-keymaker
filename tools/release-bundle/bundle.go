package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
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
	tree         string
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
	tree, err := commitTree(ctx, repo, o.commit)
	if err != nil || !commitPattern.MatchString(tree) {
		return plan{}, errCommit
	}
	files["swarma-keymaker.service"] = unit
	return plan{repo: repo, target: target, files: files, tree: tree}, nil
}

func buildEnv(work, moduleCache string) []string {
	proxy := "off"
	if moduleCache != "" {
		proxy = (&url.URL{Scheme: "file", Path: filepath.Join(moduleCache, "cache", "download")}).String()
	}
	return []string{
		"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "HOME=" + filepath.Join(work, "home"), "XDG_CONFIG_HOME=" + filepath.Join(work, "home"),
		"TMPDIR=" + filepath.Join(work, "tmp"), "GOTMPDIR=" + filepath.Join(work, "tmp"), "GOCACHE=" + filepath.Join(work, "cache"), "GOPATH=" + filepath.Join(work, "gopath"),
		"GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=" + proxy, "GOSUMDB=off", "GOTELEMETRY=off", "CGO_ENABLED=0", "GOOS=linux", "GOARCH=" + runtime.GOARCH, "GOMAXPROCS=2",
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
	Tree      string `json:"tree"`
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	Trimpath  bool   `json:"trimpath"`
}

func assemble(ctx context.Context, o options) (err error) {
	if o.moduleCache != "" {
		cache, e := pathWithoutLinks(o.moduleCache, false)
		if e != nil {
			return errInput
		}
		st, e := os.Stat(cache)
		if e != nil || !st.IsDir() {
			return errInput
		}
		o.moduleCache = cache
	}

	// Pin the selected parent before any Git/input work can yield to another actor.
	selected, err := targetPath(o.repo, o.target)
	if err != nil {
		return err
	}
	parent, err := openRootNoLinks(filepath.Dir(selected))
	if err != nil {
		return errTarget
	}
	defer parent.Close()
	p, err := prepare(ctx, o)
	if err != nil {
		return err
	}
	root, err := createTarget(parent, filepath.Base(selected))
	if err != nil {
		return err
	}
	defer root.Close()
	anchor, err := root.Open(".")
	if err != nil {
		return err
	}
	defer anchor.Close()
	success := false
	defer func() {
		if !success {
			// Remove descendants through the pinned inode, never a substituted path.
			// Retain the directory itself: Linux has no conditional unlink-by-inode,
			// and rechecking then unlinking its parent entry would race a replacement.
			if e := cleanupRoot(root); e != nil {
				err = fmt.Errorf("bundle failed; owned target cleanup failed")
			}

		}
	}()
	for _, dir := range []string{".build", ".build/source", ".build/home", ".build/tmp", ".build/cache", ".build/gopath"} {
		if err = mkdirRootAll(root, dir); err != nil {
			return err
		}
	}
	sourceFile, err := openRootFile(root, ".build/source", os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	source, err := rootFromFile(sourceFile)
	if err != nil {
		return err
	}
	defer source.Close()
	if err = extractSource(ctx, p.repo, o.commit, source); err != nil {
		return fmt.Errorf("source snapshot refused")
	}
	if err = verifyTree(source, p.tree); err != nil {
		return err
	}
	// Descriptor 3 anchors all child paths even if the target/parent is renamed.
	work := "/proc/self/fd/3/.build"
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-modcacherw", "-p=2", "-ldflags=-buildid=", "-o", work+"/keymaker", "./cmd/keymaker")
	build.ExtraFiles = []*os.File{anchor}
	build.Dir = fmt.Sprintf("/proc/self/fd/%d", sourceFile.Fd())
	build.Env = buildEnv(work, o.moduleCache)
	if err = runConfined(build, anchor); err != nil {
		return fmt.Errorf("offline keymaker build failed")
	}
	binary, err := openRootFile(root, ".build/keymaker", os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer binary.Close()
	st, err := binary.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return errInput
	}
	versionCmd := exec.CommandContext(ctx, "/proc/self/fd/4", "version")
	versionCmd.ExtraFiles = []*os.File{anchor, binary}
	versionCmd.Dir = fmt.Sprintf("/proc/self/fd/%d", sourceFile.Fd())
	versionCmd.Env = buildEnv(work, o.moduleCache)
	var version bytes.Buffer
	versionCmd.Stdout = &version
	if err = runConfined(versionCmd, anchor); err != nil || version.String() != o.version+"\n" {
		return errVersion
	}
	info, err := buildinfo.Read(binary)
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
	record := versionRecord{Commit: o.commit, Tree: p.tree, Version: o.version, GoVersion: info.GoVersion, GOOS: "linux", GOARCH: runtime.GOARCH, Trimpath: true}
	metadata, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	p.files["VERSION.json"] = append(metadata, '\n')
	for name, body := range p.files {
		if err = writeRootFile(root, name, body, 0600); err != nil {
			return err
		}
	}
	out, err := openRootFile(root, "keymaker", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, binary)
	closeErr := out.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = root.RemoveAll(".build"); err != nil {
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
		raw, readErr := readRootFile(root, name)
		if readErr != nil {
			return readErr
		}
		digest := sha256.Sum256(raw)
		fmt.Fprintf(&manifest, "%s  %s\n", hex.EncodeToString(digest[:]), name)
	}
	if err = writeRootFile(root, "SHA256SUMS", []byte(manifest.String()), 0600); err != nil {
		return err
	}
	success = true
	return nil
}
