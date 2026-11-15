package main

import (
	"context"
	"crypto/sha256"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Both documented single-file and package entrypoints must run the J7 signing
// fixture check without changing the corpus. This catches helpers hidden from
// single-file compilation; it checks offline CLI compatibility, not live authority.
func TestDocumentedVectorEntrypoints(t *testing.T) {
	env := make([]string, 0, len(os.Environ())+1)
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "GOTOOLCHAIN=") {
			env = append(env, variable)
		}
	}
	env = append(env, "GOTOOLCHAIN=local")
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOROOT() == "" {
		// -trimpath may omit the embedded GOROOT. Resolve PATH only in that
		// case, then require the build toolchain's exact version and platform.
		var err error
		goTool, err = exec.LookPath("go")
		if err != nil {
			t.Fatal(err)
		}
	}
	goTool, err := filepath.Abs(goTool)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	version := exec.CommandContext(ctx, goTool, "version")
	version.Env = env
	version.WaitDelay = 5 * time.Second
	output, err := version.CombinedOutput()
	wantVersion := "go version " + runtime.Version() + " " + runtime.GOOS + "/" + runtime.GOARCH
	if err != nil || strings.TrimSpace(string(output)) != wantVersion {
		t.Fatalf("current toolchain required: want %q, got %q: %v", wantVersion, output, err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	type corpusFile struct {
		Hash    [32]byte
		Mode    fs.FileMode
		Size    int64
		ModTime time.Time
	}
	snapshot := func(t *testing.T) map[string]corpusFile {
		t.Helper()
		files := make(map[string]corpusFile)
		err := filepath.WalkDir(filepath.Join(root, "vectors"), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				t.Fatalf("non-regular corpus file: %s", path)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[path] = corpusFile{sha256.Sum256(raw), info.Mode(), info.Size(), info.ModTime()}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatal("missing vector corpus")
		}
		return files
	}
	before := snapshot(t)
	for _, entrypoint := range []string{"./tools/vectors/main.go", "./tools/vectors"} {
		t.Run(entrypoint, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, goTool, "run", entrypoint, "-check")
			cmd.Dir = root
			cmd.WaitDelay = 5 * time.Second
			cmd.Env = env
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("go run %s -check: %v\n%s", entrypoint, err, output)
			} else if !strings.Contains(string(output), "J7 signing fixtures: exact 5 positive and 8 negative draft profile/1 byte/signature controls; live authority NOT qualified") {
				t.Errorf("missing J7 signing fixture-check output: %s", output)
			}
			if after := snapshot(t); !reflect.DeepEqual(before, after) {
				t.Error("read-only -check changed vector corpus files, modes, bytes or modification times")
			}
		})
	}
}
