package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fixtureModule struct {
	Path, Version, GoMod string
	Error                string
}

// Resolve the main module's download set offline. Unlike "go list -m all",
// this does not require unused, pruned transitive modules to be cached. go.sum
// may retain other versions without making their archives fixture prerequisites.
func fixtureModules(root string) ([]fixtureModule, error) {
	cmd := exec.Command("go", "mod", "download", "-json")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOENV=off", "GOPROXY=off", "GONOPROXY=none", "GOSUMDB=off", "GOWORK=off", "GOTOOLCHAIN=local", "GOTELEMETRY=off")
	var diagnostic bytes.Buffer
	cmd.Stderr = &diagnostic
	raw, commandErr := cmd.Output()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var modules []fixtureModule
	for {
		var module fixtureModule
		if err := decoder.Decode(&module); err == io.EOF {
			if commandErr != nil {
				return nil, fmt.Errorf("offline fixture dependency metadata: %w: %s; run go mod download before tests", commandErr, &diagnostic)
			}
			return modules, nil
		} else if err != nil {
			return nil, err
		}
		if module.Error != "" {
			return nil, fmt.Errorf("offline fixture dependency %s@%s: %s; run go mod download before tests", module.Path, module.Version, module.Error)
		}
		modules = append(modules, module)
	}
}

func copyFixtureModules(cache, dst string, modules []fixtureModule) error {
	for _, module := range modules {
		// Go supplies the escaped module/version path. Confine it to the cache
		// instead of reconstructing paths from unescaped import strings.
		rel, err := filepath.Rel(cache, module.GoMod)
		if err != nil || !filepath.IsLocal(rel) || !strings.HasSuffix(rel, ".mod") || module.Version == "" {
			return fmt.Errorf("offline fixture dependency %s@%s: expected a versioned cached module; run go mod download before tests", module.Path, module.Version)
		}
		for _, ext := range []string{".mod", ".info", ".zip"} {
			artifact := strings.TrimSuffix(rel, ".mod") + ext
			raw, err := os.ReadFile(filepath.Join(cache, artifact))
			if err != nil {
				return fmt.Errorf("offline fixture dependency %s@%s: cached %s unavailable; run go mod download before tests: %w", module.Path, module.Version, ext, err)
			}
			dest := filepath.Join(dst, artifact)
			if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
				return err
			}
			if err := os.WriteFile(dest, raw, 0600); err != nil {
				return err
			}
		}
	}
	return nil
}

// File-proxy dependencies are isolated copies of the selected module graph.
// Archives must be downloaded before tests; fixture construction never fetches.
func fixtureModuleCache(t *testing.T) string {
	t.Helper()
	cmd := exec.Command("go", "env", "GOMODCACHE")
	cmd.Env = append(os.Environ(), "GOTELEMETRY=off")
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal("module cache location", err)
	}
	modules, err := fixtureModules("../..")
	if err != nil {
		t.Fatal(err)
	}
	dst := privateTestScratch(t)
	if err := copyFixtureModules(strings.TrimSpace(string(raw)), dst, modules); err != nil {
		t.Fatal(err)
	}
	return dst
}

// A stale checksum for the previously pinned registrar must not select that
// version or require its archive. The active graph remains copyable offline.
func TestReleaseFixtureModuleCacheIgnoresStaleSums(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"go.mod", "go.sum"} {
		raw, err := os.ReadFile(filepath.Join("../..", name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "go.sum" {
			raw = append(raw, []byte("github.com/relux-works/swarma-registrar v0.0.0-20261023164451-5f44ebf3f788 h1:5PY0Ri0qGh43ImOMK0Y5pMJoq8ZcT6yAGT3oVjUjJSQ=\n")...)
		}
		writeFixture(t, filepath.Join(root, name), raw)
	}
	before, err := snapshotFiles(root)
	if err != nil {
		t.Fatal(err)
	}
	modules, err := fixtureModules(root)
	if err != nil || len(modules) == 0 {
		t.Fatal("active graph unavailable", modules, err)
	}
	for _, module := range modules {
		if module.Version == "v0.0.0-20261023164451-5f44ebf3f788" {
			t.Fatal("stale checksum selected an inactive dependency")
		}
	}
	// Use the same real cache/copy path as the offline bundle controls.
	cmd := exec.Command("go", "env", "GOMODCACHE")
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := copyFixtureModules(strings.TrimSpace(string(raw)), t.TempDir(), modules); err != nil {
		t.Fatal(err)
	}
	after, err := snapshotFiles(root)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("offline metadata query changed module inputs", err)
	}
}

// A completely unprovisioned module is refused offline with its exact identity
// and preparation command; inherited proxy exemptions cannot enable a direct
// network fallback, and no unavailable module artifact is created.
func TestReleaseFixtureModuleCacheUnavailableGraph(t *testing.T) {
	root, cache := t.TempDir(), t.TempDir()
	t.Setenv("GOMODCACHE", cache)
	t.Setenv("GONOPROXY", "example.invalid/*")
	writeFixture(t, filepath.Join(root, "go.mod"), []byte("module example.invalid/control\n\ngo 1.26.0\n\nrequire example.invalid/uncached v1.2.3\n"))
	modules, err := fixtureModules(root)
	if err == nil || modules != nil || !strings.Contains(err.Error(), "example.invalid/uncached@v1.2.3") || !strings.Contains(err.Error(), "GOPROXY=off") || !strings.Contains(err.Error(), "run go mod download before tests") {
		t.Fatal("unprovisioned dependency lost offline refusal or remedy", modules, err)
	}
	for _, ext := range []string{".mod", ".info", ".zip"} {
		if _, err := os.Stat(filepath.Join(cache, "cache", "download", "example.invalid", "uncached", "@v", "v1.2.3"+ext)); !os.IsNotExist(err) {
			t.Fatal("offline query created unavailable dependency", ext, err)
		}
	}
}

// Every missing archive component names the exact dependency and remedy without
// writing the source cache. The complete neighboring cache copies exact bytes.
func TestReleaseFixtureModuleCacheMissingArtifacts(t *testing.T) {
	for _, missing := range []string{"", ".mod", ".info", ".zip"} {
		t.Run("missing="+missing, func(t *testing.T) {
			cache, dst := t.TempDir(), t.TempDir()
			rel := filepath.Join("cache", "download", "example.invalid", "!dependency", "@v", "v1.0.0")
			module := fixtureModule{Path: "example.invalid/Dependency", Version: "v1.0.0", GoMod: filepath.Join(cache, rel+".mod")}
			if err := os.MkdirAll(filepath.Dir(module.GoMod), 0700); err != nil {
				t.Fatal(err)
			}
			for _, ext := range []string{".mod", ".info", ".zip"} {
				if ext != missing {
					writeFixture(t, filepath.Join(cache, rel+ext), []byte("fixture"+ext))
				}
			}
			before, err := snapshotFiles(cache)
			if err != nil {
				t.Fatal(err)
			}
			err = copyFixtureModules(cache, dst, []fixtureModule{module})
			if missing == "" {
				if err != nil {
					t.Fatal("complete cache refused", err)
				}
				for _, ext := range []string{".mod", ".info", ".zip"} {
					raw, err := os.ReadFile(filepath.Join(dst, rel+ext))
					if err != nil || string(raw) != "fixture"+ext {
						t.Fatal("cache copy differs", ext, err)
					}
				}
			} else if err == nil || !strings.Contains(err.Error(), "example.invalid/Dependency@v1.0.0") || !strings.Contains(err.Error(), "cached "+missing+" unavailable; run go mod download before tests") {
				t.Fatal("missing-cache diagnostic lost dependency or remedy", err)
			}
			after, err := snapshotFiles(cache)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("fixture changed source cache", err)
			}
		})
	}
}
