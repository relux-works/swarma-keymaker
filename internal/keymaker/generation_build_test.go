//go:build linux

package keymaker

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func generationProductionSettings(settings []debug.BuildSetting) error {
	for _, s := range settings {
		if s.Key == "-tags" && strings.Contains(s.Value, "genjournal_testseam") {
			return fmt.Errorf("production build contains genjournal_testseam")
		}
	}
	return nil
}

func generationProductionAPI(api string) error {
	if strings.Contains(api, "func NewTestHandle(") || strings.Contains(api, "func OpenForTest(") {
		return fmt.Errorf("production API exposes fixture constructor")
	}
	if strings.Contains(api, "func WithReaderHold(") {
		return fmt.Errorf("production API exposes fixture reader duration")
	}
	return nil
}

// A normal cmd/keymaker build must use the exact source pin without a module
// replacement and require no fixture package or tag. The
// planted build setting establishes that the check rejects the named violation;
// this does not qualify a separately built or installed release artifact.
func TestGenerationProductionBuildBoundary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-deps", "../../cmd/keymaker")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list deps: %v: %s", err, out)
	}
	for _, p := range strings.Fields(string(out)) {
		if strings.Contains(p, "genjournaltest") || strings.Contains(p, "genjournal_testseam") {
			t.Fatal("production fixture dependency", p)
		}
	}
	cmd = exec.CommandContext(ctx, "go", "doc", "-all", "github.com/relux-works/swarma-user-manager/tools/genjournal")
	api, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("normal source API: %v: %s", err, api)
	}
	if err = generationProductionAPI(string(api)); err != nil {
		t.Fatal(err)
	}
	if err = generationProductionAPI(string(api) + "\nfunc NewTestHandle(owner uint32, anchor string) *TestHandle\n"); err == nil || err.Error() != "production API exposes fixture constructor" {
		t.Fatal("fixture API control was not rejected", err)
	}
	if err = generationProductionAPI(string(api) + "\nfunc WithReaderHold(d time.Duration) TestOption\n"); err == nil || err.Error() != "production API exposes fixture reader duration" {
		t.Fatal("fixture duration API control was not rejected", err)
	}
	binary := filepath.Join(t.TempDir(), "keymaker")
	cmd = exec.CommandContext(ctx, "go", "build", "-o", binary, "../../cmd/keymaker")
	if out, err = cmd.CombinedOutput(); err != nil {
		t.Fatalf("normal production build: %v: %s", err, out)
	}
	cmd = exec.CommandContext(ctx, "go", "version", "-m", binary)
	if out, err = cmd.CombinedOutput(); err != nil {
		t.Fatalf("go version -m: %v: %s", err, out)
	}
	t.Logf("production build metadata:\n%s", out)
	binaryBytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("production binary sha256=%x", sha256.Sum256(binaryBytes))
	info, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err = generationProductionSettings(info.Settings); err != nil {
		t.Fatal(err)
	}
	foundSource := false
	for _, dep := range info.Deps {
		if dep.Path == "github.com/relux-works/swarma-user-manager" {
			foundSource = true
			if dep.Version != "v0.0.0-20261024191358-505fb9f55a6d" || dep.Replace != nil {
				t.Fatalf("production source pin or replacement differs: %+v", dep)
			}
		}
	}
	if !foundSource {
		t.Fatal("production binary does not contain the pinned generation source")
	}
	plant := append(append([]debug.BuildSetting(nil), info.Settings...), debug.BuildSetting{Key: "-tags", Value: "genjournal_testseam"})
	if err = generationProductionSettings(plant); err == nil || err.Error() != "production build contains genjournal_testseam" {
		t.Fatal("tag control not detected", err)
	}
}
