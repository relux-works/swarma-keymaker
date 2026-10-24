//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// A structurally valid, identity-matching configuration without a journal must
// refuse generation_source_unavailable before touching installation state or
// reporting readiness. Adding a journal passes this gate and reaches service
// identity validation (the control deliberately changes UID to stop there).
// This nonroot fixture does not qualify root-owned configuration loading.
// The actual binary's unsafe-config rejection is tested in cmd/keymaker.
func TestProductionConfigGenerationGate(t *testing.T) {
	if os.Getuid() == 0 {
		t.Fatal("test requires an unprivileged runner")
	}
	dir := t.TempDir()
	cfg := Config{SocketDir: dir, StateDir: dir, MasterFile: filepath.Join(dir, "master.seed"), RegistryFile: filepath.Join(dir, "registry.json"), ServiceUID: uint32(os.Getuid()), ServiceGID: uint32(os.Getgid()), Epoch: "test-epoch", RegistryRevision: "test-registry", Operator: Principal{UID: uint32(os.Getuid()), Generation: nativeToken}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = ParseConfig(bytes.NewReader(raw))
	if err != nil || cfg.GenerationJournal != nil {
		t.Fatal("valid unconfigured input refused", err)
	}
	var status bytes.Buffer
	if err = serveValidatedConfig(context.Background(), cfg, &status, nil); err != Code("generation_source_unavailable") {
		t.Fatal("unconfigured journal did not close readiness", err)
	}
	cfg.GenerationJournal = &generationJournalConfig{Path: filepath.Join(dir, "generations"), InitialFloor: gj.Floor{Hash: gj.ZeroHash}}
	cfg.ServiceUID ^= 1
	if err = serveValidatedConfig(context.Background(), cfg, &status, nil); err == nil || err.Error() != "keymaker: configuration identity mismatch" {
		t.Fatal("configured control did not reach service identity validation", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 || status.Len() != 0 {
		t.Fatal("refused startup changed state or reported readiness", entries, err, status.String())
	}
}
