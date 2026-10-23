//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ServeProduction deliberately has no static generation table or fixture flag.
// Until the user-manager publishes its journal, this readiness dependency is a
// closed gate. The exact Server/Engine below are exercised with test-only injection.
func ServeProduction(ctx context.Context, config string, status io.Writer) error {
	if os.Geteuid() == 0 {
		return failure("service must be unprivileged")
	}
	if config == "" {
		return failure("configuration required")
	}
	if e := HardenProcess(); e != nil {
		return e
	}
	generation := UnavailableGeneration{}
	if _, code := generation.Lookup(ctx, uint32(os.Getuid())); code != "" {
		return code
	}
	return serveConfigured(ctx, config, status, generation)
}

type productionConfig struct {
	SocketDir        string    `json:"socket_dir"`
	StateDir         string    `json:"state_dir"`
	MasterFile       string    `json:"master_file"`
	RegistryFile     string    `json:"registry_file"`
	ServiceUID       uint32    `json:"service_uid"`
	ServiceGID       uint32    `json:"service_gid"`
	ControlGID       uint32    `json:"control_gid"`
	Operator         Principal `json:"operator_principal"`
	Epoch            string    `json:"master_epoch"`
	RegistryRevision string    `json:"registry_revision"`
}

// Zero is a possible numeric principal/group, never evidence that a member was
// configured. Reject omitted authority fields before typed decoding defaults.
func (cfg *productionConfig) UnmarshalJSON(raw []byte) error {
	fields, err := objectMembers(raw, []string{"socket_dir", "state_dir", "master_file", "registry_file", "service_uid", "service_gid", "control_gid", "operator_principal", "master_epoch", "registry_revision"})
	if err != nil {
		return err
	}
	if _, err := objectMembers(fields["operator_principal"], []string{"uid", "generation"}); err != nil {
		return err
	}
	type plain productionConfig
	return StrictJSON(bytes.NewReader(raw), (*plain)(cfg))
}

func serveConfigured(ctx context.Context, path string, status io.Writer, generation GenerationSource) error {
	var cfg productionConfig
	if e := ProtectedConfig(path, &cfg); e != nil {
		return e
	}
	uid := uint32(os.Getuid())
	if cfg.ServiceUID != uid || cfg.ServiceGID != uint32(os.Getgid()) || cfg.Epoch == "" || cfg.RegistryRevision == "" {
		return failure("configuration identity mismatch")
	}
	for _, dir := range []string{cfg.SocketDir, cfg.StateDir, filepath.Dir(cfg.MasterFile)} {
		if e := safeAncestors(dir, uid); e != nil {
			return e
		}
	}
	var registry Registry
	if e := ProtectedConfig(cfg.RegistryFile, &registry); e != nil {
		return e
	}
	if c := registry.Validate(); c != "" {
		return c
	}
	master, e := LoadMaster(cfg.MasterFile, uid)
	if e != nil {
		return e
	}
	defer master.Close()
	state, e := OpenDirectory(cfg.StateDir, uid, 0700)
	if e != nil {
		return e
	}
	defer state.Close()
	lock, e := LockState(state, uid)
	if e != nil {
		return e
	}
	defer lock.Close()
	store, audit, auditDir, e := openCustodyState(state, uid)
	if e != nil {
		return e
	}
	defer auditDir.Close()
	defer audit.Close()
	for _, b := range store.Snapshot() {
		if b.Epoch != cfg.Epoch || b.RegistryRevision != cfg.RegistryRevision || !registry.ContainsIdentityPath(b.Path) {
			return failure("binding registry or epoch mismatch")
		}
	}
	server, e := NewDaemonServer(cfg.SocketDir, NewEngine(store, generation, master, audit), NativeConfig{Operator: cfg.Operator, Registry: registry, Epoch: cfg.Epoch, RegistryRevision: cfg.RegistryRevision}, cfg.ControlGID, nil)
	if e != nil {
		return e
	}
	fmt.Fprintf(status, "agent and control ready; memory_locked=%t\n", master.Locked())
	return server.Serve(ctx)
}
