//go:build linux

package keymaker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// ServeProduction uses only the root-policy source API. Generation readiness
// stays closed until protected configuration names a verified journal.
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
	return serveConfigured(ctx, config, status, nil)
}

type productionConfig = Config

func serveConfigured(ctx context.Context, path string, status io.Writer, generation GenerationSource) error {
	var cfg productionConfig
	if e := ProtectedConfig(path, &cfg); e != nil {
		return e
	}
	return serveValidatedConfig(ctx, cfg, status, generation)
}

// Production reaches typed startup only after ProtectedConfig succeeds. Keeping
// that load separate permits unprivileged tests of the readiness gate without
// an alternate configuration owner policy or a production fixture switch.
func serveValidatedConfig(ctx context.Context, cfg productionConfig, status io.Writer, generation GenerationSource) error {
	if generation == nil && cfg.GenerationJournal == nil {
		return Code("generation_source_unavailable")
	}
	uid := uint32(os.Getuid())
	if cfg.ServiceUID != uid || cfg.ServiceGID != uint32(os.Getgid()) || cfg.Epoch == "" || cfg.RegistryRevision == "" {
		return failure("configuration identity mismatch")
	}
	clock, err := timeconf.Production(cfg.TimePolicy, nil)
	if err != nil || timeconfidence.Start(ctx, clock) != nil {
		return Code("clock_untrusted")
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
	store, audit, auditDir, e := openCustodyStateClock(state, uid, systemAuditClock{provider: clock})
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
	if generation == nil {
		g := newJournalGeneration(productionGenerationWindow{}, store, cfg.GenerationJournal.Path, cfg.GenerationJournal.InitialFloor)
		if c := g.withWindow(ctx, func(context.Context, gj.View) Code { return "" }); c != "" {
			return c
		}
		generation = g
	}

	helper, stopHelper, e := configureRegistration(ctx, cfg.Registration, master, registry, clock, status)
	if e != nil {
		return e
	}
	defer stopHelper()
	server, e := NewDaemonServer(cfg.SocketDir, NewEngine(store, generation, master, audit), NativeConfig{Operator: cfg.Operator, Registry: registry, Epoch: cfg.Epoch, RegistryRevision: cfg.RegistryRevision, Helper: helper}, cfg.ControlGID, nil)
	if e != nil {
		return e
	}
	fmt.Fprintf(status, "agent and control ready; memory_locked=%t\n", master.Locked())
	return server.Serve(ctx)
}
