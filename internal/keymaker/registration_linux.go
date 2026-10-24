//go:build linux

package keymaker

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/enrollment"
)

type registrationConfig struct {
	Names            Names  `json:"names"`
	EnrollmentConfig string `json:"enrollment_config"`
	ApprovalFile     string `json:"approval_file"`
}

// Reuse the shipped startup Reconciler; no enrollment bootstrap is performed.
// A failed initial/live reload fences only the helper. SIGHUP retries the same
// startup challenge so an operator can reconcile after observing it. No signal
// can grant authority without the protected approval and complete verification.
func configureRegistration(ctx context.Context, cfg *registrationConfig, master *Master, registry Registry, clock *timeconf.Provider, status io.Writer) (*RegistrationHelper, func(), error) {
	if cfg == nil {
		return nil, func() {}, nil
	}
	if cfg.Names.Purpose != "host-registration" {
		return nil, nil, Code("purpose_unknown")
	}
	path, code := registry.Resolve(cfg.Names)
	if code != "" {
		return nil, nil, code
	}
	reconciler, err := enrollment.NewOperatorReconciler(cfg.ApprovalFile, nil)
	if err != nil {
		return nil, nil, failure("registration reconciliation configuration invalid")
	}
	authority := enrollment.New(cfg.EnrollmentConfig, nil, reconciler)
	helper, err := NewRegistrationHelper(master, path, authority, clock, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	fmt.Fprintf(status, "enrollment startup challenge=%s\n", reconciler.Challenge())
	reload := func() {
		code := authority.Reload(ctx)
		if code != "" {
			fmt.Fprintf(status, "registration enrollment refused: %s\n", code)
		}
	}
	reload()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	stopped := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopped:
				return
			case <-signals:
				reload()
			}
		}
	}()
	return helper, func() { signal.Stop(signals); close(stopped); <-done }, nil
}
