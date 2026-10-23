package keymaker

import (
	"context"
	"errors"
	"github.com/relux-works/swarma-keymaker/internal/enrollment"
	"github.com/relux-works/swarma-keymaker/internal/registration"
	"path/filepath"
)

type helperEntropyFailure struct{}

func (helperEntropyFailure) Read([]byte) (int, error) {
	return 0, errors.New("fixture entropy unavailable")
}
func newFailingEntropyBuilder(f *nativeFixture, t *helperTrust) (*registration.Builder, error) {
	return registration.New(t.clock, helperEntropyFailure{}, registrationSigner{f.master, helperPath})
}
func enrollmentUnreconciled(t *helperTrust) *enrollment.Authority {
	a := enrollment.New(t.config, helperFiles{base: filepath.Dir(t.config)}, nil)
	a.Reload(context.Background())
	return a
}
