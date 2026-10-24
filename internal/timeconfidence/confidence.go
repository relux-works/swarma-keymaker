// Package timeconfidence adapts the shared provider's verdict, never its policy.
package timeconfidence

import (
	"context"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

// Valid checks the shape of an authoritative provider result. Numeric ceilings,
// NTS evidence, age, uncertainty calculation and holds belong to timeconf.
func Valid(v timeconf.Sample) bool {
	return v.Trusted && v.Fresh && !v.Now.IsZero() && v.Boot != "" && v.Uncertainty >= 0 && v.Now.Before(v.AuthorityUntil)
}
func Start(ctx context.Context, p *timeconf.Provider) error {
	if p == nil {
		return timeconf.ErrUnavailable
	}
	v, err := p.StartSample(ctx)
	if err != nil || !Valid(v) {
		return timeconf.ErrUnavailable
	}
	return nil
}
func Sample(ctx context.Context, p *timeconf.Provider) (timeconf.Sample, error) {
	if p == nil {
		return timeconf.Sample{}, timeconf.ErrUnavailable
	}
	v, err := p.Sample(ctx)
	if err != nil || !Valid(v) {
		return timeconf.Sample{}, timeconf.ErrUnavailable
	}
	return v, nil
}
