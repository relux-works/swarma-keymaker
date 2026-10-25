// Package timeconfidence adapts the shared provider's verdict, never its policy.
package timeconfidence

import (
	"context"
	"math"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

// Valid checks the shape of an authoritative provider result. Numeric ceilings,
// NTS evidence, age, uncertainty calculation and holds belong to timeconf.
func Valid(v timeconf.Sample) bool {
	_, _, ok := Bounds(v)
	return ok
}

// Bounds preserves the provider's nanosecond interval [O-delta,O+delta]. It
// checks U<A, not O<A. This shape check supplies neither receipt authentication
// nor current-boot, durable continuity or bounded-handoff qualification.
func Bounds(v timeconf.Sample) (lower, upper time.Time, ok bool) {
	if !v.Trusted || !v.Fresh || v.Now.IsZero() || v.Boot == "" || v.Uncertainty < 0 {
		return lower, upper, false
	}
	o, a := v.Now.UnixNano(), v.AuthorityUntil.UnixNano()
	// UnixNano is undefined outside its int64 range. Check the exact round trip;
	// strip Go monotonic metadata so it cannot hide a UTC correction.
	if !time.Unix(0, o).Equal(v.Now.Round(0)) || !time.Unix(0, a).Equal(v.AuthorityUntil.Round(0)) {
		return lower, upper, false
	}
	d := int64(v.Uncertainty)
	if o < math.MinInt64+d || o > math.MaxInt64-d || o+d >= a {
		return lower, upper, false
	}
	return time.Unix(0, o-d).UTC(), time.Unix(0, o+d).UTC(), true
}

// SecondInterval is a conservative G4 projection, never a replacement receipt.
// Its original nanosecond predicates must also pass before using these bounds.
type SecondInterval struct {
	Lower, Upper, AuthorityUntil int64
}

func ProjectSeconds(v timeconf.Sample) (SecondInterval, bool) {
	l, u, ok := Bounds(v)
	if !ok {
		return SecondInterval{}, false
	}
	// G4 Stamp starts at 1970; checked int64 ns already imposes a stricter
	// upper limit than its year-9999 ceiling.
	if l.Unix() < 0 {
		return SecondInterval{}, false
	}
	upper := u.Unix()
	if u.Nanosecond() != 0 {
		upper++
	}
	s := SecondInterval{Lower: l.Unix(), Upper: upper, AuthorityUntil: v.AuthorityUntil.Unix()}
	// Floor lower/exclusive endpoints, ceil upper. Conversion may refuse more.
	return s, s.Upper < s.AuthorityUntil
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
