package timeconfidence

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

func sample(o int64, d time.Duration, a int64) timeconf.Sample {
	return timeconf.Sample{Now: time.Unix(0, o), Uncertainty: d, AuthorityUntil: time.Unix(0, a), Boot: "current-boot", Trusted: true, Fresh: true}
}

// U=A refuses even with O<A; an authority endpoint one ns later passes only
// this local shape predicate. Unknown, stale and unrepresentable facts refuse.
func TestQualifiedTimeAuthority(t *testing.T) {
	const s = int64(time.Second)
	good := sample(211*s, time.Second, 230*s)
	for _, tc := range []struct {
		name   string
		change func(*timeconf.Sample)
	}{
		{"upper-equals-authority", func(v *timeconf.Sample) { v.AuthorityUntil = time.Unix(212, 0) }},
		{"upper-after-authority", func(v *timeconf.Sample) { v.AuthorityUntil = time.Unix(212, -1) }},
		{"observed-at-authority", func(v *timeconf.Sample) { v.AuthorityUntil = v.Now }},
		{"observed-after-authority", func(v *timeconf.Sample) { v.AuthorityUntil = v.Now.Add(-time.Nanosecond) }},
		{"unknown", func(v *timeconf.Sample) { v.Trusted = false }},
		{"stale", func(v *timeconf.Sample) { v.Fresh = false }},
		{"missing-boot", func(v *timeconf.Sample) { v.Boot = "" }},
		{"negative-delta", func(v *timeconf.Sample) { v.Uncertainty = -1 }},
		{"upper-overflow", func(v *timeconf.Sample) {
			v.Now = time.Unix(0, math.MaxInt64)
			v.AuthorityUntil = time.Unix(0, math.MaxInt64)
		}},
		{"lower-overflow", func(v *timeconf.Sample) { v.Now = time.Unix(0, math.MinInt64) }},
		{"outside-nanoseconds", func(v *timeconf.Sample) { v.Now = time.Date(2500, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"authority-outside-nanoseconds", func(v *timeconf.Sample) { v.AuthorityUntil = time.Date(2500, 1, 1, 0, 0, 0, 0, time.UTC) }},
		{"nil-time", func(v *timeconf.Sample) { v.Now = time.Time{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := good
			tc.change(&v)
			if Valid(v) {
				t.Fatal("invalid interval accepted")
			}
			if !Valid(good) {
				t.Fatal("nearby valid control refused")
			}
		})
	}
	edge := good
	edge.AuthorityUntil = time.Unix(212, 1)
	if !Valid(edge) {
		t.Fatal("U+1ns authority refused")
	}
	if e := Start(context.Background(), nil); e != timeconf.ErrUnavailable {
		t.Fatal("nil provider start", e)
	}
	if v, e := Sample(context.Background(), nil); e != timeconf.ErrUnavailable || v != (timeconf.Sample{}) {
		t.Fatal("nil provider sample", v, e)
	}
	off, _ := timeconf.Production(nil, nil)
	if v, e := Sample(context.Background(), off); e != timeconf.ErrUnavailable || v != (timeconf.Sample{}) {
		t.Fatal("kernel clock fallback", v, e)
	}
}

// Increasing delta can only remove a pass, never enlarge authority. This checks
// the exact ns boundary rather than trusting a rounded observed-time comparison.
func TestQualifiedTimeDeltaOnlyTightens(t *testing.T) {
	v := sample(211*int64(time.Second), time.Second, 212*int64(time.Second))
	if Valid(v) {
		t.Fatal("looser delta accepted U=A")
	}
	v.Uncertainty--
	if !Valid(v) {
		t.Fatal("tighter delta control refused")
	}
}

// Projection floors L/A and ceils U, on both sides of whole seconds. G4 cannot
// represent a pre-1970 lower bound. Original and converted predicates must hold.
func TestQualifiedTimeSecondProjection(t *testing.T) {
	for _, ns := range []int64{-1, 0, 1} {
		v := sample(211*int64(time.Second)+ns, time.Second, 230*int64(time.Second)+ns)
		p, ok := ProjectSeconds(v)
		if !ok {
			t.Fatal("coarse control refused", ns)
		}
		wantL, wantU, wantA := int64(210), int64(212), int64(230)
		if ns < 0 {
			wantL--
			wantA--
		}
		if ns > 0 {
			wantU++
		}
		if p != (SecondInterval{wantL, wantU, wantA}) {
			t.Fatalf("projection %d: %+v", ns, p)
		}
	}
	v := sample(-int64(time.Second), time.Nanosecond, 3*int64(time.Second))
	if _, ok := ProjectSeconds(v); ok {
		t.Fatal("pre-1970 G4 projection accepted")
	}
	v = sample(1, time.Nanosecond, 3*int64(time.Second))
	if p, ok := ProjectSeconds(v); !ok || p != (SecondInterval{0, 1, 3}) {
		t.Fatal("G4 epoch control", p, ok)
	}
	v = sample(211*int64(time.Second), time.Second, 212*int64(time.Second)+1)
	if !Valid(v) {
		t.Fatal("exact control refused")
	}
	if _, ok := ProjectSeconds(v); ok {
		t.Fatal("coarse exclusive endpoint enlarged")
	}
}

// Arithmetic only: the provider must retain the consumed U=201 across failed
// operations/restart. These local intervals do not simulate durable continuity.
func TestQualifiedTimeConsumedVector(t *testing.T) {
	const s = int64(time.Second)
	journal := time.Unix(140, 0)
	l, u, ok := Bounds(sample(200*s, time.Second, 230*s))
	if !ok || !l.After(journal) || u.UnixNano() != 201*s {
		t.Fatal("consumed upper bound", u, ok)
	}
	for _, tc := range []struct {
		o    int64
		pass bool
	}{{171, false}, {211, true}} {
		l, _, ok := Bounds(sample(tc.o*s, time.Second, 230*s))
		if !ok || !l.After(journal) || l.After(u) != tc.pass {
			t.Fatal("floor 140 cannot replace consumed 201", tc, l)
		}
	}
}
