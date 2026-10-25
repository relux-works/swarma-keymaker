package registration

import (
	"context"
	"testing"
	"time"
)

// A later valid provider sample cannot extend a retained proof's authority:
// its U at the original A refuses, and U=A-1ns is a release-time control.
func TestQualifiedTimeRetainedAuthority(t *testing.T) {
	for _, overlap := range []bool{true, false} {
		t.Run(map[bool]string{true: "upper-equals-original-authority", false: "upper-before-original-authority"}[overlap], func(t *testing.T) {
			f := setup(t)
			p, c, clock := confidenceFixture(t, f.clock.at)
			c.e.Tracking.RootDispersion = .5
			c.e.Tracking.Reference = clock.point.Now.Add(-2046 * time.Second)
			f.builder.clock = p
			proof, code := f.builder.Build(context.Background(), f.in)
			if code != OK {
				t.Fatal("issue control", code)
			}
			at := proof.authorityUntil.Add(-500 * time.Millisecond)
			if !overlap {
				at = at.Add(-time.Nanosecond)
			}
			clock.point.Elapsed += at.Sub(clock.point.Now)
			clock.point.Now = at
			c.e.Tracking.Reference = at.Add(-time.Second)
			want := OK
			if overlap {
				want = ClockUntrusted
			}
			if code = proof.Recheck(context.Background()); code != want {
				t.Fatal("retained authority ignores uncertainty", code, want)
			}
		})
	}
}
