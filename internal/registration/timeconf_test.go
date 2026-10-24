package registration

import (
	"context"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
)

type confidenceCollector struct{ e timeconf.Evidence }

func (c *confidenceCollector) Collect(context.Context, timeconf.Policy) (timeconf.Evidence, error) {
	return c.e, nil
}

type confidenceClock struct{ point timeconf.ClockPoint }

func (c *confidenceClock) Read(context.Context) (timeconf.ClockPoint, error) { return c.point, nil }
func confidenceFixture(t *testing.T, now time.Time) (*timeconf.Provider, *confidenceCollector, *confidenceClock) {
	t.Helper()
	policy := timeconf.Policy{Source: timeconf.NTSConfig, Chronyc: "/usr/bin/chronyc", SourceFiles: []string{"/etc/chrony/chrony.conf"}, MaxSyncAge: timeconf.PlatformMaxSyncAge, MaxUncertainty: timeconf.PlatformMaxUncertainty, MaxOffset: timeconf.PlatformMaxOffset, MaxRootDistance: timeconf.PlatformMaxRootDistance, AuthorityWindow: timeconf.PlatformAuthorityWindow, BackwardTolerance: 0, StepTolerance: time.Second, Timeout: time.Second, MaxOutputBytes: 4096, Resync: "operator"}
	c := &confidenceCollector{timeconf.Evidence{Tracking: timeconf.Tracking{ReferenceID: "C0000201", Address: "192.0.2.1", Stratum: 3, Reference: now.Add(-time.Second), Leap: "Normal"}, Sources: timeconf.Sources{Count: 1, AllNTS: true, Entries: []string{"192.0.2.1"}}}}
	clock := &confidenceClock{timeconf.ClockPoint{Now: now, Elapsed: time.Hour, Boot: "fixture-boot"}}
	p, e := timeconf.New(policy, c, clock, func(timeconf.Incident) {})
	if e != nil {
		t.Fatal(e)
	}
	return p, c, clock
}

// Real provider semantics decide freshness, inclusive delta cap and step holds.
// Refusals precede signing; each rejected source has a separate trusted control.
// These fake evidence/clock interfaces do not qualify the host collector.
func TestTimeConfidenceProviderBounds(t *testing.T) {
	for _, name := range []string{"unavailable", "age-2048", "age-2047.999", "delta-over-cap", "delta-at-cap", "backward-hold"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			p, c, clock := confidenceFixture(t, f.clock.at)
			if e := timeconfidence.Start(context.Background(), p); e != nil {
				t.Fatal(e)
			}
			want := ClockUntrusted
			switch name {
			case "unavailable":
				p, _ = timeconf.Production(nil, nil)
			case "age-2048":
				c.e.Tracking.Reference = clock.point.Now.Add(-2048 * time.Second)
			case "age-2047.999":
				c.e.Tracking.Reference = clock.point.Now.Add(-2047999 * time.Millisecond)
				want = OK
			case "delta-over-cap", "delta-at-cap":
				c.e.Tracking.SystemOffset = .5
				c.e.Tracking.RootDelay = 1
				c.e.Tracking.RootDispersion = .5
				if name == "delta-over-cap" {
					c.e.Tracking.Skew = .001
				} else {
					want = OK
				}
			case "backward-hold":
				clock.point.Now = clock.point.Now.Add(-2 * time.Second)
				clock.point.Elapsed += time.Second
				c.e.Tracking.Reference = clock.point.Now.Add(-time.Second)
			}
			f.builder.clock = p
			proof, code := f.builder.Build(context.Background(), f.in)
			if code != want || (proof != nil) != (want == OK) || (f.calls != 0) != (want == OK) {
				t.Fatal("provider verdict/signature", code, want, f.calls)
			}
			if name == "backward-hold" {
				if _, code = f.builder.Build(context.Background(), f.in); code != ClockUntrusted {
					t.Fatal("hold cleared", code)
				}
			}
			control := setup(t)
			good, _, _ := confidenceFixture(t, control.clock.at)
			control.builder.clock = good
			if proof, code = control.builder.Build(context.Background(), control.in); code != OK || proof == nil || control.calls != 1 {
				t.Fatal("trusted control refused", code, control.calls)
			}
		})
	}
}

// Returned uncertainty narrows key and proof validity instead of being replaced
// by offset-only arithmetic. A grant ending between issue and recheck refuses
// clock_untrusted even if the new sample has a later grant; a fresh in-window
// control succeeds. No signed-document lifetime or authority is extended.
func TestTimeConfidenceUncertaintyAuthority(t *testing.T) {
	t.Run("uncertainty-key-bound", func(t *testing.T) {
		f := setup(t)
		p, c, _ := confidenceFixture(t, f.clock.at)
		c.e.Tracking.RootDispersion = .5
		f.builder.clock = p
		f.in.Enrolled.NotBefore = f.clock.at.Unix()
		if proof, code := f.builder.Build(context.Background(), f.in); code != KeyNotValidNow || proof != nil || f.calls != 0 {
			t.Fatal("uncertainty ignored", code, f.calls)
		}
		f.in.Enrolled.NotBefore -= 2
		if proof, code := f.builder.Build(context.Background(), f.in); code != OK || proof == nil {
			t.Fatal("neighbor refused", code)
		}
	})
	for _, end := range []bool{true, false} {
		t.Run(map[bool]string{true: "authority-end", false: "authority-neighbor"}[end], func(t *testing.T) {
			f := setup(t)
			p, c, clock := confidenceFixture(t, f.clock.at)
			c.e.Tracking.Reference = clock.point.Now.Add(-2047 * time.Second)
			f.builder.clock = p
			proof, code := f.builder.Build(context.Background(), f.in)
			if code != OK {
				t.Fatal(code)
			}
			advance := time.Second
			if !end {
				advance -= time.Millisecond
			}
			clock.point.Now = clock.point.Now.Add(advance)
			clock.point.Elapsed += advance
			// New authenticated evidence alone cannot extend this proof's original grant.
			c.e.Tracking.Reference = clock.point.Now.Add(-time.Second)
			want := OK
			if end {
				want = ClockUntrusted
			}
			if code = proof.Recheck(context.Background()); code != want {
				t.Fatal("grant endpoint", code, want)
			}
		})
	}
}

// Release refuses when the provider's full uncertainty interval reaches proof
// expiry, with an adjacent interval strictly before expiry admitted. The nominal
// timestamp alone is still before expiry in both cases.
func TestTimeConfidenceUncertainExpiry(t *testing.T) {
	for _, expired := range []bool{true, false} {
		t.Run(map[bool]string{true: "uncertainty-overlap", false: "clear-neighbor"}[expired], func(t *testing.T) {
			f := setup(t)
			p, c, clock := confidenceFixture(t, f.clock.at)
			c.e.Tracking.RootDispersion = .5
			f.builder.clock = p
			proof, code := f.builder.Build(context.Background(), f.in)
			if code != OK {
				t.Fatal(code)
			}
			margin := 100 * time.Millisecond
			if !expired {
				margin = 600 * time.Millisecond
			}
			at := proof.expires.Add(-margin)
			clock.point.Elapsed += at.Sub(clock.point.Now)
			clock.point.Now = at
			c.e.Tracking.Reference = at.Add(-time.Second)
			want := OK
			if expired {
				want = RequestExpired
			}
			if code = proof.Recheck(context.Background()); code != want {
				t.Fatal("uncertainty lost at release", code, want)
			}
		})
	}
}

// Reauthorization keeps a prepared proof's original grant and revalidates the
// current signed key window. Restoring bytes for a separate attempt obtains an
// independent current observation, without another signature or nonce.
func TestTimeConfidenceReauthorize(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "within", true: "endpoint"}[expired], func(t *testing.T) {
			f := setup(t)
			p, c, clock := confidenceFixture(t, f.clock.at)
			c.e.Tracking.Reference = clock.point.Now.Add(-2047 * time.Second)
			f.builder.clock = p
			prepared, code := f.builder.Build(context.Background(), f.in)
			if code != OK {
				t.Fatal(code)
			}
			d := 500 * time.Millisecond
			if expired {
				d = time.Second
			}
			clock.point.Now = clock.point.Now.Add(d)
			clock.point.Elapsed += d
			c.e.Tracking.Reference = clock.point.Now.Add(-time.Second)
			got, code := prepared.Reauthorize(context.Background(), f.in)
			want := OK
			if expired {
				want = ClockUntrusted
			}
			if code != want || (got != nil) != (want == OK) {
				t.Fatal("original grant reset", code, want)
			}
			if got != nil && !got.authorityUntil.Equal(prepared.authorityUntil) {
				t.Fatal("grant changed")
			}
			if _, code = f.builder.Restore(context.Background(), prepared.Envelope(), f.in); code != OK || f.calls != 1 {
				t.Fatal("separate-attempt control", code, f.calls)
			}
			changed := f.in
			changed.Enrolled.NotAfter = clock.point.Now.Unix()
			if _, code = prepared.Reauthorize(context.Background(), changed); code != KeyNotValidNow {
				t.Fatal("current enrollment ignored", code)
			}
		})
	}
	var absent *Proof
	if p, c := absent.Reauthorize(context.Background(), Input{}); p != nil || c != RequestExpired {
		t.Fatal("absent proof authorized", c)
	}
}
