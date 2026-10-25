//go:build linux

package enrollment

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
)

// The real provider's delta and A survive the Linux adapter bit-for-bit. This
// fake evidence/clock control does not qualify native collection or durability.
func TestQualifiedTimeEnrollmentPreservesProvider(t *testing.T) {
	point, e := (timeconf.SystemClock{}).Read(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	point.Now = testNow
	policy := timeconf.Policy{Source: timeconf.NTSConfig, Chronyc: "/usr/bin/chronyc", SourceFiles: []string{"/etc/chrony/chrony.conf"}, MaxSyncAge: timeconf.PlatformMaxSyncAge, MaxUncertainty: timeconf.PlatformMaxUncertainty, MaxOffset: timeconf.PlatformMaxOffset, MaxRootDistance: timeconf.PlatformMaxRootDistance, AuthorityWindow: timeconf.PlatformAuthorityWindow, StepTolerance: time.Second, Timeout: time.Second, MaxOutputBytes: 4096, Resync: "operator"}
	evidence := timeconf.Evidence{Tracking: timeconf.Tracking{ReferenceID: "C0000201", Address: "192.0.2.1", Stratum: 3, Reference: testNow.Add(-time.Second), Leap: "Normal", RootDispersion: .123456789}, Sources: timeconf.Sources{Count: 1, AllNTS: true, Entries: []string{"192.0.2.1"}}}
	p, e := timeconf.New(policy, approvalEvidence{evidence}, approvalPoint{point}, func(timeconf.Incident) {})
	if e != nil {
		t.Fatal(e)
	}
	want, e := timeconfidence.Sample(context.Background(), p)
	if e != nil {
		t.Fatal(e)
	}
	got, e := (linuxApprovalSource{context.Background(), p}).sample()
	if e != nil {
		t.Fatal(e)
	}
	if got.uncertainty != want.Uncertainty || got.uncertainty <= 0 || got.authorityUntil != want.AuthorityUntil || got.utc != want.Now.UnixNano() || got.bootID != want.Boot {
		t.Fatal("provider facts dropped or changed", got, want)
	}
}

func qualifiedApprovalInstant() approvalInstant {
	return approvalInstant{bootID: "current-boot", utc: int64(698 * time.Second), boot: int64(1598 * time.Second), trusted: true, uncertainty: time.Second, authorityUntil: time.Unix(1000, 0)}
}

// Current uncertainty only tightens the existing issue-point TTL; U at its
// deadline or A refuses. Same-boot elapsed TTL and rollback checks remain. The
// persisted issue point is unchanged; this does not prove the L_issue deadline.
func TestQualifiedTimeEnrollmentDecision(t *testing.T) {
	a := commandApproval{ID: strings.Repeat("1", 64), LedgerID: strings.Repeat("2", 64), BootID: "current-boot", ConfirmedUTC: int64(100 * time.Second), ConfirmedBoot: int64(1000 * time.Second)}
	good := qualifiedApprovalInstant()
	good.utc = int64(699*time.Second) - 1 // U=700s-1ns < O_issue+600s
	for _, tc := range []struct {
		name, want string
		change     func(*approvalInstant)
	}{
		{"delta-overlaps-deadline", "approval_expired", func(i *approvalInstant) { i.utc++ }},
		{"authority-equality", errTrust.Error(), func(i *approvalInstant) { i.authorityUntil = time.Unix(0, i.utc+int64(i.uncertainty)) }},
		{"authority-past", errTrust.Error(), func(i *approvalInstant) { i.authorityUntil = time.Unix(0, i.utc) }},
		{"unknown-authority", errTrust.Error(), func(i *approvalInstant) { i.authorityUntil = time.Time{} }},
		{"untrusted", errTrust.Error(), func(i *approvalInstant) { i.trusted = false }},
		{"negative-delta", errTrust.Error(), func(i *approvalInstant) { i.uncertainty = -1 }},
		{"another-boot", "approval_boot_changed", func(i *approvalInstant) { i.bootID = "another-boot" }},
		{"boot-age-600", "approval_expired", func(i *approvalInstant) { i.boot = a.ConfirmedBoot + int64(600*time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := good
			tc.change(&bad)
			e := approvalValid(a, &fixedApprovalSource{instant: bad})
			if e == nil || e.Error() != tc.want {
				t.Fatal("wrong refusal", e, tc.want)
			}
			if e = approvalValid(a, &fixedApprovalSource{instant: good}); e != nil {
				t.Fatal("nearby valid control", e)
			}
		})
	}
	if e := approvalValid(a, nil); e == nil {
		t.Fatal("nil source accepted")
	}
	if _, e := newCommandApproval("/fixture/pins", PinConfig{}, "state", nil); e == nil {
		t.Fatal("nil source minted approval")
	}
}

// Arithmetic only, no activation claim: issue [99,101] sets D<=699; U=699
// refuses while U=698.999999999 passes just this interval/600s time predicate.
// Durable issue delta/deadline/receipt retention is an explicit pending gate.
func TestQualifiedTimeEnrollment600Arithmetic(t *testing.T) {
	issue := timeconf.Sample{Now: time.Unix(100, 0), Uncertainty: time.Second, AuthorityUntil: time.Unix(1000, 0), Boot: "current-boot", Trusted: true, Fresh: true}
	l, u, ok := timeconfidence.Bounds(issue)
	if !ok || l.Unix() != 99 || u.Unix() != 101 {
		t.Fatal("issue bounds", l, u, ok)
	}
	deadline := l.Add(600 * time.Second)
	for _, tc := range []struct {
		ns   int64
		pass bool
	}{{0, false}, {-1, true}} {
		now := approvalInstant{bootID: issue.Boot, utc: deadline.Add(-time.Second).UnixNano() + tc.ns, boot: int64(599 * time.Second), trusted: true, uncertainty: time.Second, authorityUntil: issue.AuthorityUntil}
		upper, valid := approvalUpper(now)
		pass := valid && now.bootID == issue.Boot && now.boot < int64(600*time.Second) && upper < deadline.UnixNano()
		if pass != tc.pass || deadline.Unix() != 699 {
			t.Fatal("600-second arithmetic", tc, pass, deadline)
		}
	}
}
