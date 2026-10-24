//go:build linux

package enrollment

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
)

type approvalEvidence struct{ e timeconf.Evidence }

func (c approvalEvidence) Collect(context.Context, timeconf.Policy) (timeconf.Evidence, error) {
	return c.e, nil
}

type approvalPoint struct{ v timeconf.ClockPoint }

func (c approvalPoint) Read(context.Context) (timeconf.ClockPoint, error) { return c.v, nil }
func approvalProvider(t *testing.T) *timeconf.Provider {
	t.Helper()
	point, e := (timeconf.SystemClock{}).Read(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	point.Now = testNow
	policy := timeconf.Policy{Source: timeconf.NTSConfig, Chronyc: "/usr/bin/chronyc", SourceFiles: []string{"/etc/chrony/chrony.conf"}, MaxSyncAge: timeconf.PlatformMaxSyncAge, MaxUncertainty: timeconf.PlatformMaxUncertainty, MaxOffset: timeconf.PlatformMaxOffset, MaxRootDistance: timeconf.PlatformMaxRootDistance, AuthorityWindow: timeconf.PlatformAuthorityWindow, StepTolerance: time.Second, Timeout: time.Second, MaxOutputBytes: 4096, Resync: "operator"}
	evidence := timeconf.Evidence{Tracking: timeconf.Tracking{ReferenceID: "C0000201", Address: "192.0.2.1", Stratum: 3, Reference: testNow.Add(-time.Second), Leap: "Normal"}, Sources: timeconf.Sources{Count: 1, AllNTS: true, Entries: []string{"192.0.2.1"}}}
	p, e := timeconf.New(policy, approvalEvidence{evidence}, approvalPoint{point}, func(timeconf.Incident) {})
	if e != nil {
		t.Fatal(e)
	}
	return p
}

// Missing production policy refuses before approval creation. The same approval
// builder uses provider UTC/boot with trusted fake evidence and retains the
// independent real boottime TTL; raw kernel UTC never supplies confidence.
func TestTimeConfidenceApproval(t *testing.T) {
	if _, e := approvalSourceFor(context.Background(), LinuxFiles{}, nil); e == nil || e.Error() != "clock_untrusted" {
		t.Fatal("missing policy trusted", e)
	}
	off, _ := timeconf.Production(nil, nil)
	if _, e := newCommandApproval("/fixture/pins", PinConfig{}, "fixture-state", linuxApprovalSource{context.Background(), off}); e == nil || !strings.Contains(e.Error(), "clock_untrusted") {
		t.Fatal("unavailable provider minted receipt", e)
	}
	p := approvalProvider(t)
	if e := timeconfidence.Start(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	source := linuxApprovalSource{context.Background(), p}
	a, e := newCommandApproval("/fixture/pins", PinConfig{}, "fixture-state", source)
	if e != nil || a.ConfirmedUTC != testNow.UnixNano() || a.ConfirmedBoot <= 0 || a.BootID == "" {
		t.Fatal("provider approval control", e)
	}
	a.LedgerID = strings.Repeat("1", 64)
	if e = approvalValid(a, source); e != nil {
		t.Fatal("provider approval validation control", e)
	}
}

// Hide only the package-local clock fixture while retaining ownership metadata.
// The real production default must consume/invalidate the one-use receipt before
// failing time validation, with high-water and replay ledger bytes unchanged.
type noApprovalTimeFiles struct{ f fixtureFiles }

func (f noApprovalTimeFiles) Lstat(p string) (Metadata, error)                 { return f.f.Lstat(p) }
func (f noApprovalTimeFiles) Read(p string, n int64) ([]byte, Metadata, error) { return f.f.Read(p, n) }
func (f noApprovalTimeFiles) Readable(p string) error                          { return f.f.Readable(p) }
func (f noApprovalTimeFiles) openedMetadata(p *os.File) (Metadata, error) {
	return f.f.openedMetadata(p)
}
func TestTimeConfidenceApprovalInvalidation(t *testing.T) {
	f, high := reconciliationFixture(t)
	expectCommandApproval(t, f, high)
	before := map[string][]byte{}
	for _, name := range []string{"high-water.json", consumedName} {
		b, e := os.ReadFile(filepath.Join(f.config.StateDir, name))
		if e != nil {
			t.Fatal(e)
		}
		before[name] = b
	}
	files := noApprovalTimeFiles{f.files}
	location, e := locateConfig(f.configPath, files)
	if e != nil {
		t.Fatal(e)
	}
	r := &commandReconciler{configPath: f.configPath, files: files}
	if _, e := r.startup(context.Background(), location); e == nil || e.Error() != "clock_untrusted" {
		t.Fatal("missing confidence startup verdict", e)
	}
	if _, e := os.Stat(filepath.Join(f.config.StateDir, approvalName)); !os.IsNotExist(e) {
		t.Fatal("receipt not invalidated", e)
	}
	if _, e := os.Stat(filepath.Join(f.config.StateDir, consumingName)); e != nil {
		t.Fatal("failure evidence erased", e)
	}
	for name, want := range before {
		got, e := os.ReadFile(filepath.Join(f.config.StateDir, name))
		if e != nil || string(got) != string(want) {
			t.Fatal("refusal mutated retained state", name, e)
		}
	}
	// Independent nearby valid startup is covered by the same production receipt
	// flow with this package's explicit clock fixture, not by bypassing consumption.
	control, h := reconciliationFixture(t)
	expectCommandApproval(t, control, h)
	startApproved(t, control)
}

// The pin policy delegates nested decoding to the shared strict policy schema;
// no source/fake option or null can bypass it. Off is a valid structural control.
func TestTimeConfidencePinPolicy(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = strings.Repeat("a", 40)
	f.writeConfig()
	raw, e := os.ReadFile(f.configPath)
	if e != nil {
		t.Fatal(e)
	}
	for _, policy := range []string{`null`, `{"source":"off","fake_collector":true}`, `{"source":"chrony-nts-config"}`} {
		candidate := fmt.Sprintf("%s,\"time_policy\":%s}", strings.TrimSuffix(string(raw), "}"), policy)
		if _, e := ParseConfig([]byte(candidate)); e == nil {
			t.Fatal("bad provider pin policy accepted", policy)
		}
	}
	if _, e := ParseConfig([]byte(strings.TrimSuffix(string(raw), "}") + `,"time_policy":{"source":"off"}}`)); e != nil {
		t.Fatal("off policy control", e)
	}
}

type approvalTimeLossOps struct {
	diskOps
	clock *fixedApprovalSource
	state string
}

func (o approvalTimeLossOps) SyncDir(path string) error {
	e := o.diskOps.SyncDir(path)
	if e == nil && path == o.state {
		if _, err := os.Stat(filepath.Join(path, approvalName)); err == nil {
			o.clock.instant.trusted = false
		}
	}
	return e
}

// Confidence lost during durable receipt publication cannot clear its root
// fence or report approval. Healthy publication is the adjacent real-I/O
// control; both cases use the existing package-private elapsed-clock fixture.
func TestTimeConfidenceApprovalPublication(t *testing.T) {
	for _, loss := range []bool{true, false} {
		t.Run(map[bool]string{true: "loss", false: "trusted"}[loss], func(t *testing.T) {
			f, high := reconciliationFixture(t)
			clock := approvalTestClock(f)
			var ops durableOps = diskOps{}
			if loss {
				ops = approvalTimeLossOps{clock: clock, state: f.config.StateDir}
			}
			reports, e := runFixtureReconcile(f, StateDigest(high), nil, ops)
			if loss {
				if e == nil || !strings.Contains(e.Error(), "approval_write_failed_fenced") {
					t.Fatal("time loss unfenced publication", e)
				}
				if len(reports) != 1 || reports[0].Approved {
					t.Fatal("time loss reported success", reports)
				}
				if _, e := os.Stat(pendingPath(f.configPath)); e != nil {
					t.Fatal("publication failure erased fence", e)
				}
			} else if e != nil || len(reports) != 2 || !reports[1].Approved {
				t.Fatal("trusted publication control", e, reports)
			}
		})
	}
}
