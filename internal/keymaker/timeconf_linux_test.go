//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/control"
	proof "github.com/relux-works/swarma-keymaker/internal/registration"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
)

// Default audit confidence must never manufacture trusted UTC. A provider with
// trusted fixture evidence supplies its own instant without consulting host NTP.
func TestTimeConfidenceAuditDefault(t *testing.T) {
	if at, ok := (systemAuditClock{}).UTC(); ok || !at.IsZero() {
		t.Fatal("missing provider trusted kernel UTC", at, ok)
	}
	p, _, _ := fixtureTimeProvider(t, helperNow)
	if err := timeconfidence.Start(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if at, ok := (systemAuditClock{provider: p}).UTC(); !ok || !at.Equal(helperNow) {
		t.Fatal("trusted provider audit control", at, ok)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if at, ok := (systemAuditClock{provider: p}).UTCContext(ctx); ok || !at.IsZero() {
		t.Fatal("cancelled audit trusted time", at, ok)
	}
}

// Time policy absence closes otherwise configured startup before installation
// I/O or readiness. Generation absence retains its existing earlier refusal.
func TestTimeConfidenceStartupMissing(t *testing.T) {
	d := t.TempDir()
	cfg := Config{ServiceUID: uint32(os.Getuid()), ServiceGID: uint32(os.Getgid()), Epoch: "fixture", RegistryRevision: "fixture", SocketDir: d, StateDir: d, MasterFile: filepath.Join(d, "missing")}
	// Supplying a generation source exercises the time gate rather than its
	// independent missing-journal gate; no fake collector is selected by config.
	err := serveValidatedConfig(context.Background(), cfg, os.Stderr, UnavailableGeneration{})
	if err != Code("clock_untrusted") {
		t.Fatal("missing policy did not close time readiness", err)
	}
	entries, _ := os.ReadDir(d)
	if len(entries) != 0 {
		t.Fatal("time refusal wrote installation state")
	}
}

type fixtureTimeClock struct {
	mu    sync.Mutex
	point timeconf.ClockPoint
}

func (c *fixtureTimeClock) Read(context.Context) (timeconf.ClockPoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.point, nil
}
func (c *fixtureTimeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.point.Now = c.point.Now.Add(d)
	c.point.Elapsed += d
}

type fixtureTimeCollector struct{ e timeconf.Evidence }

func (c *fixtureTimeCollector) Collect(context.Context, timeconf.Policy) (timeconf.Evidence, error) {
	return c.e, nil
}
func fixtureTimeProvider(t *testing.T, now time.Time) (*timeconf.Provider, *fixtureTimeClock, *fixtureTimeCollector) {
	t.Helper()
	policy := timeconf.Policy{Source: timeconf.NTSConfig, Chronyc: "/usr/bin/chronyc", SourceFiles: []string{"/etc/chrony/chrony.conf"}, MaxSyncAge: timeconf.PlatformMaxSyncAge, MaxUncertainty: timeconf.PlatformMaxUncertainty, MaxOffset: timeconf.PlatformMaxOffset, MaxRootDistance: timeconf.PlatformMaxRootDistance, AuthorityWindow: timeconf.PlatformAuthorityWindow, StepTolerance: time.Second, Timeout: time.Second, MaxOutputBytes: 4096, Resync: "operator"}
	clock := &fixtureTimeClock{point: timeconf.ClockPoint{Now: now, Elapsed: time.Hour, Boot: "fixture-boot"}}
	c := &fixtureTimeCollector{timeconf.Evidence{Tracking: timeconf.Tracking{ReferenceID: "C0000201", Address: "192.0.2.1", Stratum: 3, Reference: now.Add(-time.Second), Leap: "Normal"}, Sources: timeconf.Sources{Count: 1, AllNTS: true, Entries: []string{"192.0.2.1"}}}}
	p, e := timeconf.New(policy, c, clock, func(timeconf.Incident) {})
	if e != nil {
		t.Fatal(e)
	}
	return p, clock, c
}

// No-policy production confidence refuses on the real helper socket before
// entropy/signing, retained success or a success audit. A trusted provider with
// fake collector/clock interfaces yields one verifiable success on the same path.
func TestTimeConfidenceHelperUnavailable(t *testing.T) {
	for _, bad := range []bool{true, false} {
		t.Run(map[bool]string{true: "unavailable", false: "trusted"}[bad], func(t *testing.T) {
			f, tr := helperSetup(t)
			p, _, _ := fixtureTimeProvider(t, helperNow)
			if bad {
				p, _ = timeconf.Production(nil, nil)
			}
			signer := &reloadCountingSigner{signer: registrationSigner{f.master, helperPath}}
			entropy := bytes.NewReader(make([]byte, 16))
			b, e := proof.New(p, entropy, signer)
			if e != nil {
				t.Fatal(e)
			}
			tr.helper.builder = b
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			before := nativeSnapshot(t, f)
			want := Code("")
			if bad {
				want = "clock_untrusted"
			}
			helperCall(t, f, c, 2, want)
			f.stop(t)
			expected := int32(1)
			if bad {
				expected = 0
			}
			if signer.calls.Load() != expected {
				t.Fatal("unexpected signature", signer.calls.Load())
			}
			if bad && (entropy.Len() != 16 || !bytes.Equal(before, nativeSnapshot(t, f))) {
				t.Fatal("untrusted time consumed entropy or retained success")
			}
			raw, e := os.ReadFile(filepath.Join(f.state.Name(), "audit", auditName(1)))
			if e != nil {
				t.Fatal(e)
			}
			seen := false
			for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte{'\n'}) {
				var r AuditRecord
				if e = json.Unmarshal(line, &r); e != nil {
					t.Fatal(e)
				}
				if r.Operation == "sign_registration" {
					seen = true
					if bad && (r.Result == "success" || r.RefusalCode == nil || *r.RefusalCode != "clock_untrusted") {
						t.Fatal("untrusted helper success audit", r)
					}
				}
			}
			if !seen {
				t.Fatal("missing helper audit")
			}
		})
	}
}

type timeconfSyncAdvance struct {
	durableFile
	once    sync.Once
	advance func()
}

func (w *timeconfSyncAdvance) Sync() error { e := w.durableFile.Sync(); w.once.Do(w.advance); return e }

// Final audit Sync crosses evidence's exclusive authority endpoint. The response
// must be clock_untrusted; omitting the post-audit recheck releases a proof. A
// neighboring sync that leaves evidence fresh releases a verifiable proof.
func TestTimeConfidenceHelperAfterAudit(t *testing.T) {
	for _, expired := range []bool{true, false} {
		t.Run(map[bool]string{true: "expired", false: "fresh"}[expired], func(t *testing.T) {
			f, tr := helperSetup(t)
			p, clock, collector := fixtureTimeProvider(t, helperNow)
			collector.e.Tracking.Reference = helperNow.Add(-2047 * time.Second)
			h, e := NewRegistrationHelper(f.master, helperPath, tr.authority, p, bytes.NewReader(make([]byte, 16)))
			if e != nil {
				t.Fatal(e)
			}
			f.native.Config.Helper = h
			f.config.Helper = h
			probe := &nativeFenceProbe{native: f.native, method: "sign_registration", before: func() {
				f.store.journal.mu.Lock()
				defer f.store.journal.mu.Unlock()
				d := time.Millisecond
				if expired {
					d = 2 * time.Second
				}
				f.store.journal.writer = &timeconfSyncAdvance{durableFile: f.store.journal.writer, advance: func() { clock.advance(d) }}
			}}
			wire, e := control.New(f.native, f.native, f.native, probe, f.native)
			if e != nil {
				t.Fatal(e)
			}
			f.server.controlWire = wire
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			want := Code("")
			if expired {
				want = "clock_untrusted"
			}
			helperCall(t, f, c, 2, want)
		})
	}
}

// Embedded policy uses the provider's strict decoder. Missing policy remains
// structurally valid/off, but production startup refuses it; malformed, looser,
// unknown and null configurations cannot select authority through the schema.
func TestTimeConfidenceConfig(t *testing.T) {
	base := `{"socket_dir":"/run/keymaker","state_dir":"/var/lib/keymaker","master_file":"/var/lib/keymaker/master","registry_file":"/etc/keymaker/registry","service_uid":1,"service_gid":1,"control_gid":1,"operator_principal":{"uid":1,"generation":"x"},"master_epoch":"x","registry_revision":"x"}`
	for _, raw := range []string{`null`, `{"source":"off","fake_collector":true}`, `{"source":"chrony-nts-config"}`, `{"source":"off","source":"off"}`} {
		if _, err := ParseConfig(strings.NewReader(strings.TrimSuffix(base, "}") + `,"time_policy":` + raw + `}`)); err == nil {
			t.Fatal("invalid provider policy accepted", raw)
		}
	}
	cfg, err := ParseConfig(strings.NewReader(strings.TrimSuffix(base, "}") + `,"time_policy":{"source":"off"}}`))
	if err != nil || cfg.TimePolicy == nil || cfg.TimePolicy.Source != timeconf.Off {
		t.Fatal("off control", err)
	}
}

// Section11 permits missing confidence to record null time/unknown rather than
// invent UTC. A subsequent trusted provider sample restores timestamped records.
func TestTimeConfidenceAuditNullTime(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	fd, e := OpenDirectory(dir, uint32(os.Getuid()), 0700)
	if e != nil {
		t.Fatal(e)
	}
	defer fd.Close()
	j, e := OpenJournal(fd, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if c := j.Append(AuditRecord{Operation: "pubkey", Result: "success"}); c != "" {
		t.Fatal(c)
	}
	p, _, _ := fixtureTimeProvider(t, helperNow)
	j.clock = systemAuditClock{provider: p}
	if c := j.Append(AuditRecord{Operation: "pubkey", Result: "success"}); c != "" {
		t.Fatal(c)
	}
	raw, e := os.ReadFile(filepath.Join(dir, auditName(1)))
	if e != nil {
		t.Fatal(e)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte{'\n'})
	if len(lines) != 2 {
		t.Fatal("record count", len(lines))
	}
	for i, line := range lines {
		var r AuditRecord
		if e = json.Unmarshal(line, &r); e != nil {
			t.Fatal(e)
		}
		if i == 0 {
			if r.Time != nil || r.Result != "unknown" {
				t.Fatal("fabricated confidence", r)
			}
		} else if r.Time == nil || *r.Time != helperNow.Format("2006-01-02T15:04:05Z") || r.Result != "success" {
			t.Fatal("trusted audit control", r)
		}
	}
}
