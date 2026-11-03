//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
)

// Missing policy and unhealthy/over-cap evidence close startup before path access; healthy evidence reaches path validation.
func TestTimeConfidenceStartupEvidence(t *testing.T) {
	d := t.TempDir()
	cfg := Config{ServiceUID: uint32(os.Getuid()), ServiceGID: uint32(os.Getgid()), Epoch: "fixture", RegistryRevision: "fixture", SocketDir: filepath.Join(d, "absent-socket"), StateDir: filepath.Join(d, "absent-state"), MasterFile: filepath.Join(d, "absent-master")}
	var status bytes.Buffer
	if err := serveValidatedConfig(context.Background(), cfg, &status, UnavailableGeneration{}); err != Code("clock_untrusted") {
		t.Fatal("missing policy", err)
	}
	for _, kind := range []string{"over-cap", "unhealthy", "expired", "inclusive-cap"} {
		t.Run(kind, func(t *testing.T) {
			p, _, collector := fixtureTimeProvider(t, helperNow)
			collector.e.Tracking.SystemOffset = 0.5
			collector.e.Tracking.RootDispersion = 1
			switch kind {
			case "over-cap":
				collector.e.Tracking.RootDispersion += 0.000000001
			case "unhealthy":
				collector.e.Tracking.Leap = "Not synchronised"
			case "expired":
				collector.e.Tracking.Reference = helperNow.Add(-2048 * time.Second)
			}
			err := serveWithClock(context.Background(), cfg, &status, UnavailableGeneration{}, p)
			if kind == "inclusive-cap" {
				if err == nil || err.Error() != "keymaker: unsafe configured ancestor" {
					t.Fatal("healthy sample did not reach path gate", err)
				}
				p, _, collector = fixtureTimeProvider(t, helperNow)
				collector.e.Tracking.SystemOffset = 0.5
				collector.e.Tracking.RootDispersion = 1
				if err := timeconfidence.Start(context.Background(), p); err != nil {
					t.Fatal("inclusive cap refused", err)
				}
			} else if err != Code("clock_untrusted") {
				t.Fatal("bad evidence reached paths", err)
			}
		})
	}
	entries, err := os.ReadDir(d)
	if err != nil || len(entries) != 0 || status.Len() != 0 {
		t.Fatal("refusal created state/socket or readiness", entries, err, status.String())
	}
}

// Missing, non-0700, wrong-owner and seed-parent state directories refuse; a service-owned 0700 child opens without writes.
// Only equality with the seed parent is refused: master_file under state_dir/sub
// is accepted by this directory gate. This does not qualify loading that seed.
func TestStartupStateDirectory(t *testing.T) {
	for _, kind := range []string{"missing", "group-writable", "other-writable", "mode-0750", "mode-0701", "wrong-owner", "master-parent", "nested-master", "valid"} {
		t.Run(kind, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0700); err != nil {
				t.Fatal(err)
			}
			child := filepath.Join(parent, "state")
			if kind != "missing" {
				if err := os.Mkdir(child, 0700); err != nil {
					t.Fatal(err)
				}
			}
			cfg := Config{StateDir: child, MasterFile: filepath.Join(parent, "master.seed")}
			uid := uint32(os.Getuid())
			switch kind {
			case "group-writable":
				if err := os.Chmod(child, 0720); err != nil {
					t.Fatal(err)
				}
			case "mode-0750":
				if err := os.Chmod(child, 0750); err != nil {
					t.Fatal(err)
				}
			case "mode-0701":
				if err := os.Chmod(child, 0701); err != nil {
					t.Fatal(err)
				}
			case "nested-master":
				sub := filepath.Join(child, "sub")
				if err := os.Mkdir(sub, 0700); err != nil {
					t.Fatal(err)
				}
				cfg.MasterFile = filepath.Join(sub, "master.seed")
			case "other-writable":
				if err := os.Chmod(child, 0702); err != nil {
					t.Fatal(err)
				}
			// A mismatched expected service UID probes real fstat ownership without chown or privileges.
			case "wrong-owner":
				uid ^= 1
			case "master-parent":
				cfg.StateDir = parent
			}
			fd, err := openStateDirectory(cfg, uid)
			if kind == "valid" || kind == "nested-master" {
				if err != nil {
					t.Fatal("valid state refused", err)
				}
				fd.Close()
			} else {
				if fd != nil {
					fd.Close()
					t.Fatal("unsafe state opened")
				}
				want := "keymaker: unsafe directory ownership or mode"
				if kind == "missing" {
					want = "keymaker: unsafe directory"
				}
				if kind == "master-parent" {
					want = "keymaker: state directory must differ from master parent"
				}
				if err == nil || err.Error() != want {
					t.Fatal("wrong refusal", err)
				}
				control := filepath.Join(parent, "control")
				if err := os.Mkdir(control, 0700); err != nil {
					t.Fatal(err)
				}
				cfg.StateDir = control
				fd, err = openStateDirectory(cfg, uint32(os.Getuid()))
				if err != nil {
					t.Fatal("nearby private child control", err)
				}
				fd.Close()
			}
			entries, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					t.Fatal("state check wrote file", entry.Name())
				}
				children, err := os.ReadDir(filepath.Join(parent, entry.Name()))
				if kind == "nested-master" && entry.Name() == "state" {
					if err != nil || len(children) != 1 || children[0].Name() != "sub" || !children[0].IsDir() {
						t.Fatal("nested seed parent changed", children, err)
					}
					children, err = os.ReadDir(filepath.Join(child, "sub"))
				}
				if err != nil || len(children) != 0 {
					t.Fatal("state check changed child", entry.Name(), err)
				}
			}
		})
	}
}

// The shipped policy passes Production validation at the inclusive backward bound;
// missing bounds fail decoding and invalid tolerances return no provider. No clock evidence is collected.
func TestTimeConfidencePackagedPolicy(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	var policy map[string]json.RawMessage
	if err := json.Unmarshal(fields["time_policy"], &policy); err != nil {
		t.Fatal(err)
	}
	delete(policy, "backward_tolerance_ns")
	fields["time_policy"], err = json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConfig(bytes.NewReader(bad)); err == nil {
		t.Fatal("incomplete policy accepted")
	}
	cfg, err := ParseConfig(bytes.NewReader(raw))
	if err != nil || cfg.TimePolicy == nil || cfg.TimePolicy.Source != timeconf.NTSConfig || cfg.TimePolicy.MaxUncertainty != 1500*time.Millisecond {
		t.Fatal("valid example refused or cap drift", cfg.TimePolicy, err)
	}
	// Broker e7619df: collect_linux.go:249-254 calls New; provider.go:65-67
	// invokes Policy.Validate. policy.go:30,63 accepts at most one second.
	if cfg.TimePolicy.BackwardTolerance != time.Second {
		t.Fatal("packaged backward tolerance drift", cfg.TimePolicy.BackwardTolerance)
	}
	provider, err := timeconf.Production(cfg.TimePolicy, nil)
	if err != nil || provider == nil {
		t.Fatal("provider refused packaged policy", err)
	}
	for _, tolerance := range []time.Duration{-time.Nanosecond, time.Second + time.Nanosecond} {
		t.Run(tolerance.String(), func(t *testing.T) {
			invalid := *cfg.TimePolicy
			invalid.BackwardTolerance = tolerance
			provider, err := timeconf.Production(&invalid, nil)
			if err != timeconf.ErrUnavailable || provider != nil {
				t.Fatal("invalid tolerance did not refuse with no provider", provider, err)
			}
		})
	}
	doc, err := os.ReadFile("../../packaging/README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, tail, ok := strings.Cut(string(doc), "```json\n")
	if !ok {
		t.Fatal("documented policy missing")
	}
	block, _, ok := strings.Cut(tail, "\n```")
	if !ok {
		t.Fatal("documented policy block unclosed")
	}
	var documented struct {
		TimePolicy timeconf.Policy `json:"time_policy"`
	}
	if err := json.Unmarshal([]byte(block), &documented); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*cfg.TimePolicy, documented.TimePolicy) {
		t.Fatal("example and documentation policy differ")
	}
}

// For both chrony sources, config load refuses 0 and 999999999 ns without publishing
// config or changing fixture files; 1000000000 ns is accepted.
func TestTimeConfidenceConfigBackwardMinimum(t *testing.T) {
	original, err := os.ReadFile("../../packaging/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		source    timeconf.Source
		tolerance time.Duration
	}{
		{timeconf.NTSConfig, 0}, {timeconf.NTSConfig, time.Second - time.Nanosecond}, {timeconf.NTSConfig, time.Second},
		{timeconf.NTSAuthData, 0}, {timeconf.NTSAuthData, time.Second - time.Nanosecond}, {timeconf.NTSAuthData, time.Second},
	} {
		source, tolerance := tc.source, tc.tolerance
		t.Run(string(source)+"/"+tolerance.String(), func(t *testing.T) {
			root := t.TempDir()
			seed := []byte("seed sentinel")
			registry := []byte("registry sentinel")
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(original, &fields); err != nil {
				t.Fatal(err)
			}
			for key, name := range map[string]string{"socket_dir": "socket", "state_dir": "state", "master_file": "master.seed", "registry_file": "registry.json"} {
				fields[key], err = json.Marshal(filepath.Join(root, name))
				if err != nil {
					t.Fatal(err)
				}
			}
			for name, content := range map[string][]byte{"master.seed": seed, "registry.json": registry} {
				if err := os.WriteFile(filepath.Join(root, name), content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			var policy map[string]json.RawMessage
			if err := json.Unmarshal(fields["time_policy"], &policy); err != nil {
				t.Fatal(err)
			}
			policy["source"], err = json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			policy["backward_tolerance_ns"], err = json.Marshal(tolerance)
			if err != nil {
				t.Fatal(err)
			}
			fields["time_policy"], err = json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			var direct Config
			directErr := direct.UnmarshalJSON(raw)
			offline, offlineErr := ParseConfig(bytes.NewReader(raw))
			var served productionConfig
			serveErr := StrictJSON(bytes.NewReader(raw), &served)
			if tolerance < time.Second {
				if directErr == nil || directErr.Error() != "keymaker: invalid time policy" {
					t.Fatal("wrong decoder refusal", directErr)
				}
				for _, err := range []error{offlineErr, serveErr} {
					if err == nil || err.Error() != "keymaker: invalid configuration" {
						t.Fatal("wrong config-load refusal", err)
					}
				}
				for _, cfg := range []Config{direct, offline, served} {
					if !reflect.DeepEqual(cfg, Config{}) {
						t.Fatal("refused load published configuration")
					}
				}
			} else {
				if directErr != nil || offlineErr != nil || serveErr != nil {
					t.Fatal("one-second control refused", directErr, offlineErr, serveErr)
				}
				for _, cfg := range []Config{direct, offline, served} {
					if cfg.TimePolicy == nil || cfg.TimePolicy.BackwardTolerance != time.Second || cfg.MasterFile != filepath.Join(root, "master.seed") {
						t.Fatal("accepted control changed configuration")
					}
				}
			}
			entries, err := os.ReadDir(root)
			if err != nil || len(entries) != 2 {
				t.Fatal("config load created sockets or state", entries, err)
			}
			for name, want := range map[string][]byte{"master.seed": seed, "registry.json": registry} {
				got, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || !bytes.Equal(got, want) {
					t.Fatal("config load changed input", name, err)
				}
			}
		})
	}
}

// At 1 s, 500 real-SystemClock samples have zero refusals/holds: clock-read jitter only, not a real step or slewing, and not host qualification.
func TestTimeConfidenceSystemClockAvailability(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseConfig(bytes.NewReader(raw))
	if err != nil || cfg.TimePolicy == nil || cfg.TimePolicy.BackwardTolerance != time.Second {
		t.Fatal("packaged one-second policy", err)
	}
	collector := &fixtureTimeCollector{timeconf.Evidence{
		Tracking: timeconf.Tracking{ReferenceID: "C0000201", Address: "192.0.2.1", Stratum: 3, Reference: time.Now().UTC().Add(-time.Second), Leap: "Normal"},
		Sources:  timeconf.Sources{Count: 1, AllNTS: true, Entries: []string{"192.0.2.1"}},
	}}
	holds := 0
	provider, err := timeconf.New(*cfg.TimePolicy, collector, timeconf.SystemClock{}, func(incident timeconf.Incident) {
		if incident.Code == "clock_step_hold" {
			holds++
		}
	})
	if err != nil {
		t.Fatal("provider construction", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	refusals := 0
	for i := 0; i < 500; i++ {
		var sample timeconf.Sample
		if i == 0 {
			sample, err = provider.StartSample(ctx)
		} else {
			sample, err = provider.Sample(ctx)
		}
		if err != nil || !sample.Trusted || !sample.Fresh {
			refusals++
		}
	}
	if refusals != 0 || holds != 0 {
		t.Fatalf("500 samples: refusals=%d holds=%d", refusals, holds)
	}
}

// Directly injected off policy refuses before path access, writes or readiness. Startup
// returns a Code, not a wire envelope; TestTimeConfidenceNonRetryable in control
// separately proves clock_untrusted maps to retryable=false (with a busy control).
func TestTimeConfidenceStartupOff(t *testing.T) {
	d := t.TempDir()
	cfg := Config{ServiceUID: uint32(os.Getuid()), ServiceGID: uint32(os.Getgid()), Epoch: "fixture", RegistryRevision: "fixture", SocketDir: filepath.Join(d, "socket"), StateDir: filepath.Join(d, "state"), MasterFile: filepath.Join(d, "master.seed"), RegistryFile: filepath.Join(d, "registry.json")}
	if err := json.Unmarshal([]byte(`{"source":"off"}`), &cfg.TimePolicy); err != nil {
		t.Fatal(err)
	}
	if cfg.TimePolicy == nil || cfg.TimePolicy.Source != timeconf.Off {
		t.Fatal("explicit off policy not applied", cfg.TimePolicy)
	}
	var status bytes.Buffer
	if err := serveValidatedConfig(context.Background(), cfg, &status, UnavailableGeneration{}); err != Code("clock_untrusted") {
		t.Fatal("off policy did not refuse", err)
	}
	entries, err := os.ReadDir(d)
	if err != nil || len(entries) != 0 || status.Len() != 0 {
		t.Fatal("off policy changed installation state or readiness", entries, err, status.String())
	}
}

// The real startup path refuses non-0700 state before registry validation or
// seed loading. Both later inputs are independently invalid; a private state
// control reaches the registry refusal. This nonroot fixture does not qualify
// root-owned registry loading or successful service startup.
func TestStartupStateDirectoryBeforeInputs(t *testing.T) {
	// Keep even interrupted fixtures outside the repository scanned by other packages.
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	repository, err = filepath.EvalSymlinks(repository)
	if err != nil {
		t.Fatal(err)
	}
	var d string
	for _, root := range []string{os.TempDir(), os.Getenv("HOME")} {
		if root == "" {
			continue
		}
		parent, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		relative, err := filepath.Rel(repository, parent)
		if err != nil || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))) {
			continue
		}
		if err := safeAncestors(parent, uint32(os.Getuid())); err != nil {
			continue
		}
		d, err = os.MkdirTemp(parent, ".keymaker-startup-")
		if err == nil {
			break
		}
	}
	if d == "" {
		t.Skip("requires a writable os.TempDir() or HOME outside the repository with root/service-owned, non-symlink, non-group/other-writable ancestors")
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	state := filepath.Join(d, "state")
	if err := os.Mkdir(state, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0750); err != nil {
		t.Fatal(err)
	}
	cfg := Config{SocketDir: d, StateDir: state, MasterFile: filepath.Join(d, "master.seed"), RegistryFile: filepath.Join(d, "registry.json")}
	seed := []byte("invalid fixture seed")
	registry := []byte("invalid fixture registry")
	for name, raw := range map[string][]byte{cfg.MasterFile: seed, cfg.RegistryFile: registry} {
		if err := os.WriteFile(name, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	uid := uint32(os.Getuid())
	if master, err := LoadMaster(cfg.MasterFile, uid); err == nil || err.Error() != "keymaker: invalid master file length" {
		if master != nil {
			master.Close()
		}
		t.Fatal("invalid seed control", err)
	}
	var parsed Registry
	registryErr := ProtectedConfig(cfg.RegistryFile, &parsed)
	if registryErr == nil {
		t.Fatal("invalid registry control accepted")
	}
	for _, valid := range []bool{false, true} {
		if valid {
			if err := os.Chmod(state, 0700); err != nil {
				t.Fatal(err)
			}
		}
		p, _, _ := fixtureTimeProvider(t, helperNow)
		var status bytes.Buffer
		err := serveWithClock(context.Background(), cfg, &status, UnavailableGeneration{}, p)
		want := "keymaker: unsafe directory ownership or mode"
		if valid {
			want = registryErr.Error()
		}
		if err == nil || err.Error() != want || status.Len() != 0 {
			t.Fatal("startup order or readiness", valid, err, status.String())
		}
		entries, err := os.ReadDir(state)
		if err != nil || len(entries) != 0 {
			t.Fatal("refusal wrote state", entries, err)
		}
		entries, err = os.ReadDir(d)
		if err != nil || len(entries) != 3 {
			t.Fatal("refusal changed installation entries", entries, err)
		}
		for name, raw := range map[string][]byte{cfg.MasterFile: seed, cfg.RegistryFile: registry} {
			got, err := os.ReadFile(name)
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatal("refusal changed input", name, err)
			}
		}
	}
}
