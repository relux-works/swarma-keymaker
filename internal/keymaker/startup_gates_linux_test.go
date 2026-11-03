//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/relux-works/swarma-credential-broker/timeconf"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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

// Missing, writable, wrong-owner and seed-parent state directories refuse; a service-owned 0700 child opens without writes.
func TestStartupStateDirectory(t *testing.T) {
	for _, kind := range []string{"missing", "group-writable", "other-writable", "wrong-owner", "master-parent", "valid"} {
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
			if kind == "valid" {
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
				if err != nil || len(children) != 0 {
					t.Fatal("state check changed child", entry.Name(), err)
				}
			}
		})
	}
}

// The shipped policy decodes strictly; omitting a required provider bound refuses without changing the example.
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
