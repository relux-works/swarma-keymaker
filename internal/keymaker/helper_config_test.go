package keymaker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/enrollment"
)

// Protected configuration cannot contain aliases, omitted helper authority or
// station-purpose selectors. Omitting the entire optional helper disables it;
// complete purpose-2 configuration constructs a fenced helper without killing A.
func TestHelperConfiguration(t *testing.T) {
	base := productionConfig{SocketDir: "/fixture/sockets", StateDir: "/fixture/state", MasterFile: "/fixture/seed", RegistryFile: "/fixture/registry", Epoch: "fixture", RegistryRevision: "fixture", Operator: Principal{1, nativeToken}}
	raw, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	var cfg productionConfig
	if err := StrictJSON(bytes.NewReader(raw), &cfg); err != nil || cfg.Registration != nil {
		t.Fatal("optional helper absent", err)
	}
	helper := map[string]any{"names": map[string]any{"purpose": "host-registration", "product": "sample", "project": "core", "agent": "station-a"}, "enrollment_config": "/fixture/pins.json", "approval_file": "/fixture/approval.json"}
	for _, scenario := range []string{"missing-names", "missing-enrollment", "extra", "null", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			var fields map[string]any
			json.Unmarshal(raw, &fields)
			encoded, _ := json.Marshal(helper)
			var h map[string]any
			json.Unmarshal(encoded, &h)
			switch scenario {
			case "missing-names":
				delete(h, "names")
			case "missing-enrollment":
				delete(h, "enrollment_config")
			case "extra":
				h["key"] = "caller-key"
			}
			fields["registration_helper"] = h
			if scenario == "null" {
				fields["registration_helper"] = nil
			}
			encoded, _ = json.Marshal(fields)
			var cfg productionConfig
			e := StrictJSON(bytes.NewReader(encoded), &cfg)
			if (e == nil) != (scenario == "valid") {
				t.Fatal("helper configuration schema verdict", e)
			}
		})
	}
	f, trust := helperSetup(t)
	for _, path := range []string{"m/1'/1'/1'/1'", "m/2'/1'/1'/1'", "m/3'/1'/1'/1'"} {
		t.Run(path, func(t *testing.T) {
			h, e := NewRegistrationHelper(f.master, path, trust.authority, trust.clock, rand.Reader)
			if (h != nil) != (path == helperPath) || (e == nil) != (path == helperPath) {
				t.Fatal("helper path purpose mismatch", e)
			}
		})
	}
	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h, stop, e := configureRegistration(cctx, &registrationConfig{Names: Names{"host-registration", "sample", "core", "station-a"}, EnrollmentConfig: "/fixture/missing-pins.json", ApprovalFile: "/fixture/missing-approval.json"}, f.master, nativeRegistry(), io.Discard)
	if e != nil || h == nil {
		t.Fatal("unavailable enrollment killed helper owner", e)
	}
	defer stop()
	_, code := h.authority.Authorize(context.Background(), 1, nativeToken, h.key, helperName, helperAudience, helperNow, helperNow)
	if code != enrollment.EnrollmentUnavailable {
		t.Fatal("missing enrollment admitted", code)
	}
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, healthy := (kernelRegistrationClock{}).Now(cancelled); healthy {
		t.Fatal("cancelled clock trusted")
	}
}
