//go:build linux

package keymaker

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// Config is the daemon's configuration schema. Offline parsing checks the same
// required members and types; serve additionally enforces protected ownership,
// current service identity, registry/state recovery and generation readiness.
type generationJournalConfig struct {
	Path         string   `json:"path"`
	InitialFloor gj.Floor `json:"initial_floor"`
}

// J7 pins are configuration only; both new runtime profiles still refuse startup.
// ProtectedConfig supplies the root-owner/ancestor boundary before runtime use.
type j7PolicyConfiguration struct {
	Path      string    `json:"path"`
	HolderUID uint32    `json:"holder_uid"`
	Schema    string    `json:"schema"`
	Instance  string    `json:"instance"`
	Identity  uint64    `json:"identity_registration_number"`
	Launcher  Principal `json:"launcher_principal"`
}
type j7StateConfiguration struct {
	Path            string `json:"path"`
	Minimum         int    `json:"minimum_reader_schema"`
	ExpectedVersion uint64 `json:"expected_version"`
	ExpectedDigest  string `json:"expected_digest"`
}
type Config struct {
	J7Policy          *j7PolicyConfiguration   `json:"j7_policy,omitempty"`
	J7State           *j7StateConfiguration    `json:"j7_state,omitempty"`
	ServiceRole       string                   `json:"service_role,omitempty"`
	J7KeyFile         string                   `json:"j7_key_file,omitempty"`
	InstanceID        string                   `json:"instance_id,omitempty"`
	TimePolicy        *timeconf.Policy         `json:"time_policy,omitempty"`
	GenerationJournal *generationJournalConfig `json:"generation_journal,omitempty"`
	Registration      *registrationConfig      `json:"registration_helper,omitempty"`
	SocketDir         string                   `json:"socket_dir"`
	StateDir          string                   `json:"state_dir"`
	MasterFile        string                   `json:"master_file"`
	RegistryFile      string                   `json:"registry_file"`
	ServiceUID        uint32                   `json:"service_uid"`
	ServiceGID        uint32                   `json:"service_gid"`
	ControlGID        uint32                   `json:"control_gid"`
	Operator          Principal                `json:"operator_principal"`
	Epoch             string                   `json:"master_epoch"`
	RegistryRevision  string                   `json:"registry_revision"`
}

func (cfg *Config) UnmarshalJSON(raw []byte) error {
	// Closed role variants prevent a new profile from carrying legacy master,
	// helper or socket settings. Omission remains the unchanged legacy schema.
	var role struct {
		ServiceRole string `json:"service_role"`
	}
	if json.Unmarshal(raw, &role) != nil {
		return failure("invalid service role")
	}
	var rawFields map[string]json.RawMessage
	if json.Unmarshal(raw, &rawFields) != nil {
		return failure("invalid service role")
	}
	if _, exists := rawFields["service_role"]; exists && role.ServiceRole == "" {
		return failure("invalid service role")
	}
	if role.ServiceRole != "" && role.ServiceRole != "legacy" {
		if !validJ7Role(role.ServiceRole) {
			return failure("unknown service role")
		}
		if _, err := objectMembers(raw, []string{"service_role", "j7_key_file", "instance_id", "service_uid", "service_gid", "master_epoch", "registry_revision"}, "j7_policy", "j7_state"); err != nil {
			return err
		}
		type plain Config
		var parsed plain
		if StrictJSON(bytes.NewReader(raw), &parsed) != nil || !validJ7Instance(parsed.InstanceID) || parsed.Epoch == "" || parsed.RegistryRevision == "" || !filepath.IsAbs(parsed.J7KeyFile) || filepath.Clean(parsed.J7KeyFile) != parsed.J7KeyFile {
			return failure("invalid key role configuration")
		}
		if rawPolicy, ok := rawFields["j7_policy"]; ok {
			if messageRequired(rawPolicy, reflect.TypeFor[j7PolicyConfiguration]()) != nil || parsed.J7Policy == nil {
				return failure("invalid J7 policy pins")
			}
			p := parsed.J7Policy
			if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path || p.HolderUID != parsed.ServiceUID || p.Schema != "keymaker-j7-policy/1" || p.Instance != parsed.InstanceID || p.Identity == 0 || p.Identity > j7SafeInteger || !validGeneration(p.Launcher.Generation) {
				return failure("invalid J7 policy pins")
			}
		}
		if rawState, ok := rawFields["j7_state"]; ok {
			if messageRequired(rawState, reflect.TypeFor[j7StateConfiguration]()) != nil || parsed.J7State == nil {
				return failure("invalid J7 state pins")
			}
			p := parsed.J7State
			if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path || !j7StateSchema(p.Minimum) || p.ExpectedVersion == 0 || p.ExpectedVersion > j7SafeInteger || !validDigest(p.ExpectedDigest) {
				return failure("invalid J7 state pins")
			}
		}
		*cfg = Config(parsed)
		return nil
	}
	fields, err := objectMembers(raw, []string{"socket_dir", "state_dir", "master_file", "registry_file", "service_uid", "service_gid", "control_gid", "operator_principal", "master_epoch", "registry_revision"}, "registration_helper", "generation_journal", "time_policy", "service_role")
	if err != nil {
		return failure("invalid service configuration members")
	}
	if _, err := objectMembers(fields["operator_principal"], []string{"uid", "generation"}); err != nil {
		return err
	}
	if raw, ok := fields["registration_helper"]; ok {
		helper, err := objectMembers(raw, []string{"names", "enrollment_config", "approval_file"})
		if err != nil {
			return err
		}
		if _, err := objectMembers(helper["names"], []string{"purpose", "product", "project", "agent"}); err != nil {
			return err
		}
	}
	if raw, ok := fields["generation_journal"]; ok {
		journal, err := objectMembers(raw, []string{"path", "initial_floor"})
		if err != nil {
			return err
		}
		if _, err := objectMembers(journal["initial_floor"], []string{"seq", "hash"}); err != nil {
			return err
		}
	}
	if raw, ok := fields["time_policy"]; ok {
		policy, err := timeconf.DecodePolicy(raw)
		// Zero or microsecond tolerances refuse two-clock read jitter as a backward step (measured on one VM with a fake collector); one second is the shared platform value.
		if err != nil || policy.BackwardTolerance < time.Second {
			return failure("invalid time policy")
		}
	}
	type plain Config
	var parsed plain
	if err := StrictJSON(bytes.NewReader(raw), &parsed); err != nil {
		return failure("invalid service configuration types")
	}
	for _, path := range []string{parsed.SocketDir, parsed.StateDir, parsed.MasterFile, parsed.RegistryFile} {
		if !filepath.IsAbs(path) {
			return failure("service configuration requires absolute paths")
		}
	}
	if parsed.Epoch == "" || parsed.RegistryRevision == "" {
		return failure("service configuration pins required")
	}
	if g := parsed.GenerationJournal; g != nil {
		if !filepath.IsAbs(g.Path) || filepath.Clean(g.Path) != g.Path || !validGenerationFloor(g.InitialFloor) {
			return failure("invalid generation journal configuration")
		}
	}
	*cfg = Config(parsed)
	return nil
}

// ParseConfig performs no filesystem lookups or writes. ProtectedConfig feeds
// this same Config decoder after validating the operator-owned configuration.
func ParseConfig(r io.Reader) (Config, error) {
	var cfg Config
	err := StrictJSON(r, &cfg)
	return cfg, err
}
