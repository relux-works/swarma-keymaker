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

// J7 pins are configuration only. The request role is served by the ordered
// startup in j7_service_linux.go; the delegation role still refuses startup.
// ProtectedConfig supplies the root-owner/ancestor boundary before runtime use.
type j7PolicyConfiguration struct {
	Path      string    `json:"path"`
	HolderUID uint32    `json:"holder_uid"`
	Schema    string    `json:"schema"`
	Instance  string    `json:"instance"`
	Identity  uint64    `json:"identity_registration_number"`
	Launcher  Principal `json:"launcher_principal"`
}

// The request role names a separate protected head file and carries no moving
// pin: its configuration bytes stay static across served requests. The frozen
// delegation variant keeps its inline pins and is not served.
type j7StateConfiguration struct {
	Path            string `json:"path"`
	Minimum         int    `json:"minimum_reader_schema"`
	HeadFile        string `json:"head_file,omitempty"`
	ExpectedVersion uint64 `json:"expected_version,omitempty"`
	ExpectedDigest  string `json:"expected_digest,omitempty"`
}

// The socket group is connection admission only; kernel peer credentials are
// the authentication. Group membership is a deployment duty.
type j7SocketConfiguration struct {
	Dir   string `json:"dir"`
	Group uint32 `json:"group"`
}

// The four static-gate inputs are named here and read only by the gate step.
type j7StaticGateConfiguration struct {
	ApproverKeyFile string `json:"approver_key_file"`
	StatementFile   string `json:"statement_file"`
	SignatureFile   string `json:"signature_file"`
	DigestFile      string `json:"digest_file"`
}

func cleanAbsolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/"
}

type Config struct {
	maLive            *maLiveConfiguration
	J7Policy          *j7PolicyConfiguration     `json:"j7_policy,omitempty"`
	J7State           *j7StateConfiguration      `json:"j7_state,omitempty"`
	J7Socket          *j7SocketConfiguration     `json:"socket,omitempty"`
	StaticGate        *j7StaticGateConfiguration `json:"static_gate,omitempty"`
	ServiceRole       string                     `json:"service_role,omitempty"`
	J7KeyFile         string                     `json:"j7_key_file,omitempty"`
	InstanceID        string                     `json:"instance_id,omitempty"`
	TimePolicy        *timeconf.Policy           `json:"time_policy,omitempty"`
	GenerationJournal *generationJournalConfig   `json:"generation_journal,omitempty"`
	Registration      *registrationConfig        `json:"registration_helper,omitempty"`
	SocketDir         string                     `json:"socket_dir"`
	StateDir          string                     `json:"state_dir"`
	MasterFile        string                     `json:"master_file"`
	RegistryFile      string                     `json:"registry_file"`
	ServiceUID        uint32                     `json:"service_uid"`
	ServiceGID        uint32                     `json:"service_gid"`
	ControlGID        uint32                     `json:"control_gid"`
	Operator          Principal                  `json:"operator_principal"`
	Epoch             string                     `json:"master_epoch"`
	RegistryRevision  string                     `json:"registry_revision"`
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
	if role.ServiceRole == "message-author" {
		return unmarshalMALiveConfig(raw, cfg)
	}
	if role.ServiceRole != "" && role.ServiceRole != "legacy" {
		if !validJ7Role(role.ServiceRole) {
			return failure("unknown service role")
		}
		// The request role alone may carry the service members; the frozen
		// delegation variant keeps its original closed set.
		optional := []string{"j7_policy", "j7_state"}
		request := role.ServiceRole == j7RequestRole
		if request {
			optional = append(optional, "time_policy", "generation_journal", "socket", "static_gate")
		}
		if _, err := objectMembers(raw, []string{"service_role", "j7_key_file", "instance_id", "service_uid", "service_gid", "master_epoch", "registry_revision"}, optional...); err != nil {
			return err
		}
		for _, name := range optional {
			if value, ok := rawFields[name]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return failure("invalid key role configuration")
			}
		}
		type plain Config
		var parsed plain
		if StrictJSON(bytes.NewReader(raw), &parsed) != nil || !validJ7Instance(parsed.InstanceID) || parsed.Epoch == "" || parsed.RegistryRevision == "" || !filepath.IsAbs(parsed.J7KeyFile) || filepath.Clean(parsed.J7KeyFile) != parsed.J7KeyFile {
			return failure("invalid key role configuration")
		}
		if request && (parsed.ServiceUID == 0 || parsed.ServiceGID == 0) {
			return Code("role_not_permitted")
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
			// The request role names the head file; inline pins there would go
			// stale after the first served request and are refused.
			members := []string{"path", "minimum_reader_schema", "expected_version", "expected_digest"}
			if request {
				members = []string{"path", "minimum_reader_schema", "head_file"}
			}
			if _, err := objectMembers(rawState, members); err != nil || parsed.J7State == nil {
				return failure("invalid J7 state pins")
			}
			p := parsed.J7State
			// Configuration stays pinned to4/5; trusted internal state6 is separate.
			if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path || (p.Minimum != 4 && p.Minimum != 5) {
				return failure("invalid J7 state pins")
			}
			if request && !cleanAbsolute(p.HeadFile) {
				return failure("invalid J7 state pins")
			}
			if !request && (p.ExpectedVersion == 0 || p.ExpectedVersion > j7SafeInteger || !validDigest(p.ExpectedDigest)) {
				return failure("invalid J7 state pins")
			}
		}
		if rawTime, ok := rawFields["time_policy"]; ok {
			policy, err := timeconf.DecodePolicy(rawTime)
			if err != nil || policy.BackwardTolerance < time.Second || parsed.TimePolicy == nil {
				return failure("invalid time policy")
			}
		}
		if rawJournal, ok := rawFields["generation_journal"]; ok {
			journal, err := objectMembers(rawJournal, []string{"path", "initial_floor"})
			if err != nil {
				return failure("invalid generation journal configuration")
			}
			if _, err := objectMembers(journal["initial_floor"], []string{"seq", "hash"}); err != nil {
				return failure("invalid generation journal configuration")
			}
			g := parsed.GenerationJournal
			if g == nil || !cleanAbsolute(g.Path) || !validGenerationFloor(g.InitialFloor) {
				return failure("invalid generation journal configuration")
			}
		}
		if rawSocket, ok := rawFields["socket"]; ok {
			if _, err := objectMembers(rawSocket, []string{"dir", "group"}); err != nil || parsed.J7Socket == nil || !cleanAbsolute(parsed.J7Socket.Dir) {
				return failure("invalid J7 socket configuration")
			}
		}
		if rawGate, ok := rawFields["static_gate"]; ok {
			if _, err := objectMembers(rawGate, []string{"approver_key_file", "statement_file", "signature_file", "digest_file"}); err != nil || parsed.StaticGate == nil {
				return failure("invalid static gate configuration")
			}
			g := parsed.StaticGate
			files := []string{g.ApproverKeyFile, g.StatementFile, g.SignatureFile, g.DigestFile}
			for i, file := range files {
				if !cleanAbsolute(file) {
					return failure("invalid static gate configuration")
				}
				for _, other := range files[:i] {
					if other == file {
						return failure("invalid static gate configuration")
					}
				}
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
