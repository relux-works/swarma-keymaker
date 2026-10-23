//go:build linux

package keymaker

import (
	"bytes"
	"io"
	"path/filepath"
)

// Config is the daemon's configuration schema. Offline parsing checks the same
// required members and types; serve additionally enforces protected ownership,
// current service identity, registry/state recovery and generation readiness.
type Config struct {
	Registration     *registrationConfig `json:"registration_helper,omitempty"`
	SocketDir        string              `json:"socket_dir"`
	StateDir         string              `json:"state_dir"`
	MasterFile       string              `json:"master_file"`
	RegistryFile     string              `json:"registry_file"`
	ServiceUID       uint32              `json:"service_uid"`
	ServiceGID       uint32              `json:"service_gid"`
	ControlGID       uint32              `json:"control_gid"`
	Operator         Principal           `json:"operator_principal"`
	Epoch            string              `json:"master_epoch"`
	RegistryRevision string              `json:"registry_revision"`
}

func (cfg *Config) UnmarshalJSON(raw []byte) error {
	fields, err := objectMembers(raw, []string{"socket_dir", "state_dir", "master_file", "registry_file", "service_uid", "service_gid", "control_gid", "operator_principal", "master_epoch", "registry_revision"}, "registration_helper")
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
