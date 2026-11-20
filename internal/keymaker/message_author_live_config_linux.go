//go:build linux

package keymaker

import (
	"bytes"
	"github.com/relux-works/swarma-credential-broker/timeconf"
	"time"
)

type maLiveConfiguration struct {
	IssuerPin string    `json:"issuer_pin,omitempty"`
	Role      string    `json:"service_role"`
	Instance  string    `json:"instance_id"`
	UID       uint32    `json:"service_uid"`
	GID       uint32    `json:"service_gid"`
	Epoch     string    `json:"master_epoch"`
	Registry  string    `json:"registry_revision"`
	Operator  Principal `json:"operator_principal"`
	State     struct {
		Path    string `json:"path"`
		Minimum int    `json:"minimum_reader_schema"`
		Head    string `json:"head_file"`
	} `json:"state"`
	Socket     j7SocketConfiguration    `json:"socket"`
	Time       *timeconf.Policy         `json:"time_policy,omitempty"`
	Generation *generationJournalConfig `json:"generation_journal,omitempty"`
}

func unmarshalMALiveConfig(raw []byte, cfg *Config) error {
	fields, e := objectMembers(raw, []string{"service_role", "instance_id", "service_uid", "service_gid", "master_epoch", "registry_revision", "operator_principal", "state", "socket"}, "time_policy", "generation_journal", "issuer_pin")
	if e != nil {
		return e
	}
	var m maLiveConfiguration
	if StrictJSON(bytes.NewReader(raw), &m) != nil || m.Role != messageAuthorRole || !validJ7Instance(m.Instance) || m.Epoch == "" || m.Registry == "" || !validGeneration(m.Operator.Generation) {
		return failure("invalid message-author configuration")
	}
	if m.IssuerPin != "" && !cleanAbsolute(m.IssuerPin) {
		return failure("invalid issuer pin path")
	}
	if m.IssuerPin == "" {
		m.IssuerPin = maIssuerPinDefault
	}
	if m.UID == 0 || m.GID == 0 {
		return Code("role_not_permitted")
	}
	if _, e = objectMembers(fields["operator_principal"], []string{"uid", "generation"}); e != nil {
		return e
	}
	if _, e = objectMembers(fields["state"], []string{"path", "minimum_reader_schema", "head_file"}); e != nil {
		return e
	}
	if _, e = objectMembers(fields["socket"], []string{"dir", "group"}); e != nil {
		return e
	}
	if m.State.Minimum != maLiveSchema || !cleanAbsolute(m.State.Path) || !cleanAbsolute(m.State.Head) || !cleanAbsolute(m.Socket.Dir) || m.Socket.Group == 0 || j7PathWithin(m.State.Path, m.Socket.Dir) || j7PathWithin(m.Socket.Dir, m.State.Path) || j7PathWithin(m.State.Path, m.State.Head) || j7PathWithin(m.Socket.Dir, m.State.Head) {
		return failure("invalid message-author state pins")
	}
	if raw, ok := fields["time_policy"]; ok {
		p, e := timeconf.DecodePolicy(raw)
		if e != nil || m.Time == nil || p.BackwardTolerance < time.Second || p.MaxSyncAge > 2048*time.Second || p.MaxUncertainty > 1500*time.Millisecond {
			return failure("invalid time policy")
		}
	}
	if raw, ok := fields["generation_journal"]; ok {
		g, e := objectMembers(raw, []string{"path", "initial_floor"})
		if e != nil {
			return e
		}
		if _, e = objectMembers(g["initial_floor"], []string{"seq", "hash"}); e != nil {
			return e
		}
		if m.Generation == nil || !cleanAbsolute(m.Generation.Path) || !validGenerationFloor(m.Generation.InitialFloor) {
			return failure("invalid generation journal configuration")
		}
	}
	*cfg = Config{ServiceRole: m.Role, ServiceUID: m.UID, ServiceGID: m.GID, InstanceID: m.Instance, Epoch: m.Epoch, RegistryRevision: m.Registry, Operator: m.Operator, maLive: &m}
	return nil
}
