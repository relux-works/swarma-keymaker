package keymaker

import (
	"bytes"
	"context"
	"github.com/relux-works/swarma-envelope/record"
	"reflect"
)

const maLiveSchema = 7
const maLiveAttemptLimit = 65536
const maLiveStateLimit = 256 << 20

// Two existing generation anchors are each capped at 4096 bytes. Snapshot
// commits can retain the old, staging and new copies at the same time.
const maLiveStateOverhead = 8192

// The six states record effect knowledge, not connection state. Fenced is a
// separate continuity overlay; neither startup nor a healthy provider clears it.
type maLiveInventory struct {
	Format   string          `json:"format"`
	Instance string          `json:"instance"`
	Epoch    string          `json:"master_epoch"`
	Registry string          `json:"registry_revision"`
	Fenced   bool            `json:"fenced"`
	Attempts []maLiveAttempt `json:"attempts"`
}
type maLiveAttempt struct {
	Caller      Principal `json:"caller"`
	ID          string    `json:"id"`
	Method      string    `json:"method"`
	Preimage    []byte    `json:"preimage"`
	Binding     Binding   `json:"binding"`
	Instance    string    `json:"instance"`
	Key         string    `json:"key"`
	Attestation string    `json:"author_attestation"`
	Status      string    `json:"status"`
	Signature   []byte    `json:"signature"`
	SuccessSeq  uint64    `json:"success_audit_seq"`
	SuccessHash string    `json:"success_audit_hash"`
}

func (m *maLiveInventory) UnmarshalJSON(raw []byte) error {
	if _, e := objectMembers(raw, []string{"format", "instance", "master_epoch", "registry_revision", "fenced", "attempts"}); e != nil {
		return e
	}
	type plain maLiveInventory
	return StrictJSON(bytes.NewReader(raw), (*plain)(m))
}
func (a *maLiveAttempt) UnmarshalJSON(raw []byte) error {
	fields, e := objectMembers(raw, []string{"caller", "id", "method", "preimage", "binding", "instance", "key", "author_attestation", "status", "success_audit_seq", "success_audit_hash"}, "signature")
	if e != nil {
		return e
	}
	if _, ok := fields["signature"]; !ok {
		return failure("missing signature knowledge")
	}
	if e = messageRequired(fields["caller"], reflect.TypeFor[Principal]()); e != nil {
		return e
	}
	if e = messageRequired(fields["binding"], reflect.TypeFor[Binding]()); e != nil {
		return e
	}
	type plain maLiveAttempt
	return StrictJSON(bytes.NewReader(raw), (*plain)(a))
}
func maLiveStatus(status string) bool {
	switch status {
	case "intent", "invoking", "result", "handoff_unknown", "released", "dead":
		return true
	}
	return false
}
func (s *Store) validateMALive() error {
	m := s.maLive
	if s.schema != maLiveSchema || m == nil || m.Format != "keymaker-message-author-state/1" || !validJ7Instance(m.Instance) || m.Epoch == "" || m.Registry == "" || m.Attempts == nil || len(m.Attempts) > maLiveAttemptLimit || s.j7 != nil || s.j7Signing != nil || s.messages != nil || len(s.requests) != 0 {
		return failure("invalid message-author state")
	}
	paths := map[string]bool{}
	for _, b := range s.records {
		if b.Epoch != m.Epoch || b.RegistryRevision != m.Registry || paths[b.Epoch+":"+b.Path] {
			return failure("invalid message-author binding history")
		}
		paths[b.Epoch+":"+b.Path] = true
	}
	ids := map[requestKey]bool{}
	for _, a := range m.Attempts {
		id := requestKey{Caller: a.Caller, ID: a.ID}
		if ids[id] || !maLiveID(a.ID) || !maLiveStatus(a.Status) || a.Method != "sign_message_author" || len(a.Preimage) > 24576 || a.Caller != (Principal{a.Binding.UID, a.Binding.Generation}) || a.Instance != m.Instance || a.Binding.Epoch != m.Epoch || a.Binding.RegistryRevision != m.Registry {
			return failure("invalid message-author attempt")
		}
		ids[id] = true
		if _, c := prepareMessageAuthor(a.Preimage, a.Key, a.Attestation); c != "" {
			return failure("invalid message-author intent")
		}
		found := false
		for _, b := range s.records {
			if b.Number == a.Binding.Number {
				copy := b
				copy.Status = a.Binding.Status
				found = copy == a.Binding
			}
		}
		if !found || a.Binding.Status != "active" {
			return failure("lost message-author binding")
		}
		if len(a.Signature) > 0 && record.VerifySignature(a.Key, a.Signature, a.Preimage) != nil {
			return failure("invalid message-author signature")
		}
		hasResult := a.Status == "result" || a.Status == "handoff_unknown" || a.Status == "released" || a.Status == "dead" && len(a.Signature) > 0
		if hasResult && (len(a.Signature) != 64 || a.SuccessSeq == 0 || !validDigest(a.SuccessHash)) || !hasResult && (len(a.Signature) != 0 || a.SuccessSeq != 0 || a.SuccessHash != "") {
			return failure("invalid message-author result proof")
		}
	}
	return nil
}
func (s *Store) maLiveIndex(p Principal, id string) int {
	for i := range s.maLive.Attempts {
		a := &s.maLive.Attempts[i]
		if a.Caller == p && a.ID == id {
			return i
		}
	}
	return -1
}

// All callers hold Store. Journal-first pair commits preserve the existing
// snapshot protocol. Once a durable effect starts its commit is completed even
// if the request expires; the delivery barrier separately suppresses late bytes.
func (s *Store) persistMALive(ctx context.Context) Code {
	if auditContextExpired(ctx) {
		return "request_deadline_exceeded"
	}
	if s.failed || s.journal == nil || s.dir == nil || s.version >= j7SafeInteger || s.validateMALive() != nil {
		return "message_author_unqualified"
	}
	version := s.version + 1
	bound, e := canonical(s.disk(version, bindingCommit{Seq: j7SafeInteger, Hash: string(bytes.Repeat([]byte("0"), 64))}))
	if e != nil || !maLiveStateRoom(len(bound)) || !s.maLiveRoom() {
		return "state_capacity_exceeded"
	}
	digest, e := s.contentDigest(version)
	if e != nil {
		return "state_capacity_exceeded"
	}
	// Cancellation can abandon the wait before this commit, never the paired
	// snapshot after the journal has made an effect durable.
	commit, c := s.journal.commitBindingContext(ctx, version, digest)
	if c != "" {
		if c == "request_deadline_exceeded" {
			return c
		}
		s.failed = true
		s.maLive.Fenced = true
		return c
	}
	raw, e := canonical(s.disk(version, commit))
	if e != nil || len(raw) > len(bound) {
		s.failed = true
		s.maLive.Fenced = true
		return "message_author_unqualified"
	}
	if c = s.installMessageSnapshot(context.WithoutCancel(ctx), raw); c != "" {
		s.failed = true
		s.maLive.Fenced = true
		return "message_author_unqualified"
	}
	s.version, s.auditSeq, s.auditHash = version, commit.Seq, commit.Hash
	return ""
}

// Reserve the complete durable result and both snapshot files before invoking.
// This is a size calculation only: it never installs invented result bytes.
func (s *Store) maLiveRoom() bool {
	m := *s.maLive
	m.Attempts = append([]maLiveAttempt(nil), m.Attempts...)
	for i := range m.Attempts {
		a := &m.Attempts[i]
		if a.Status == "intent" || a.Status == "invoking" {
			a.Signature = make([]byte, 64)
			a.Status = "handoff_unknown"
			a.SuccessSeq = j7SafeInteger
			a.SuccessHash = string(bytes.Repeat([]byte("0"), 64))
		}
	}
	d := s.disk(j7SafeInteger, bindingCommit{Seq: j7SafeInteger, Hash: string(bytes.Repeat([]byte("0"), 64))})
	d.MALive = &m
	raw, e := canonical(d)
	return e == nil && maLiveStateRoom(len(raw))
}

func maLiveStateRoom(bytes int) bool {
	return bytes >= 0 && bytes <= (maLiveStateLimit-maLiveStateOverhead)/3
}
