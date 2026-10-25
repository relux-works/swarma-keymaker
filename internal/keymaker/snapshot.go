package keymaker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// References are excluded from the committed body to avoid a circular hash.
// Version, all binding bytes and the next issued number are committed together.
func (s *Store) contentDigest(version uint64) (string, error) {
	if s.schema == 2 {
		body, e := s.messageBody(version)
		if e != nil {
			return "", e
		}
		return messageHash(body), nil
	}
	body := struct {
		Version  uint64            `json:"version"`
		Next     uint64            `json:"next_registration_number"`
		Records  []Binding         `json:"records"`
		Requests []retainedRequest `json:"requests"`
	}{version, s.next, s.records, s.requests}
	b, err := canonical(body)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func objectMembers(raw []byte, required []string, optional ...string) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if StrictJSON(bytes.NewReader(raw), &fields) != nil || fields == nil {
		return nil, failure("invalid snapshot object")
	}
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key := range fields {
		if !allowed[key] {
			return nil, failure("unknown snapshot member")
		}
	}
	for _, key := range required {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, failure("incomplete snapshot object")
		}
	}
	return fields, nil
}

// UnmarshalJSON requires every persisted member, including explicit empty
// records. Typed strict decoding also rejects unknown fields at every level.
func (disk *bindingDisk) UnmarshalJSON(raw []byte) error {
	fields, err := objectMembers(raw, []string{"next_registration_number", "version", "audit_seq", "audit_hash", "requests"}, "records", "schema_version", "messages")
	if err != nil {
		return err
	}
	if _, ok := fields["records"]; !ok {
		return failure("missing snapshot records")
	}
	_, schema := fields["schema_version"]
	_, messages := fields["messages"]
	if schema || messages {
		if !schema || !messages || string(fields["schema_version"]) != "2" || bytes.Equal(bytes.TrimSpace(fields["messages"]), []byte("null")) {
			return failure("invalid message schema")
		}
	}
	var requests []json.RawMessage
	if json.Unmarshal(fields["requests"], &requests) != nil {
		return failure("invalid retained requests")
	}
	for _, raw := range requests {
		row, e := objectMembers(raw, []string{"caller", "id", "method", "arguments", "status"}, "result")
		if e != nil {
			return e
		}
		if _, ok := row["result"]; !ok {
			return failure("missing retained result")
		}
		if _, e := objectMembers(row["caller"], []string{"uid", "generation"}); e != nil {
			return e
		}
	}
	if value, ok := fields["records"]; ok {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return failure("null snapshot records")
		}
		var records []json.RawMessage
		if json.Unmarshal(value, &records) != nil {
			return failure("invalid snapshot records")
		}
		for _, record := range records {
			row, e := objectMembers(record, []string{"uid", "generation", "path", "owner", "registration_number", "lifetime", "registrar_principal", "status", "master_epoch", "registry_revision"})
			if e != nil {
				return e
			}
			if _, e = objectMembers(row["registrar_principal"], []string{"uid", "generation"}); e != nil {
				return e
			}
		}
	}
	type plain bindingDisk
	return StrictJSON(bytes.NewReader(raw), (*plain)(disk))
}

func (s *Store) matchesCommit(commit bindingCommit) bool {
	if commit.Version == 0 || s.version != commit.Version || s.auditSeq != commit.Seq || s.auditHash != commit.Hash {
		return false
	}
	digest, err := s.contentDigest(s.version)
	return err == nil && digest == commit.Digest
}
