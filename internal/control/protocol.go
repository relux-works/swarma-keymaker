package control

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"regexp"
	"time"
)

// Code is a stable refusal code, never a free-form diagnostic.
type Code string

const (
	FrameTooLarge          Code = "frame_too_large"
	FrameTruncated         Code = "frame_truncated"
	FrameMalformed         Code = "frame_malformed"
	CCJNoncanonical        Code = "ccj_noncanonical"
	RequestMalformed       Code = "request_malformed"
	RequestConflict        Code = "request_conflict"
	DeadlineExceeded       Code = "request_deadline_exceeded"
	VersionUnsupported     Code = "version_unsupported"
	HelloRequired          Code = "hello_required"
	HelloAlreadyNegotiated Code = "hello_already_negotiated"
	OperationUnsupported   Code = "operation_unsupported"
)

// Keep foreign/free-form handler diagnostics off the wire. These are the stable
// specification codes; adding one requires an explicit contract update.
func validCode(code Code) bool {
	switch code {
	case FrameTooLarge, FrameTruncated, FrameMalformed, CCJNoncanonical, RequestMalformed, RequestConflict, DeadlineExceeded, VersionUnsupported, HelloRequired, HelloAlreadyNegotiated, OperationUnsupported,
		"peer_identity_unavailable", "generation_source_unavailable", "generation_inactive", "generation_mismatch", "binding_not_found", "peer_binding_mismatch", "binding_conflict", "role_not_permitted", "identity_revoked", "persistent_revoke_requires_operator", "operator_record_unavailable", "operator_record_invalid", "path_not_hardened", "path_invalid", "purpose_unknown", "name_invalid", "name_unknown", "name_registry_invalid", "index_exhausted", "sign_data_not_sshsig", "sshsig_malformed", "namespace_not_permitted", "sign_key_mismatch", "sign_flags_unsupported", "agent_message_unsupported", "request_expired", "enrollment_unavailable", "enrollment_unverified", "enrollment_unsupported", "host_revoked", "uid_map_required", "uid_not_permitted", "name_not_permitted", "audience_mismatch", "key_not_enrolled", "key_not_valid_now", "entropy_unavailable", "clock_untrusted", "rate_limited", "busy", "state_capacity_exceeded", "audit_unavailable":
		return true
	}
	return false
}
func retryable(code Code) bool {
	switch code {
	case "rate_limited", "busy", "generation_source_unavailable", "enrollment_unavailable", "audit_unavailable", DeadlineExceeded:
		return true
	}
	return false
}

func readFrame(r io.Reader) ([]byte, Code) {
	var header [4]byte
	n, err := io.ReadFull(r, header[:])
	if n == 0 && errors.Is(err, io.EOF) {
		return nil, ""
	}
	if err != nil {
		return nil, readCode(err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size > MaxFrame {
		return nil, FrameTooLarge
	}
	if size == 0 {
		return nil, FrameMalformed
	}
	body := make([]byte, int(size))
	if _, err = io.ReadFull(r, body); err != nil {
		return nil, readCode(err)
	}
	return body, ""
}
func readCode(err error) Code {
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return DeadlineExceeded
	}
	return FrameTruncated
}
func writeFrame(w io.Writer, obj Object) error {
	body, err := Marshal(obj)
	if err != nil {
		return err
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if err = writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, body)
}
func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Request is a validated wire envelope. Method-specific schemas and authority
// remain the Handler's responsibility. Timeout is excluded from effect identity.
type Request struct {
	ID      string
	Method  string
	Params  Object
	Timeout time.Duration
}

func envelope(obj Object) (Request, any, Code) {
	var req Request
	var echoed any
	if id, ok := obj["request_id"].(string); ok && idPattern.MatchString(id) {
		req.ID = id
		echoed = id
	}
	method, ok := obj["method"].(string)
	req.Method = method
	if !ok || req.ID == "" {
		return req, echoed, RequestMalformed
	}
	if method == "hello" {
		if !members(obj, "method", "request_id", "versions") {
			return req, echoed, RequestMalformed
		}
		versions, ok := obj["versions"].([]any)
		if !ok || len(versions) == 0 {
			return req, echoed, RequestMalformed
		}
		seen := map[int64]bool{}
		offered := false
		for _, v := range versions {
			n, ok := v.(int64)
			if !ok || n <= 0 || seen[n] {
				return req, echoed, RequestMalformed
			}
			seen[n] = true
			offered = offered || n == 1
		}
		req.Timeout = frameBudget
		req.Params = Object{"versions": versions}
		if !offered {
			return req, echoed, VersionUnsupported
		}
		return req, echoed, ""
	}
	if !members(obj, "method", "params", "request_id", "timeout_ms") {
		return req, echoed, RequestMalformed
	}
	params, ok := obj["params"].(Object)
	if !ok {
		return req, echoed, RequestMalformed
	}
	timeout, ok := obj["timeout_ms"].(int64)
	if !ok || timeout < 1 || timeout > 2000 {
		return req, echoed, RequestMalformed
	}
	req.Params = params
	req.Timeout = time.Duration(timeout) * time.Millisecond
	return req, echoed, ""
}
func members(obj Object, names ...string) bool {
	if len(obj) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := obj[name]; !ok {
			return false
		}
	}
	return true
}
