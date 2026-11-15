package control

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

type capReader struct {
	header            [4]byte
	offset, bodyBytes int
}

func (r *capReader) Read(p []byte) (int, error) {
	if r.offset < 4 {
		n := copy(p, r.header[r.offset:])
		r.offset += n
		return n, nil
	}
	// A virtual body avoids constructing attacker-selected body storage in tests.
	for i := range p {
		p[i] = 'x'
	}
	r.bodyBytes += len(p)
	return len(p), nil
}

// The first over-cap header consumes only four bytes and no body allocation;
// the adjacent maximum-size frame remains accepted. Allocation count is bounded
// to the escaping four-byte header, not an attacker-sized backing array.
func TestFrameCapBeforeBodyRead(t *testing.T) {
	r := &capReader{}
	binary.BigEndian.PutUint32(r.header[:], MaxFrame+1)
	allocations := testing.AllocsPerRun(10, func() {
		r.offset = 0
		r.bodyBytes = 0
		body, code := readFrame(r)
		if code != FrameTooLarge || body != nil || r.offset != 4 || r.bodyBytes != 0 {
			t.Fatalf("code=%s body=%d header=%d body-read=%d", code, len(body), r.offset, r.bodyBytes)
		}
	})
	if allocations > 1 {
		t.Fatalf("over-cap allocated %.0f times; at most header allocation allowed", allocations)
	}
	r.offset = 0
	r.bodyBytes = 0
	binary.BigEndian.PutUint32(r.header[:], MaxFrame)
	b, code := readFrame(r)
	if code != "" || len(b) != MaxFrame || r.bodyBytes != MaxFrame {
		t.Fatalf("cap control: %s len=%d read=%d", code, len(b), r.bodyBytes)
	}
}

// Even a uint32-maximum advertised body is refused without a single body read.
func TestFrameHugeHeaderNoBody(t *testing.T) {
	r := &capReader{}
	binary.BigEndian.PutUint32(r.header[:], ^uint32(0))
	if _, code := readFrame(r); code != FrameTooLarge || r.bodyBytes != 0 {
		t.Fatalf("%s body=%d", code, r.bodyBytes)
	}
}

type timeoutReader struct{}

func (timeoutReader) Read([]byte) (int, error) { return 0, timeoutError{} }

type timeoutError struct{}

func (timeoutError) Error() string   { return "test timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// Partial-header and partial-body EOF are truncation; a read timeout is a
// deadline, while clean EOF, zero length and a complete frame remain distinct.
func TestFrameReadFailures(t *testing.T) {
	good := packet([]byte(`{}`))
	for n := 1; n < len(good); n++ {
		_, code := readFrame(bytes.NewReader(good[:n]))
		if code != FrameTruncated {
			t.Fatalf("prefix %d: %s", n, code)
		}
	}
	if b, c := readFrame(bytes.NewReader(nil)); b != nil || c != "" {
		t.Fatalf("clean EOF: %q %s", b, c)
	}
	if _, c := readFrame(bytes.NewReader(make([]byte, 4))); c != FrameMalformed {
		t.Fatal(c)
	}
	if _, c := readFrame(timeoutReader{}); c != DeadlineExceeded {
		t.Fatal(c)
	}
	if _, c := readFrame(io.MultiReader(bytes.NewReader(good[:5]), timeoutReader{})); c != DeadlineExceeded {
		t.Fatal(c)
	}
	if b, c := readFrame(bytes.NewReader(good)); string(b) != "{}" || c != "" {
		t.Fatalf("control: %q %s", b, c)
	}
}

func packet(body []byte) []byte {
	b := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(b, uint32(len(body)))
	copy(b[4:], body)
	return b
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

// Response framing handles short writes and refuses unsupported/oversize
// output before any bytes are emitted; a zero-progress writer fails promptly.
func TestFrameWriter(t *testing.T) {
	w := &shortWriter{}
	obj := Object{"a": int64(1)}
	if err := writeFrame(w, obj); err != nil {
		t.Fatal(err)
	}
	if b, c := readFrame(bytes.NewReader(w.Bytes())); string(b) != `{"a":1}` || c != "" {
		t.Fatalf("%q %s", b, c)
	}
	w.Reset()
	if err := writeFrame(w, Object{"bad": 1.5}); err == nil || w.Len() != 0 {
		t.Fatal("invalid output written")
	}
	if err := writeFrame(w, Object{"large": strings.Repeat("x", MaxFrame)}); err == nil || w.Len() != 0 {
		t.Fatal("oversize output written")
	}
	if err := writeAll(zeroWriter{}, []byte{1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}

// Grant-evidence uncertainty has one closed terminal code. An invented alias
// remains invalid; this does not grant a handler or a retry fallback.
func TestJ7EvidenceRefusalCode(t *testing.T) {
	if !validCode("delegation_evidence_unavailable") || retryable("delegation_evidence_unavailable") {
		t.Fatal("grant evidence refusal lost terminal spelling")
	}
	if validCode("delegation_live") || validCode("delegation_evidence_pending") {
		t.Fatal("unpublished evidence verdict admitted")
	}
}

// The new typed profile's explicit semantic codes survive the closed wire
// filter and remain nonretryable; free-form or misspelled diagnostics do not.
func TestJ7DelegationRefusalCodes(t *testing.T) {
	for _, code := range []Code{"CONTRACT_ENCODING", "CONTRACT_PROFILE", "CONTRACT_FIELD", "CONTRACT_ACTIONS", "CONTRACT_REPOS", "CONTRACT_BUDGET", "CONTRACT_NOTE", "CONTRACT_PARENT", "CONTRACT_DELEGATE", "DELEGATE_NO_NOTARY", "CONTRACT_HASH", "CONTRACT_MISMATCH", "SCOPE_MISMATCH", "BUDGET_MISMATCH", "CONSENT_TAGS", "PARENT_ID_MISMATCH", "CHAIN_DEPTH", "NOT_DELEGABLE", "SUBJECT_MISMATCH", "CHILD_ORDINAL", "CHILD_AGENT_NOT_ALLOWED", "CHILD_GRANTEE_NOT_ALLOWED", "CHILD_ACTIONS_WIDER", "CHILD_REPOS_WIDER", "CHILD_BUDGET_OVER", "CHILD_WINDOW_NOT_NESTED", "DELEGATION_REQUEST"} {
		if !validCode(code) || retryable(code) {
			t.Fatal("typed refusal lost or retryable", code)
		}
	}
	for _, code := range []Code{"contract_parent", "CHILD_UNCHECKED", "LIVE", "internal node failure"} {
		if validCode(code) {
			t.Fatal("foreign diagnostic reached wire", code)
		}
	}
}

// Each published native code accepts exactly its prescribed retry bit; foreign
// strings accept neither bit. This is data validation, not an effect verdict.
func TestValidRefusal(t *testing.T) {
	retry := []Code{"rate_limited", "busy", "generation_source_unavailable", "enrollment_unavailable", "audit_unavailable", DeadlineExceeded}
	terminal := []Code{FrameTooLarge, FrameTruncated, FrameMalformed, CCJNoncanonical, RequestMalformed, RequestConflict, VersionUnsupported, HelloRequired, HelloAlreadyNegotiated, OperationUnsupported,
		"run_identity_unavailable", "j7_state_fenced", "delegation_evidence_unavailable", "GRANT_NOT_FOR_RUN", "CONSENT_NOT_FOR_RUN", "registration_malformed", "registration_signature_invalid", "registration_id_mismatch", "custody_unavailable", "peer_identity_unavailable", "generation_source_fenced", "generation_inactive", "generation_mismatch", "binding_not_found", "peer_binding_mismatch", "binding_conflict", "role_not_permitted", "identity_revoked", "persistent_revoke_requires_operator", "operator_record_unavailable", "operator_record_invalid", "path_not_hardened", "path_invalid", "purpose_unknown", "name_invalid", "name_unknown", "name_registry_invalid", "index_exhausted", "sign_data_not_sshsig", "sshsig_malformed", "namespace_not_permitted", "sign_key_mismatch", "sign_flags_unsupported", "agent_message_unsupported", "request_expired", "enrollment_unverified", "enrollment_unsupported", "host_revoked", "uid_map_required", "uid_not_permitted", "name_not_permitted", "audience_mismatch", "key_not_enrolled", "key_not_valid_now", "entropy_unavailable", "clock_untrusted", "state_capacity_exceeded",
		"CONTRACT_ENCODING", "CONTRACT_PROFILE", "CONTRACT_FIELD", "CONTRACT_ACTIONS", "CONTRACT_REPOS", "CONTRACT_BUDGET", "CONTRACT_NOTE", "CONTRACT_PARENT", "CONTRACT_DELEGATE", "DELEGATE_NO_NOTARY", "CONTRACT_HASH", "CONTRACT_MISMATCH", "SCOPE_MISMATCH", "BUDGET_MISMATCH", "CONSENT_TAGS", "PARENT_ID_MISMATCH", "CHAIN_DEPTH", "NOT_DELEGABLE", "SUBJECT_MISMATCH", "CHILD_ORDINAL", "CHILD_AGENT_NOT_ALLOWED", "CHILD_GRANTEE_NOT_ALLOWED", "CHILD_ACTIONS_WIDER", "CHILD_REPOS_WIDER", "CHILD_BUDGET_OVER", "CHILD_WINDOW_NOT_NESTED", "DELEGATION_REQUEST"}
	for _, row := range []struct {
		codes []Code
		bit   bool
	}{{retry, true}, {terminal, false}} {
		for _, code := range row.codes {
			if !ValidRefusal(code, row.bit) || ValidRefusal(code, !row.bit) {
				t.Fatalf("refusal pair mismatch: %s", code)
			}
		}
	}
	for _, code := range []Code{"", "LIVE", "run_bind_unknown", "run_end_unknown", "station_caller_unqualified", "free form diagnostic", "ROLE_NOT_PERMITTED"} {
		if ValidRefusal(code, false) || ValidRefusal(code, true) {
			t.Fatalf("foreign refusal accepted: %s", code)
		}
	}
}
