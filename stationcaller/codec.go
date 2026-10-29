// Package stationcaller encodes and decodes the proposed station-caller native
// wire subset after externally owned hello negotiation. It performs no I/O,
// signing, signature verification, plan lookup or authority/currentness checks.
package stationcaller

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

const (
	MaxFrame                      = control.MaxFrame
	MaxRegistrationNumber         = control.MaxInteger
	PubkeyMethod          Method  = "station_caller_pubkey"
	SignMethod            Method  = "sign_station_caller"
	DispatcherRequest     Profile = "dispatcher-request/1"
	CallerDelegation      Profile = "caller-delegation/1"
	Unqualified                   = "station_caller_unqualified"
	PlanUnavailable               = "station_caller_plan_unavailable"
	PlanInvalid                   = "station_caller_plan_invalid"
)

// Local codec errors are distinct from a decoded Refusal. Every failed decoder
// returns the zero value, and every failed encoder returns nil bytes.
var (
	ErrFrameTooLarge  = errors.New("stationcaller: frame too large")
	ErrFrameMalformed = errors.New("stationcaller: zero frame length")
	ErrFrameTruncated = errors.New("stationcaller: incomplete frame")
	ErrTrailingData   = errors.New("stationcaller: trailing frame data")
	ErrCanonical      = errors.New("stationcaller: noncanonical CCJ-1 object")
	ErrRequest        = errors.New("stationcaller: invalid request")
	ErrResponse       = errors.New("stationcaller: invalid response")
)

type Method string
type Profile string

// Request has no extension map or caller-selected identity. For PubkeyMethod,
// Profile and PlanID must be empty; SignMethod requires both exact values.
type Request struct {
	ID        string
	TimeoutMS int64
	Method    Method
	Profile   Profile
	PlanID    string
}

// PublicKeyResult describes bytes only, not an authenticated association. Path
// is the canonical four-component hardened purpose-6 registry sibling; its name
// indices are positive 31-bit values. Epoch is an opaque nonempty UTF-8 string.
type PublicKeyResult struct {
	Key                string
	Path               string
	RegistrationNumber int64
	Epoch              string
}

// SignatureResult contains canonical encoded public key/signature bytes.
// Parsing them does not verify the signature, origin, plan or authority.
type SignatureResult struct{ Key, Signature string }

// Refusal is a successfully decoded wire error, with exact published code and
// retryability. It is not a local parse failure or an effect-outcome statement.
type Refusal struct {
	Code      string
	Retryable bool
}

// Response has exactly one nonnil alternative. ID is a valid native request ID;
// empty denotes wire null on refusals only. Framing/canonical refusals require
// null. Whether another refusal echoes the parsed ID is a transport obligation.
type Response struct {
	ID        string
	PublicKey *PublicKeyResult
	Signature *SignatureResult
	Refusal   *Refusal
}

// EncodeRequestFrame returns one complete length-prefixed canonical frame.
func EncodeRequestFrame(r Request) ([]byte, error) {
	if !validID(r.ID) || r.TimeoutMS < 1 || r.TimeoutMS > 2000 {
		return nil, ErrRequest
	}
	params := control.Object{}
	switch r.Method {
	case PubkeyMethod:
		if r.Profile != "" || r.PlanID != "" {
			return nil, ErrRequest
		}
	case SignMethod:
		if !validProfile(r.Profile) || !hexToken(r.PlanID, "sha256:", 64) {
			return nil, ErrRequest
		}
		params = control.Object{"profile": string(r.Profile), "plan_id": r.PlanID}
	default:
		return nil, ErrRequest
	}
	return marshalFrame(control.Object{"method": string(r.Method), "params": params, "request_id": r.ID, "timeout_ms": r.TimeoutMS})
}

// DecodeRequestFrame accepts exactly one complete frame of this method subset.
func DecodeRequestFrame(frame []byte) (Request, error) {
	o, err := decodeFrame(frame)
	if err != nil {
		return Request{}, err
	}
	if !members(o, "method", "params", "request_id", "timeout_ms") {
		return Request{}, ErrRequest
	}
	id, iok := o["request_id"].(string)
	ms, tok := o["timeout_ms"].(int64)
	m, mok := o["method"].(string)
	p, pok := o["params"].(control.Object)
	if !iok || !tok || !mok || !pok {
		return Request{}, ErrRequest
	}
	r := Request{ID: id, TimeoutMS: ms, Method: Method(m)}
	switch r.Method {
	case PubkeyMethod:
		if !members(p) {
			return Request{}, ErrRequest
		}
	case SignMethod:
		if !members(p, "profile", "plan_id") {
			return Request{}, ErrRequest
		}
		profile, a := p["profile"].(string)
		plan, b := p["plan_id"].(string)
		if !a || !b {
			return Request{}, ErrRequest
		}
		r.Profile, r.PlanID = Profile(profile), plan
	default:
		return Request{}, ErrRequest
	}
	if _, err := EncodeRequestFrame(r); err != nil {
		return Request{}, err
	}
	return r, nil
}

// EncodeResponseFrame uses the outstanding request's method: responses have no
// method field. The caller must additionally correlate nonnull response IDs.
func EncodeResponseFrame(method Method, r Response) ([]byte, error) {
	if method != PubkeyMethod && method != SignMethod {
		return nil, ErrResponse
	}
	alternatives := 0
	if r.PublicKey != nil {
		alternatives++
	}
	if r.Signature != nil {
		alternatives++
	}
	if r.Refusal != nil {
		alternatives++
	}
	if alternatives != 1 || r.ID != "" && !validID(r.ID) {
		return nil, ErrResponse
	}
	o := control.Object{"request_id": r.ID}
	if e := r.Refusal; e != nil {
		retry, ok := refusalRetryable(e.Code)
		if !ok || retry != e.Retryable || framingCode(e.Code) && r.ID != "" {
			return nil, ErrResponse
		}
		if r.ID == "" {
			o["request_id"] = nil
		}
		o["error"] = control.Object{"code": e.Code, "retryable": e.Retryable}
	} else {
		if !validID(r.ID) {
			return nil, ErrResponse
		}
		if p := r.PublicKey; p != nil {
			if method != PubkeyMethod || !validBase64(p.Key, "ed25519:", 32) || !validPath(p.Path) || p.RegistrationNumber < 1 || p.RegistrationNumber > MaxRegistrationNumber || p.Epoch == "" {
				return nil, ErrResponse
			}
			o["result"] = control.Object{"key": p.Key, "path": p.Path, "registration_number": p.RegistrationNumber, "master_epoch": p.Epoch}
		} else {
			s := r.Signature
			if method != SignMethod || !validBase64(s.Key, "ed25519:", 32) || !validBase64(s.Signature, "", 64) {
				return nil, ErrResponse
			}
			o["result"] = control.Object{"key": s.Key, "sig": s.Signature}
		}
	}
	return marshalFrame(o)
}

// DecodeResponseFrame returns a typed result or Refusal, never a partial result
// alongside a parse error. It cannot infer whether a service effect occurred.
func DecodeResponseFrame(method Method, frame []byte) (Response, error) {
	o, err := decodeFrame(frame)
	if err != nil {
		return Response{}, err
	}
	r := Response{}
	if o["request_id"] != nil {
		id, ok := o["request_id"].(string)
		if !ok || !validID(id) {
			return Response{}, ErrResponse
		}
		r.ID = id
	}
	if members(o, "request_id", "error") {
		e, ok := o["error"].(control.Object)
		if !ok || !members(e, "code", "retryable") {
			return Response{}, ErrResponse
		}
		code, a := e["code"].(string)
		retry, b := e["retryable"].(bool)
		if !a || !b {
			return Response{}, ErrResponse
		}
		r.Refusal = &Refusal{Code: code, Retryable: retry}
	} else if members(o, "request_id", "result") {
		p, ok := o["result"].(control.Object)
		if !ok {
			return Response{}, ErrResponse
		}
		switch method {
		case PubkeyMethod:
			if !members(p, "key", "path", "registration_number", "master_epoch") {
				return Response{}, ErrResponse
			}
			key, a := p["key"].(string)
			path, b := p["path"].(string)
			n, c := p["registration_number"].(int64)
			epoch, d := p["master_epoch"].(string)
			if !a || !b || !c || !d {
				return Response{}, ErrResponse
			}
			r.PublicKey = &PublicKeyResult{Key: key, Path: path, RegistrationNumber: n, Epoch: epoch}
		case SignMethod:
			if !members(p, "key", "sig") {
				return Response{}, ErrResponse
			}
			key, a := p["key"].(string)
			sig, b := p["sig"].(string)
			if !a || !b {
				return Response{}, ErrResponse
			}
			r.Signature = &SignatureResult{Key: key, Signature: sig}
		default:
			return Response{}, ErrResponse
		}
	} else {
		return Response{}, ErrResponse
	}
	if _, err := EncodeResponseFrame(method, r); err != nil {
		return Response{}, err
	}
	return r, nil
}

func decodeFrame(frame []byte) (control.Object, error) {
	if len(frame) < 4 {
		return nil, ErrFrameTruncated
	}
	n := uint64(binary.BigEndian.Uint32(frame[:4]))
	if n > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	if n == 0 {
		return nil, ErrFrameMalformed
	}
	if uint64(len(frame)-4) < n {
		return nil, ErrFrameTruncated
	}
	if uint64(len(frame)-4) > n {
		return nil, ErrTrailingData
	}
	o, err := control.Decode(frame[4:])
	if err != nil {
		return nil, ErrCanonical
	}
	return o, nil
}
func marshalFrame(o control.Object) ([]byte, error) {
	b, err := control.Marshal(o)
	if err != nil {
		return nil, ErrCanonical
	}
	frame := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(frame, uint32(len(b)))
	copy(frame[4:], b)
	return frame, nil
}
func members(o control.Object, names ...string) bool {
	if len(o) != len(names) {
		return false
	}
	for _, n := range names {
		if _, ok := o[n]; !ok {
			return false
		}
	}
	return true
}
func validID(s string) bool { return hexToken(s, "", 32) }
func hexToken(s, prefix string, n int) bool {
	if len(s) != len(prefix)+n || !strings.HasPrefix(s, prefix) {
		return false
	}
	for _, c := range s[len(prefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validProfile(p Profile) bool {
	switch p {
	case DispatcherRequest, CallerDelegation:
		return true
	}
	return false
}
func validBase64(s, prefix string, n int) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	text := s[len(prefix):]
	if len(text) != base64.RawURLEncoding.EncodedLen(n) {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(text)
	return err == nil && len(b) == n && base64.RawURLEncoding.EncodeToString(b) == text
}
func validPath(path string) bool {
	// A structurally valid path cannot exceed three ten-digit name indices.
	if len(path) > len("m/6'/2147483647'/2147483647'/2147483647'") {
		return false
	}
	parts := strings.Split(path, "/")
	if len(parts) != 5 || parts[0] != "m" || parts[1] != "6'" {
		return false
	}
	for _, p := range parts[2:] {
		if !strings.HasSuffix(p, "'") {
			return false
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(p, "'"), 10, 31)
		if err != nil || n == 0 || strconv.FormatUint(n, 10)+"'" != p {
			return false
		}
	}
	return true
}
func framingCode(code string) bool {
	switch code {
	case "frame_too_large", "frame_truncated", "frame_malformed", "ccj_noncanonical":
		return true
	}
	return false
}

// This codec-local vocabulary deliberately does not register production methods,
// purposes or error codes. The base native vocabulary and the supplement's
// binding_provisioned/three new refusals retain their documented retryability.
func refusalRetryable(code string) (bool, bool) {
	switch code {
	case "rate_limited", "busy", "generation_source_unavailable", "enrollment_unavailable", "audit_unavailable", "request_deadline_exceeded":
		return true, true
	case "frame_too_large", "frame_truncated", "frame_malformed", "ccj_noncanonical", "request_malformed", "request_conflict", "version_unsupported", "hello_required", "hello_already_negotiated", "operation_unsupported",
		"registration_malformed", "registration_signature_invalid", "registration_id_mismatch", "custody_unavailable", "peer_identity_unavailable", "generation_source_fenced", "generation_inactive", "generation_mismatch", "binding_not_found", "peer_binding_mismatch", "binding_conflict", "role_not_permitted", "identity_revoked", "persistent_revoke_requires_operator", "operator_record_unavailable", "operator_record_invalid", "path_not_hardened", "path_invalid", "purpose_unknown", "name_invalid", "name_unknown", "name_registry_invalid", "index_exhausted", "sign_data_not_sshsig", "sshsig_malformed", "namespace_not_permitted", "sign_key_mismatch", "sign_flags_unsupported", "agent_message_unsupported", "request_expired", "enrollment_unverified", "enrollment_unsupported", "host_revoked", "uid_map_required", "uid_not_permitted", "name_not_permitted", "audience_mismatch", "key_not_enrolled", "key_not_valid_now", "entropy_unavailable", "clock_untrusted", "state_capacity_exceeded",
		"provision_state_invalid", "binding_provisioned", "message_too_large", "signer_identity_unavailable", "signer_identity_malformed", "signer_identity_mismatch", Unqualified, PlanUnavailable, PlanInvalid:
		return false, true
	}
	return false, false
}
