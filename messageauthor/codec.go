// Package messageauthor converts the fixture-only message-author wire subset
// into detached values. It provides no I/O, signer, identity or authority source.
package messageauthor

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/relux-works/swarma-envelope/record"
	control "github.com/relux-works/swarma-keymaker/messageauthor/internal/frame"
)

const (
	MaxFrame              = control.MaxFrame
	MaxPreimage           = 24576
	MaxAttestation        = 8192
	IdentityMethod Method = "message_author_identity"
	SignMethod     Method = "sign_message_author"
)

var (
	ErrFrameTooLarge  = errors.New("messageauthor: frame too large")
	ErrFrameMalformed = errors.New("messageauthor: zero frame length")
	ErrFrameTruncated = errors.New("messageauthor: incomplete frame")
	ErrTrailingData   = errors.New("messageauthor: trailing frame data")
	ErrCanonical      = errors.New("messageauthor: noncanonical CCJ-1 object")
	ErrRequest        = errors.New("messageauthor: invalid request")
	ErrResponse       = errors.New("messageauthor: invalid response")
)

type Method string

// Request carries no identity/key/path/digest selector. Preimage is sign-only;
// accepting its bounded bytes here does not admit them for signing.
type Request struct {
	ID        string
	TimeoutMS int64
	Method    Method
	Preimage  []byte
}
type IdentityResult struct {
	KeyID, AuthorAttestation string
	Attestation              []byte
}
type SignatureResult struct {
	KeyID     string
	Signature []byte
}
type Refusal struct {
	Code      string
	Retryable bool
}

// Response has exactly one alternative. An empty ID denotes an uncorrelated
// wire-null refusal. A retry bit says nothing about durable effect outcome.
type Response struct {
	ID        string
	Identity  *IdentityResult
	Signature *SignatureResult
	Refusal   *Refusal
}

func validID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validRequest(r Request) bool {
	if !validID(r.ID) || r.TimeoutMS < 1 || r.TimeoutMS > 2000 {
		return false
	}
	switch r.Method {
	case IdentityMethod:
		return len(r.Preimage) == 0
	case SignMethod:
		return len(r.Preimage) <= MaxPreimage
	}
	return false
}

// EncodeRequestFrame emits a bounded canonical body after externally owned hello.
func EncodeRequestFrame(r Request) ([]byte, error) {
	if !validRequest(r) {
		return nil, ErrRequest
	}
	p := control.Object{}
	if r.Method == SignMethod {
		p["preimage"] = base64.RawURLEncoding.EncodeToString(r.Preimage)
	}
	return marshalFrame(control.Object{"method": string(r.Method), "params": p, "request_id": r.ID, "timeout_ms": r.TimeoutMS}, ErrRequest)
}
func DecodeRequestFrame(frame []byte) (Request, error) {
	o, e := decodeFrame(frame)
	if e != nil {
		return Request{}, e
	}
	if !members(o, "method", "params", "request_id", "timeout_ms") {
		return Request{}, ErrRequest
	}
	id, a := o["request_id"].(string)
	ms, b := o["timeout_ms"].(int64)
	m, c := o["method"].(string)
	p, d := o["params"].(control.Object)
	if !a || !b || !c || !d {
		return Request{}, ErrRequest
	}
	r := Request{ID: id, TimeoutMS: ms, Method: Method(m)}
	switch r.Method {
	case IdentityMethod:
		if !members(p) {
			return Request{}, ErrRequest
		}
	case SignMethod:
		if !members(p, "preimage") {
			return Request{}, ErrRequest
		}
		s, ok := p["preimage"].(string)
		if !ok {
			return Request{}, ErrRequest
		}
		v, ok := decodeBytes(s, MaxPreimage, -1)
		if !ok {
			return Request{}, ErrRequest
		}
		r.Preimage = v
	default:
		return Request{}, ErrRequest
	}
	if !validRequest(r) {
		return Request{}, ErrRequest
	}
	return r, nil
}
func validKey(s string) bool {
	if len(s) != 50 || !strings.HasPrefix(s, "bip340:") {
		return false
	}
	a, _, e := record.KeyBytes(s)
	return e == nil && a == "bip340" && record.ValidateKey(s) == nil
}

// validResponse requires context held by the caller, never inferred from wire.
func validResponse(q Request, r Response) bool {
	if !validRequest(q) || r.ID != "" && (!validID(r.ID) || r.ID != q.ID) {
		return false
	}
	n := 0
	if r.Identity != nil {
		n++
	}
	if r.Signature != nil {
		n++
	}
	if r.Refusal != nil {
		n++
	}
	if n != 1 {
		return false
	}
	if e := r.Refusal; e != nil {
		retry, ok := refusalRetryable(e.Code)
		if !ok || retry != e.Retryable {
			return false
		}
		if framingCode(e.Code) && r.ID != "" {
			return false
		}
		return true
	}
	if r.ID == "" {
		return false
	}
	if p := r.Identity; p != nil {
		return q.Method == IdentityMethod && len(p.Attestation) > 0 && len(p.Attestation) <= MaxAttestation && record.IsContentID(p.AuthorAttestation) && validKey(p.KeyID)
	}
	s := r.Signature
	return q.Method == SignMethod && len(s.Signature) == 64 && validKey(s.KeyID)
}

// EncodeResponseFrame checks the outstanding request ID and method. Public
// attestation/signature bytes are grammar only, not a verification result.
func EncodeResponseFrame(q Request, r Response) ([]byte, error) {
	if !validResponse(q, r) {
		return nil, ErrResponse
	}
	var id any
	if r.ID != "" {
		id = r.ID
	}
	o := control.Object{"request_id": id}
	switch {
	case r.Refusal != nil:
		o["error"] = control.Object{"code": r.Refusal.Code, "retryable": r.Refusal.Retryable}
	case r.Identity != nil:
		p := r.Identity
		o["result"] = control.Object{"key_id": p.KeyID, "author_attestation": p.AuthorAttestation, "attestation": base64.RawURLEncoding.EncodeToString(p.Attestation)}
	case r.Signature != nil:
		p := r.Signature
		o["result"] = control.Object{"key_id": p.KeyID, "signature": base64.RawURLEncoding.EncodeToString(p.Signature)}
	}
	return marshalFrame(o, ErrResponse)
}
func DecodeResponseFrame(q Request, frame []byte) (Response, error) {
	o, e := decodeFrame(frame)
	if e != nil {
		return Response{}, e
	}
	r := Response{}
	if o["request_id"] != nil {
		id, ok := o["request_id"].(string)
		// Only received null may use the Go empty-ID sentinel.
		if !ok || !validID(id) {
			return Response{}, ErrResponse
		}
		r.ID = id
	}
	if members(o, "request_id", "error") {
		p, ok := o["error"].(control.Object)
		if !ok || !members(p, "code", "retryable") {
			return Response{}, ErrResponse
		}
		code, a := p["code"].(string)
		retry, b := p["retryable"].(bool)
		if !a || !b {
			return Response{}, ErrResponse
		}
		r.Refusal = &Refusal{code, retry}
	} else if members(o, "request_id", "result") {
		p, ok := o["result"].(control.Object)
		if !ok {
			return Response{}, ErrResponse
		}
		key, ok := p["key_id"].(string)
		if !ok {
			return Response{}, ErrResponse
		}
		switch q.Method {
		case IdentityMethod:
			if !members(p, "key_id", "author_attestation", "attestation") {
				return Response{}, ErrResponse
			}
			tid, a := p["author_attestation"].(string)
			s, b := p["attestation"].(string)
			if !a || !b {
				return Response{}, ErrResponse
			}
			v, ok := decodeBytes(s, MaxAttestation, -1)
			if !ok {
				return Response{}, ErrResponse
			}
			r.Identity = &IdentityResult{key, tid, v}
		case SignMethod:
			if !members(p, "key_id", "signature") {
				return Response{}, ErrResponse
			}
			s, ok := p["signature"].(string)
			if !ok {
				return Response{}, ErrResponse
			}
			v, ok := decodeBytes(s, 64, 64)
			if !ok {
				return Response{}, ErrResponse
			}
			r.Signature = &SignatureResult{key, v}
		default:
			return Response{}, ErrResponse
		}
	} else {
		return Response{}, ErrResponse
	}
	if !validResponse(q, r) {
		return Response{}, ErrResponse
	}
	return r, nil
}

// FrameLength checks the fixed header before a caller allocates a body buffer.
func FrameLength(h [4]byte) (int, error) {
	n := binary.BigEndian.Uint32(h[:])
	if n > MaxFrame {
		return 0, ErrFrameTooLarge
	}
	if n == 0 {
		return 0, ErrFrameMalformed
	}
	return int(n), nil
}
func decodeFrame(frame []byte) (control.Object, error) {
	if len(frame) < 4 {
		return nil, ErrFrameTruncated
	}
	n, e := FrameLength([4]byte(frame[:4]))
	if e != nil {
		return nil, e
	}
	if len(frame)-4 < n {
		return nil, ErrFrameTruncated
	}
	if len(frame)-4 > n {
		return nil, ErrTrailingData
	}
	o, e := control.Decode(frame[4:])
	if e != nil {
		return nil, ErrCanonical
	}
	return o, nil
}
func marshalFrame(o control.Object, failure error) ([]byte, error) {
	b, e := control.Marshal(o)
	if e != nil {
		return nil, failure
	}
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out, nil
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
func decodeBytes(s string, max, exact int) ([]byte, bool) {
	if len(s) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, false
	}
	if exact >= 0 && len(s) != base64.RawURLEncoding.EncodedLen(exact) {
		return nil, false
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, e == nil && len(b) <= max && (exact < 0 || len(b) == exact) && base64.RawURLEncoding.EncodeToString(b) == s
}
func framingCode(c string) bool {
	switch c {
	case "frame_too_large", "frame_truncated", "frame_malformed", "ccj_noncanonical":
		return true
	}
	return false
}

// Codec-local vocabulary only: no production route or control code registration.
func refusalRetryable(c string) (bool, bool) {
	switch c {
	case "busy", "rate_limited", "generation_source_unavailable", "audit_unavailable", "request_deadline_exceeded":
		return true, true
	case "frame_too_large", "frame_truncated", "frame_malformed", "ccj_noncanonical", "request_malformed", "request_conflict", "version_unsupported", "hello_required", "hello_already_negotiated", "operation_unsupported", "peer_identity_unavailable", "generation_source_fenced", "generation_inactive", "generation_mismatch", "binding_not_found", "peer_binding_mismatch", "binding_conflict", "identity_revoked", "role_not_permitted", "custody_unavailable", "entropy_unavailable", "clock_untrusted", "key_not_enrolled", "key_not_valid_now", "sign_key_mismatch", "state_capacity_exceeded", "signer_preimage_too_large", "signer_tag_malformed", "signer_domain_refused", "signer_payload_invalid", "signer_identity_unavailable", "signer_identity_malformed", "signer_identity_mismatch", "message_author_unqualified":
		return false, true
	}
	return false, false
}
