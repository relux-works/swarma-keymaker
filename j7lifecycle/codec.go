// Package j7lifecycle converts the closed native lifecycle wire subset to and
// from inert values. It provides no transport, signing, authority or run state.
package j7lifecycle

import (
	"encoding/binary"
	"errors"
	"unicode/utf8"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

const (
	MaxFrame            = control.MaxFrame
	MaxDepth            = control.MaxDepth
	MaxInteger          = control.MaxInteger
	MaxTimeoutMS        = 2000
	HelloMethod  Method = "hello"
	BindMethod   Method = "j7_run_bind"
	EndMethod    Method = "j7_run_end"
	RebindMethod Method = "j7_run_rebind"
)

// Local failures are distinct from a decoded wire Refusal. Encoders return nil
// bytes and decoders return the zero value on every local failure.
var (
	ErrFrameTooLarge  = errors.New("j7lifecycle: frame too large")
	ErrFrameMalformed = errors.New("j7lifecycle: zero frame length")
	ErrFrameTruncated = errors.New("j7lifecycle: incomplete frame")
	ErrTrailingData   = errors.New("j7lifecycle: trailing frame data")
	ErrCanonical      = errors.New("j7lifecycle: noncanonical CCJ-1 object")
	ErrRequest        = errors.New("j7lifecycle: invalid request")
	ErrResponse       = errors.New("j7lifecycle: invalid response")
)

type Method string

// Principal describes supplied bytes, not an authenticated account. Generation
// is opaque, nonempty UTF-8; current generation evidence belongs to the holder.
type Principal struct {
	UID        uint32
	Generation string
}
type Origin struct{ Kind, EventID, GrantID, TipHash, Mode, CommandID string }
type BindParams struct {
	IdentityRegistrationNumber uint64
	InputPrincipal             Principal
	Origin                     *Origin // nil encodes explicit null for a child
	ParentRun                  string
}

// Request has exactly one method variant. Hello uses Versions and zero timeout;
// bind uses Bind; end/rebind use RunID. All unused fields must be empty.
type Request struct {
	ID        string
	Method    Method
	TimeoutMS int64
	Versions  []int64
	Bind      *BindParams
	RunID     string
}
type RunResult struct{ RunID, State string }
type Refusal struct {
	Code      string
	Retryable bool
}

// Response has exactly one nonnil result alternative or Refusal. An empty ID
// denotes wire null on refusals only and cannot acknowledge an effect. Even a
// correlated retryable refusal does not prove that no durable commit occurred.
type Response struct {
	ID      string
	Version *int64
	Run     *RunResult
	Refusal *Refusal
}

// EncodeRequestFrame emits one bounded canonical frame; it performs no I/O.
func EncodeRequestFrame(r Request) ([]byte, error) {
	if !validRequest(r) {
		return nil, ErrRequest
	}
	o := control.Object{"method": string(r.Method), "request_id": r.ID}
	if r.Method == HelloMethod {
		versions := make([]any, len(r.Versions))
		for i, v := range r.Versions {
			versions[i] = v
		}
		o["versions"] = versions
	} else {
		p := control.Object{"run_id": r.RunID}
		if r.Method == BindMethod {
			b := r.Bind
			var origin any
			if x := b.Origin; x != nil {
				origin = control.Object{"kind": x.Kind, "event_id": x.EventID, "grant_id": x.GrantID, "tip_hash": x.TipHash, "mode": x.Mode, "command_id": x.CommandID}
			}
			p = control.Object{"identity_registration_number": b.IdentityRegistrationNumber, "input_principal": control.Object{"uid": b.InputPrincipal.UID, "generation": b.InputPrincipal.Generation}, "origin": origin, "parent_run": b.ParentRun}
		}
		o["params"], o["timeout_ms"] = p, r.TimeoutMS
	}
	return encodeFrame(o, ErrRequest)
}

// DecodeRequestFrame accepts exactly one complete frame. A syntactically valid
// hello offer without version 1 is retained; the server refuses that offer.
func DecodeRequestFrame(frame []byte) (Request, error) {
	o, err := decodeFrame(frame)
	if err != nil {
		return Request{}, err
	}
	id, a := o["request_id"].(string)
	m, b := o["method"].(string)
	if !a || !b {
		return Request{}, ErrRequest
	}
	r := Request{ID: id, Method: Method(m)}
	if r.Method == HelloMethod {
		if !members(o, "method", "request_id", "versions") {
			return Request{}, ErrRequest
		}
		v, ok := o["versions"].([]any)
		if !ok {
			return Request{}, ErrRequest
		}
		r.Versions = make([]int64, len(v))
		for i, x := range v {
			n, ok := x.(int64)
			if !ok {
				return Request{}, ErrRequest
			}
			r.Versions[i] = n
		}
	} else {
		if !members(o, "method", "params", "request_id", "timeout_ms") {
			return Request{}, ErrRequest
		}
		ms, ok := o["timeout_ms"].(int64)
		if !ok {
			return Request{}, ErrRequest
		}
		r.TimeoutMS = ms
		p, ok := o["params"].(control.Object)
		if !ok {
			return Request{}, ErrRequest
		}
		switch r.Method {
		case BindMethod:
			if !members(p, "identity_registration_number", "input_principal", "origin", "parent_run") {
				return Request{}, ErrRequest
			}
			n, ok := p["identity_registration_number"].(int64)
			if !ok || n < 1 {
				return Request{}, ErrRequest
			}
			parent, ok := p["parent_run"].(string)
			if !ok {
				return Request{}, ErrRequest
			}
			input, ok := p["input_principal"].(control.Object)
			if !ok || !members(input, "uid", "generation") {
				return Request{}, ErrRequest
			}
			uid, ok := input["uid"].(int64)
			if !ok || uid < 1 || uid > 1<<32-1 {
				return Request{}, ErrRequest
			}
			gen, ok := input["generation"].(string)
			if !ok {
				return Request{}, ErrRequest
			}
			r.Bind = &BindParams{IdentityRegistrationNumber: uint64(n), InputPrincipal: Principal{uint32(uid), gen}, ParentRun: parent}
			if p["origin"] != nil {
				x, ok := p["origin"].(control.Object)
				if !ok || !members(x, "kind", "event_id", "grant_id", "tip_hash", "mode", "command_id") {
					return Request{}, ErrRequest
				}
				origin := &Origin{}
				for key, dst := range map[string]*string{"kind": &origin.Kind, "event_id": &origin.EventID, "grant_id": &origin.GrantID, "tip_hash": &origin.TipHash, "mode": &origin.Mode, "command_id": &origin.CommandID} {
					v, ok := x[key].(string)
					if !ok {
						return Request{}, ErrRequest
					}
					*dst = v
				}
				r.Bind.Origin = origin
			}
		case EndMethod, RebindMethod:
			if !members(p, "run_id") {
				return Request{}, ErrRequest
			}
			id, ok := p["run_id"].(string)
			if !ok {
				return Request{}, ErrRequest
			}
			r.RunID = id
		default:
			return Request{}, ErrRequest
		}
	}
	if !validRequest(r) {
		return Request{}, ErrRequest
	}
	return r, nil
}

// EncodeResponseFrame validates against the locally outstanding request. The
// wire contains no method echo; bind/rebind success cannot distinguish methods.
func EncodeResponseFrame(expected Request, r Response) ([]byte, error) {
	if !validResponse(expected, r) {
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
	case r.Version != nil:
		o["result"] = control.Object{"version": *r.Version}
	case r.Run != nil:
		o["result"] = control.Object{"run_id": r.Run.RunID, "state": r.Run.State}
	}
	return encodeFrame(o, ErrResponse)
}

// DecodeResponseFrame checks the ID, closed result schema and known run/state
// against expected. Null-ID refusals remain uncorrelated data, never success.
func DecodeResponseFrame(expected Request, frame []byte) (Response, error) {
	o, err := decodeFrame(frame)
	if err != nil {
		return Response{}, err
	}
	r := Response{}
	if o["request_id"] != nil {
		id, ok := o["request_id"].(string)
		if !ok || !hexToken(id, 32) {
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
		r.Refusal = &Refusal{code, retry}
	} else if members(o, "request_id", "result") {
		p, ok := o["result"].(control.Object)
		if !ok {
			return Response{}, ErrResponse
		}
		if expected.Method == HelloMethod {
			if !members(p, "version") {
				return Response{}, ErrResponse
			}
			v, ok := p["version"].(int64)
			if !ok {
				return Response{}, ErrResponse
			}
			r.Version = &v
		} else {
			if !members(p, "run_id", "state") {
				return Response{}, ErrResponse
			}
			id, a := p["run_id"].(string)
			state, b := p["state"].(string)
			if !a || !b {
				return Response{}, ErrResponse
			}
			r.Run = &RunResult{id, state}
		}
	} else {
		return Response{}, ErrResponse
	}
	if !validResponse(expected, r) {
		return Response{}, ErrResponse
	}
	return r, nil
}

func validRequest(r Request) bool {
	if !hexToken(r.ID, 32) {
		return false
	}
	if r.Method == HelloMethod {
		// Each version needs at least a digit and separator. Reject an obviously
		// over-cap offer before allocating the encoding slice or duplicate map.
		if r.TimeoutMS != 0 || r.Bind != nil || r.RunID != "" || len(r.Versions) == 0 || len(r.Versions) > MaxFrame/2 {
			return false
		}
		seen := make(map[int64]bool, len(r.Versions))
		for _, v := range r.Versions {
			if v < 1 || v > MaxInteger || seen[v] {
				return false
			}
			seen[v] = true
		}
		return true
	}
	if len(r.Versions) != 0 || r.TimeoutMS < 1 || r.TimeoutMS > MaxTimeoutMS {
		return false
	}
	switch r.Method {
	case BindMethod:
		b := r.Bind
		if b == nil || r.RunID != "" || b.IdentityRegistrationNumber == 0 || b.IdentityRegistrationNumber > uint64(MaxInteger) || b.InputPrincipal.UID == 0 || b.InputPrincipal.Generation == "" || len(b.InputPrincipal.Generation) > MaxFrame || !utf8.ValidString(b.InputPrincipal.Generation) {
			return false
		}
		if b.ParentRun == "" {
			return b.Origin != nil && validOrigin(*b.Origin)
		}
		return b.Origin == nil && hexToken(b.ParentRun, 32)
	case EndMethod, RebindMethod:
		return r.Bind == nil && hexToken(r.RunID, 32)
	}
	return false
}
func validOrigin(o Origin) bool {
	if o.Kind == "owner_command" {
		return hexToken(o.CommandID, 64) && o.EventID == "" && o.GrantID == "" && o.TipHash == "" && o.Mode == ""
	}
	return o.Kind == "admission" && hexToken(o.EventID, 64) && hexToken(o.GrantID, 64) && hexToken(o.TipHash, 64) && o.Mode == "enforcing" && o.CommandID == ""
}
func validResponse(q Request, r Response) bool {
	if !validRequest(q) || r.ID != "" && (!hexToken(r.ID, 32) || r.ID != q.ID) {
		return false
	}
	count := 0
	if r.Version != nil {
		count++
	}
	if r.Run != nil {
		count++
	}
	if r.Refusal != nil {
		count++
	}
	if count != 1 {
		return false
	}
	if e := r.Refusal; e != nil {
		if len(e.Code) > MaxFrame || !control.ValidRefusal(control.Code(e.Code), e.Retryable) {
			return false
		}
		switch e.Code {
		case "frame_too_large", "frame_truncated", "frame_malformed", "ccj_noncanonical":
			return r.ID == ""
		}
		return true
	}
	if r.ID == "" {
		return false
	}
	if q.Method == HelloMethod {
		return r.Version != nil && *r.Version == 1 && offersOne(q.Versions)
	}
	if r.Run == nil || !hexToken(r.Run.RunID, 32) {
		return false
	}
	if q.Method == EndMethod {
		return r.Run.State == "ended" && r.Run.RunID == q.RunID
	}
	if q.Method == RebindMethod {
		return r.Run.State == "live" && r.Run.RunID == q.RunID
	}
	return q.Method == BindMethod && r.Run.State == "live"
}
func offersOne(v []int64) bool {
	for _, n := range v {
		if n == 1 {
			return true
		}
	}
	return false
}
func hexToken(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
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
func decodeFrame(frame []byte) (control.Object, error) {
	if len(frame) < 4 {
		return nil, ErrFrameTruncated
	}
	n := binary.BigEndian.Uint32(frame[:4])
	if n > MaxFrame {
		return nil, ErrFrameTooLarge
	}
	if n == 0 {
		return nil, ErrFrameMalformed
	}
	if len(frame)-4 < int(n) {
		return nil, ErrFrameTruncated
	}
	if len(frame)-4 > int(n) {
		return nil, ErrTrailingData
	}
	o, err := control.Decode(frame[4:])
	if err != nil {
		return nil, ErrCanonical
	}
	return o, nil
}
func encodeFrame(o control.Object, failure error) ([]byte, error) {
	body, err := control.Marshal(o)
	if err != nil {
		return nil, failure
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	return frame, nil
}
