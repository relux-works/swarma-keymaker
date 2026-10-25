package keymaker

import (
	"bytes"
	"encoding/json"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

const maxRetainedRequests = 65536
const stateBudget = 256 << 20

type requestKey struct {
	Caller Principal
	ID     string
}
type retainedRequest struct {
	Caller    Principal       `json:"caller"`
	ID        string          `json:"id"`
	Method    string          `json:"method"`
	Arguments string          `json:"arguments"`
	Status    string          `json:"status"`
	Result    json.RawMessage `json:"result"`
}

func mutation(method string) bool { return method == "register" || method == "revoke" }
func requestArguments(r control.Request) ([]byte, Code) {
	b, err := control.Marshal(r.Params)
	if err != nil {
		return nil, "request_malformed"
	}
	return b, ""
}
func (s *Store) validateRequests() error {
	if len(s.requests) > maxRetainedRequests {
		return failure("retained request budget exceeded")
	}
	for i, r := range s.requests {
		if !validGeneration(r.Caller.Generation) || len(r.ID) != 32 || (r.Method != "hello" && r.Method != "pubkey" && !mutation(r.Method) && r.Method != "sign_registration") {
			return failure("invalid retained request")
		}
		for _, c := range r.ID {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return failure("invalid retained request id")
			}
		}
		if _, err := control.Decode([]byte(r.Arguments)); err != nil {
			return failure("invalid retained arguments")
		}
		if r.Status == "pending" {
			if !mutation(r.Method) || !bytes.Equal(r.Result, []byte("null")) {
				return failure("invalid retained intent")
			}
		} else if r.Status == "committed" {
			if _, err := control.Decode(r.Result); err != nil {
				return failure("invalid retained result")
			}
		} else {
			return failure("invalid retained status")
		}
		key := requestKey{r.Caller, r.ID}
		if _, ok := s.requestIndex[key]; ok {
			return failure("duplicate retained request")
		}
		s.requestIndex[key] = i
	}
	return nil
}
func (s *Store) retained(p Principal, r control.Request) (*retainedRequest, Code) {
	if s.failed {
		return nil, "audit_unavailable"
	}
	args, c := requestArguments(r)
	if c != "" {
		return nil, c
	}
	i, ok := s.requestIndex[requestKey{p, r.ID}]
	if !ok {
		return nil, ""
	}
	prior := &s.requests[i]
	if prior.Method != r.Method || prior.Arguments != string(args) {
		return nil, "request_conflict"
	}
	if prior.Status != "committed" {
		return nil, "audit_unavailable"
	}
	return prior, ""
}
func (s *Store) resultObject(r *retainedRequest) (control.Object, Code) {
	obj, err := control.Decode(r.Result)
	if err != nil {
		s.failed = true
		return nil, "audit_unavailable"
	}
	return obj, ""
}

// Preflight the combined binding/result budget before an intent or effect. The
// largest references reserve room for the real journal position and hash.
func (s *Store) fitsState(records []Binding, next uint64, requests []retainedRequest) bool {
	if len(requests) > maxRetainedRequests {
		return false
	}
	b, err := json.Marshal(bindingDisk{Next: next, Records: records, Requests: requests, Version: 9007199254740991, AuditSeq: 9007199254740991, AuditHash: string(bytes.Repeat([]byte("0"), 64)), SchemaVersion: s.schema, Messages: s.messages})
	return err == nil && len(b) <= stateBudget && (s.schema != 2 || s.messageFits(len(b)))
}
func (s *Store) appendRequest(r retainedRequest) {
	s.requestIndex[requestKey{r.Caller, r.ID}] = len(s.requests)
	s.requests = append(s.requests, r)
}
