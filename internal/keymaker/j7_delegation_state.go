package keymaker

import (
	"context"
	"os"
)

const j7DelegationSchema = 6

func j7SigningStateSchema(schema int) bool {
	return schema == j7SigningSchema || schema == j7DelegationSchema
}

// A trusted stopped operator chooses this reader, never a caller field or a
// missing-file branch. Keep the historical schema5 reader and opener unchanged.
func openJ7DelegationStore(dir *os.File, uid uint32, clock AuditClock, expected j7Expectation) (*Store, error) {
	s, _, _, e := openCustodyStateMessage(dir, uid, clock, j7DelegationSchema, false, expected)
	if e != nil {
		return nil, e
	}
	if !s.j7HeadMatches(expected) || s.j7UnknownHandoff() {
		s.Close()
		return nil, failure("J7 delegation continuity unavailable")
	}
	return s, nil
}
func (s *Store) migrateJ7Delegation(ctx context.Context, expected j7Expectation) Code {
	if !s.mu.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	defer s.mu.Unlock()
	if s.failed || s.schema != j7SigningSchema || s.j7 == nil || s.j7Signing == nil || s.validateJ7() != nil || !s.j7HeadMatches(expected) {
		return "j7_state_fenced"
	}
	for _, r := range s.requests {
		if r.Status != "committed" {
			return "j7_state_fenced"
		}
	}
	s.schema = j7DelegationSchema
	return s.commitJ7(ctx)
}
