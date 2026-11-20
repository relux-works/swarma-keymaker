package keymaker

import (
	"context"
	"strings"
)

func maLiveOperation(op string) bool {
	switch op {
	case "message_author_attestation_issue", "message_author_attestation_renew", "message_author_attestation_fence", "message_author_issuer_seed_init", "message_author_identity", "sign_message_author", "message_author_init", "message_author_enroll", "message_author_retire", "message_author_release", "message_author_fence", "message_author_reconcile":
		return true
	}
	return false
}
func validMALiveAudit(r AuditRecord) error {
	if !maLiveOperation(r.Operation) {
		if strings.HasPrefix(r.Operation, "message_author_") || strings.HasPrefix(r.Operation, "sign_message_author") {
			return failure("unknown message-author audit operation")
		}
		return nil
	}
	if r.Surface != "control" || r.Domain == nil || r.Result != "success" || r.RefusalCode != nil || r.CustodyCause != nil {
		return failure("invalid message-author audit")
	}
	domain := "control"
	if r.Operation == "sign_message_author" {
		domain = "swarma-msg"
		if r.PayloadDigest == nil || !validDigest(*r.PayloadDigest) || r.RequestID == nil || !maLiveID(*r.RequestID) || r.PeerUID == nil || r.Generation == nil {
			return failure("invalid message-author sign audit")
		}
	} else if strings.HasPrefix(r.Operation, "message_author_attestation_") {
		if r.PayloadDigest == nil || !validDigest(*r.PayloadDigest) {
			return failure("missing issuer evidence digest")
		}
	} else if r.PayloadDigest != nil {
		return failure("payload in message-author control audit")
	}
	if *r.Domain != domain {
		return failure("invalid message-author audit domain")
	}
	if r.Path != nil || r.Epoch != nil {
		return failure("unexpected message-author audit material")
	}
	return nil
}
func (j *Journal) observeMALive(r AuditRecord) error {
	if e := validMALiveAudit(r); e != nil {
		return e
	}
	if strings.HasPrefix(r.Operation, "message_author_attestation_") {
		if j.maIssuerEvents == nil {
			j.maIssuerEvents = map[uint64]AuditRecord{}
		}
		j.maIssuerEvents[r.Seq] = r
	}
	if r.Operation == "sign_message_author" {
		if j.maLiveEvents == nil {
			j.maLiveEvents = map[uint64]AuditRecord{}
		}
		if len(j.maLiveEvents) >= maLiveAttemptLimit {
			return failure("message-author audit proof capacity")
		}
		j.maLiveEvents[r.Seq] = r
	}
	return nil
}
func (s *Store) maLiveAudit(ctx context.Context, p Principal, id, op string, digest *string) Code {
	_, _, c := s.maLiveAppend(ctx, p, id, op, digest)
	return c
}

// Capture the exact synced receipt under the journal lock. Concurrent hello or
// refusal audit records must never substitute their later head for sign success.
func (s *Store) maLiveAppend(ctx context.Context, p Principal, id, op string, digest *string) (uint64, string, Code) {
	if s.failed || s.journal == nil || !maLiveOperation(op) {
		return 0, "", "audit_unavailable"
	}
	domain := "control"
	if op == "sign_message_author" {
		domain = "swarma-msg"
	}
	r := AuditRecord{Surface: "control", Operation: op, Domain: &domain, Result: "success", PayloadDigest: digest}
	if id != "" {
		r.RequestID = &id
	}
	if p.Generation != "" {
		r.PeerUID = &p.UID
		r.Generation = &p.Generation
	}
	j := s.journal
	if !j.mu.LockContext(ctx) {
		return 0, "", "request_deadline_exceeded"
	}
	defer j.mu.Unlock()
	if c := j.appendContextLocked(ctx, r); c != "" {
		if c != "request_deadline_exceeded" && c != "clock_untrusted" {
			s.failed = true
			s.maLive.Fenced = true
		}
		return 0, "", c
	}
	return j.seq, j.previous, ""
}

// Only a reconciled pair and its protected head permit this classification.
// This reader has no custody parameter and cannot invoke signing on recovery.
func (s *Store) recoverMALive(ctx context.Context) Code {
	if s.maLive == nil || s.failed || s.journal == nil {
		return "message_author_unqualified"
	}
	wasFenced := s.maLive.Fenced
	changed := s.recoverMAIssuers()
	var rows []int
	for i := range s.maLive.Attempts {
		a := &s.maLive.Attempts[i]
		switch a.Status {
		case "intent", "dead":
		case "invoking":
			// A sign-audit tail beyond the paired invoking head may have been
			// interrupted during sync. Readability does not prove continuity;
			// only stopped reconciliation can resolve this overlay to dead.
			if s.maLiveUnpairedSign(*a) {
				s.maLive.Fenced = true
			} else {
				a.Status = "dead"
				rows = append(rows, i)
			}
			changed = true
		case "result", "handoff_unknown", "released":
			if !s.maLiveResultProven(*a) {
				s.maLive.Fenced = true
				changed = true
			}
		default:
			s.maLive.Fenced = true
			changed = true
		}
	}
	if changed {
		if !wasFenced && s.maLive.Fenced {
			if c := s.maLiveAudit(ctx, Principal{}, "", "message_author_fence", nil); c != "" {
				return c
			}
		}
		return s.persistMALive(ctx, rows...)
	}
	return ""
}

// reconcileMALive is a stopped-operator primitive, never a socket operation.
// The protected expected head and complete paired snapshot/journal are the
// proof. Reading bytes or observing a recovered provider alone is insufficient.
// It has no custody, issuer, entropy or signing dependency.
func (s *Store) reconcileMALive(ctx context.Context, operator Principal, expected j7Expectation) Code {
	if !s.mu.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	defer s.mu.Unlock()
	if s.maLive == nil || s.failed || s.journal == nil || !s.j7HeadMatches(expected) || !s.matchesCommit(s.journal.binding) {
		return "message_author_unqualified"
	}
	if s.validateMALive() != nil {
		return "message_author_unqualified"
	}
	for _, a := range s.maLive.Attempts {
		if a.Status == "result" || a.Status == "handoff_unknown" || a.Status == "released" {
			if !s.maLiveResultProven(a) {
				return "message_author_unqualified"
			}
		}
	}
	// Reassert durability of every retained part, including the audit directory,
	// before changing the overlay. A failed writer cannot prove its own recovery.
	s.journal.mu.Lock()
	ok := !s.journal.failed && s.journal.file != nil && s.journal.file.Sync() == nil && s.auditDir.Sync() == nil && s.dir.Sync() == nil
	s.journal.mu.Unlock()
	if !ok {
		return "audit_unavailable"
	}
	if c := s.maLiveAudit(ctx, operator, "", "message_author_reconcile", nil); c != "" {
		return c
	}
	var rows []int
	for i := range s.maLive.Attempts {
		if s.maLive.Attempts[i].Status == "invoking" {
			s.maLive.Attempts[i].Status = "dead"
			rows = append(rows, i)
		}
	}
	s.maLive.Fenced = false
	return s.persistMALive(context.WithoutCancel(ctx), rows...)
}
func (s *Store) maLiveResultProven(a maLiveAttempt) bool {
	s.journal.mu.Lock()
	r, ok := s.journal.maLiveEvents[a.SuccessSeq]
	s.journal.mu.Unlock()
	return ok && r.Digest == a.SuccessHash && r.RequestID != nil && *r.RequestID == a.ID && r.PeerUID != nil && *r.PeerUID == a.Caller.UID && r.Generation != nil && *r.Generation == a.Caller.Generation && r.PayloadDigest != nil && *r.PayloadDigest == maLiveHash(a.Preimage)
}

func (s *Store) maLiveUnpairedSign(a maLiveAttempt) bool {
	s.journal.mu.Lock()
	defer s.journal.mu.Unlock()
	for seq, r := range s.journal.maLiveEvents {
		if seq > s.auditSeq && r.RequestID != nil && *r.RequestID == a.ID && r.PeerUID != nil && *r.PeerUID == a.Caller.UID && r.Generation != nil && *r.Generation == a.Caller.Generation {
			return true
		}
	}
	return false
}
