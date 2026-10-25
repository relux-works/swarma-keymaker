package keymaker

import (
	"context"
	"strings"
)

// Five bounded records suffice for S2 issuance. Eight leave headroom for its
// control events within the existing journal control/refusal budget.
const messageAuditReserve = 8 * 8192

type messageAuditTicket struct {
	journal   *Journal
	remaining int64
}
type messageAuditContextKey struct{}

func (j *Journal) reserveMessageAudit(ctx context.Context) (context.Context, func(), Code) {
	if !j.mu.LockContext(ctx) {
		return ctx, func() {}, "request_deadline_exceeded"
	}
	defer j.mu.Unlock()
	if j.failed || j.total+j.messageReserved+messageAuditReserve > j.totalLimit {
		return ctx, func() {}, "audit_unavailable"
	}
	ticket := &messageAuditTicket{journal: j, remaining: messageAuditReserve}
	j.messageReserved += ticket.remaining
	return context.WithValue(ctx, messageAuditContextKey{}, ticket), func() { j.mu.Lock(); j.messageReserved -= ticket.remaining; ticket.remaining = 0; j.mu.Unlock() }, ""
}
func (j *Journal) messageAuditBudget(ctx context.Context, bytes int64) (int64, bool) {
	ticket, _ := ctx.Value(messageAuditContextKey{}).(*messageAuditTicket)
	if ticket == nil || ticket.journal != j {
		return j.messageReserved, true
	}
	return j.messageReserved - ticket.remaining, ticket.remaining >= bytes
}
func (j *Journal) chargeMessageAudit(ctx context.Context, bytes int64) {
	ticket, _ := ctx.Value(messageAuditContextKey{}).(*messageAuditTicket)
	if ticket != nil && ticket.journal == j {
		ticket.remaining -= bytes
		j.messageReserved -= bytes
	}
}

// Keep the original event records in the replayed journal view. Their exact
// artifact digest and resolved identity must precede the partnered commit;
// merely finding an operation name somewhere in history is insufficient.
func (j *Journal) observeMessageEvent(r AuditRecord) error {
	phase := ""
	switch r.Operation {
	case "message_certification_fence":
		phase = "intent"
	case "message_attestation_issue", "message_attestation_renew":
		phase = "issued"
	case "message_certification_abort":
		phase = "aborted"
	case "message_certification_reconcile":
		phase = "reconcile"
	case "message_publication", "message_certification_activate":
		return failure("unqualified message audit operation")
	default:
		return nil
	}
	if !j.messageHistory || r.Surface != "control" || r.Domain == nil || *r.Domain != "control" || r.RequestID == nil || r.PayloadDigest == nil || !validDigest(*r.PayloadDigest) || r.PeerUID == nil || r.Generation == nil || r.Path == nil || r.Epoch == nil || r.RefusalCode != nil || (r.Result != "success" && r.Result != "unknown") {
		return failure("invalid message audit")
	}
	parts := strings.Split(*r.RequestID, ":")
	if len(parts) != 3 || parts[0] != "msg" || !messageID(parts[1]) || parts[2] != phase || ValidatePath(*r.Path, "agent-identity") != "" {
		return failure("invalid message audit identity")
	}
	if j.messageEvents == nil {
		j.messageEvents = map[string]AuditRecord{}
	}
	if _, exists := j.messageEvents[*r.RequestID]; exists {
		return failure("duplicate message phase audit")
	}
	j.messageEvents[*r.RequestID] = r
	return nil
}
func (s *Store) messageEventMatches(id, phase, operation, digest string, b Binding, before, after uint64) bool {
	if s.journal == nil {
		return true
	}
	j := s.journal
	r, ok := j.messageEvents["msg:"+id+":"+phase]
	first, firstOK := j.messageCommits[before]
	last, lastOK := j.messageCommits[after]
	return ok && firstOK && lastOK && r.Seq > first.Seq && r.Seq < last.Seq && r.Operation == operation && r.PayloadDigest != nil && *r.PayloadDigest == digest && r.PeerUID != nil && *r.PeerUID == b.UID && r.Generation != nil && *r.Generation == b.Generation && r.Path != nil && *r.Path == b.Path && r.Epoch != nil && *r.Epoch == b.Epoch
}
func (s *Store) validateMessageEvents(tx messageTransaction, intent messageIntent) error {
	if !s.messageEventMatches(tx.ID, "intent", "message_certification_fence", tx.Intent.Hash, intent.Binding, tx.BaseVersion, tx.BaseVersion+1) {
		return failure("unmatched message fence audit")
	}
	if tx.Phase == "issued" {
		operation := "message_attestation_issue"
		if tx.Kind == "renew" {
			operation = "message_attestation_renew"
		}
		if !s.messageEventMatches(tx.ID, "issued", operation, tx.Candidate.Hash, intent.Binding, tx.BaseVersion+2, tx.BaseVersion+3) {
			return failure("unmatched message issuance audit")
		}
	}
	if tx.Resolution != nil {
		var resolution messageResolution
		if s.readMessageArtifact(tx.ID, *tx.Resolution, &resolution) != "" {
			return failure("missing resolution audit evidence")
		}
		phase, operation := "reconcile", "message_certification_reconcile"
		if resolution.Outcome == "aborted" {
			phase, operation = "aborted", "message_certification_abort"
		}
		if !s.messageEventMatches(tx.ID, phase, operation, tx.Resolution.Hash, intent.Binding, resolution.Version, resolution.Version+1) {
			return failure("unmatched message resolution audit")
		}
	}
	return nil
}
