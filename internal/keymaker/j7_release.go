//go:build linux

package keymaker

import (
	"context"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

// WithActive holds the actual generation, policy, Store and custody barriers
// through control's socket callback. A successful write is not durably released
// until its following commit; uncertainty is never guessed into enrollment.
func (a *j7RequestCustody) WithActive(ctx context.Context, peer control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	if !j7SigningMethod(r.Method) {
		return a.j7Lifecycle.WithActive(ctx, peer, r, result, release)
	}
	p, c := j7ParseRequest(r)
	if c != "" {
		return control.Code(c)
	}
	// Preliminary authority keeps unauthorized calls away from the node's journals.
	c = a.withRun(ctx, peer, r, p, func(j7Run, *j7PolicyTable, string, func(*[32]byte) ([]byte, error)) Code { return "" })
	if c != "" {
		return control.Code(c)
	}
	observed := time.Now()
	var checked int64
	if p.grant != nil {
		checked, c = a.now(ctx)
		if c != "" {
			return control.Code(c)
		}
		if c = a.evidence.check(ctx, *p.grant, p.evidence, checked); c != "" {
			return control.Code(c)
		}
	}
	c = a.withRun(ctx, peer, r, p, func(run j7Run, table *j7PolicyTable, public string, _ func(*[32]byte) ([]byte, error)) Code {
		s := a.store
		ch := j7ChannelFrom(ctx)
		if !ch.active() {
			return "run_identity_unavailable"
		}
		if p.grant != nil {
			now, c := a.now(ctx)
			if c != "" {
				return c
			}
			if now < checked || now-checked > 2 || time.Since(observed) > 2*time.Second {
				return "delegation_evidence_unavailable"
			}
		}
		prior, c := s.retained(nativePrincipal(peer), r)
		if c != "" {
			return c
		}
		record := s.j7SigningRecord(nativePrincipal(peer), r.ID)
		if prior == nil || record == nil || record.Run != run.ID || record.Binding != run.Binding || record.Origin != run.Origin {
			return "request_conflict"
		}
		encoded, e := control.Marshal(result)
		if e != nil || string(encoded) != string(prior.Result) || j7Hash(encoded) != record.ResultHash {
			return "request_conflict"
		}
		if key, ok := result["public_key"].(string); ok && key != public {
			return "custody_unavailable"
		}
		if c := s.j7Point("signing-before-handoff"); c != "" {
			return c
		}
		// Set unknown before any byte can escape, including a retained-result retry.
		previous := s.j7Signing
		effectStarted := false
		defer func() {
			if !effectStarted {
				s.j7Signing = previous
			}
		}()
		s.j7Signing = cloneJ7Signing(s.j7Signing)
		record = s.j7SigningRecord(nativePrincipal(peer), r.ID)
		if record.Release == "prepared" && p.operation == "consent_v3" {
			// First handoff records the entry actually authorizing release,
			// including its current and-use value. A known earlier release on
			// retry keeps its historical entry; current enrollment still checks
			// current policy independently.
			row := j7PolicyRowFor(table, run.Origin.key())
			if row == nil {
				return "CONSENT_NOT_FOR_RUN"
			}
			for _, entry := range row.Consent {
				if entry.Contract == p.consent.Contract && entry.Booking == p.consent.Booking && entry.Privacy == p.consent.Privacy {
					record.Consent = entry
				}
			}
		}
		record.Release = "handoff_unknown"
		if r.Method == "j7_enroll" {
			enrollment, c := a.enrollmentLocked(run, p, table)
			if c != "" {
				return c
			}
			if !s.j7Enrolled(enrollment.Origin, enrollment.Identity, enrollment.Grant) {
				if len(s.j7Signing.Enrollments) >= j7HistoryLimit {
					return "state_capacity_exceeded"
				}
				s.j7Signing.Enrollments = append(s.j7Signing.Enrollments, enrollment)
			}
		}
		if !s.fitsState(s.records, s.next, s.requests) {
			return "state_capacity_exceeded"
		}
		effectStarted = true
		if c := s.commitJ7(ctx); c != "" {
			return c
		}
		if c := s.j7Point("signing-handoff-unknown"); c != "" {
			s.failed = true
			return "j7_state_fenced"
		}
		// One callback only; a partial/failed transport remains durably unknown.
		if c := Code(release(ctx)); c != "" {
			s.failed = true
			return c
		}
		if c := s.j7Point("signing-after-write"); c != "" {
			s.failed = true
			return "j7_state_fenced"
		}
		record.Release = "released"
		if c := s.commitJ7(ctx); c != "" {
			record.Release = "handoff_unknown"
			return c
		}
		return ""
	})
	return control.Code(c)
}
