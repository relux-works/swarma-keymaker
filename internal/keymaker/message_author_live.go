package keymaker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-keymaker/messageauthor"
)

type maLiveTuple struct {
	Key, T      string
	Attestation []byte
}

// WithCurrent holds the selected binding's local renewal exclusion throughout
// commit. It proves ONE current tuple over the complete START interval. A
// filename, previous connection or caller assertion cannot implement this seam.
type maLiveCurrent interface {
	WithCurrent(context.Context, Binding, j7GateTime, func(maLiveTuple) Code) Code
}
type maLiveUnqualified struct{}

func (maLiveUnqualified) WithCurrent(context.Context, Binding, j7GateTime, func(maLiveTuple) Code) Code {
	return "message_author_unqualified"
}

type maLiveHolder struct {
	budget      *maLiveBudget
	store       *Store
	key         *messageAuthorKey
	generations GenerationSource
	current     maLiveCurrent
	clock       func(context.Context) (j7GateTime, Code)
	invoke      func(*Store, Binding, *messageAuthorPlan, func() Code) ([]byte, Code)
	// Running ownership covers crypto AND handoff. A duplicate never overlaps a
	// callback; every waiter still takes its own complete authority barrier.
	mu      sync.Mutex
	running map[requestKey]chan struct{}
}

func maLiveID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func (h *maLiveHolder) claim(ctx context.Context, p Principal, id string) (func(), Code) {
	k := requestKey{p, id}
	for {
		h.mu.Lock()
		if h.running == nil {
			h.running = map[requestKey]chan struct{}{}
		}
		if wait := h.running[k]; wait != nil {
			h.mu.Unlock()
			select {
			case <-ctx.Done():
				return nil, "request_deadline_exceeded"
			case <-wait:
				continue
			}
		}
		ch := make(chan struct{})
		h.running[k] = ch
		h.mu.Unlock()
		return func() { h.mu.Lock(); delete(h.running, k); close(ch); h.mu.Unlock() }, ""
	}
}
func (h *maLiveHolder) selected(ctx context.Context, p Principal, id string) (Binding, Code) {
	if h == nil || h.store == nil {
		return Binding{}, "message_author_unqualified"
	}
	s := h.store
	if !s.mu.LockContext(ctx) {
		return Binding{}, "request_deadline_exceeded"
	}
	defer s.mu.Unlock()
	if s.failed || s.maLive == nil || s.maLive.Fenced {
		return Binding{}, "message_author_unqualified"
	}
	b, c := s.lookup(p.UID, p.Generation)
	if c != "" || b.Epoch != s.maLive.Epoch || b.RegistryRevision != s.maLive.Registry {
		return Binding{}, s.maLiveTerminal(ctx, p, id, "message_author_unqualified")
	}
	return b, ""
}

// Caller holds Store. Proven identity loss terminally suppresses a retained
// attempt; transient provider, clock and custody availability failures do not.
func (s *Store) maLiveTerminal(ctx context.Context, p Principal, id string, fresh Code) Code {
	if i := s.maLiveIndex(p, id); i >= 0 {
		s.maLive.Attempts[i].Status = "dead"
		if c := s.persistMALive(ctx, i); c != "" {
			return c
		}
		return "message_author_unqualified"
	}
	return fresh
}
func maLiveHash(raw []byte) string { v := sha256.Sum256(raw); return hex.EncodeToString(v[:]) }
func (h *maLiveHolder) conflict(ctx context.Context, p Principal, r messageauthor.Request) Code {
	s := h.store
	if !s.mu.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	defer s.mu.Unlock()
	if s.maLive == nil {
		return "message_author_unqualified"
	}
	if i := s.maLiveIndex(p, r.ID); i >= 0 {
		a := s.maLive.Attempts[i]
		if a.Method != string(r.Method) || !bytes.Equal(a.Preimage, r.Preimage) {
			return "request_conflict"
		}
	}
	return ""
}
func maLiveRefusal(id string, c Code) messageauthor.Response {
	return messageauthor.Response{ID: id, Refusal: &messageauthor.Refusal{Code: string(c), Retryable: control.ValidRefusal(control.Code(c), true)}}
}

// qualified fixes the exclusion order. Selection before the chain is only a
// candidate: the exact record is checked again under Store. A renewal/retirement
// that wins any gap is observed before the callback can disclose bytes.
func (h *maLiveHolder) qualified(ctx context.Context, p Principal, r messageauthor.Request, fn func(*Store, maLiveTuple) Code) Code {
	b, c := h.selected(ctx, p, r.ID)
	if c != "" {
		return c
	}
	c = h.withGeneration(ctx, p, func(ctx context.Context) Code {
		if h.clock == nil {
			return "clock_untrusted"
		}
		at, c := h.clock(ctx)
		if c != "" || !at.startBoundsValid() {
			return "clock_untrusted"
		}
		if h.current == nil {
			return "message_author_unqualified"
		}
		return h.current.WithCurrent(ctx, b, at, func(tuple maLiveTuple) Code {
			if _, e := messageauthor.EncodeResponseFrame(messageauthor.Request{ID: r.ID, TimeoutMS: r.TimeoutMS, Method: messageauthor.IdentityMethod}, messageauthor.Response{ID: r.ID, Identity: &messageauthor.IdentityResult{KeyID: tuple.Key, AuthorAttestation: tuple.T, Attestation: tuple.Attestation}}); e != nil {
				return "message_author_unqualified"
			}
			s := h.store
			if !s.mu.LockContext(ctx) {
				return "request_deadline_exceeded"
			}
			defer s.mu.Unlock()
			if s.failed || s.maLive == nil || s.maLive.Fenced {
				return "message_author_unqualified"
			}
			now, c := s.lookup(p.UID, p.Generation)
			if c != "" || now != b || b.Epoch != s.maLive.Epoch || b.RegistryRevision != s.maLive.Registry {
				return "message_author_unqualified"
			}
			if h.key == nil {
				maLiveSetCause(ctx, custodyUnloaded)
				return "custody_unavailable"
			}
			h.key.mu.Lock()
			defer h.key.mu.Unlock()
			if !h.key.mapped || cap(h.key.seed) < 4096 {
				maLiveSetCause(ctx, custodyProtectionFailed)
				return "custody_unavailable"
			}
			if h.key.instance != s.maLive.Instance || h.key.epoch != s.maLive.Epoch || h.key.registry != s.maLive.Registry {
				maLiveSetCause(ctx, custodyProtectionFailed)
				return s.maLiveTerminal(ctx, p, r.ID, "custody_unavailable")
			}
			public, c := h.key.selectedHeld(s, b, nil, nil)
			if c != "" {
				if c == "custody_unavailable" {
					cause := custodyProtectionFailed
					if h.key.closed {
						cause = custodyClosed
					} else if len(h.key.seed) != 32 {
						cause = custodyUnloaded
					}
					maLiveSetCause(ctx, cause)
				}
				return c
			}
			i := s.maLiveIndex(p, r.ID)
			if i >= 0 {
				a := &s.maLive.Attempts[i]
				if a.Method != string(r.Method) || !bytes.Equal(a.Preimage, r.Preimage) {
					return "request_conflict"
				}
				if a.Attestation != tuple.T {
					a.Status = "dead"
					if c = s.persistMALive(ctx, i); c != "" {
						return c
					}
					return "signer_identity_mismatch"
				}
				if a.Binding != b || a.Instance != s.maLive.Instance || a.Key != tuple.Key || a.Key != messageAuthorPublicString(public) {
					a.Status = "dead"
					if c = s.persistMALive(ctx, i); c != "" {
						return c
					}
					return "message_author_unqualified"
				}
				if a.Status == "dead" {
					return "message_author_unqualified"
				}
			}
			if messageAuthorPublicString(public) != tuple.Key {
				return "signer_identity_mismatch"
			}
			return fn(s, tuple)
		})
	})
	if c == "generation_inactive" || c == "generation_mismatch" {
		// A terminal GEN loss cannot disclose bytes. Retain the loss locally;
		// this path has no custody/signing callback and never clears a fence.
		s := h.store
		if !s.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		defer s.mu.Unlock()
		if !s.failed && !s.maLive.Fenced {
			return s.maLiveTerminal(ctx, p, r.ID, "message_author_unqualified")
		}
		return "message_author_unqualified"
	}
	return c

}

// handle owns no peer authentication: only the Unix server supplies the kernel
// principal and generation captured at accept. No client UID selector exists.
func (h *maLiveHolder) handle(ctx context.Context, p Principal, r messageauthor.Request, deliver func(context.Context, messageauthor.Response) Code) Code {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(r.TimeoutMS)*time.Millisecond)
	defer cancel()
	if !maLiveID(r.ID) || r.TimeoutMS < 1 || r.TimeoutMS > 2000 {
		return "request_malformed"
	}
	if r.Method != messageauthor.IdentityMethod && r.Method != messageauthor.SignMethod {
		return "operation_unsupported"
	}
	if len(r.Preimage) > messageauthor.MaxPreimage {
		return "signer_preimage_too_large"
	}
	if ctx.Value(maLiveChargedKey{}) != true {
		if c := h.charge(p, r.Method == messageauthor.SignMethod); c != "" {
			return c
		}
	}
	if c := h.conflict(ctx, p, r); c != "" {
		return c
	}
	release, c := h.claim(ctx, p, r.ID)
	if c != "" {
		return c
	}
	defer release()
	if c = h.conflict(ctx, p, r); c != "" {
		return c
	}
	if h.store == nil || h.store.journal == nil {
		return "message_author_unqualified"
	}
	ctx, unreserve, c := h.store.journal.reserveMessageAudit(ctx)
	if c != "" {
		return c
	}
	defer unreserve()
	c = h.qualified(ctx, p, r, func(s *Store, tuple maLiveTuple) Code {
		if r.Method == messageauthor.IdentityMethod {
			return s.maLiveAudit(ctx, p, r.ID, "message_author_identity", nil)
		}
		if i := s.maLiveIndex(p, r.ID); i < 0 || s.maLive.Attempts[i].Status == "intent" {
			s.journal.mu.Lock()
			held, _ := s.journal.messageAuditBudget(ctx, 0)
			room := s.journal.total+held+messageAuditReserve <= s.journal.totalLimit-s.journal.reserve
			s.journal.mu.Unlock()
			if !room {
				return "audit_unavailable"
			}
		}
		plan, c := prepareMessageAuthor(r.Preimage, tuple.Key, tuple.T)
		if c != "" {
			return c
		}
		i := s.maLiveIndex(p, r.ID)
		if i < 0 {
			if len(s.maLive.Attempts) >= maLiveAttemptLimit {
				return "state_capacity_exceeded"
			}
			b, c := s.lookup(p.UID, p.Generation)
			if c != "" {
				return "message_author_unqualified"
			}
			s.maLive.Attempts = append(s.maLive.Attempts, maLiveAttempt{Caller: p, ID: r.ID, Method: string(r.Method), Preimage: append([]byte(nil), r.Preimage...), Binding: b, Instance: s.maLive.Instance, Key: tuple.Key, Attestation: tuple.T, Status: "intent"})
			i = len(s.maLive.Attempts) - 1
			if c = s.persistMALive(ctx, i); c != "" {
				if c == "state_capacity_exceeded" || c == "request_deadline_exceeded" {
					s.maLive.Attempts = s.maLive.Attempts[:i]
				}
				return c
			}
		}
		a := &s.maLive.Attempts[i]
		if a.Status != "intent" {
			return ""
		}
		invoke := h.invoke
		if invoke == nil {
			invoke = h.key.selectedHeld
		}
		signature, c := invoke(s, a.Binding, plan, func() Code {
			if auditContextExpired(ctx) {
				return "request_deadline_exceeded"
			}
			a.Status = "invoking"
			c := s.persistMALive(ctx, i)
			if c == "request_deadline_exceeded" || c == "state_capacity_exceeded" {
				a.Status = "intent"
			}
			return c
		})
		if c != "" {
			if c == "custody_unavailable" {
				maLiveSetCause(ctx, custodyProtectionFailed)
			}
			if a.Status == "invoking" {
				a.Status = "dead"
				if pc := s.persistMALive(context.WithoutCancel(ctx), i); pc != "" {
					return pc
				}
				return "message_author_unqualified"
			}
			return c
		}
		digest := maLiveHash(r.Preimage)
		seq, hash, c := s.maLiveAppend(context.WithoutCancel(ctx), p, r.ID, "sign_message_author", &digest)
		if c != "" {
			erase(signature)
			a.Status = "dead"
			if c == "clock_untrusted" {
				if pc := s.persistMALive(context.WithoutCancel(ctx), i); pc != "" {
					return pc
				}
			}
			return c
		}
		if c := s.messagePoint("ma-success-audit"); c != "" {
			erase(signature)
			return c
		}
		a.Signature = append([]byte(nil), signature...)
		erase(signature)
		a.SuccessSeq, a.SuccessHash = seq, hash
		a.Status = "result"
		c = s.persistMALive(context.WithoutCancel(ctx), i)
		if c != "" {
			erase(a.Signature)
			a.Signature = nil
			a.SuccessSeq = 0
			a.SuccessHash = ""
			a.Status = "dead"
		}
		return c
	})
	if c != "" {
		return c
	}
	if r.Method == messageauthor.SignMethod {
		c = h.qualified(ctx, p, r, func(s *Store, tuple maLiveTuple) Code {
			i := s.maLiveIndex(p, r.ID)
			a := &s.maLive.Attempts[i]
			if a.Status != "result" && a.Status != "handoff_unknown" && a.Status != "released" {
				return "message_author_unqualified"
			}
			if c := s.maLiveAudit(ctx, p, r.ID, "message_author_release", nil); c != "" {
				return c
			}
			a.Status = "handoff_unknown"
			return s.persistMALive(ctx, i)
		})
		if c != "" {
			return c
		}
	}
	// Re-enter the full chain AFTER the handoff marker's durability work. This is
	// the actual disclosure barrier, not a previously sampled currentness claim.
	return h.qualified(ctx, p, r, func(s *Store, tuple maLiveTuple) Code {
		response := messageauthor.Response{ID: r.ID}
		var a *maLiveAttempt
		if r.Method == messageauthor.IdentityMethod {
			response.Identity = &messageauthor.IdentityResult{KeyID: tuple.Key, AuthorAttestation: tuple.T, Attestation: append([]byte(nil), tuple.Attestation...)}
		} else {
			i := s.maLiveIndex(p, r.ID)
			if i < 0 {
				return "message_author_unqualified"
			}
			a = &s.maLive.Attempts[i]
			if a.Status != "handoff_unknown" {
				return "message_author_unqualified"
			}
			response.Signature = &messageauthor.SignatureResult{KeyID: a.Key, Signature: append([]byte(nil), a.Signature...)}
		}
		if !s.journal.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		if s.journal.failed {
			s.journal.mu.Unlock()
			s.failed = true
			return "audit_unavailable"
		}
		if c := s.messagePoint("ma-before-disclosure"); c != "" {
			s.journal.mu.Unlock()
			return c
		}
		if auditContextExpired(ctx) {
			s.journal.mu.Unlock()
			return "request_deadline_exceeded"
		}
		c := deliver(ctx, response)
		s.journal.mu.Unlock()
		if c != "" {
			return c
		}
		if auditContextExpired(ctx) {
			return "request_deadline_exceeded"
		}
		if a != nil {
			a.Status = "released"
			return s.persistMALive(context.WithoutCancel(ctx), s.maLiveIndex(p, r.ID))
		}
		return ""
	})
}

// Test providers use the complete interval. Production never manufactures a
// tuple or admits one using a single wall-clock point.
func maLiveInterval(at j7GateTime, notBefore, notAfter time.Time) bool {
	return at.startBoundsValid() && !at.Lower.Before(notBefore) && at.Upper.Before(notAfter)
}

func maLiveSetCause(ctx context.Context, c custodyCause) {
	if p, ok := ctx.Value(maLiveCauseKey{}).(*custodyCause); ok {
		*p = c
	}
}

type maLiveChargedKey struct{}

func (h *maLiveHolder) charge(p Principal, sign bool) Code {
	h.mu.Lock()
	if h.budget == nil {
		h.budget = &maLiveBudget{}
	}
	b := h.budget
	h.mu.Unlock()
	return b.charge(p, sign)
}

func (h *maLiveHolder) withGeneration(ctx context.Context, p Principal, fn func(context.Context) Code) Code {
	if h.generations == nil {
		return "generation_source_unavailable"
	}
	return h.generations.WithActive(ctx, p.UID, p.Generation, fn)
}
