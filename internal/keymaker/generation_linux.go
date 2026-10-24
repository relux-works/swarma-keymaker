//go:build linux

package keymaker

import (
	"context"
	"errors"
	"strconv"
	"time"

	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// generationWindow matches the format owner's release-authorizing API exactly.
// The implementation must yield a completely verified, locked view; Checkpoint
// and diagnostic Inspect are not implementations of this interface.
type generationWindow interface {
	WithEvidence(context.Context, string, gj.Floor, func(gj.View, time.Time) error) error
}

type journalGeneration struct {
	gate     auditGate
	window   generationWindow
	store    *Store
	anchor   generationAnchor
	enrolled bool
	fenced   bool
}

func newJournalGeneration(window generationWindow, store *Store, path string, initial gj.Floor) *journalGeneration {
	a, fenced := loadGenerationAnchor(store, path, initial)
	return &journalGeneration{window: window, store: store, anchor: a, enrolled: store.journal.generation.Anchor != nil, fenced: fenced}
}

func generationSourceCode(err error) Code {
	if err == nil {
		return ""
	}
	var code Code
	if errors.As(err, &code) {
		return code
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "request_deadline_exceeded"
	}
	var r *gj.Refusal
	if errors.As(err, &r) {
		switch r.Code {
		case "journal_rollback", "journal_fork", "journal_writer_stale", "journal_capacity_reserve":
			return "generation_source_fenced"
		case "journal_reader_deadline", "journal_lock_timeout":
			return "request_deadline_exceeded"
		case "generation_mismatch":
			return "generation_mismatch"
		case "generation_inactive", "generation_missing":
			return "generation_inactive"
		}
	}
	return "generation_source_unavailable"
}

// A fence latches before any further authority call. The authenticated incident
// record survives restart; if its append fails, admission stays closed locally
// and replay retries the incident, never a success. Ordinary per-request refusal
// audits are separate from this single incident record.
func (g *journalGeneration) fence(ctx context.Context) Code {
	g.fenced = true
	j := g.store.journal
	if j.generation.Fenced {
		return "generation_source_fenced"
	}
	domain, code := "control", Code("generation_source_fenced")
	if c := j.AppendContext(ctx, AuditRecord{Surface: "control", Domain: &domain, Operation: "generation_fence", Path: &g.anchor.Path, Result: "refused", RefusalCode: &code}); c != "" {
		return c
	}
	return code
}

func (g *journalGeneration) withWindow(ctx context.Context, commit func(context.Context, gj.View) Code) Code {
	// Serialize floor advances before acquiring a source lock, avoiding local
	// reader queues inside the shared source window. Cancellation abandons waits.
	if !g.gate.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	defer g.gate.Unlock()
	if g.fenced {
		return g.fence(ctx)
	}
	if !g.store.mu.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	loaded, damaged := loadGenerationAnchor(g.store, g.anchor.Path, g.anchor.Floor)
	g.store.mu.Unlock()
	if damaged || loaded != g.anchor {
		return g.fence(ctx)
	}
	if g.window == nil {
		return "generation_source_unavailable"
	}
	err := g.window.WithEvidence(ctx, g.anchor.Path, g.anchor.Floor, func(v gj.View, deadline time.Time) error {
		bounded, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		if auditContextExpired(bounded) {
			return Code("request_deadline_exceeded")
		}
		if err := v.Capacity(); err != nil {
			return err
		}
		// The source verifies continuity against exactly this floor. Do not replace
		// the durable floor with an unverified tail, even on a rejected predicate.
		if !g.enrolled || v.Tail != g.anchor.Floor {
			a := generationAnchor{Path: g.anchor.Path, Floor: v.Tail}
			if c := persistGenerationAnchor(bounded, g.store, a); c != "" {
				// A journal-first partial publication is never recovered automatically.
				if c != "request_deadline_exceeded" {
					g.fenced = true
				}
				return c
			}
			g.anchor = a
			g.enrolled = true
		}
		if auditContextExpired(bounded) {
			return Code("request_deadline_exceeded")
		}
		if c := commit(bounded, v); c != "" {
			return c
		}
		if auditContextExpired(bounded) {
			return Code("request_deadline_exceeded")
		}
		return nil
	})
	code := generationSourceCode(err)
	if code == "generation_source_fenced" {
		return g.fence(ctx)
	}
	return code
}

func viewGeneration(v gj.View, uid uint32) (Generation, Code) {
	for _, r := range v.Rows {
		if r.UID == int64(uid) {
			if r.State != "active" {
				return Generation{}, "generation_inactive"
			}
			if err := v.Active(int64(uid), r.Generation); err != nil {
				return Generation{}, generationSourceCode(err)
			}
			return Generation{UID: uid, Generation: r.Generation, State: r.State, Revision: strconv.FormatInt(v.Tail.Seq, 10) + ":" + v.Tail.Hash, Provenance: gj.Format, Verified: true}, ""
		}
	}
	return Generation{}, "generation_inactive"
}
func (g *journalGeneration) Lookup(ctx context.Context, uid uint32) (Generation, Code) {
	var result Generation
	code := g.withWindow(ctx, func(_ context.Context, v gj.View) Code { var c Code; result, c = viewGeneration(v, uid); return c })
	return result, code
}
func (g *journalGeneration) WithActive(ctx context.Context, uid uint32, token string, commit func(context.Context) Code) Code {
	return g.WithEvidence(ctx, []GenerationCondition{{Principal: Principal{uid, token}}}, commit)
}
func (g *journalGeneration) WithEvidence(ctx context.Context, conditions []GenerationCondition, commit func(context.Context) Code) Code {
	if len(conditions) == 0 {
		return "generation_source_unavailable"
	}
	return g.withWindow(ctx, func(bounded context.Context, v gj.View) Code {
		for _, c := range conditions {
			code := Code("")
			if c.Retired {
				r, ok := v.Generation(c.Principal.Generation)
				if !ok || r.UID != int64(c.Principal.UID) {
					code = "generation_mismatch"
				} else if r.State != "retiring" && r.State != "removed" {
					code = "generation_inactive"
				}
			} else {
				active, ac := viewGeneration(v, c.Principal.UID)
				code = ac
				if code == "" && active.Generation != c.Principal.Generation {
					code = "generation_mismatch"
				}
			}
			if c.Verdict != nil {
				*c.Verdict = code
			} else if code != "" {
				return code
			}
		}
		return commit(bounded)
	})
}

// Notifications close idle connections on uncertainty as well as retirement.
// Polls always use a new verified window; cached rows never authorize releases.
func (g *journalGeneration) Watch(uid uint32, token string) (<-chan struct{}, func()) {
	changed := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer close(changed)
		timer := time.NewTicker(100 * time.Millisecond)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				poll, stop := context.WithTimeout(ctx, gj.ReaderHold)
				v, c := g.Lookup(poll, uid)
				stop()
				if c != "" || v.Generation != token {
					return
				}
			}
		}
	}()
	return changed, cancel
}
