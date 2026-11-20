//go:build linux

package keymaker

import (
	"context"
	"crypto/rand"
	"os"
	"sort"
	"strconv"
	"syscall"
)

// initMALive is reachable only from the explicit stopped-operator command.
// It creates no key. Any partial initialization remains evidence and prevents
// a subsequent init from treating the directory as virgin.
func initMALive(ctx context.Context, dir *os.File, uid uint32, clock AuditClock, instance, epoch, registry string) (*Store, Code) {
	if !validJ7Instance(instance) || epoch == "" || registry == "" {
		return nil, "request_malformed"
	}
	s, e := loadStoreMessage(dir, uid, 0, false)
	if e != nil || !s.initialized {
		return nil, "message_author_unqualified"
	}
	s.initialized = false
	s.schema = maLiveSchema
	s.maLive = &maLiveInventory{Format: "keymaker-message-author-state/2", Instance: instance, Epoch: epoch, Registry: registry, Attempts: []maLiveAttempt{}, Issuers: []maIssuerRecord{}}
	if syscall.Mkdirat(int(dir.Fd()), "audit", 0700) != nil || dir.Sync() != nil {
		return nil, "audit_unavailable"
	}
	fd, e := syscall.Openat(int(dir.Fd()), "audit", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, "audit_unavailable"
	}
	audit := os.NewFile(uintptr(fd), "audit")
	j, e := openJournal(audit, uid, clock, rand.Reader)
	if e != nil {
		audit.Close()
		return nil, "audit_unavailable"
	}
	s.journal, s.auditDir = j, audit
	if c := s.maLiveAudit(ctx, Principal{}, "", "message_author_init", nil); c != "" {
		s.Close()
		return nil, c
	}
	if c := s.persistMALive(ctx); c != "" {
		s.Close()
		return nil, c
	}
	return s, ""
}
func openMALive(dir *os.File, uid uint32, clock AuditClock, expected j7Expectation) (*Store, Code) {
	s, _, _, e := openCustodyStateMessage(dir, uid, clock, maLiveSchema, false, expected)
	if e != nil {
		if e == Code("message_author_state_schema_unsupported") {
			return nil, "message_author_state_schema_unsupported"
		}
		return nil, "message_author_unqualified"
	}
	if !s.j7HeadMatches(expected) {
		s.Close()
		return nil, "message_author_unqualified"
	}
	if c := s.recoverMALive(context.Background()); c != "" {
		s.Close()
		return nil, c
	}
	return s, ""
}
func (s *Store) enrollMALive(ctx context.Context, p Principal, b Binding) Code {
	if !s.mu.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	defer s.mu.Unlock()
	if s.maLive == nil || s.failed || s.maLive.Fenced {
		return "message_author_unqualified"
	}
	if b.Epoch != s.maLive.Epoch || b.RegistryRevision != s.maLive.Registry {
		return "binding_conflict"
	}
	if b.Number == 0 || b.Number >= j7SafeInteger || b.Status != "active" {
		return "binding_conflict"
	}
	for _, old := range s.records {
		if old.Number == b.Number || old.Epoch == b.Epoch && old.Path == b.Path || old.Status == "active" && old.UID == b.UID && old.Generation == b.Generation {
			return "binding_conflict"
		}
	}
	records := append(append([]Binding{}, s.records...), b)
	sort.Slice(records, func(i, j int) bool { return records[i].Number < records[j].Number })
	next := records[len(records)-1].Number + 1
	if c := validateBindings(records, next); c != "" {
		return c
	}
	raw, e := canonical(records)
	if e != nil {
		return "message_author_unqualified"
	}
	bound := s.maLiveBodySize(j7SafeInteger, len(s.maLive.Attempts), s.maLiveCache.total) + maLiveReceiptBound +
		len(raw) - len(s.maLiveCache.records) + len(strconv.FormatUint(next, 10)) - len(strconv.FormatUint(s.next, 10))
	if !maLiveStateRoom(bound + maLiveRetireReserve) {
		return "state_capacity_exceeded"
	}
	if c := s.maLiveAudit(ctx, p, "", "message_author_enroll", nil); c != "" {
		return c
	}
	s.records = records
	s.next = next
	if s.maLiveRefreshBindings() != nil {
		return "message_author_unqualified"
	}
	return s.persistMALiveAdmission(context.WithoutCancel(ctx))
}
func (s *Store) retireMALive(ctx context.Context, p Principal, number uint64) Code {
	if !s.mu.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	defer s.mu.Unlock()
	if s.maLive == nil || s.failed || s.maLive.Fenced {
		return "message_author_unqualified"
	}
	for i, b := range s.records {
		if b.Number == number {
			if b.Status != "active" {
				return "identity_revoked"
			}
			if c := s.maLiveAudit(ctx, p, "", "message_author_retire", nil); c != "" {
				return c
			}
			s.records[i].Status = "revoked"
			for n := range s.maLive.Issuers {
				r := &s.maLive.Issuers[n]
				if r.Binding.Number == number {
					if r.Current != nil {
						r.Tombstones = append(r.Tombstones, r.Current.T)
					}
					if r.Pending != nil {
						r.Tombstones = append(r.Tombstones, r.Pending.T)
					}
					r.Current = nil
					r.Pending = nil
					if r.Phase != "fenced" {
						r.Phase = "withdrawn"
					}
					r.CancelSeq = 0
					r.CancelHash = ""
				}
			}
			if s.maLiveRefreshBindings() != nil {
				return "message_author_unqualified"
			}
			var changed []int
			for n := range s.maLive.Attempts {
				a := &s.maLive.Attempts[n]
				if a.Binding.Number == number {
					a.Status = "dead"
					changed = append(changed, n)
				}
			}
			c := s.persistMALive(context.WithoutCancel(ctx), changed...)
			s.notify(number)
			return c
		}
	}
	return "binding_not_found"
}
