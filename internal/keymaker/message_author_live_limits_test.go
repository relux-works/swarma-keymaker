//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keymaker/internal/control"
)

// Fill the byte budget with maximum-size valid dead preimages, far below the
// row cap. An unused binding pads the final few bytes without inventing success
// proofs. Its retirement specifically exercises active -> revoked growth.
func maLiveFillByteBound(t *testing.T, f *maLiveFixture, target int) Binding {
	t.Helper()
	s := f.h.store
	b := f.b
	b.Number, b.UID, b.Path = 2, b.UID+1, "m/1'/1'/2'/4'"
	if c := s.enrollMALive(t.Context(), fixtureOperator, b); c != "" {
		t.Fatal("enroll byte control", c)
	}
	seed := maLiveIntent(f)
	seed.Status = "dead"
	seed.Preimage = maLiveSizedPreimage(t, f, 24576)
	_, size, err := maLiveRowBytes(seed)
	if err != nil {
		t.Fatal(err)
	}
	used := func() int {
		return s.maLiveBodySize(j7SafeInteger, len(s.maLive.Attempts), s.maLiveCache.total) + maLiveReceiptBound
	}
	for used()+size+1 <= target {
		a := seed
		a.ID = fmt.Sprintf("%032x", len(s.maLive.Attempts)+1)
		s.maLive.Attempts = append(s.maLive.Attempts, a)
		// No repeated full inventory validation is needed for fixture accounting.
		s.maLiveCache.total += size
	}
	gap := target - used()
	if gap < 0 || len(s.maLive.Attempts) == 0 || len(s.maLive.Attempts) >= maLiveAttemptLimit {
		t.Fatal("byte fixture bound", gap)
	}
	s.records[1].Owner += strings.Repeat("x", gap)
	if err := s.validateMALive(); err != nil {
		t.Fatal("valid byte fixture", err)
	}
	if used() != target {
		t.Fatal("inexact byte fixture", used(), target)
	}
	if c := s.persistMALive(t.Context()); c != "" {
		t.Fatal("persist byte fixture", c)
	}
	if _, err := loadStoreMessage(f.dir, s.uid, maLiveSchema, false); err != nil {
		t.Fatal("reopened byte control", err)
	}
	t.Logf("byte_bound=%d rows=%d maximum_preimage=24576", target, len(s.maLive.Attempts))
	return s.records[1]
}

// The request must drive the persist byte check, rather than the row check:
// refusal has zero invocations and leaves the durable pair and memory unchanged.
// Removing one retained dead row in this fixture admits a fresh maximum P.
func TestMALiveStateCapBeforeIntent(t *testing.T) {
	f := newMALiveFixture(t)
	s := f.h.store
	ceiling := (maLiveStateLimit-maLiveStateOverhead)/3 - maLiveRetireReserve
	maLiveFillByteBound(t, f, ceiling)
	expected := maLiveExpected(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, c := openMALive(f.dir, s.uid, fixtureAuditClock{}, expected)
	if c != "" {
		t.Fatal("byte-cap paired restart", c)
	}
	t.Cleanup(func() { reopened.Close() })
	f.h.store = reopened
	s = reopened
	before, err := os.ReadFile(filepath.Join(f.dir.Name(), "bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	rows, seq, version := len(s.maLive.Attempts), s.journal.seq, s.version
	f.preimage = maLiveSizedPreimage(t, f, 24576)
	f.refusal(t, f.request(), "state_capacity_exceeded", 0)
	after, err := os.ReadFile(filepath.Join(f.dir.Name(), "bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.maLive.Attempts) != rows || s.journal.seq != seq || s.version != version || s.failed || s.maLive.Fenced || !bytes.Equal(before, after) {
		t.Fatal("byte-cap refusal changed intent/journal/version/fence")
	}
	// Fixture-only relaxation: no production eviction is introduced.
	_, needed, err := maLiveRowBytes(maLiveIntent(f))
	if err != nil {
		t.Fatal(err)
	}
	trim := max(0, needed-s.maLiveCache.reserved[rows-1]) + 1
	s.records[1].Owner = s.records[1].Owner[:len(s.records[1].Owner)-trim]
	s.maLive.Attempts = s.maLive.Attempts[:rows-1]
	if err := s.validateMALive(); err != nil {
		t.Fatal(err)
	}
	if c := s.persistMALive(t.Context()); c != "" {
		t.Fatal(c)
	}
	out, c := f.call(t.Context(), f.request())
	if c != "" || out.Signature == nil || f.calls.Load() != 1 || record.VerifySignature(f.v.Key, out.Signature.Signature, f.preimage) != nil {
		t.Fatal("fresh below-byte-cap control", c)
	}
	replay, c := f.call(t.Context(), f.request())
	if c != "" || replay.Signature == nil || !bytes.Equal(out.Signature.Signature, replay.Signature.Signature) || f.calls.Load() != 1 {
		t.Fatal("byte-cap replay control", c)
	}
}

// The full loader accepts the absolute reserved-byte ceiling and rejects a
// structurally valid serialized overrun; no row-count or corrupt-row gate masks it.
func TestMALiveStateCapLoad(t *testing.T) {
	f := newMALiveFixture(t)
	s := f.h.store
	ceiling := (maLiveStateLimit - maLiveStateOverhead) / 3
	maLiveFillByteBound(t, f, ceiling)
	s.records[1].Owner += strings.Repeat("x", 128)
	raw, err := canonical(s.disk(s.version, bindingCommit{Seq: s.auditSeq, Hash: s.auditHash}))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= ceiling {
		t.Fatal("load negative did not exceed physical encoded ceiling", len(raw), ceiling)
	}
	if err = os.WriteFile(filepath.Join(f.dir.Name(), "bindings.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadStoreMessage(f.dir, s.uid, maLiveSchema, false); err == nil || err.Error() != failure("message-author state capacity").Error() {
		t.Fatal("over-byte-cap state loaded or wrong gate", err)
	}
}

// At the exact fresh-work ceiling a fresh attempt refuses, while retiring an
// unused binding consumes one reserved byte, survives load, and never signs.
func TestMALiveRetireByteCeiling(t *testing.T) {
	f := newMALiveFixture(t)
	s := f.h.store
	b := maLiveFillByteBound(t, f, (maLiveStateLimit-maLiveStateOverhead)/3-maLiveRetireReserve)
	seq, version := s.journal.seq, s.version
	f.refusal(t, f.request(), "state_capacity_exceeded", 0)
	if s.journal.seq != seq || s.version != version {
		t.Fatal("fresh work used retire headroom")
	}
	candidate := b
	candidate.Number = 3
	candidate.UID++
	candidate.Path = "m/1'/1'/2'/5'"
	if c := s.enrollMALive(t.Context(), fixtureOperator, candidate); c != "state_capacity_exceeded" || len(s.records) != 2 || s.journal.seq != seq || s.version != version {
		t.Fatal("enroll consumed retire reserve", c)
	}
	if c := s.retireMALive(t.Context(), fixtureOperator, b.Number); c != "" {
		t.Fatal("retirement refused at ceiling", c)
	}
	disk, err := loadStoreMessage(f.dir, s.uid, maLiveSchema, false)
	if err != nil || disk.records[1].Status != "revoked" || s.failed || s.maLive.Fenced || f.calls.Load() != 0 {
		t.Fatal("retirement lost durable tombstone", err)
	}
}

// Expired and cancelled request contexts cannot strand terminal evidence only
// in memory. Reopening the actual journal/snapshot pair retains dead and cannot
// resurrect a released signature. A separate unchanged holder signs normally.
func TestMALiveExpiredDeadDurable(t *testing.T) {
	for _, mode := range []string{"expired", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newMALiveFixture(t)
			f.control(t)
			s := f.h.store
			var ctx context.Context
			var cancel context.CancelFunc
			if mode == "expired" {
				ctx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			} else {
				ctx, cancel = context.WithCancel(t.Context())
				cancel()
			}
			defer cancel()
			s.mu.Lock()
			c := s.maLiveTerminal(ctx, Principal{f.b.UID, f.b.Generation}, f.request().ID, "message_author_unqualified")
			s.mu.Unlock()
			if c != "message_author_unqualified" {
				t.Fatal("terminal persist retained request cancellation", c)
			}
			expected := maLiveExpected(t, s)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, c := openMALive(f.dir, s.uid, fixtureAuditClock{}, expected)
			if c != "" {
				t.Fatal("dead restart", c)
			}
			defer reopened.Close()
			if reopened.maLive.Attempts[0].Status != "dead" || f.calls.Load() != 1 {
				t.Fatal("terminal dead mark not durable")
			}
			newMALiveFixture(t).control(t)
		})
	}
}

// Generic and native mutation APIs cannot bypass the schema-7 operator/cache
// boundary or invoke a verifier. Only explicit message-author enroll/retire
// changes bindings, and their durable positive controls remain available.
type maLiveRevokeCounter struct{ calls *int }

func (v maLiveRevokeCounter) VerifyEphemeral(context.Context, Binding) Code { (*v.calls)++; return "" }

func TestMALiveGenericMutatorsRefuse(t *testing.T) {
	for _, method := range []string{"register", "revoke", "unbind", "native-register", "native-revoke", "native-sign_registration", "persist"} {
		t.Run(method, func(t *testing.T) {
			f := newMALiveFixture(t)
			s := f.h.store
			before := append([]Binding(nil), s.records...)
			next, seq, version := s.next, s.journal.seq, s.version
			var c Code
			verifierCalls := 0
			switch method {
			case "register":
				_, c = s.Register(fixtureOperator, fixtureOperator, f.b)
			case "revoke":
				c = s.Revoke(t.Context(), fixtureOperator, fixtureOperator, f.b.Number, maLiveRevokeCounter{&verifierCalls})
			case "unbind":
				c = s.Unbind(fixtureOperator, fixtureOperator, f.b.UID, f.b.Generation)
			case "persist":
				c = s.persistContext(t.Context())
			default:
				n := &Native{Engine: &Engine{Store: s, Generations: newGenerations(fixtureOperator.UID, fixtureOperator.Generation)}, Config: NativeConfig{Operator: fixtureOperator}}
				r := control.Request{ID: strings.Repeat("b", 32), Method: strings.TrimPrefix(method, "native-")}
				ctx := context.WithValue(t.Context(), nativeConnectionKey{}, &nativeConnection{requestID: r.ID})
				_, code := n.Handle(ctx, control.Peer{UID: fixtureOperator.UID, Generation: fixtureOperator.Generation}, r)
				c = Code(code)
				expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				_, late := n.Handle(expired, control.Peer{UID: fixtureOperator.UID, Generation: fixtureOperator.Generation}, r)
				cancel()
				if late != control.DeadlineExceeded {
					t.Fatal("native schema guard ignored request deadline", late)
				}
			}
			if c != "operation_unsupported" || verifierCalls != 0 || !reflect.DeepEqual(s.records, before) || s.next != next || s.journal.seq != seq || s.version != version || s.failed || s.maLive.Fenced || len(s.requests) != 0 {
				t.Fatal("generic mutator changed schema-7 state", c)
			}
			b := f.b
			b.Number = 2
			b.UID++
			b.Path = "m/1'/1'/2'/4'"
			if c = s.enrollMALive(t.Context(), fixtureOperator, b); c != "" {
				t.Fatal("operator enroll control", c)
			}
			if c = s.retireMALive(t.Context(), fixtureOperator, b.Number); c != "" {
				t.Fatal("operator retire control", c)
			}
			disk, err := loadStoreMessage(f.dir, s.uid, maLiveSchema, false)
			if err != nil || disk.records[1].Status != "revoked" {
				t.Fatal("operator durable control", err)
			}
			f.control(t)
		})
	}
}

// Identity-loss cause metadata is scoped to the exact control refusal record;
// unrelated codes/domains/operations/results cannot borrow that exception.
func TestMALiveLossAuditCauseScope(t *testing.T) {
	domain := "control"
	code := Code("message_author_unqualified")
	cause := custodyProtectionFailed
	good := AuditRecord{Surface: "control", Operation: "unparsed", Domain: &domain, Result: "refused", RefusalCode: &code, CustodyCause: &cause}
	if !validAuditCustody(good) {
		t.Fatal("identity loss cause control")
	}
	for _, field := range []string{"surface", "domain", "operation", "result", "code", "cause"} {
		r := good
		switch field {
		case "surface":
			r.Surface = "agent"
		case "domain":
			d := "swarma-msg"
			r.Domain = &d
		case "operation":
			r.Operation = "sign"
		case "result":
			r.Result = "success"
		case "code":
			c := Code("clock_untrusted")
			r.RefusalCode = &c
		case "cause":
			c := custodyClosed
			r.CustodyCause = &c
		}
		if validAuditCustody(r) {
			t.Fatal("unrelated refusal borrowed loss cause", field)
		}
	}
}
