package keymaker

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/relux-works/swarma-keymaker/messageauthor"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func maLiveExpected(t *testing.T, s *Store) j7Expectation {
	t.Helper()
	d, e := s.contentDigest(s.version)
	if e != nil {
		t.Fatal(e)
	}
	return j7Expectation{s.version, d}
}
func (f *maLiveFixture) restart(t *testing.T) Code {
	t.Helper()
	expected := maLiveExpected(t, f.h.store)
	f.h.store.Close()
	s, c := openMALive(f.dir, uint32(os.Getuid()), fixtureAuditClock{}, expected)
	if c == "" {
		f.h.store = s
		t.Cleanup(func() { s.Close() })
	}
	return c
}
func maLiveIntent(f *maLiveFixture) maLiveAttempt {
	r := f.request()
	return maLiveAttempt{Caller: Principal{f.b.UID, f.b.Generation}, ID: r.ID, Method: string(r.Method), Preimage: r.Preimage, Binding: f.b, Instance: f.h.store.maLive.Instance, Key: f.v.Key, Attestation: f.v.T, Status: "intent"}
}

// Each durable table-7.3 state is opened from actual paired files. Recovery has
// no key dependency and the test counter cannot increase during the open.
func TestMALiveCrashStatusMatrix(t *testing.T) {
	for _, status := range []string{"absent", "intent", "invoking", "result", "handoff_unknown", "released", "dead", "result-unproven", "partial", "missing", "wrong-head"} {
		t.Run(status, func(t *testing.T) {
			f := newMALiveFixture(t)
			s := f.h.store
			switch status {
			case "absent":
			case "intent", "invoking", "dead":
				a := maLiveIntent(f)
				a.Status = status
				s.maLive.Attempts = append(s.maLive.Attempts, a)
				if c := s.persistMALive(t.Context(), 0); c != "" {
					t.Fatal(c)
				}
			case "partial", "missing", "wrong-head":
				f.control(t)
			default:
				f.control(t)
				a := &s.maLive.Attempts[0]
				a.Status = status
				if status == "result-unproven" {
					a.Status = "result"
					a.SuccessHash = strings.Repeat("0", 64)
				}
				if c := s.persistMALive(t.Context(), 0); c != "" {
					t.Fatal(c)
				}
			}
			before := f.calls.Load()
			if status == "partial" || status == "missing" || status == "wrong-head" {
				expected := maLiveExpected(t, s)
				s.Close()
				path := filepath.Join(f.dir.Name(), "bindings.json")
				if status == "partial" {
					if e := os.WriteFile(path, []byte(`{"message_author":`), 0600); e != nil {
						t.Fatal(e)
					}
				}
				if status == "missing" {
					if e := os.Remove(path); e != nil {
						t.Fatal(e)
					}
				}
				if status == "wrong-head" {
					expected.Digest = strings.Repeat("0", 64)
				}
				got, c := openMALive(f.dir, uint32(os.Getuid()), fixtureAuditClock{}, expected)
				if c != "message_author_unqualified" || got != nil || f.calls.Load() != before {
					t.Fatal("unknown evidence inferred absence/completion", c)
				}
				t.Logf("fenced admission invocation_count=%d", before)
				newMALiveFixture(t).control(t)
				return
			}
			if c := f.restart(t); c != "" {
				t.Fatal("restart", c)
			}
			if f.calls.Load() != before {
				t.Fatal("recovery invoked crypto")
			}
			if status == "absent" {
				if len(f.h.store.maLive.Attempts) != 0 {
					t.Fatal("absence synthesized attempt")
				}
				f.control(t)
				return
			}
			a := f.h.store.maLive.Attempts[0]
			want := status
			if status == "invoking" {
				want = "dead"
			}
			if status == "result-unproven" {
				want = "result"
			}
			if a.Status != want {
				t.Fatal("recovery row", a.Status, want)
			}
			if status == "result-unproven" {
				if !f.h.store.maLive.Fenced {
					t.Fatal("unproven audit admitted result")
				}
				f.refusal(t, f.request(), "message_author_unqualified", before)
			} else if want == "dead" {
				f.refusal(t, f.request(), "message_author_unqualified", before)
			} else if want == "intent" {
				f.control(t)
			} else {
				old := append([]byte(nil), a.Signature...)
				out, c := f.call(t.Context(), f.request())
				if c != "" || out.Signature == nil || !bytes.Equal(old, out.Signature.Signature) || f.calls.Load() != before {
					t.Fatal("recovery changed/re-signed result", c)
				}
			}
			t.Logf("recovered %s invocation_count=%d", want, f.calls.Load())
			if want == "dead" || status == "result-unproven" {
				newMALiveFixture(t).control(t)
			}
		})
	}
}

type maLiveFaultWriter struct {
	durableFile
	writeFault, syncFault bool
}

func (w maLiveFaultWriter) Write(p []byte) (int, error) {
	if w.writeFault {
		return 0, errors.New("fixture append fault")
	}
	return w.durableFile.Write(p)
}
func (w maLiveFaultWriter) Sync() error {
	if w.syncFault {
		return errors.New("fixture sync fault")
	}
	return w.durableFile.Sync()
}

// A known journal failure closes authority before a callback and retains the
// invocation evidence. A healthy, independent store is the positive control.
func TestMALiveKnownAuditFailure(t *testing.T) {
	for _, at := range []string{"admission-append", "success-sync", "release-sync"} {
		t.Run(at, func(t *testing.T) {
			f := newMALiveFixture(t)
			j := f.h.store.journal
			if at == "admission-append" {
				j.writer = maLiveFaultWriter{durableFile: j.writer, writeFault: true}
			}
			if at == "success-sync" {
				original := f.h.invoke
				f.h.invoke = func(s *Store, b Binding, p *messageAuthorPlan, before func() Code) ([]byte, Code) {
					sig, c := original(s, b, p, before)
					j.writer = maLiveFaultWriter{durableFile: j.writer, syncFault: true}
					return sig, c
				}
			}
			if at == "release-sync" {
				f.source.before = func(n int) {
					if n == 2 {
						j.writer = maLiveFaultWriter{durableFile: j.writer, syncFault: true}
					}
				}
			}
			wantCount := int32(1)
			if at == "admission-append" {
				wantCount = 0
			}
			f.refusal(t, f.request(), "audit_unavailable", wantCount)
			if !j.failed || !f.h.store.failed || !f.h.store.maLive.Fenced {
				t.Fatal("known journal failure left admission open")
			}
			f.refusal(t, f.request(), "audit_unavailable", wantCount)
			newMALiveFixture(t).control(t)
		})
	}
}

// A corrupt post-crypto result is terminal even if the outer snapshot verifier
// would also reject it. Skipping the primitive's self-verification changes the
// asserted status, so that fallback cannot hide the narrowing plant.
func TestMALiveSelfVerifyFailure(t *testing.T) {
	// Probe the actual primitive before the independent snapshot verifier can
	// reject the same corrupt bytes and hide a missing self-verification gate.
	t.Run("primitive", func(t *testing.T) {
		g := newMALiveFixture(t)
		primitiveCalls := 0
		g.h.key.beforeVerify = func(s []byte) { primitiveCalls++; s[0] ^= 1 }
		p, c := prepareMessageAuthor(g.request().Preimage, g.source.tuple.Key, g.source.tuple.T)
		if c != "" {
			t.Fatal(c)
		}
		sig, c := g.h.key.signSelected(g.h.store, g.b, p)
		if c != "custody_unavailable" || len(sig) != 0 || primitiveCalls != 1 {
			t.Fatal("primitive released corrupt signature", c)
		}
		t.Logf("direct primitive invocation_count=%d; retained/public bytes=0", primitiveCalls)
		g.h.key.beforeVerify = nil
		g.control(t)
	})
	f := newMALiveFixture(t)
	f.h.key.beforeVerify = func(s []byte) { s[0] ^= 1 }
	f.refusal(t, f.request(), "message_author_unqualified", 1)
	a := f.h.store.maLive.Attempts[0]
	if a.Status != "dead" || len(a.Signature) != 0 || a.SuccessSeq != 0 {
		t.Fatal("self-verify failure did not retain dead unsigned outcome")
	}
	f.h.key.beforeVerify = nil
	f.refusal(t, f.request(), "message_author_unqualified", 1)
	newMALiveFixture(t).control(t)
}

// RESOLVE demands the exact protected head, paired continuity and supporting
// audit. A healthy source or a readable signature alone never clears a fence.
func TestMALiveUnknownAuditNeedsResolve(t *testing.T) {
	f := newMALiveFixture(t)
	f.control(t)
	s := f.h.store
	s.maLive.Fenced = true
	if c := s.persistMALive(t.Context(), 0); c != "" {
		t.Fatal(c)
	}
	expected := maLiveExpected(t, s)
	f.refusal(t, f.request(), "message_author_unqualified", 1)
	wrong := expected
	wrong.Version++
	if c := s.reconcileMALive(t.Context(), fixtureOperator, wrong); c != "message_author_unqualified" || !s.maLive.Fenced {
		t.Fatal("single source/readback cleared uncertainty", c)
	}
	a := &s.maLive.Attempts[0]
	original := a.SuccessHash
	a.SuccessHash = strings.Repeat("0", 64)
	// Even a self-consistent snapshot/head does not prove the missing sign audit.
	if c := s.persistMALive(t.Context(), 0); c != "" {
		t.Fatal(c)
	}
	if c := s.reconcileMALive(t.Context(), fixtureOperator, maLiveExpected(t, s)); c != "message_author_unqualified" || !s.maLive.Fenced {
		t.Fatal("unproven result resolved", c)
	}
	a.SuccessHash = original
	if c := s.persistMALive(t.Context(), 0); c != "" {
		t.Fatal(c)
	}
	if c := s.reconcileMALive(t.Context(), fixtureOperator, maLiveExpected(t, s)); c != "" || s.maLive.Fenced {
		t.Fatal("audited exact proof refused", c)
	}
	f.control(t)
	raw, e := os.ReadFile(filepath.Join(f.dir.Name(), "audit", s.journal.file.Name()))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(raw, []byte(`"operation":"message_author_reconcile"`)) {
		t.Fatal("resolution not audited")
	}
}

// Diagnostics may expose only fixed capability placeholders and the complete-P
// digest. All material stays in the protected state, never in journal fields.
func TestMALiveNoMaterialInDiagnostics(t *testing.T) {
	f := newMALiveFixture(t)
	out := f.control(t)
	if got := fmt.Sprintf("%+v", f.h.key); got != "[message-author custody]" {
		t.Fatal("capability formatting exposed material")
	}
	if raw, e := f.h.key.MarshalJSON(); e == nil || raw != nil {
		t.Fatal("capability serialized")
	}
	if raw, e := f.h.key.MarshalText(); e == nil || raw != nil {
		t.Fatal("capability serialized as text")
	}
	raw, e := os.ReadFile(filepath.Join(f.dir.Name(), "audit", f.h.store.journal.file.Name()))
	if e != nil {
		t.Fatal(e)
	}
	for _, blob := range [][]byte{f.preimage, []byte(f.v.Preimage), []byte(f.v.Attestation), out.Signature.Signature, []byte(f.v.Signature)} {
		if len(blob) > 0 && bytes.Contains(raw, blob) {
			t.Fatal("material in audit")
		}
	}
	if !bytes.Contains(raw, []byte(maLiveHash(f.preimage))) {
		t.Fatal("complete-P digest missing")
	}
}

// The closed operation/domain contract is checked before touching the writer;
// every allowed operation has its exact positive shape beside wrong domains.
func TestMALiveAuditOperations(t *testing.T) {
	for _, op := range []string{"message_author_identity", "sign_message_author", "message_author_init", "message_author_enroll", "message_author_retire", "message_author_release", "message_author_fence", "message_author_reconcile"} {
		t.Run(op, func(t *testing.T) {
			f := newMALiveFixture(t)
			s := f.h.store
			var digest *string
			if op == "sign_message_author" {
				v := maLiveHash(f.preimage)
				digest = &v
			}
			if c := s.maLiveAudit(t.Context(), Principal{f.b.UID, f.b.Generation}, f.request().ID, op, digest); c != "" {
				t.Fatal(c)
			}
			before := s.journal.seq
			domain := "wrong"
			id := f.request().ID
			r := AuditRecord{Operation: op, Domain: &domain, Surface: "control", Result: "success", PayloadDigest: digest, RequestID: &id, PeerUID: &f.b.UID, Generation: &f.b.Generation}
			if c := s.journal.Append(r); c != "audit_unavailable" || s.journal.seq != before || s.journal.failed {
				t.Fatal("wrong domain touched journal", c)
			}
			domain = "control"
			if op == "sign_message_author" {
				domain = "swarma-msg"
			}
			leak := "forbidden raw input"
			r.Domain = &domain
			r.Path = &leak
			if c := s.journal.Append(r); c != "audit_unavailable" || s.journal.seq != before {
				t.Fatal("raw material written", c)
			}
			f.control(t)
		})
	}
}

// A different connection can append hello/refusal audit after sign sync. Only
// the exact sign receipt proves this result, including after physical restart.
func TestMALiveAuditReceiptAssociation(t *testing.T) {
	f := newMALiveFixture(t)
	f.h.store.messageFault = func(point string) Code {
		if point == "ma-success-audit" {
			d := "control"
			id := strings.Repeat("e", 32)
			if c := f.h.store.journal.AppendContext(t.Context(), AuditRecord{Surface: "control", Operation: "hello", Domain: &d, RequestID: &id, Result: "success"}); c != "" {
				t.Fatal(c)
			}
		}
		return ""
	}
	f.control(t)
	f.h.store.messageFault = nil
	if !f.h.store.maLiveResultProven(f.h.store.maLive.Attempts[0]) {
		t.Fatal("unrelated audit head substituted for sign receipt")
	}
	if c := f.restart(t); c != "" {
		t.Fatal("exact audit receipt restart", c)
	}
	f.control(t)
}

// Time can become untrusted after the qualified-current sample but before the
// audit samples its own clock. This is a per-request clock refusal, not a known
// writer failure or uncertainty fence, including a retained release attempt.
func TestMALiveAuditTimeRefusal(t *testing.T) {
	for _, at := range []string{"identity", "after-invocation", "release"} {
		t.Run(at, func(t *testing.T) {
			f := newMALiveFixture(t)
			j := f.h.store.journal
			r := f.request()
			count := int32(0)
			switch at {
			case "identity":
				r.Method = messageauthor.IdentityMethod
				r.Preimage = nil
				j.clock = uncertainAuditClock{}
			case "after-invocation":
				count = 1
				original := f.h.invoke
				f.h.invoke = func(s *Store, b Binding, p *messageAuthorPlan, before func() Code) ([]byte, Code) {
					sig, c := original(s, b, p, before)
					j.clock = uncertainAuditClock{}
					return sig, c
				}
			case "release":
				count = 1
				f.source.before = func(n int) {
					if n == 2 {
						j.clock = uncertainAuditClock{}
					}
				}
			}
			f.refusal(t, r, "clock_untrusted", count)
			if j.failed || f.h.store.failed || f.h.store.maLive.Fenced {
				t.Fatal("temporary audit time latched failure/fence")
			}
			j.clock = fixtureAuditClock{}
			f.source.before = nil
			if at == "after-invocation" {
				if c := f.restart(t); c != "" {
					t.Fatal(c)
				}
				f.refusal(t, r, "message_author_unqualified", 1)
				newMALiveFixture(t).control(t)
			} else {
				f.control(t)
			}
		})
	}
}
