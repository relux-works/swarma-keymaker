package keymaker

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func messageMaintenanceFixture(t *testing.T, f *messageStateFixture) *messageMaintenance {
	t.Helper()
	if f.store != nil {
		if e := f.store.Close(); e != nil {
			t.Fatal(e)
		}
		f.store = nil
	}
	m, e := openMessageMaintenance(f.dir, uint32(os.Getuid()), f.floor, fixtureAuditClock{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func messageExpected(tx messageTransaction, outcome string) messageRecoveryExpectation {
	e := messageRecoveryExpectation{Transaction: tx.ID, BaseDigest: tx.BaseDigest, Outcome: outcome}
	if tx.Candidate != nil {
		e.CandidateDigest = tx.Candidate.Hash
	}
	return e
}

// Exact surviving intents may abort, and journal-committed issued candidates may
// be installed from retained bytes without signing. Both remain unavailable in
// S2; unknown/wrong outcomes, missing bytes and changed expected hashes leave all
// evidence untouched. These fixtures start without T1: S2 cannot activate it.
func TestMsgV27RenewalRestart(t *testing.T) {
	t.Run("no-signing-capability", func(t *testing.T) {
		typ := reflect.TypeFor[messageMaintenance]()
		for n := 0; n < typ.NumField(); n++ {
			if field := typ.Field(n); field.Type == reflect.TypeFor[*messageIssuer]() || field.Type == reflect.TypeFor[*Master]() {
				t.Error("reconciliation gained signing capability", field.Name)
			}
		}
		file, e := parser.ParseFile(token.NewFileSet(), "message_reconcile.go", nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				switch id.Name {
				case "Master", "messageIssuer", "messageCertification", "prepare", "prepareAt", "Sign", "withPurpose":
					t.Error("reconciliation gained signing capability", id.Name)
				}
			}
			return true
		})
	})
	for _, stage := range []string{"intent", "prepared", "issued"} {
		t.Run(stage, func(t *testing.T) {
			f := messageStateSetup(t)
			// Crash immediately after the selected phase's durable journal commit.
			f.store.messageFault = func(point string) Code {
				if point == "after-commit" && f.store.messages.Transactions[0].Phase == stage {
					return "audit_unavailable"
				}
				return ""
			}
			_, code := f.service.issue(t.Context(), f.binding)
			if code != "audit_unavailable" {
				t.Fatal("fault was not reached", code)
			}
			tx := f.store.messages.Transactions[0]
			m := messageMaintenanceFixture(t, f)
			outcome := "abort"
			if stage == "issued" {
				outcome = "commit"
			}
			expected := messageExpected(tx, outcome)
			for _, bad := range []string{"hash", "outcome"} {
				wrong := expected
				if bad == "hash" {
					wrong.BaseDigest = strings.Repeat("f", 64)
				} else if outcome == "abort" {
					wrong.Outcome = "commit"
				} else {
					wrong.Outcome = "abort"
				}
				before := recoveryFiles(t, f.path)
				if code = m.reconcile(t.Context(), wrong); code != "audit_unavailable" {
					t.Fatal("unproved recovery accepted", bad, code)
				}
				if !equalMessageFiles(before, recoveryFiles(t, f.path)) {
					t.Fatal("wrong recovery changed evidence", bad)
				}
			}
			if code = m.reconcile(t.Context(), expected); code != "" {
				t.Fatal("exact recovery control", code)
			}
			a := m.store.messages.Associations[0]
			if a.Current != nil || (outcome == "commit" && (a.Pending == nil || *a.Pending != tx.ID)) || (outcome == "abort" && a.Pending != nil) {
				t.Fatal("recovery changed authority/fence")
			}
			if _, code = m.store.messageCurrent(f.binding); code != "key_not_enrolled" {
				t.Fatal("recovery exposed a certificate", code)
			}
			before := recoveryFiles(t, f.path)
			if code = m.reconcile(t.Context(), expected); code != "" || !equalMessageFiles(before, recoveryFiles(t, f.path)) {
				t.Fatal("resolution retry was not exact/idempotent", code)
			}
			if e := m.Close(); e != nil {
				t.Fatal(e)
			}
			f.reopen(t)
			if a := f.store.messages.Associations[0]; outcome == "commit" && (a.Pending == nil || *a.Pending != tx.ID) {
				t.Fatal("restart cleared uncertain fence")
			}
			if _, code = f.store.messageCurrent(f.binding); code != "key_not_enrolled" {
				t.Fatal("restart cleared uncertain fence", code)
			}
		})
	}
	t.Run("missing-candidate", func(t *testing.T) {
		f := messageStateSetup(t)
		if _, c := f.service.issue(t.Context(), f.binding); c != "" {
			t.Fatal(c)
		}
		tx := f.store.messages.Transactions[0]
		m := messageMaintenanceFixture(t, f)
		path := filepath.Join(f.path, "message-tx", tx.ID, tx.Candidate.Hash)
		original, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.Remove(path); e != nil {
			t.Fatal(e)
		}
		before := recoveryFiles(t, f.path)
		if c := m.reconcile(t.Context(), messageExpected(tx, "commit")); c != "audit_unavailable" {
			t.Fatal("missing bytes regenerated", c)
		}
		if !equalMessageFiles(before, recoveryFiles(t, f.path)) {
			t.Fatal("missing-artifact recovery wrote evidence")
		}
		if e = os.WriteFile(path, original, 0600); e != nil {
			t.Fatal(e)
		}
		if c := m.reconcile(t.Context(), messageExpected(tx, "commit")); c != "" {
			t.Fatal("restored exact bytes control", c)
		}
	})
}

// Interruptions after actual file operations model process loss, not hardware
// persistence guarantees. Uncommitted artifacts stay closed with no destructive
// recovery; exact journal-committed phases recover without new certificates.
func TestMsgCrashMatrix(t *testing.T) {
	for _, phase := range []string{"intent", "prepared", "issued"} {
		for _, point := range []string{"before-commit", "after-commit", "snapshot-write", "snapshot-sync", "snapshot-rename", "snapshot-directory-sync"} {
			t.Run(phase+"/"+point, func(t *testing.T) {
				f := messageStateSetup(t)
				hit := false
				f.store.messageFault = func(p string) Code {
					if p == point && len(f.store.messages.Transactions) > 0 && f.store.messages.Transactions[0].Phase == phase {
						hit = true
						return "audit_unavailable"
					}
					return ""
				}
				_, code := f.service.issue(t.Context(), f.binding)
				if !hit || code != "audit_unavailable" {
					t.Fatal("fault not reached", hit, code)
				}
				tx := f.store.messages.Transactions[0]
				m := messageMaintenanceFixture(t, f)
				expected := messageExpected(tx, "abort")
				if phase == "issued" {
					expected.Outcome = "commit"
				}
				before := recoveryFiles(t, f.path)
				code = m.reconcile(t.Context(), expected)
				if point == "before-commit" {
					if code != "audit_unavailable" || !equalMessageFiles(before, recoveryFiles(t, f.path)) {
						t.Fatal("uncommitted artifact outcome guessed", code)
					}
				} else if code != "" {
					t.Fatal("exact surviving commit did not recover", code)
				}
				if len(m.store.messages.Certificates) > 1 {
					t.Fatal("crash recovery created certificate")
				}
				for _, a := range m.store.messages.Associations {
					if a.Current != nil {
						t.Fatal("crash recovery created authority")
					}
				}
			})
		}
	}
	for _, point := range []string{"artifact-write", "artifact-sync", "artifact-directory-sync", "signed"} {
		t.Run(point, func(t *testing.T) {
			f := messageStateSetup(t)
			hit := false
			f.store.messageFault = func(p string) Code {
				if p == point {
					hit = true
					return "audit_unavailable"
				}
				return ""
			}
			_, code := f.service.issue(t.Context(), f.binding)
			if !hit || code != "audit_unavailable" {
				t.Fatal("artifact fault not reached", code)
			}
			m := messageMaintenanceFixture(t, f)
			before := recoveryFiles(t, f.path)
			expected := messageRecoveryExpectation{Transaction: strings.Repeat("31", 16), BaseDigest: strings.Repeat("f", 64), Outcome: "abort"}
			if point == "signed" {
				expected = messageExpected(m.store.messages.Transactions[0], "abort")
			}
			code = m.reconcile(t.Context(), expected)
			if point == "signed" {
				if code != "" {
					t.Fatal("known intent abort control", code)
				}
			} else if code != "audit_unavailable" || !equalMessageFiles(before, recoveryFiles(t, f.path)) {
				t.Fatal("unknown artifact guessed", code)
			}
		})
	}
}

type messageJournalFault struct {
	file      *os.File
	operation string
	mode      string
	hit       bool
	last      []byte
}

func (w *messageJournalFault) Write(b []byte) (int, error) {
	w.last = append(w.last[:0], b...)
	if bytes.Contains(b, []byte(`"operation":"`+w.operation+`"`)) && w.mode == "partial" {
		w.hit = true
		n, e := w.file.Write(b[:len(b)/2])
		if e != nil {
			return n, e
		}
		return n, errors.New("fixture interrupted append")
	}
	return w.file.Write(b)
}
func (w *messageJournalFault) Sync() error {
	if bytes.Contains(w.last, []byte(`"operation":"`+w.operation+`"`)) {
		w.hit = true
		return errors.New("fixture lost sync acknowledgement")
	}
	return w.file.Sync()
}

// A real partial journal line refuses restart without edits. A complete commit
// whose Sync acknowledgement was lost is recoverable only from its exact body;
// an uncommitted fence event leaves an orphan intent and remains unknown.
func TestMsgJournalUncertainty(t *testing.T) {
	for _, operation := range []string{"message_certification_fence", "binding_commit"} {
		for _, mode := range []string{"partial", "sync"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				f := messageStateSetup(t)
				w := &messageJournalFault{file: f.store.journal.file, operation: operation, mode: mode}
				f.store.journal.writer = w
				_, code := f.service.issue(t.Context(), f.binding)
				if code != "audit_unavailable" || !w.hit {
					t.Fatal("journal fault not reached", code)
				}
				tx := f.store.messages.Transactions[0]
				if e := f.store.Close(); e != nil {
					t.Fatal(e)
				}
				f.store = nil
				before := recoveryFiles(t, f.path)
				m, e := openMessageMaintenance(f.dir, uint32(os.Getuid()), f.floor, fixtureAuditClock{})
				if mode == "partial" {
					if e == nil {
						m.Close()
						t.Fatal("partial journal accepted")
					}
					if !equalMessageFiles(before, recoveryFiles(t, f.path)) {
						t.Fatal("partial journal changed")
					}
					return
				}
				if e != nil {
					t.Fatal(e)
				}
				defer m.Close()
				code = m.reconcile(t.Context(), messageExpected(tx, "abort"))
				if operation == "binding_commit" {
					if code != "" {
						t.Fatal("exact commit recovery", code)
					}
				} else if code != "audit_unavailable" || !equalMessageFiles(before, recoveryFiles(t, f.path)) {
					t.Fatal("fence without body guessed", code)
				}
			})
		}
	}
}

// Real-store barriers serialize two issuers and withdrawal behind an intent.
// One candidate commits; the queued duplicate sees its fence. Cancelled waiters
// add no artifacts, and a withdrawal ordered first cannot be resurrected.
func TestMsgConcurrentCertification(t *testing.T) {
	f := messageStateSetup(t)
	entered, release := make(chan struct{}), make(chan struct{})
	once := false
	f.store.messageFault = func(p string) Code {
		if p == "before-commit" && !once {
			once = true
			close(entered)
			<-release
		}
		return ""
	}
	first := make(chan Code, 1)
	go func() { _, c := f.service.issue(t.Context(), f.binding); first <- c }()
	<-entered
	secondStarted, second := make(chan struct{}), make(chan Code, 1)
	go func() { close(secondStarted); _, c := f.service.issue(t.Context(), f.binding); second <- c }()
	<-secondStarted
	close(release)
	if c := <-first; c != "" {
		t.Fatal("first issuer", c)
	}
	if c := <-second; c != "key_not_enrolled" {
		t.Fatal("concurrent issuer bypassed fence", c)
	}
	if len(f.store.messages.Transactions) != 1 || len(f.store.messages.Certificates) != 1 {
		t.Fatal("duplicate concurrent certification")
	}
	f.reopen(t)
	before := recoveryFiles(t, f.path)
	f.store.mu.Lock()
	ctx, cancel := context.WithCancel(t.Context())
	enteredWait := make(chan struct{})
	f.service.generations = messageGenerationProbe{f.service.generations, enteredWait}
	waiter := make(chan Code, 1)
	go func() { _, c := f.service.issue(ctx, f.binding); waiter <- c }()
	<-enteredWait
	cancel()
	if c := <-waiter; c != "request_deadline_exceeded" {
		t.Fatal("cancelled waiter", c)
	}
	f.store.mu.Unlock()
	if !equalMessageFiles(before, recoveryFiles(t, f.path)) {
		t.Fatal("cancelled issuer wrote artifacts")
	}
	if c := f.store.Unbind(fixtureOperator, fixtureOperator, f.binding.UID, f.binding.Generation); c != "" {
		t.Fatal(c)
	}
	if _, c := f.service.issue(t.Context(), f.binding); c != "binding_not_found" {
		t.Fatal("withdrawn binding resurrected", c)
	}
}

type messageGenerationProbe struct {
	GenerationSource
	entered chan struct{}
}

func (g messageGenerationProbe) WithActive(ctx context.Context, uid uint32, generation string, fn func(context.Context) Code) Code {
	return g.GenerationSource.WithActive(ctx, uid, generation, func(ctx context.Context) Code {
		select {
		case <-g.entered:
		default:
			close(g.entered)
		}
		return fn(ctx)
	})
}

// Production files cannot construct or open the internal issuance/reconciliation
// capabilities. This source boundary complements the existing real native
// operation_unsupported controls; it does not qualify a production evidence feed.
func TestMsgIssuerUnreachable(t *testing.T) {
	entries, e := os.ReadDir(".")
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "message_") {
			continue
		}
		file, e := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if e != nil {
			t.Fatal(e)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				switch id.Name {
				case "messageIssuer", "messageCertification", "openMessageStore", "openMessageMaintenance", "loadMessageSchemaFloor":
					t.Error("production reached certification capability", name, id.Name)
				}
			}
			return true
		})
	}
}

// A surviving full staging write still needs a successful file-sync boundary
// before rename. Refusal there preserves every byte; the healthy retry installs
// the exact committed candidate, retains its fence, and creates no certificate.
func TestMsgRecoveryStagingSync(t *testing.T) {
	f := messageStateSetup(t)
	f.store.messageFault = func(point string) Code {
		if point == "snapshot-write" && f.store.messages.Transactions[0].Phase == "issued" {
			return "audit_unavailable"
		}
		return ""
	}
	if _, c := f.service.issue(t.Context(), f.binding); c != "audit_unavailable" {
		t.Fatal("write interruption not reached", c)
	}
	tx := f.store.messages.Transactions[0]
	m := messageMaintenanceFixture(t, f)
	before := recoveryFiles(t, f.path)
	hit := false
	m.store.messageFault = func(point string) Code {
		if point == "recovery-staging-sync" {
			hit = true
			return "audit_unavailable"
		}
		return ""
	}
	if c := m.reconcile(t.Context(), messageExpected(tx, "commit")); c != "audit_unavailable" || !hit {
		t.Fatal("recovery skipped staging sync boundary", c, hit)
	}
	if !equalMessageFiles(before, recoveryFiles(t, f.path)) {
		t.Fatal("failed staging sync installed snapshot")
	}
	m.store.messageFault = nil
	if c := m.reconcile(t.Context(), messageExpected(tx, "commit")); c != "" {
		t.Fatal("synced staging control", c)
	}
	if len(m.store.messages.Certificates) != 1 || m.store.messages.Associations[0].Pending == nil || m.store.messages.Associations[0].Current != nil {
		t.Fatal("staging recovery changed candidate authority")
	}
}
