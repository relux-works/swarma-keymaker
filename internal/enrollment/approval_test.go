//go:build linux

package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/registry"
)

type fixedApprovalSource struct {
	instant approvalInstant
	err     error
}

func (s *fixedApprovalSource) sample() (approvalInstant, error) { return s.instant, s.err }
func approvalTestClock(f *fixture) *fixedApprovalSource {
	s := &fixedApprovalSource{instant: approvalInstant{bootID: "test-boot", utc: testNow.UnixNano(), boot: int64(time.Hour), trusted: true, authorityUntil: testNow.Add(time.Hour)}}
	f.files.approvalClock = s
	return s
}
func readCommandApproval(t *testing.T, f *fixture) commandApproval {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(f.config.StateDir, approvalName))
	if e != nil {
		t.Fatal(e)
	}
	var a commandApproval
	if e = strictJSON(b, &a); e != nil {
		t.Fatal(e)
	}
	return a
}
func removeTestApproval(t *testing.T, f *fixture) {
	t.Helper()
	if e := os.Remove(filepath.Join(f.config.StateDir, approvalName)); e != nil && !errors.Is(e, os.ErrNotExist) {
		t.Fatal(e)
	}
}
func approvalModeFixture(t *testing.T, bootstrap bool) (*fixture, *registry.HighWater, string) {
	t.Helper()
	if bootstrap {
		f := cleanBootstrapFixture(t)
		r := bootstrapPreview(t, f)
		return f, nil, r.StateSHA256
	}
	f, h := reconciliationFixture(t)
	return f, h, StateDigest(h)
}
func approveMode(t *testing.T, f *fixture, digest string, bootstrap bool) {
	t.Helper()
	if e := reconcileCommandMode(context.Background(), f.configPath, digest, nil, io.Discard, io.Discard, f.files, diskOps{}, bootstrap); e != nil {
		t.Fatal(e)
	}
}
func freshApprovalControl(t *testing.T, f *fixture) {
	t.Helper()
	removeTestApproval(t, f)
	h, e := newFileStore(context.Background(), f.config.StateDir, f.files, f.config.ObjectFormat).read()
	if e != nil {
		t.Fatal(e)
	}
	expectCommandApproval(t, f, h)
	startApproved(t, f).Close()
}

// Restoring consumed receipt bytes, including restoration of its approved state
// digest, never supplies a second startup. A new confirmation on the SAME state
// succeeds and uses a different random ID. Actual ledger/inode I/O is exercised.
func TestReconcileApprovalReplayAfterConsumption(t *testing.T) {
	for _, kind := range []string{"restored-receipt", "rollback-to-approved-digest", "already-recorded-id"} {
		t.Run(kind, func(t *testing.T) {
			f, h := reconciliationFixture(t)
			expectCommandApproval(t, f, h)
			receiptPath := filepath.Join(f.config.StateDir, approvalName)
			saved, e := os.ReadFile(receiptPath)
			if e != nil {
				t.Fatal(e)
			}
			old := readCommandApproval(t, f)
			statePath := filepath.Join(f.config.StateDir, "high-water.json")
			state, e := os.ReadFile(statePath)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "already-recorded-id" {
				if e = consumeApproval(context.Background(), f.config, f.files, old, diskOps{}); e != nil {
					t.Fatal(e)
				}
			} else {
				startApproved(t, f).Close()
				if e = os.WriteFile(receiptPath, saved, 0644); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "rollback-to-approved-digest" {
				changed := h.Clone()
				changed.NameOwners["later_local_evidence"] = "sample"
				b, e := json.Marshal(stateRecord{1, changed})
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(statePath, b, 0600); e != nil {
					t.Fatal(e)
				}
				assertBootstrapFenced(t, f)
				if e = os.WriteFile(statePath, state, 0600); e != nil {
					t.Fatal(e)
				}
			}
			before := reconciliationImage(t, f)
			assertBootstrapFenced(t, f)
			if kind == "rollback-to-approved-digest" {
				// The earlier mismatched-state attempt already invalidated it.
				assertUnchanged(t, f, before)
			} else {
				assertReceiptInvalidated(t, f, before)
			}
			if e = os.Remove(filepath.Join(f.config.StateDir, consumingName)); e != nil {
				t.Fatal(e)
			}
			assertBootstrapFenced(t, f)
			expectCommandApproval(t, f, h)
			if next := readCommandApproval(t, f); next.ID == old.ID || next.LedgerID != old.LedgerID {
				t.Fatal("fresh confirmation reused ID or reset ledger")
			}
			startApproved(t, f).Close()
		})
	}
}

// Both command modes bind boot identity and trusted UTC/boot time. Every stale
// or untrustworthy startup invalidates consent, then explicit recovery and fresh
// confirmation on that same state succeeds. The one-nanosecond TTL boundary
// has a valid adjacent control; these are injected clocks, not host clock edits.
func TestReconcileApprovalBootAndTime(t *testing.T) {
	for _, bootstrap := range []bool{false, true} {
		mode := "reconcile"
		if bootstrap {
			mode = "bootstrap"
		}
		t.Run(mode, func(t *testing.T) {
			for _, kind := range []string{"different-boot", "expired", "boot-expired", "untrusted", "rolled-back", "boot-rolled-back", "unreadable-boot", "clock-discontinuity"} {
				t.Run(kind, func(t *testing.T) {
					f, _, digest := approvalModeFixture(t, bootstrap)
					clock := approvalTestClock(f)
					original := clock.instant
					approveMode(t, f, digest, bootstrap)
					switch kind {
					case "different-boot":
						clock.instant.bootID = "another-boot"
					case "expired":
						clock.instant.utc += int64(approvalTTL)
						clock.instant.boot += int64(approvalTTL)
					case "boot-expired":
						clock.instant.boot += int64(approvalTTL)
						clock.instant.utc += int64(approvalTTL - time.Second)
					case "untrusted":
						clock.instant.trusted = false
					case "rolled-back":
						clock.instant.utc--
					case "boot-rolled-back":
						clock.instant.boot--
					case "unreadable-boot":
						clock.err = errors.New("boot_id_unavailable: fixture read denial")
					case "clock-discontinuity":
						clock.instant.boot += int64(time.Minute)
						clock.instant.utc += int64(time.Minute - 3*time.Second)
					}
					before := reconciliationImage(t, f)
					assertBootstrapFenced(t, f)
					assertReceiptInvalidated(t, f, before)
					clock.err = nil
					clock.instant = original
					repairConsumptionAndConfirm(t, f)
				})
			}
			t.Run("just-inside-ttl", func(t *testing.T) {
				f, _, digest := approvalModeFixture(t, bootstrap)
				clock := approvalTestClock(f)
				approveMode(t, f, digest, bootstrap)
				clock.instant.utc += int64(approvalTTL) - 1
				clock.instant.boot += int64(approvalTTL) - 1
				startApproved(t, f).Close()
			})
		})
	}
}

// An unavailable/untrusted time source at confirmation publishes nothing in
// either mode. A freshly trusted confirmation on the identical fixture admits.
func TestReconcileApprovalConfirmationClock(t *testing.T) {
	for _, bootstrap := range []bool{false, true} {
		for _, kind := range []string{"untrusted", "unreadable-boot", "empty-boot"} {
			t.Run(stringMode(bootstrap)+"/"+kind, func(t *testing.T) {
				f, _, digest := approvalModeFixture(t, bootstrap)
				clock := approvalTestClock(f)
				original := clock.instant
				switch kind {
				case "untrusted":
					clock.instant.trusted = false
				case "unreadable-boot":
					clock.err = errors.New("boot_id_unavailable")
				case "empty-boot":
					clock.instant.bootID = ""
				}
				before := reconciliationImage(t, f)
				e := reconcileCommandMode(context.Background(), f.configPath, digest, nil, io.Discard, io.Discard, f.files, diskOps{}, bootstrap)
				if e == nil {
					t.Fatal("untrusted confirmation accepted")
				}
				assertUnchanged(t, f, before)
				assertBootstrapFenced(t, f)
				clock.err = nil
				clock.instant = original
				approveMode(t, f, digest, bootstrap)
				startApproved(t, f).Close()
			})
		}
	}
}
func stringMode(bootstrap bool) string {
	if bootstrap {
		return "bootstrap"
	}
	return "reconcile"
}

type crashApprovalOps struct{ diskOps }

func (o crashApprovalOps) Close(f *os.File) error {
	e := o.diskOps.Close(f)
	if e == nil && filepath.Base(f.Name()) == consumedName && os.Getenv("APPROVAL_CRASH_STAGE") == "ledger-close" {
		os.Exit(73)
	}
	return e
}

func (o crashApprovalOps) SyncDir(path string) error {
	if os.Getenv("APPROVAL_CRASH_STAGE") == "receipt-directory-sync" {
		if _, err := os.Lstat(filepath.Join(path, testConsumingName)); errors.Is(err, os.ErrNotExist) {
			os.Exit(73)
		}
	}
	return o.diskOps.SyncDir(path)
}

// The child exits after append+file-fsync+close but before receipt removal or
// authority grant. Even a still-present/restored receipt then refuses; a fresh
// confirmation succeeds. This models process death, not physical power loss.
func TestReconcileApprovalConsumptionCrash(t *testing.T) {
	if os.Getenv("APPROVAL_CONSUME_CHILD") == "1" {
		base, path, state := os.Getenv("APPROVAL_BASE"), os.Getenv("APPROVAL_CONFIG"), os.Getenv("APPROVAL_STATE")
		files := fixtureFiles{base: base, override: map[string]Metadata{state: {Mode: os.ModeDir | 0700, UID: uint32(os.Geteuid())}}}
		r := &commandReconciler{configPath: path, files: files, consumeOps: crashApprovalOps{}}
		a := New(path, files, r)
		a.Reload(context.Background())
		t.Fatal("crash boundary not reached")
		return
	}
	for _, stage := range []string{"ledger-close", "receipt-directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			f, h := reconciliationFixture(t)
			expectCommandApproval(t, f, h)
			receipt, e := os.ReadFile(filepath.Join(f.config.StateDir, approvalName))
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReconcileApprovalConsumptionCrash$", "-test.v")
			for _, v := range os.Environ() {
				if !strings.HasPrefix(v, "SSH_AUTH_SOCK=") {
					cmd.Env = append(cmd.Env, v)
				}
			}
			cmd.Env = append(cmd.Env, "APPROVAL_CONSUME_CHILD=1", "APPROVAL_CRASH_STAGE="+stage, "APPROVAL_BASE="+f.base, "APPROVAL_CONFIG="+f.configPath, "APPROVAL_STATE="+f.config.StateDir)
			output, e := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("crash not reached: %v %s", e, output)
			}
			t.Logf("owned crash child pid=%d exit=73", cmd.Process.Pid)
			if e = os.WriteFile(filepath.Join(f.config.StateDir, approvalName), receipt, 0644); e != nil {
				t.Fatal(e)
			}
			assertBootstrapFenced(t, f)
			repairConsumptionAndConfirm(t, f)
		})
	}
}

type stagedCommandWriter struct {
	t            *testing.T
	f            *fixture
	stream       string
	call, failAt int
	summaryFinal int
	events       *[]string
}

func (w *stagedCommandWriter) Write(b []byte) (int, error) {
	w.call++
	*w.events = append(*w.events, w.stream)
	finalCall := w.summaryFinal
	if finalCall == 0 {
		finalCall = 3
	}
	final := (w.stream == "stdout" && w.call == 2) || (w.stream == "summary" && w.call == finalCall)
	if final {
		if _, e := os.Stat(pendingPath(w.f.configPath)); e != nil {
			w.t.Errorf("output escaped durable fence: %s call %d: %v", w.stream, w.call, e)
		}
	}
	if w.call == w.failAt {
		return 0, io.ErrClosedPipe
	}
	return len(b), nil
}

// Preview, prompt, final JSON and final summary failures all report the actual
// I/O error and leave startup fenced in BOTH modes. Final JSON failure prevents
// the summary; final-summary failure follows successful JSON and still fences.
// Each negative fixture is paired with fresh confirmation/all writes succeeding.
func TestReconcileCommandOutputFailures(t *testing.T) {
	for _, bootstrap := range []bool{false, true} {
		for _, stage := range []string{"preview-stdout", "final-stdout", "summary", "prompt", "final-summary", "all-writes", "confirm-final-stdout", "confirm-final-summary", "confirm-all-writes"} {
			t.Run(stringMode(bootstrap)+"/"+stage, func(t *testing.T) {
				f, _, digest := approvalModeFixture(t, bootstrap)
				events := []string{}
				out := &stagedCommandWriter{t: t, f: f, stream: "stdout", events: &events}
				summary := &stagedCommandWriter{t: t, f: f, stream: "summary", events: &events}
				confirm := ""
				var input io.Reader = strings.NewReader(digest + "\n")
				finalSummaryCall := 3
				if strings.HasPrefix(stage, "confirm-") {
					confirm = digest
					input = nil
					summary.summaryFinal = 2
					finalSummaryCall = 2
				}
				switch stage {
				case "preview-stdout":
					out.failAt = 1
				case "final-stdout", "confirm-final-stdout":
					out.failAt = 2
				case "summary":
					summary.failAt = 1
				case "prompt":
					summary.failAt = 2
				case "final-summary", "confirm-final-summary":
					summary.failAt = finalSummaryCall
				}
				e := reconcileCommandMode(context.Background(), f.configPath, confirm, input, out, summary, f.files, diskOps{}, bootstrap)
				if stage == "all-writes" || stage == "confirm-all-writes" {
					if e != nil {
						t.Fatal(e)
					}
					startApproved(t, f).Close()
					return
				}
				if !errors.Is(e, io.ErrClosedPipe) {
					t.Fatalf("output error swallowed or wrong error: %v", e)
				}
				if strings.HasSuffix(stage, "final-stdout") && summary.call != finalSummaryCall-1 {
					t.Fatal("final summary emitted after stdout failure")
				}
				if strings.HasSuffix(stage, "final-summary") && (out.call != 2 || summary.call != finalSummaryCall) {
					t.Fatal("summary failure did not follow successful final stdout")
				}
				assertBootstrapFenced(t, f)
				if strings.Contains(stage, "final-") {
					if _, e = os.Stat(pendingPath(f.configPath)); e != nil {
						t.Fatal("publication fence lost", e)
					}
				}
				control, _, controlDigest := approvalModeFixture(t, bootstrap)
				approveMode(t, control, controlDigest, bootstrap)
				startApproved(t, control).Close()
			})
		}
	}
}

// The record cannot be recreated by startup or silently reset by confirmation.
// Missing, replaced and malformed ledgers refuse before any append and keep
// the receipt invalidated. Repair by this fixture still needs fresh confirmation.
func TestReconcileConsumedLedgerIntegrity(t *testing.T) {
	for _, kind := range []string{"missing", "different-generation", "partial", "duplicate-id", "hardlink", "symlink", "mode", "owner"} {
		t.Run(kind, func(t *testing.T) {
			f, h := reconciliationFixture(t)
			expectCommandApproval(t, f, h)
			path := filepath.Join(f.config.StateDir, consumedName)
			original, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "missing":
				e = os.Remove(path)
			case "different-generation":
				e = os.WriteFile(path, []byte(ledgerPrefix+strings.Repeat("0", 64)+"\n"), 0600)
			case "partial":
				e = os.WriteFile(path, append(original, []byte("partial")...), 0600)
			case "duplicate-id":
				id := strings.Repeat("0", 64) + "\n"
				e = os.WriteFile(path, append(original, []byte(id+id)...), 0600)
			case "hardlink":
				e = os.Link(path, filepath.Join(f.base, "ledger-copy"))
			case "symlink":
				target := filepath.Join(f.base, "ledger-original")
				if e = os.Rename(path, target); e == nil {
					e = os.Symlink(target, path)
				}
			case "mode":
				e = os.Chmod(path, 0666)
			case "owner":
				f.files.override[path] = Metadata{Mode: 0600, UID: *f.config.ServiceUID + 1, Links: 1}
			}
			if e != nil {
				t.Fatal(e)
			}
			before := reconciliationImage(t, f)
			assertBootstrapFenced(t, f)
			assertReceiptInvalidated(t, f, before)
			delete(f.files.override, path)
			if kind == "hardlink" {
				if e = os.Remove(filepath.Join(f.base, "ledger-copy")); e != nil {
					t.Fatal(e)
				}
			}
			if kind == "symlink" {
				if e = os.Remove(path); e != nil {
					t.Fatal(e)
				}
			}
			if e = os.WriteFile(path, original, 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.Chmod(path, 0600); e != nil {
				t.Fatal(e)
			}
			repairConsumptionAndConfirm(t, f)
		})
	}
}

type ledgerFaultOps struct {
	diskOps
	stage   string
	reached bool
}

func (o *ledgerFaultOps) Write(f *os.File, b []byte) (int, error) {
	if filepath.Base(f.Name()) == consumedName {
		switch o.stage {
		case "write":
			o.reached = true
			return 0, io.ErrClosedPipe
		case "partial-write":
			o.reached = true
			n, e := o.diskOps.Write(f, b[:1])
			if e != nil {
				return n, e
			}
			return n, io.ErrClosedPipe
		case "short-write":
			o.reached = true
			return 0, nil
		}
	}
	return o.diskOps.Write(f, b)
}
func (o *ledgerFaultOps) Sync(f *os.File) error {
	if filepath.Base(f.Name()) == consumedName && o.stage == "sync" {
		o.reached = true
		return io.ErrClosedPipe
	}
	return o.diskOps.Sync(f)
}
func (o *ledgerFaultOps) Close(f *os.File) error {
	e := o.diskOps.Close(f)
	if e == nil && filepath.Base(f.Name()) == consumedName && o.stage == "close" {
		o.reached = true
		return io.ErrClosedPipe
	}
	return e
}

func (o *ledgerFaultOps) SyncDir(path string) error {
	if o.stage == "directory-sync" {
		if _, err := os.Stat(filepath.Join(path, consumedName)); err == nil {
			o.reached = true
			return io.ErrClosedPipe
		}
	}
	return o.diskOps.SyncDir(path)
}

// Ledger creation follows the same full-write/fsync/checked-close guarantees as
// Store publication. Each reached fault leaves the root fence in both modes;
// unchanged high-water or bootstrap state never supplies consent by itself.
func TestReconcileConsumedLedgerPublicationFailures(t *testing.T) {
	for _, bootstrap := range []bool{false, true} {
		for _, stage := range []string{"write", "partial-write", "short-write", "sync", "close", "directory-sync"} {
			t.Run(stringMode(bootstrap)+"/"+stage, func(t *testing.T) {
				f, _, digest := approvalModeFixture(t, bootstrap)
				ops := &ledgerFaultOps{stage: stage}
				e := reconcileCommandMode(context.Background(), f.configPath, digest, nil, io.Discard, io.Discard, f.files, ops, bootstrap)
				if e == nil || !ops.reached {
					t.Fatalf("ledger fault not reached/refused: %v", e)
				}
				if stage == "short-write" {
					if !errors.Is(e, io.ErrShortWrite) {
						t.Fatal(e)
					}
				} else if !errors.Is(e, io.ErrClosedPipe) {
					t.Fatal(e)
				}
				if _, e = os.Stat(pendingPath(f.configPath)); e != nil {
					t.Fatal("lost publication fence", e)
				}
				assertBootstrapFenced(t, f)
				control, _, digest := approvalModeFixture(t, bootstrap)
				approveMode(t, control, digest, bootstrap)
				startApproved(t, control).Close()
			})
		}
	}
}

// A failing append, fsync or close cannot grant authority or modify high-water.
// This tests the attempted process, not a claim about physical disk fault repair.
func TestReconcileConsumedLedgerConsumptionFailures(t *testing.T) {
	for _, stage := range []string{"write", "partial-write", "short-write", "sync", "close"} {
		t.Run(stage, func(t *testing.T) {
			f, h := reconciliationFixture(t)
			expectCommandApproval(t, f, h)
			before, e := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
			if e != nil {
				t.Fatal(e)
			}
			ops := &ledgerFaultOps{stage: stage}
			r := &commandReconciler{configPath: f.configPath, files: f.files, consumeOps: ops}
			a := New(f.configPath, f.files, r)
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			key, code := authorize(a)
			expectCode(t, EnrollmentUnverified, code)
			a.Close()
			if !ops.reached || key != (EnrolledKey{}) {
				t.Fatal("fault missed or authority escaped")
			}
			after, e := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
			if e != nil || !bytes.Equal(before, after) {
				t.Fatal("consumption fault changed high-water", e)
			}
			control, h := reconciliationFixture(t)
			expectCommandApproval(t, control, h)
			startApproved(t, control).Close()
		})
	}
}

// The rollback-specific diagnostic is an operator output too: its failure is
// returned without consent, while successful diagnostics report the true refusal.
func TestReconcileRollbackSummaryFailure(t *testing.T) {
	f, h := reconciliationFixture(t)
	entries := f.valid()
	entries[0].Path = "enrollments/alternate.json"
	f.config.Revision = f.commit(entries, "", true)
	f.writeConfig()
	events := []string{}
	summary := &stagedCommandWriter{t: t, f: f, stream: "summary", events: &events, failAt: 2}
	before := reconciliationImage(t, f)
	e := reconcileCommand(context.Background(), f.configPath, StateDigest(h), nil, io.Discard, summary, f.files, diskOps{})
	if !errors.Is(e, io.ErrClosedPipe) || summary.call != 2 {
		t.Fatalf("diagnostic failure not reported: %v", e)
	}
	assertBootstrapFenced(t, f)
	assertUnchanged(t, f, before)
	reports, e := runFixtureReconcile(f, StateDigest(h), nil, diskOps{})
	if e == nil || len(reports) != 1 || !strings.Contains(reports[0].Reason, "registry_rollback") {
		t.Fatal("successful diagnostic lost real refusal", e)
	}
	control, h := reconciliationFixture(t)
	expectCommandApproval(t, control, h)
	startApproved(t, control).Close()
}
