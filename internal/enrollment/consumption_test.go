//go:build linux

package enrollment

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

const testConsumingName = "reconciliation.consuming"

type consumptionStepOps struct {
	diskOps
	stage          string
	reached        bool
	crash          bool
	directorySyncs int
}

func (o *consumptionStepOps) hit(stage string) error {
	if o.stage != stage {
		return nil
	}
	o.reached = true
	if o.crash {
		os.Exit(73)
	}
	return syscall.EIO
}
func (o *consumptionStepOps) RenameNoReplace(old, next string) error {
	if e := o.hit("rename"); e != nil {
		return e
	}
	if e := o.diskOps.RenameNoReplace(old, next); e != nil {
		return e
	}
	return o.hit("after-rename")
}
func (o *consumptionStepOps) Write(f *os.File, b []byte) (int, error) {
	if filepath.Base(f.Name()) == consumedName {
		if e := o.hit("ledger-write"); e != nil {
			return 0, e
		}
		if o.stage == "ledger-short-write" {
			o.reached = true
			return 0, nil
		}
		if o.stage == "ledger-partial-write" {
			o.reached = true
			n, e := o.diskOps.Write(f, b[:1])
			if e != nil {
				return n, e
			}
			return n, syscall.EIO
		}
	}
	return o.diskOps.Write(f, b)
}
func (o *consumptionStepOps) Sync(f *os.File) error {
	if filepath.Base(f.Name()) == consumedName {
		if e := o.hit("ledger-sync"); e != nil {
			return e
		}
	}
	return o.diskOps.Sync(f)
}
func (o *consumptionStepOps) Close(f *os.File) error {
	if filepath.Base(f.Name()) == consumedName {
		if e := o.hit("ledger-close"); e != nil {
			return e
		}
	}
	return o.diskOps.Close(f)
}
func (o *consumptionStepOps) Remove(path string) error {
	if e := o.hit("unlink"); e != nil {
		return e
	}
	return os.Remove(path)
}
func (o *consumptionStepOps) SyncDir(path string) error {
	o.directorySyncs++
	stage := "rename-sync"
	if o.directorySyncs > 1 {
		stage = "final-sync"
	}
	if e := o.hit(stage); e != nil {
		return e
	}
	return o.diskOps.SyncDir(path)
}

func attemptConsumption(t *testing.T, f *fixture, ops durableOps) {
	t.Helper()
	a := New(f.configPath, f.files, &commandReconciler{configPath: f.configPath, files: f.files, consumeOps: ops})
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	key, code := authorize(a)
	expectCode(t, EnrollmentUnverified, code)
	if key != (EnrolledKey{}) {
		t.Fatal("failed consumption released key")
	}
	a.Close()
}

// Earlier invalidation is the only permitted mutation on an invalid ledger or
// replay: the entire receipt inode moves, while ledger/high-water/config stay.
func assertReceiptInvalidated(t *testing.T, f *fixture, before map[string]string) {
	t.Helper()
	want := make(map[string]string, len(before))
	for k, v := range before {
		want[k] = v
	}
	receipt, ok := want[approvalName]
	if !ok {
		t.Fatal("no original receipt")
	}
	delete(want, approvalName)
	want[testConsumingName] = receipt
	if got := reconciliationImage(t, f); !reflect.DeepEqual(want, got) {
		t.Fatalf("invalidation changed more than receipt: want=%v got=%v", want, got)
	}
}

// Recovery here is an explicit fixture-only operator action, never service or
// command behavior. Preserve every complete ledger ID, discard only an observed
// interrupted trailing append, then demand a NEW command confirmation and ID.
func repairConsumptionAndConfirm(t *testing.T, f *fixture) {
	t.Helper()
	for _, name := range []string{testConsumingName, approvalName} {
		if e := os.Remove(filepath.Join(f.config.StateDir, name)); e != nil && !errors.Is(e, os.ErrNotExist) {
			t.Fatal(e)
		}
	}
	path := filepath.Join(f.config.StateDir, consumedName)
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		end := bytes.LastIndexByte(b, '\n')
		if end < 0 {
			t.Fatal("no intact ledger header")
		}
		if e = os.WriteFile(path, b[:end+1], 0600); e != nil {
			t.Fatal(e)
		}
	}
	// Cleanup itself is no consent. No startup can succeed before this new command.
	assertBootstrapFenced(t, f)
	freshApprovalControl(t, f)
}

// Each reached post-rename failure must fence the attempted AND later default
// startup without file repair/restoration between them. High-water never changes;
// separate explicit cleanup plus fresh confirmation on the SAME state admits.
func TestApprovalConsumptionFailureRequiresConfirmation(t *testing.T) {
	for _, bootstrap := range []bool{false, true} {
		for _, stage := range []string{"rename-sync", "ledger-write", "ledger-short-write", "ledger-partial-write", "ledger-sync", "ledger-close", "unlink", "final-sync"} {
			t.Run(stringMode(bootstrap)+"/"+stage, func(t *testing.T) {
				f, _, digest := approvalModeFixture(t, bootstrap)
				approveMode(t, f, digest, bootstrap)
				before, e := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
				if e != nil {
					t.Fatal(e)
				}
				ops := &consumptionStepOps{stage: stage}
				attemptConsumption(t, f, ops)
				if !ops.reached {
					t.Fatal("intended consumption boundary not reached")
				}
				assertBootstrapFenced(t, f)
				after, e := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
				if e != nil || !bytes.Equal(before, after) {
					t.Fatal("failure changed high-water", e)
				}
				if _, e = os.Lstat(filepath.Join(f.config.StateDir, approvalName)); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("post-rename error left a valid receipt", e)
				}
				if stage != "final-sync" {
					if _, e = os.Lstat(filepath.Join(f.config.StateDir, testConsumingName)); e != nil {
						t.Fatal("consumption evidence missing", e)
					}
				}
				repairConsumptionAndConfirm(t, f)
			})
		}
	}
}

// A consuming file fences all startup and both command modes even when a valid
// receipt is also present. Commands never erase evidence; explicit operator
// cleanup alone still refuses until fresh confirmation supplies another ID.
func TestApprovalConsumingEvidenceRequiresConfirmation(t *testing.T) {
	for _, bootstrap := range []bool{false, true} {
		for _, receiptPresent := range []bool{false, true} {
			layout := "marker-only"
			if receiptPresent {
				layout = "with-receipt"
			}
			t.Run(stringMode(bootstrap)+"/"+layout, func(t *testing.T) {
				f, _, digest := approvalModeFixture(t, bootstrap)
				approveMode(t, f, digest, bootstrap)
				path := filepath.Join(f.config.StateDir, approvalName)
				receipt, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.Rename(path, filepath.Join(f.config.StateDir, testConsumingName)); e != nil {
					t.Fatal(e)
				}
				if receiptPresent {
					if e = os.WriteFile(path, receipt, 0644); e != nil {
						t.Fatal(e)
					}
				}
				before := reconciliationImage(t, f)
				assertBootstrapFenced(t, f)
				assertUnchanged(t, f, before)
				for _, commandBootstrap := range []bool{false, true} {
					e = reconcileCommandMode(context.Background(), f.configPath, digest, nil, io.Discard, io.Discard, f.files, diskOps{}, commandBootstrap)
					if e == nil {
						t.Fatal("command erased consuming evidence")
					}
					assertUnchanged(t, f, before)
				}
				repairConsumptionAndConfirm(t, f)
			})
		}
	}
}

// The one explicit limit: an atomic rename failure with no filesystem effect is
// indistinguishable from a start that never attempted consumption. Exactly one
// later start may consume that unchanged receipt; a third start cannot reuse it.
func TestApprovalConsumptionRenameFailureLimit(t *testing.T) {
	for _, bootstrap := range []bool{false, true} {
		t.Run(stringMode(bootstrap), func(t *testing.T) {
			f, _, digest := approvalModeFixture(t, bootstrap)
			approveMode(t, f, digest, bootstrap)
			before := reconciliationImage(t, f)
			ops := &consumptionStepOps{stage: "rename"}
			attemptConsumption(t, f, ops)
			if !ops.reached {
				t.Fatal("rename failure not reached")
			}
			assertUnchanged(t, f, before)
			startApproved(t, f).Close()
			assertBootstrapFenced(t, f)
			freshApprovalControl(t, f)
		})
	}
}

// Actual child process death at every operation boundary after invalidation
// never allows an automatic restart. Parent fixtures retain files verbatim until
// the refusal is proved, then explicit recovery/new confirmation is the control.
// These are process crashes; physical power-loss behavior is not qualified.
func TestApprovalConsumptionCrashRequiresConfirmation(t *testing.T) {
	if os.Getenv("CONSUMPTION_STEP_CHILD") == "1" {
		base, path, state := os.Getenv("CONSUMPTION_BASE"), os.Getenv("CONSUMPTION_CONFIG"), os.Getenv("CONSUMPTION_STATE")
		files := fixtureFiles{base: base, override: map[string]Metadata{state: {Mode: os.ModeDir | 0700, UID: uint32(os.Geteuid())}}}
		ops := &consumptionStepOps{stage: os.Getenv("CONSUMPTION_STAGE"), crash: true}
		a := New(path, files, &commandReconciler{configPath: path, files: files, consumeOps: ops})
		a.Reload(context.Background())
		t.Fatal("crash point not reached")
		return
	}
	for _, bootstrap := range []bool{false, true} {
		for _, stage := range []string{"after-rename", "rename-sync", "ledger-write", "ledger-sync", "ledger-close", "unlink", "final-sync"} {
			t.Run(stringMode(bootstrap)+"/"+stage, func(t *testing.T) {
				f, _, digest := approvalModeFixture(t, bootstrap)
				approveMode(t, f, digest, bootstrap)
				before, e := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
				if e != nil {
					t.Fatal(e)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestApprovalConsumptionCrashRequiresConfirmation$", "-test.v")
				cmd.Env = consumptionChildEnv()
				cmd.Env = append(cmd.Env, "CONSUMPTION_STEP_CHILD=1", "CONSUMPTION_STAGE="+stage, "CONSUMPTION_BASE="+f.base, "CONSUMPTION_CONFIG="+f.configPath, "CONSUMPTION_STATE="+f.config.StateDir)
				out, e := cmd.CombinedOutput()
				var exit *exec.ExitError
				if !errors.As(e, &exit) || exit.ExitCode() != 73 {
					t.Fatalf("crash not reached: %v %s", e, out)
				}
				t.Logf("owned crash child pid=%d exit=73 stage=%s", cmd.Process.Pid, stage)
				assertBootstrapFenced(t, f)
				after, e := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
				if e != nil || !bytes.Equal(before, after) {
					t.Fatal("crash changed high-water", e)
				}
				repairConsumptionAndConfirm(t, f)
			})
		}
	}
}
func consumptionChildEnv() []string {
	var env []string
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "SSH_AUTH_SOCK=") {
			env = append(env, v)
		}
	}
	return env
}

type realConsumptionAppendOps struct {
	diskOps
	reached  bool
	writeErr error
}

func (o *realConsumptionAppendOps) Write(f *os.File, b []byte) (int, error) {
	n, e := o.diskOps.Write(f, b)
	if filepath.Base(f.Name()) == consumedName {
		o.reached = true
		o.writeErr = e
	}
	return n, e
}

// Only the owned child changes its RLIMIT_FSIZE. Actual Linux ledger Write
// returns EFBIG without bytes; restoring the limit touches no consent/state file.
// The next startup refuses; cleanup plus NEW confirmation succeeds on same state.
func TestApprovalConsumptionRealAppendFailureRequiresConfirmation(t *testing.T) {
	if os.Getenv("CONSUMPTION_EFBIG_CHILD") == "1" {
		bootstrap := os.Getenv("CONSUMPTION_EFBIG_MODE") == "bootstrap"
		f, _, digest := approvalModeFixture(t, bootstrap)
		approveMode(t, f, digest, bootstrap)
		info, e := os.Stat(filepath.Join(f.config.StateDir, consumedName))
		if e != nil {
			t.Fatal(e)
		}
		var original syscall.Rlimit
		if e = syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); e != nil {
			t.Fatal(e)
		}
		limit := original
		limit.Cur = uint64(info.Size())
		signal.Ignore(syscall.SIGXFSZ)
		if e = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); e != nil {
			t.Fatal(e)
		}
		defer syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original)
		ops := &realConsumptionAppendOps{}
		attemptConsumption(t, f, ops)
		if e = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original); e != nil {
			t.Fatal(e)
		}
		if !ops.reached || !errors.Is(ops.writeErr, syscall.EFBIG) {
			t.Fatalf("real EFBIG not reached: %v", ops.writeErr)
		}
		assertBootstrapFenced(t, f)
		repairConsumptionAndConfirm(t, f)
		return
	}
	for _, mode := range []string{"reconcile", "bootstrap"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestApprovalConsumptionRealAppendFailureRequiresConfirmation$", "-test.v")
			cmd.Env = append(consumptionChildEnv(), "CONSUMPTION_EFBIG_CHILD=1", "CONSUMPTION_EFBIG_MODE="+mode)
			out, e := cmd.CombinedOutput()
			t.Logf("owned EFBIG child pid=%d: %s", cmd.Process.Pid, out)
			if e != nil {
				t.Fatalf("EFBIG regression/control failed: %v", e)
			}
		})
	}
}
