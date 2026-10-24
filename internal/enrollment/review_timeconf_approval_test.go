//go:build linux

package enrollment

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type reviewConsumptionTimeLoss struct {
	diskOps
	clock        *fixedApprovalSource
	state        string
	removed, hit bool
}

func (o *reviewConsumptionTimeLoss) Remove(path string) error {
	e := o.diskOps.Remove(path)
	if e == nil && path == filepath.Join(o.state, consumingName) {
		o.removed = true
	}
	return e
}
func (o *reviewConsumptionTimeLoss) SyncDir(path string) error {
	e := o.diskOps.SyncDir(path)
	if e == nil && path == o.state && o.removed {
		o.clock.instant.trusted = false
		o.hit = true
	}
	return e
}

// Confidence lost during the last durable consumption operation must not
// authorize startup. The adjacent real-I/O control preserves confidence.
func TestReviewApprovalFinalSyncConfidence(t *testing.T) {
	for _, loss := range []bool{false, true} {
		t.Run(map[bool]string{false: "trusted", true: "lost-after-final-sync"}[loss], func(t *testing.T) {
			f, high := reconciliationFixture(t)
			clock := approvalTestClock(f)
			expectCommandApproval(t, f, high)
			assertConsumed := reviewConsumptionEvidence(t, f)
			var ops durableOps = diskOps{}
			lossOps := &reviewConsumptionTimeLoss{clock: clock, state: f.config.StateDir}
			if loss {
				ops = lossOps
			}
			r := &commandReconciler{configPath: f.configPath, files: f.files, consumeOps: ops}
			e := r.Check(context.Background(), high)
			assertConsumed()
			if loss {
				if !lossOps.hit {
					t.Fatal("injection not reached")
				}
				if e == nil {
					t.Fatal("startup accepted after confidence lost during final directory Sync")
				}
			} else if e != nil {
				t.Fatal("healthy control", e)
			}
		})
	}
}

// The same final-Sync loss must also fence the exported Authority.Reload path.
func TestReviewApprovalFinalSyncReload(t *testing.T) {
	for _, loss := range []bool{false, true} {
		t.Run(map[bool]string{false: "trusted", true: "lost-after-final-sync"}[loss], func(t *testing.T) {
			f, high := reconciliationFixture(t)
			clock := approvalTestClock(f)
			expectCommandApproval(t, f, high)
			assertConsumed := reviewConsumptionEvidence(t, f)
			var ops durableOps = diskOps{}
			lossOps := &reviewConsumptionTimeLoss{clock: clock, state: f.config.StateDir}
			if loss {
				ops = lossOps
			}
			r := &commandReconciler{configPath: f.configPath, files: f.files, consumeOps: ops}
			a := New(f.configPath, f.files, r)
			defer a.Close()
			code := a.Reload(context.Background())
			assertConsumed()
			if loss {
				if !lossOps.hit {
					t.Fatal("injection not reached")
				}
				if code != EnrollmentUnverified {
					t.Fatal("final Sync confidence loss did not fence Authority.Reload", code)
				}
			} else if code != OK {
				t.Fatal("healthy control", code)
			}
		})
	}
}

type reviewApprovalOutputClock struct {
	clock     *fixedApprovalSource
	loss, hit bool
}

func (w *reviewApprovalOutputClock) Write(b []byte) (int, error) {
	if strings.Contains(string(b), `"approved":true`) {
		w.hit = true
		if w.loss {
			w.clock.instant.trusted = false
		}
	}
	return len(b), nil
}

// Report/output I/O occurs after the current time recheck but before removing
// the approval fence; loss there must retain the fence, with a healthy control.
func TestReviewApprovalOutputConfidence(t *testing.T) {
	for _, loss := range []bool{false, true} {
		t.Run(map[bool]string{false: "trusted", true: "lost-during-output"}[loss], func(t *testing.T) {
			f, high := reconciliationFixture(t)
			clock := approvalTestClock(f)
			out := &reviewApprovalOutputClock{clock: clock, loss: loss}
			var summary strings.Builder
			e := reconcileCommand(context.Background(), f.configPath, StateDigest(high), nil, out, &summary, f.files, diskOps{})
			if !out.hit {
				t.Fatal("output injection not reached", e)
			}
			if loss {
				if e == nil || !strings.Contains(e.Error(), "approval_write_failed_fenced") {
					t.Fatal("approval cleared fence after confidence loss during output", e)
				}
				if _, e := os.Stat(pendingPath(f.configPath)); e != nil {
					t.Fatal("failure erased fence", e)
				}
			} else if e != nil {
				t.Fatal("healthy control", e)
			}
		})
	}
}

// After the final consumption Sync, failure must retain the used ID in the
// durable replay ledger, keep high-water bytes unchanged and never resurrect a
// reusable receipt. The same state assertions also cover the healthy neighbor.
func reviewConsumptionEvidence(t *testing.T, f *fixture) func() {
	t.Helper()
	raw, e := os.ReadFile(filepath.Join(f.config.StateDir, approvalName))
	if e != nil {
		t.Fatal(e)
	}
	var a commandApproval
	if e = json.Unmarshal(raw, &a); e != nil {
		t.Fatal(e)
	}
	high, e := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
	if e != nil {
		t.Fatal(e)
	}
	return func() {
		t.Helper()
		raw, e := os.ReadFile(filepath.Join(f.config.StateDir, consumedName))
		if e != nil || !bytes.Contains(raw, []byte("\n"+a.ID+"\n")) {
			t.Fatal("consumed ID not retained", e)
		}
		raw, e = os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
		if e != nil || !bytes.Equal(raw, high) {
			t.Fatal("time verdict changed high-water", e)
		}
		for _, name := range []string{approvalName, consumingName} {
			if _, e = os.Stat(filepath.Join(f.config.StateDir, name)); !os.IsNotExist(e) {
				t.Fatal("consumed receipt reusable", name, e)
			}
		}
	}
}
