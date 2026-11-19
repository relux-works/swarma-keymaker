package keymaker

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type maLiveCrashPoint struct {
	State string
	Head  j7Expectation
	Calls int32
}
type maLiveCrashSync struct {
	durableFile
	f      *maLiveFixture
	marker string
}

func (w maLiveCrashSync) Sync() error {
	// The audit record has reached Write but not Sync. The parent kills this
	// exact child PID after the fixture has sealed its previous paired head.
	p := maLiveCrashPoint{w.f.dir.Name(), j7Expectation{}, w.f.calls.Load()}
	d, e := w.f.h.store.contentDigest(w.f.h.store.version)
	if e != nil {
		return e
	}
	p.Head = j7Expectation{w.f.h.store.version, d}
	raw, e := json.Marshal(p)
	if e != nil {
		return e
	}
	if e = os.WriteFile(w.marker, raw, 0600); e != nil {
		return e
	}
	select {}
}

// This entry point runs only in the parent-owned test child, never as a service
// or a test without the exact private marker. It uses historical public keys.
func TestMALiveAuditSyncProcess(t *testing.T) {
	marker := os.Getenv("KEYMAKER_MA_AUDIT_SYNC_CHILD")
	if marker == "" {
		return
	}
	root := os.Getenv("GOTMPDIR")
	if root == "" {
		root = os.Getenv("TMPDIR")
	}
	if !filepath.IsAbs(root) || !filepath.IsAbs(marker) || !strings.HasPrefix(marker, filepath.Clean(root)+string(os.PathSeparator)) {
		t.Fatal("child marker outside isolated scratch")
	}
	f := newMALiveFixture(t)
	original := f.h.invoke
	f.h.invoke = func(s *Store, b Binding, p *messageAuthorPlan, before func() Code) ([]byte, Code) {
		sig, c := original(s, b, p, before)
		s.journal.writer = maLiveCrashSync{s.journal.writer, f, marker}
		return sig, c
	}
	f.call(t.Context(), f.request())
	t.Fatal("crash sync point returned")
}

// Kill at the actual write/sync boundary leaves an unpaired sign-audit tail.
// Automatic replay fences; only an audited exact-head proof resolves to dead.
// Recovery never invokes crypto, and no result or absence is inferred.
func TestMALiveKilledAuditSync(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, "point.json")
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "-test.run=^TestMALiveAuditSyncProcess$", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), "TMPDIR="+root, "TMP="+root, "TEMP="+root, "GOTMPDIR="+root, "KEYMAKER_MA_AUDIT_SYNC_CHILD="+marker)
	var log bytes.Buffer
	cmd.Stdout = &log
	cmd.Stderr = &log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	stopped := false
	defer func() {
		if !stopped {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	var point maLiveCrashPoint
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, read := os.ReadFile(marker)
		if read == nil {
			if json.Unmarshal(raw, &point) != nil {
				t.Fatal("child marker incomplete")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not reach audit sync")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if point.Calls != 1 || !strings.HasPrefix(point.State, root+string(os.PathSeparator)) {
		t.Fatal("unexpected child evidence")
	}
	if e = cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	e = cmd.Wait()
	stopped = true
	if e == nil || cmd.ProcessState.ExitCode() != -1 {
		t.Fatal("expected killed child", e)
	}
	t.Logf("owned child pid=%d actual_exit=%d (expected SIGKILL), signing invocation_count=1", cmd.Process.Pid, cmd.ProcessState.ExitCode())
	dir, e := OpenDirectory(point.State, uint32(os.Getuid()), 0700)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	s, c := openMALive(dir, uint32(os.Getuid()), fixtureAuditClock{}, point.Head)
	if c != "" {
		t.Fatal("unknown tail classification", c)
	}
	defer s.Close()
	if !s.maLive.Fenced || len(s.maLive.Attempts) != 1 || len(s.maLive.Attempts[0].Signature) != 0 {
		t.Fatal("unknown audit inferred absence/result")
	}
	if c = s.recoverMALive(t.Context()); c != "" || !s.maLive.Fenced {
		t.Fatal("healthy readback cleared audit uncertainty", c)
	}
	if c = s.reconcileMALive(t.Context(), fixtureOperator, maLiveExpected(t, s)); c != "" || s.maLive.Fenced || s.maLive.Attempts[0].Status != "dead" {
		t.Fatal("operator proof did not resolve possible invocation only to dead", c)
	}
	t.Log("fenced readback and audited dead resolution: recovery invocation_count=0")
	newMALiveFixture(t).control(t)
}
