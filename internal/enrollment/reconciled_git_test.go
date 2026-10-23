package enrollment

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A deliberately stalled local Git config include is cut off by the production
// process deadline. This is isolated FIFO data, not a live repository service.
func TestReconciledGitDeadline(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	fifo := filepath.Join(f.base, "stalled-include")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	config := filepath.Join(f.repo, "config")
	b, e := os.ReadFile(config)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(config, append(b, []byte("\n[include]\n\tpath = "+fifo+"\n")...), 0600); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	elapsed := time.Since(start)
	t.Logf("blocked Git cutoff=%s", elapsed)
	if elapsed > 5*time.Second {
		t.Fatal("Git deadline exceeded")
	}
	if e = os.WriteFile(config, b, 0600); e != nil {
		t.Fatal(e)
	}
	expectCode(t, OK, a.Reload(context.Background()))
}

// Missing promised objects cannot trigger a network fetch; restoring the exact
// local object is accepted. This test does not observe network syscalls.
func TestReconciledPromisorNoFetch(t *testing.T) {
	f := newFixture(t)
	entries := f.valid()
	f.config.Revision = f.commit(entries, "", true)
	a := f.authority()
	oid := strings.TrimSpace(string(f.git(entries[0].Bytes, "hash-object", "--stdin")))
	obj := filepath.Join(f.repo, "objects", oid[:2], oid[2:])
	backup := filepath.Join(f.base, "object-backup")
	if e := os.Rename(obj, backup); e != nil {
		t.Fatal(e)
	}
	f.git(nil, "config", "remote.origin.url", "http://127.0.0.1:9/reviewer-registry")
	f.git(nil, "config", "remote.origin.promisor", "true")
	f.git(nil, "config", "extensions.partialClone", "origin")
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	if e := os.Rename(backup, obj); e != nil {
		t.Fatal(e)
	}
	expectCode(t, OK, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, OK, code)
}
