//go:build linux && genjournal_testseam

package keymaker

// PENDING: execute only after the format owner's WithEvidence/OpenForTest head
// is supplied and pinned. This is an executable contract, never a skipped test.
// Production builds must not enable this tag (generation_build_test.go).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
	"golang.org/x/sys/unix"
)

func generationFixture(t *testing.T, raw []byte) (string, string) {
	t.Helper()
	anchor := t.TempDir()
	if e := os.Chmod(anchor, 0755); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(anchor, "generations")
	if e := os.Mkdir(dir, 0755); e != nil {
		t.Fatal(e)
	}
	for name, raw := range map[string][]byte{"gate.lock": nil, "data.lock": nil, "journal": raw} {
		if e := os.WriteFile(filepath.Join(dir, name), raw, 0644); e != nil {
			t.Fatal(e)
		}
	}
	return dir, anchor
}
func generationTestJournal(t *testing.T, anchor string) generationWindow {
	t.Helper()
	return gj.OpenForTest(uint32(os.Getuid()), anchor)
}
func generationPending(t *testing.T, mode string) []byte {
	t.Helper()
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		t.Fatal(e)
	}
	var ts unix.Timespec
	if e := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); e != nil {
		t.Fatal(e)
	}
	started := ts.Sec*1000 + ts.Nsec/1000000
	id := strings.TrimSpace(string(boot))
	if mode == "stale" {
		started -= 2000
	}
	if mode == "future-start" {
		started += 10000
	}
	if mode == "other-boot" {
		id = "00000000-0000-0000-0000-000000000000"
	}
	raw, e := ccj.Marshal(map[string]any{"format": "gen-journal-pending/1", "boot_id": id, "budget_ms": int64(1000), "started_ms": started}, ccj.RegistrationMalformed)
	if e != nil {
		t.Fatal(e)
	}
	raw = append(raw, '\n')
	switch mode {
	case "empty":
		return nil
	case "malformed":
		return []byte("invalid marker")
	case "noncanonical":
		return append([]byte(" "), raw...)
	case "bad-budget":
		return bytes.Replace(raw, []byte(`"budget_ms":1000`), []byte(`"budget_ms":999`), 1)
	case "duplicate-field":
		return append(append([]byte{}, raw[:len(raw)-2]...), []byte(",\"budget_ms\":1000}\n")...)
	case "oversized":
		return bytes.Repeat([]byte("x"), 513)
	}
	return raw
}

// Materialize exact capacity boundaries using only public Encode and Digest.
// Valid removed filler incarnations consume bytes; no padding bypasses CCJ.
func generationCapacityBytes(t *testing.T, target int) []byte {
	t.Helper()
	var rows []gj.Record
	total := 0
	add := func(uid int64, gen, state string) {
		r := gj.Record{Seq: int64(len(rows) + 1), Prev: gj.ZeroHash, UID: uid, Generation: gen, State: state, Writer: "user-manager", Time: "2026-01-01T00:00:00Z"}
		b, e := gj.Encode(r)
		if e != nil {
			t.Fatal(e)
		}
		rows = append(rows, r)
		total += len(b)
	}
	add(4294967294, strings.Repeat("f", 32), "creating")
	add(4294967294, strings.Repeat("f", 32), "active")
	for n := 1; ; n++ {
		old, totalBefore := len(rows), total
		add(1, fmt.Sprintf("%032x", n), "creating")
		add(1, fmt.Sprintf("%032x", n), "removed")
		if total > target || target-total == 1 {
			rows = rows[:old]
			total = totalBefore
			break
		}
	}
	gap := target - total
	if gap%2 != 0 {
		rows[2].Writer = "operator-manual"
		gap -= 3
	}
	for i := 2; gap > 0 && i < len(rows); i += 2 {
		digits := gap / 2
		if digits > 9 {
			digits = 9
		}
		uid := int64(1)
		for j := 0; j < digits; j++ {
			uid *= 10
		}
		rows[i].UID = uid
		rows[i+1].UID = uid
		gap -= digits * 2
	}
	if gap != 0 {
		t.Fatal("capacity fixture gap", gap)
	}
	var raw []byte
	prev := gj.ZeroHash
	for _, r := range rows {
		r.Prev = prev
		b, e := gj.Encode(r)
		if e != nil {
			t.Fatal(e)
		}
		raw = append(raw, b...)
		prev = gj.Digest(b)
	}
	if len(raw) != target {
		t.Fatal("capacity fixture size", len(raw), target)
	}
	return raw
}

type generationVectorCase struct {
	Name, File, Expect, Control string
	Floor                       *gj.Floor
	Fixture                     *struct{ Target, Violation string }
}

func materializeGenerationCase(t *testing.T, c generationVectorCase) (string, generationWindow) {
	t.Helper()
	raw := generationBytes(t, "active")
	if c.File != "" {
		var e error
		raw, e = os.ReadFile(filepath.Join("testdata", "gen-journal", c.File))
		if e != nil {
			t.Fatal(e)
		}
	}
	if c.Fixture != nil && c.Fixture.Target == "capacity" {
		size := gj.MaxFile - 529
		switch c.Fixture.Violation {
		case "valid":
		case "deficit":
			size++
		case "full":
			size = gj.MaxFile
		default:
			t.Fatal("unknown capacity fixture")
		}
		raw = generationCapacityBytes(t, size)
	}
	dir, anchor := generationFixture(t, raw)
	window := generationTestJournal(t, anchor)
	if c.Fixture == nil || c.Fixture.Target == "capacity" {
		return dir, window
	}
	target, violation := c.Fixture.Target, c.Fixture.Violation
	path := filepath.Join(dir, target)
	if target == "directory" {
		path = dir
	}
	if target == "ancestor" {
		path = anchor
	}
	switch {
	case target == "writer.pending":
		if e := os.WriteFile(path, generationPending(t, violation), 0644); e != nil {
			t.Fatal(e)
		}
	case violation == "owner":
		// Non-root execution cannot chown individual files. This is an expected-owner
		// mismatch at the protected boundary, not isolated target-inode qualification.
		window = gj.OpenForTest(uint32(os.Getuid())+1, anchor)
	case violation == "mode":
		if e := os.Chmod(path, 0777); e != nil {
			t.Fatal(e)
		}
	case violation == "symlink":
		if target == "ancestor" {
			link := filepath.Join(anchor, "link")
			if e := os.Symlink(dir, link); e != nil {
				t.Fatal(e)
			}
			dir = filepath.Join(link, "child")
		} else {
			if e := os.Rename(path, path+".real"); e != nil {
				t.Fatal(e)
			}
			if e := os.Symlink(path+".real", path); e != nil {
				t.Fatal(e)
			}
		}
	case violation == "missing":
		if e := os.Remove(path); e != nil {
			t.Fatal(e)
		}
	case violation == "hardlink":
		if e := os.Link(path, path+".link"); e != nil {
			t.Fatal(e)
		}
	case violation == "file-size":
		if e := os.Truncate(path, gj.MaxFile+1); e != nil {
			t.Fatal(e)
		}
	default:
		t.Fatal("unknown fixture", target, violation)
	}
	return dir, window
}

// All 67 manifest verdicts pass through the adapter's protected window. Format
// validity is distinct from active admission (creating/removed remain valid
// histories). Ownership rows exercise boundary mismatch, as documented above.
// Source files are never changed by this read-only consumer.
func TestGenerationTaggedVectors(t *testing.T) {
	raw, e := os.ReadFile("testdata/gen-journal/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	var manifest struct{ Cases []generationVectorCase }
	if e = json.Unmarshal(raw, &manifest); e != nil {
		t.Fatal(e)
	}
	if len(manifest.Cases) != 67 {
		t.Fatal("inventory changed")
	}
	for _, c := range manifest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			dir, window := materializeGenerationCase(t, c)
			s, _ := generationStore(t)
			floor := gj.Floor{Hash: gj.ZeroHash}
			if c.Floor != nil {
				floor = *c.Floor
			}
			observed := "not-called"
			spy := generationWindowFunc(func(ctx context.Context, path string, floor gj.Floor, fn func(gj.View, time.Time) error) error {
				err := window.WithEvidence(ctx, path, floor, fn)
				observed = "ok"
				if err != nil {
					var r *gj.Refusal
					if !errors.As(err, &r) {
						t.Fatalf("unexpected window error %v", err)
					}
					observed = r.Code
				}
				return err
			})
			g := newJournalGeneration(spy, s, dir, floor)
			called := false
			code := g.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" })
			if observed != c.Expect {
				t.Fatalf("format verdict=%s want=%s adapter=%s", observed, c.Expect, code)
			}
			expected := Code("")
			if c.Expect != "ok" {
				expected = generationSourceCode(&gj.Refusal{Code: c.Expect})
			}
			if code != expected || called != (c.Expect == "ok") {
				t.Fatal("adapter verdict/effect mismatch", code, expected, called)
			}
		})
	}
}

// Missing protected files and the directory containing marker evidence refuse
// without recreating any source object. Restoring the same fixture is an active
// control; source absence is transient rather than permission to bootstrap it.
func TestGenerationTaggedNoCreate(t *testing.T) {
	for _, target := range []string{"gate.lock", "data.lock", "journal", "directory"} {
		t.Run(target, func(t *testing.T) {
			dir, anchor := generationFixture(t, generationBytes(t, "active"))
			s, _ := generationStore(t)
			g := newJournalGeneration(generationTestJournal(t, anchor), s, dir, gj.Floor{Hash: gj.ZeroHash})
			if c := g.withWindow(context.Background(), func(context.Context, gj.View) Code { return "" }); c != "" {
				t.Fatal(c)
			}
			path := filepath.Join(dir, target)
			if target == "directory" {
				path = dir
			}
			if e := os.Rename(path, path+".saved"); e != nil {
				t.Fatal(e)
			}
			before := recoveryFiles(t, anchor)
			if c := g.withWindow(context.Background(), func(context.Context, gj.View) Code { t.Fatal("missing source admitted"); return "" }); c != "generation_source_unavailable" {
				t.Fatal(c)
			}
			after := recoveryFiles(t, anchor)
			if fmt.Sprint(before) != fmt.Sprint(after) {
				t.Fatal("reader created or altered source")
			}
			if _, e := os.Lstat(path); !os.IsNotExist(e) {
				t.Fatal("missing source recreated", e)
			}
			if e := os.Rename(path+".saved", path); e != nil {
				t.Fatal(e)
			}
			if c := g.withWindow(context.Background(), func(context.Context, gj.View) Code { return "" }); c != "" {
				t.Fatal("restored control", c)
			}
		})
	}
}

func generationLock(t *testing.T, path string, kind int) *os.File {
	t.Helper()
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = syscall.Flock(int(f.Fd()), kind); e != nil {
		f.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() })
	return f
}

// Real inode locks order a reader's release before a competing exclusive writer.
// The writer cannot acquire data until release exits; the pending marker blocks
// later readers. This is a local fixture, not root-owned storage qualification.
func TestGenerationTaggedReleaseWins(t *testing.T) {
	dir, anchor := generationFixture(t, generationBytes(t, "active"))
	s, _ := generationStore(t)
	g := newJournalGeneration(generationTestJournal(t, anchor), s, dir, gj.Floor{Hash: gj.ZeroHash})
	code := g.withWindow(context.Background(), func(context.Context, gj.View) Code {
		if e := os.WriteFile(filepath.Join(dir, "writer.pending"), generationPending(t, "present"), 0644); e != nil {
			t.Fatal(e)
		}
		gate := generationLock(t, filepath.Join(dir, "gate.lock"), syscall.LOCK_EX|syscall.LOCK_NB)
		data, e := os.OpenFile(filepath.Join(dir, "data.lock"), os.O_RDWR, 0)
		if e != nil {
			t.Fatal(e)
		}
		defer data.Close()
		if e = syscall.Flock(int(data.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != syscall.EWOULDBLOCK {
			t.Fatal("writer overtook held reader", e)
		}
		syscall.Flock(int(gate.Fd()), syscall.LOCK_UN)
		return ""
	})
	if code != "" {
		t.Fatal(code)
	}
	generationLock(t, filepath.Join(dir, "data.lock"), syscall.LOCK_EX|syscall.LOCK_NB)
}

// A retirement committed under exclusive data exclusion before the final read
// prevents the prepared old generation's release; active admission is its control.
func TestGenerationTaggedRetirementWins(t *testing.T) {
	raw := generationBytes(t, "active")
	v, e := gj.Verify(bytes.NewReader(raw), gj.Floor{Hash: gj.ZeroHash})
	if e != nil {
		t.Fatal(e)
	}
	r := v.Rows[0]
	dir, anchor := generationFixture(t, raw)
	s, _ := generationStore(t)
	g := newJournalGeneration(generationTestJournal(t, anchor), s, dir, gj.Floor{Hash: gj.ZeroHash})
	if c := g.WithActive(context.Background(), uint32(r.UID), r.Generation, func(context.Context) Code { return "" }); c != "" {
		t.Fatal(c)
	}
	gate := generationLock(t, filepath.Join(dir, "gate.lock"), syscall.LOCK_EX)
	data := generationLock(t, filepath.Join(dir, "data.lock"), syscall.LOCK_EX)
	line, e := gj.Encode(gj.Record{Seq: v.Tail.Seq + 1, Prev: v.Tail.Hash, UID: r.UID, Generation: r.Generation, State: "retiring", Writer: "operator-manual", Time: "2026-01-01T00:00:00Z"})
	if e != nil {
		t.Fatal(e)
	}
	f, e := os.OpenFile(filepath.Join(dir, "journal"), os.O_WRONLY|os.O_APPEND, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.Write(line)
	if e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	syscall.Flock(int(data.Fd()), syscall.LOCK_UN)
	syscall.Flock(int(gate.Fd()), syscall.LOCK_UN)
	if c := g.WithActive(context.Background(), uint32(r.UID), r.Generation, func(context.Context) Code { t.Fatal("retirement released"); return "" }); c != "generation_inactive" {
		t.Fatal(c)
	}
}

// A published writer intent drains real shared data locks despite continuing
// reader attempts. The active loop is a control before intent; readers never
// hold a source lock while waiting for the writer's completion.
func TestGenerationTaggedWriterProgress(t *testing.T) {
	dir, anchor := generationFixture(t, generationBytes(t, "active"))
	s, _ := generationStore(t)
	g := newJournalGeneration(generationTestJournal(t, anchor), s, dir, gj.Floor{Hash: gj.ZeroHash})
	if c := g.withWindow(context.Background(), func(context.Context, gj.View) Code { return "" }); c != "" {
		t.Fatal(c)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	entered := make(chan struct{}, 1)
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			g.withWindow(ctx, func(context.Context, gj.View) Code {
				select {
				case entered <- struct{}{}:
				default:
				}
				time.Sleep(time.Millisecond)
				return ""
			})
		}
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("active reader control did not run")
	}
	if e := os.WriteFile(filepath.Join(dir, "writer.pending"), generationPending(t, "present"), 0644); e != nil {
		t.Fatal(e)
	}
	gate, e := os.OpenFile(filepath.Join(dir, "gate.lock"), os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer gate.Close()
	gateDeadline := time.Now().Add(time.Second)
	for {
		err := syscall.Flock(int(gate.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK || time.Now().After(gateDeadline) {
			t.Fatal("writer gate did not drain", err)
		}
		time.Sleep(time.Millisecond)
	}
	defer syscall.Flock(int(gate.Fd()), syscall.LOCK_UN)
	data, e := os.OpenFile(filepath.Join(dir, "data.lock"), os.O_RDWR, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer data.Close()
	deadline := time.Now().Add(time.Second)
	for {
		e = syscall.Flock(int(data.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if e == nil {
			break
		}
		if e != syscall.EWOULDBLOCK || time.Now().After(deadline) {
			t.Fatal("continuous readers prevented writer", e)
		}
		time.Sleep(time.Millisecond)
	}
	defer syscall.Flock(int(data.Fd()), syscall.LOCK_UN)
}

// The deterministic gap requires an upstream hook unavailable in the ordinary
// public API. Until the agreed tagged seam supplies it this contract fails as
// PENDING, never skips or claims that publishing before the first read suffices.
func TestGenerationTaggedPendingGap(t *testing.T) {
	dir, anchor := generationFixture(t, generationBytes(t, "active"))
	s, _ := generationStore(t)
	journal := generationTestJournal(t, anchor)
	boundary, ok := journal.(interface {
		WithEvidenceAtBoundary(context.Context, string, gj.Floor, func(), func(gj.View, time.Time) error) error
	})
	if !ok {
		t.Fatal("PENDING upstream genjournal_testseam exact pending-check boundary")
	}
	for _, pending := range []bool{false, true} {
		observed := false
		window := generationWindowFunc(func(ctx context.Context, path string, floor gj.Floor, commit func(gj.View, time.Time) error) error {
			return boundary.WithEvidenceAtBoundary(ctx, path, floor, func() {
				observed = true
				if pending {
					if e := os.WriteFile(filepath.Join(dir, "writer.pending"), generationPending(t, "present"), 0644); e != nil {
						t.Fatal(e)
					}
				}
			}, commit)
		})
		g := newJournalGeneration(window, s, dir, gj.Floor{Hash: gj.ZeroHash})
		called := false
		code := g.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" })
		expected := Code("")
		if pending {
			expected = "generation_source_unavailable"
		}
		if !observed || code != expected || called == pending {
			t.Fatal("pending gap admitted or active control denied", code, called, observed)
		}
	}
}
