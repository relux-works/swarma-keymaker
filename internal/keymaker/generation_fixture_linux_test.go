//go:build linux && genjournal_testseam

package keymaker

// These fixtures use the source owner's tagged API at the pinned public commit.
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
	"sync"
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
	return generationFixtureHandle(uint32(os.Getuid()), anchor)
}

func generationFixtureHandle(owner uint32, anchor string) *gj.TestHandle {
	// Semantic fixtures isolate verdicts from ordinary anchor-sync latency in
	// both normal and race runs. Dedicated deadline tests use default handles.
	return gj.NewTestHandle(owner, anchor, gj.WithReaderHold(generationFixtureReaderHold))
}

// A fixture's callback receives a real deadline with the selected bound. The
// two-argument neighbor stays at 250ms beside the semantic fixture handle;
// the extension does not qualify production timing.
func TestGenerationTaggedReaderHoldWindow(t *testing.T) {
	if gj.ReaderHold != 250*time.Millisecond {
		t.Fatal("production reader bound changed", gj.ReaderHold)
	}
	dir, anchor := generationFixture(t, generationBytes(t, "active"))
	for _, tc := range []struct {
		name string
		h    *gj.TestHandle
		hold time.Duration
	}{
		{"selected", generationFixtureHandle(uint32(os.Getuid()), anchor), generationFixtureReaderHold},
		{"default", gj.NewTestHandle(uint32(os.Getuid()), anchor), gj.ReaderHold},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			err := tc.h.WithEvidence(context.Background(), dir, gj.Floor{Hash: gj.ZeroHash}, func(_ gj.View, deadline time.Time) error {
				called = true
				left := time.Until(deadline)
				if left <= 0 || left > tc.hold || (tc.hold > gj.ReaderHold && left <= gj.ReaderHold) {
					t.Fatalf("reader deadline remaining=%s want bound=%s", left, tc.hold)
				}
				return nil
			})
			if err != nil || !called {
				t.Fatal("valid reader control refused", err, called)
			}
		})
	}
}

// Invalid duration or nil options refuse the actual consumer API and adapter
// before callbacks or source/local persistence; a later positive option cannot
// erase invalid input. The same source and pristine store then admit normally.
func TestGenerationTaggedReaderHoldRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []gj.TestOption
	}{
		{"zero", []gj.TestOption{gj.WithReaderHold(0)}},
		{"negative", []gj.TestOption{gj.WithReaderHold(-time.Nanosecond)}},
		{"nil", []gj.TestOption{nil}},
		{"invalid-then-positive", []gj.TestOption{gj.WithReaderHold(0), gj.WithReaderHold(time.Second)}},
		{"positive-then-invalid", []gj.TestOption{gj.WithReaderHold(time.Second), gj.WithReaderHold(-time.Second)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, anchor := generationFixture(t, generationBytes(t, "active"))
			s, state := generationStore(t)
			window := gj.NewTestHandle(uint32(os.Getuid()), anchor, tc.options...)
			g := newJournalGeneration(window, s, dir, gj.Floor{Hash: gj.ZeroHash})
			sourceBefore, stateBefore := recoveryFiles(t, anchor), recoveryFiles(t, state.Name())
			called := false
			err := window.WithEvidence(context.Background(), dir, gj.Floor{Hash: gj.ZeroHash}, func(gj.View, time.Time) error { called = true; return nil })
			var refusal *gj.Refusal
			if !errors.As(err, &refusal) || refusal.Code != "journal_reader_hold" || called {
				t.Fatal("invalid hold source verdict/effect", err, called)
			}
			code := g.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" })
			if code != "generation_source_unavailable" || called {
				t.Fatal("invalid hold adapter verdict/effect", code, called)
			}
			if fmt.Sprint(sourceBefore) != fmt.Sprint(recoveryFiles(t, anchor)) || fmt.Sprint(stateBefore) != fmt.Sprint(recoveryFiles(t, state.Name())) {
				t.Fatal("invalid hold changed source or local state")
			}
			good := newJournalGeneration(generationTestJournal(t, anchor), s, dir, gj.Floor{Hash: gj.ZeroHash})
			if code = good.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" }); code != "" || !called {
				t.Fatal("valid reader control refused", code, called)
			}
		})
	}
}

// A real anchor audit sync can outlast the default 250ms reader window. Finish
// its durable publication, but refuse before the predicate/handoff callback.
// The same enrolled state then admits with sync unblocked. This reproduces a
// callback-expiry mechanism, not the exact uninstrumented reviewer I/O stall.
func TestGenerationTaggedAnchorSyncDeadline(t *testing.T) {
	for _, name := range []string{"active", "floor-ancestor"} {
		t.Run(name, func(t *testing.T) {
			dir, anchor := generationFixture(t, generationBytes(t, name))
			before := recoveryFiles(t, anchor)
			s, _ := generationStore(t)
			j := s.journal
			writer := j.writer
			barrier := &admissionSyncBarrier{durableFile: writer, entered: make(chan struct{}), resume: make(chan struct{})}
			j.writer = barrier
			var once sync.Once
			resume := func() { once.Do(func() { close(barrier.resume) }) }
			deadline := make(chan time.Time, 1)
			// Deliberately use the ordinary two-argument handle even under race.
			h := gj.NewTestHandle(uint32(os.Getuid()), anchor)
			window := generationWindowFunc(func(ctx context.Context, path string, floor gj.Floor, commit func(gj.View, time.Time) error) error {
				return h.WithEvidence(ctx, path, floor, func(v gj.View, d time.Time) error {
					deadline <- d
					return commit(v, d)
				})
			})
			g := newJournalGeneration(window, s, dir, gj.Floor{Hash: gj.ZeroHash})
			called := false
			done := make(chan struct{})
			var code Code
			go func() {
				defer close(done)
				code = g.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" })
			}()
			defer func() { resume(); <-done; j.writer = writer }()
			select {
			case <-barrier.entered:
			case <-done:
				t.Fatal("reader did not reach the controlled sync", code)
			case <-time.After(3 * time.Second):
				t.Fatal("reader failed to reach the sync barrier")
			}
			d := <-deadline
			if left := time.Until(d); left > gj.ReaderHold {
				t.Fatal("unexpected default reader bound", left)
			}
			<-time.After(time.Until(d) + time.Millisecond)
			resume()
			<-done
			if code != "request_deadline_exceeded" || called {
				t.Fatal("late anchor sync admitted a callback", code, called)
			}
			loaded, damaged := loadGenerationAnchor(s, dir, gj.Floor{Hash: gj.ZeroHash})
			if damaged || !g.enrolled || loaded != g.anchor || j.generation.Anchor == nil || loaded != *j.generation.Anchor || generationIncidentCount(t, s) != 0 {
				t.Fatal("expired sync lost publication or spuriously fenced", loaded, damaged)
			}
			if fmt.Sprint(before) != fmt.Sprint(recoveryFiles(t, anchor)) {
				t.Fatal("reader changed the source")
			}
			// The next call needs no floor advance and must not publish again.
			writes := barrier.writes.Load()
			g.window = h
			if code = g.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" }); code != "" || !called || barrier.writes.Load() != writes {
				t.Fatal("enrolled positive control failed or rewrote the floor", code, called)
			}
		})
	}
}

// Delay the real Sync, preserving its result and counting exercised calls.
// This fixture changes local latency only, never durability or source policy.
type generationSyncDelay struct {
	durableFile
	delay time.Duration
	calls int
}

func (w *generationSyncDelay) Sync() error {
	w.calls++
	time.Sleep(w.delay)
	return w.durableFile.Sync()
}

// The two positive vector histories still admit after a real 300ms anchor
// sync with the semantic fixture window. The same delay must refuse before
// callback entry with the default 250ms handle, after durable publication.
// This isolates the reviewer's latency mechanism; it does not qualify storage.
func TestGenerationTaggedVectorSyncDelay(t *testing.T) {
	for _, name := range []string{"active", "floor-ancestor"} {
		t.Run(name, func(t *testing.T) {
			for _, semantic := range []bool{true, false} {
				label := "default-window"
				if semantic {
					label = "semantic-window"
				}
				t.Run(label, func(t *testing.T) {
					dir, anchor := generationFixture(t, generationBytes(t, name))
					before := recoveryFiles(t, anchor)
					s, _ := generationStore(t)
					writer := s.journal.writer
					delayed := &generationSyncDelay{durableFile: writer, delay: 300 * time.Millisecond}
					s.journal.writer = delayed
					defer func() { s.journal.writer = writer }()
					h := gj.NewTestHandle(uint32(os.Getuid()), anchor)
					if semantic {
						h = generationFixtureHandle(uint32(os.Getuid()), anchor)
					}
					g := newJournalGeneration(h, s, dir, gj.Floor{Hash: gj.ZeroHash})
					called := false
					code := g.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" })
					want := Code("request_deadline_exceeded")
					if semantic {
						want = ""
					}
					if code != want || called != semantic || delayed.calls != 1 {
						t.Fatal("delayed anchor sync verdict/effect", code, want, called, delayed.calls)
					}
					loaded, damaged := loadGenerationAnchor(s, dir, gj.Floor{Hash: gj.ZeroHash})
					if damaged || !g.enrolled || loaded != g.anchor || s.journal.generation.Anchor == nil || loaded != *s.journal.generation.Anchor || generationIncidentCount(t, s) != 0 {
						t.Fatal("delayed sync lost publication or spuriously fenced", loaded, damaged)
					}
					if fmt.Sprint(before) != fmt.Sprint(recoveryFiles(t, anchor)) {
						t.Fatal("delayed reader changed the source")
					}
					// A fresh default window succeeds without another anchor sync.
					g.window = gj.NewTestHandle(uint32(os.Getuid()), anchor)
					called = false
					if code = g.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" }); code != "" || !called || delayed.calls != 1 {
						t.Fatal("fresh enrolled control failed or republished", code, called, delayed.calls)
					}
				})
			}
		})
	}
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
		window = generationFixtureHandle(uint32(os.Getuid())+1, anchor)
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
	checkVector := func(t *testing.T, c generationVectorCase) {
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
		// Independent section15 mapping; do not derive expected values by
		// calling the adapter's own classifier.
		expected := Code("generation_source_unavailable")
		switch c.Expect {
		case "ok":
			expected = ""
		case "journal_rollback", "journal_fork", "journal_writer_stale", "journal_capacity_reserve":
			expected = "generation_source_fenced"
		}
		if code != expected || called != (c.Expect == "ok") {
			t.Fatal("adapter verdict/effect mismatch", code, expected, called)
		}
	}
	controls := map[string]generationVectorCase{}
	for _, c := range manifest.Cases {
		controls[c.Name] = c
	}
	for _, negative := range []bool{true, false} {
		for _, c := range manifest.Cases {
			if (c.Expect != "ok") != negative {
				continue
			}
			t.Run(c.Name, func(t *testing.T) {
				checkVector(t, c)
				if c.Control != "" {
					control, ok := controls[c.Control]
					if !ok {
						t.Fatal("unknown positive control", c.Control)
					}
					t.Run("positive-control-"+control.Name, func(t *testing.T) { checkVector(t, control) })
				}
			})
		}
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

// Publishing intent in the exact first-check-to-gate gap must prevent release.
// The source owner's tagged hook schedules this boundary; its ordinary production
// API exposes no scheduling hook. The unmodified first-check neighbor releases.
func TestGenerationTaggedPendingGap(t *testing.T) {
	dir, _ := generationFixture(t, generationBytes(t, "active"))
	s, _ := generationStore(t)
	boundary := generationFixtureHandle(uint32(os.Getuid()), dir)
	for _, pending := range []bool{false, true} {
		observed := false
		window := generationWindowFunc(func(ctx context.Context, path string, floor gj.Floor, commit func(gj.View, time.Time) error) error {
			return boundary.WithEvidenceAtBoundary(ctx, floor, func() {
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

// The production delegate keeps root policy even when linked beside a tagged
// fixture handle. It rejects our service-owned tree without creating files;
// the exact same bytes admit through the explicit test-only handle.
func TestGenerationTaggedProductionPolicy(t *testing.T) {
	if os.Getuid() == 0 {
		t.Fatal("this ownership boundary requires an unprivileged fixture")
	}
	dir, anchor := generationFixture(t, generationBytes(t, "active"))
	before := recoveryFiles(t, anchor)
	called := false
	err := (productionGenerationWindow{}).WithEvidence(context.Background(), dir, gj.Floor{Hash: gj.ZeroHash}, func(gj.View, time.Time) error { called = true; return nil })
	var refusal *gj.Refusal
	if !errors.As(err, &refusal) || refusal.Code != "journal_owner" || called {
		t.Fatal("production fixture policy escape", err, called)
	}
	if fmt.Sprint(before) != fmt.Sprint(recoveryFiles(t, anchor)) {
		t.Fatal("production reader changed source")
	}
	err = generationTestJournal(t, anchor).WithEvidence(context.Background(), dir, gj.Floor{Hash: gj.ZeroHash}, func(gj.View, time.Time) error { called = true; return nil })
	if err != nil || !called {
		t.Fatal("explicit fixture control denied", err, called)
	}
}

// The actual protected reader receives the persisted floor after Keymaker
// restart. A valid shorter source or equal-sequence alternate chain fences once;
// restoring good source bytes does not clear that incident. The intact file
// is the positive control; writes occur only in this isolated fixture.
func TestGenerationTaggedAnchorRestart(t *testing.T) {
	for _, mode := range []string{"intact", "rollback", "fork"} {
		t.Run(mode, func(t *testing.T) {
			raw := generationBytes(t, "active")
			dir, anchor := generationFixture(t, raw)
			s, state := generationStore(t)
			window := generationTestJournal(t, anchor)
			g := newJournalGeneration(window, s, dir, gj.Floor{Hash: gj.ZeroHash})
			if c := g.withWindow(context.Background(), func(context.Context, gj.View) Code { return "" }); c != "" {
				t.Fatal(c)
			}
			floor := g.anchor.Floor
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "rollback":
				raw = generationBytes(t, "creating")
			case "fork":
				raw = generationBytes(t, "equal-seq-fork")
				v, e := gj.Verify(bytes.NewReader(raw), gj.Floor{Hash: gj.ZeroHash})
				if e != nil || v.Tail.Seq != floor.Seq || v.Tail.Hash == floor.Hash {
					t.Fatal("fork fixture is not a valid alternate chain", e)
				}
			}
			gate := generationLock(t, filepath.Join(dir, "gate.lock"), syscall.LOCK_EX)
			data := generationLock(t, filepath.Join(dir, "data.lock"), syscall.LOCK_EX)
			f, e := os.OpenFile(filepath.Join(dir, "journal"), os.O_WRONLY|os.O_TRUNC, 0)
			if e != nil {
				t.Fatal(e)
			}
			_, e = f.Write(raw)
			if e == nil {
				e = f.Sync()
			}
			f.Close()
			if e != nil {
				t.Fatal(e)
			}
			syscall.Flock(int(data.Fd()), syscall.LOCK_UN)
			syscall.Flock(int(gate.Fd()), syscall.LOCK_UN)
			next, e := fixtureOpenStore(state, uint32(os.Getuid()))
			if e != nil {
				t.Fatal(e)
			}
			defer next.Close()
			resumed := newJournalGeneration(window, next, dir, gj.Floor{Hash: gj.ZeroHash})
			if resumed.anchor.Floor != floor {
				t.Fatal("restart reset floor")
			}
			called := false
			code := resumed.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" })
			if mode == "intact" {
				if code != "" || !called || generationIncidentCount(t, next) != 0 {
					t.Fatal("intact restart denied", code)
				}
				return
			}
			if code != "generation_source_fenced" || called || generationIncidentCount(t, next) != 1 {
				t.Fatal("rollback/fork admitted after restart", code, called)
			}
			if e := os.WriteFile(filepath.Join(dir, "journal"), generationBytes(t, "active"), 0644); e != nil {
				t.Fatal(e)
			}
			if code = resumed.withWindow(context.Background(), func(context.Context, gj.View) Code { t.Fatal("restored source cleared incident"); return "" }); code != "generation_source_fenced" || generationIncidentCount(t, next) != 1 {
				t.Fatal("incident recovered or duplicated", code)
			}
		})
	}
}
