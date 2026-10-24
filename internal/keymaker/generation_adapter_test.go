//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

type generationWindowFunc func(context.Context, string, gj.Floor, func(gj.View, time.Time) error) error

func (f generationWindowFunc) WithEvidence(c context.Context, p string, a gj.Floor, fn func(gj.View, time.Time) error) error {
	return f(c, p, a, fn)
}

// This fake delegates byte semantics to the format owner. It does not qualify
// filesystem policy or locking; those require the upstream tagged seam. Its
// explicit semantic budget isolates anchor durability from production timing.
func byteGenerationWindow(raw *[]byte) generationWindowFunc {
	return func(ctx context.Context, _ string, floor gj.Floor, fn func(gj.View, time.Time) error) error {
		v, err := gj.Verify(bytes.NewReader(*raw), floor)
		if err != nil {
			return err
		}
		return fn(v, time.Now().Add(generationFixtureReaderHold))
	}
}
func generationBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("testdata", "gen-journal", name+".jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func generationStore(t *testing.T) (*Store, *os.File) {
	t.Helper()
	d := t.TempDir()
	if e := os.Chmod(d, 0700); e != nil {
		t.Fatal(e)
	}
	dir, e := OpenDirectory(d, uint32(os.Getuid()), 0700)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { dir.Close() })
	s, e := fixtureOpenStore(dir, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}
func fixtureJournalGeneration(t *testing.T, s *Store, raw *[]byte) *journalGeneration {
	t.Helper()
	return newJournalGeneration(byteGenerationWindow(raw), s, "/protected/generations", gj.Floor{Hash: gj.ZeroHash})
}
func generationIncidentCount(t *testing.T, s *Store) int {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(s.dir.Name(), "audit", auditName(1)))
	if e != nil {
		t.Fatal(e)
	}
	return bytes.Count(b, []byte(`"operation":"generation_fence"`))
}

// Verified active history enrolls only pristine state and survives restart. A
// shorter chain or same-sequence fork latches exactly one incident across restart,
// and restoring the earlier good journal never automatically clears the fence.
func TestGenerationAnchorContinuity(t *testing.T) {
	for _, mode := range []string{"intact", "rollback", "fork", "missing", "corrupt", "pending", "established-unenrolled"} {
		t.Run(mode, func(t *testing.T) {
			s, dir := generationStore(t)
			raw := generationBytes(t, "active")
			g := fixtureJournalGeneration(t, s, &raw)
			if mode == "established-unenrolled" {
				if _, c := s.Register(fixtureOperator, fixtureOperator, fixtureBinding(uint32(os.Getuid()))); c != "" {
					t.Fatal(c)
				}
			} else {
				if c := g.withWindow(context.Background(), func(context.Context, gj.View) Code { return "" }); c != "" {
					t.Fatal(c)
				}
				// A configured replacement floor cannot reset an established anchor.
				if g.anchor.Floor.Seq != 2 {
					t.Fatal("unexpected active tail", g.anchor)
				}
			}
			switch mode {
			case "rollback":
				raw = generationBytes(t, "creating")
			case "fork":
				raw = bytes.ReplaceAll(raw, []byte(`"time":"2025-01-01T00:00:01Z"`), []byte(`"time":"2025-01-01T00:00:02Z"`))
				// Re-encode a distinct valid two-record chain independently of the source
				// fixture's timestamps; Verify must identify a fork rather than bad bytes.
				raw = nil
				prev := gj.ZeroHash
				for i, state := range []string{"creating", "active"} {
					line, e := gj.Encode(gj.Record{Seq: int64(i + 1), Prev: prev, UID: 1001, Generation: strings.Repeat("a", 32), State: state, Writer: "user-manager", Time: "2026-01-01T00:00:00Z"})
					if e != nil {
						t.Fatal(e)
					}
					raw = append(raw, line...)
					prev = gj.Digest(line)
				}
			case "missing":
				if e := os.Remove(filepath.Join(dir.Name(), "generation.anchor")); e != nil {
					t.Fatal(e)
				}
			case "corrupt":
				if e := os.WriteFile(filepath.Join(dir.Name(), "generation.anchor"), []byte(`{}`), 0600); e != nil {
					t.Fatal(e)
				}
			case "pending":
				if e := os.WriteFile(filepath.Join(dir.Name(), "generation.next"), []byte("interrupted"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			// Detect damage in the live reader as well as startup.
			called := false
			code := g.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" })
			if mode == "intact" {
				if code != "" || !called || generationIncidentCount(t, s) != 0 {
					t.Fatal("intact denied", code, called)
				}

				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				recovered, err := fixtureOpenStore(dir, uint32(os.Getuid()))
				if err != nil {
					t.Fatal(err)
				}
				defer recovered.Close()
				next := newJournalGeneration(byteGenerationWindow(&raw), recovered, "/protected/generations", gj.Floor{Seq: 999, Hash: strings.Repeat("f", 64)})
				if next.anchor.Floor != g.anchor.Floor {
					t.Fatal("configured floor replaced established anchor")
				}
				if c := next.withWindow(context.Background(), func(context.Context, gj.View) Code { return "" }); c != "" {
					t.Fatal("intact restart", c)
				}
				return
			}
			if code != "generation_source_fenced" || called || generationIncidentCount(t, s) != 1 {
				t.Fatal("incident not fenced once", code, called, generationIncidentCount(t, s))
			}
			raw = generationBytes(t, "active")
			if code = g.withWindow(context.Background(), func(context.Context, gj.View) Code { t.Fatal("auto recovered"); return "" }); code != "generation_source_fenced" {
				t.Fatal(code)
			}
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			recovered, e := fixtureOpenStore(dir, uint32(os.Getuid()))
			if e != nil {
				t.Fatal(e)
			}
			defer recovered.Close()
			g = fixtureJournalGeneration(t, recovered, &raw)
			if code = g.withWindow(context.Background(), func(context.Context, gj.View) Code { t.Fatal("restart recovered"); return "" }); code != "generation_source_fenced" || generationIncidentCount(t, recovered) != 1 {
				t.Fatal("restart fence", code)
			}
		})
	}
}

// Each incident classification has an active control. Live pending markers are
// transient; stale writers, forks, rollback and reserve violations latch once.
func TestGenerationSourceIncidentClassification(t *testing.T) {
	for _, source := range []string{"journal_writer_pending", "journal_writer_stale", "journal_rollback", "journal_fork", "journal_capacity_reserve", "journal_chain", "journal_missing"} {
		t.Run(source, func(t *testing.T) {
			s, _ := generationStore(t)
			raw := generationBytes(t, "active")
			g := fixtureJournalGeneration(t, s, &raw)
			if c := g.withWindow(context.Background(), func(context.Context, gj.View) Code { return "" }); c != "" {
				t.Fatal(c)
			}
			g.window = generationWindowFunc(func(context.Context, string, gj.Floor, func(gj.View, time.Time) error) error {
				return &gj.Refusal{Code: source}
			})
			code := g.withWindow(context.Background(), func(context.Context, gj.View) Code { t.Fatal("error reached effect"); return "" })
			fenced := source == "journal_writer_stale" || source == "journal_rollback" || source == "journal_fork" || source == "journal_capacity_reserve"
			expected := Code("generation_source_unavailable")
			if fenced {
				expected = "generation_source_fenced"
			}
			if code != expected {
				t.Fatalf("%s: %s want %s", source, code, expected)
			}
			g.window = byteGenerationWindow(&raw)
			code = g.withWindow(context.Background(), func(context.Context, gj.View) Code { return "" })
			if fenced {
				if code != "generation_source_fenced" || generationIncidentCount(t, s) != 1 {
					t.Fatal(code)
				}
			} else if code != "" || generationIncidentCount(t, s) != 0 {
				t.Fatal("transient failed control", code)
			}
		})
	}
}

// Current active tuples and retained retired generations are evaluated in one
// view. A deferred target verdict reaches the retained-result decision; ordinary
// mismatches suppress the callback. UID reuse never authorizes an old active token.
func TestGenerationEvidencePredicates(t *testing.T) {
	s, _ := generationStore(t)
	raw := generationBytes(t, "recycle")
	g := fixtureJournalGeneration(t, s, &raw)
	v, e := gj.Verify(bytes.NewReader(raw), gj.Floor{Hash: gj.ZeroHash})
	if e != nil {
		t.Fatal(e)
	}
	active := v.Rows[0]
	var retired gj.Row
	for _, r := range v.History {
		if r.State == "removed" {
			retired = r
		}
	}
	if retired.Generation == "" {
		t.Fatal("fixture has no tombstone")
	}
	for _, mode := range []string{"active", "retired", "mismatch", "reused", "not-retired", "deferred"} {
		t.Run(mode, func(t *testing.T) {
			condition := GenerationCondition{Principal: Principal{uint32(active.UID), active.Generation}}
			expected := Code("")
			deferred := Code("generation_source_unavailable")
			switch mode {
			case "retired":
				condition = GenerationCondition{Principal: Principal{uint32(retired.UID), retired.Generation}, Retired: true}
			case "mismatch":
				condition.Principal.Generation = strings.Repeat("f", 32)
				expected = "generation_mismatch"
			case "reused":
				condition.Principal.Generation = retired.Generation
				expected = "generation_mismatch"
			case "not-retired":
				condition.Retired = true
				expected = "generation_inactive"
			case "deferred":
				condition.Principal.Generation = retired.Generation
				condition.Verdict = &deferred
			}
			called := false
			c := g.WithEvidence(context.Background(), []GenerationCondition{condition}, func(ctx context.Context) Code {
				called = true
				if _, ok := ctx.Deadline(); !ok {
					t.Error("unbounded context")
				}
				return ""
			})
			if c != expected || called != (expected == "") {
				t.Fatal(mode, c, called)
			}
			if mode == "deferred" && deferred != "generation_mismatch" {
				t.Fatal("lost deferred verdict", deferred)
			}
		})
	}
}

// A configured nonzero initial floor must be an actual ancestor. Verified newer
// tails advance durably even when the current lifecycle denies admission; after
// restart the old active journal cannot reset that newer retiring checkpoint.
func TestGenerationAnchorAdvance(t *testing.T) {
	s, dir := generationStore(t)
	raw := generationBytes(t, "active")
	first, e := gj.Verify(bytes.NewReader(generationBytes(t, "creating")), gj.Floor{Hash: gj.ZeroHash})
	if e != nil {
		t.Fatal(e)
	}
	g := newJournalGeneration(byteGenerationWindow(&raw), s, "/protected/generations", first.Tail)
	active, e := gj.Verify(bytes.NewReader(raw), gj.Floor{Hash: gj.ZeroHash})
	if e != nil {
		t.Fatal(e)
	}
	uid := uint32(active.Rows[0].UID)
	if _, c := g.Lookup(context.Background(), uid); c != "" || g.anchor.Floor != active.Tail {
		t.Fatal("nonzero enrollment", c, g.anchor)
	}
	raw = generationBytes(t, "retiring")
	retired, e := gj.Verify(bytes.NewReader(raw), active.Tail)
	if e != nil {
		t.Fatal(e)
	}
	if _, c := g.Lookup(context.Background(), uid); c != "generation_inactive" || g.anchor.Floor != retired.Tail {
		t.Fatal("verified denied read lost advance", c, g.anchor)
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
	recovered, e := fixtureOpenStore(dir, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	defer recovered.Close()
	next := newJournalGeneration(byteGenerationWindow(&raw), recovered, "/protected/generations", gj.Floor{Hash: gj.ZeroHash})
	if next.anchor.Floor != retired.Tail {
		t.Fatal("restart lost newer tail")
	}
	raw = generationBytes(t, "active")
	if _, c := next.Lookup(context.Background(), uid); c != "generation_source_fenced" || generationIncidentCount(t, recovered) != 1 {
		t.Fatal("restart accepted old active tail", c)
	}
}

// The two sides of journal-first anchor publication must agree after restart.
// Restoring one side or leaving a staged write fences without repair. Restoring
// the complete old pair is the explicit limit of local continuity: WC1 external
// restore authorization remains pending and this test does not claim to supply it.
func TestGenerationAnchorCrashImages(t *testing.T) {
	for _, mode := range []string{"intact", "old-anchor", "old-journal", "journal-only", "staged", "joint-old-pair"} {
		t.Run(mode, func(t *testing.T) {
			s, dir := generationStore(t)
			raw := generationBytes(t, "active")
			g := fixtureJournalGeneration(t, s, &raw)
			if c := g.withWindow(context.Background(), func(context.Context, gj.View) Code { return "" }); c != "" {
				t.Fatal(c)
			}
			anchorPath := filepath.Join(dir.Name(), "generation.anchor")
			journalPath := filepath.Join(dir.Name(), "audit", auditName(1))
			read := func(path string) []byte {
				t.Helper()
				b, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				return b
			}
			write := func(path string, b []byte) {
				t.Helper()
				if e := os.WriteFile(path, b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			oldAnchor, oldJournal := read(anchorPath), read(journalPath)
			raw = generationBytes(t, "retiring")
			if c := g.withWindow(context.Background(), func(context.Context, gj.View) Code { return "" }); c != "" {
				t.Fatal(c)
			}
			if e := s.Close(); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "old-anchor":
				write(anchorPath, oldAnchor)
			case "old-journal":
				write(journalPath, oldJournal)
			case "joint-old-pair":
				write(anchorPath, oldAnchor)
				write(journalPath, oldJournal)
			case "journal-only":
				if e := os.Remove(anchorPath); e != nil {
					t.Fatal(e)
				}
			case "staged":
				write(filepath.Join(dir.Name(), "generation.next"), read(anchorPath))
			}
			var before []byte
			if mode != "journal-only" {
				before = read(anchorPath)
			}
			next, e := fixtureOpenStore(dir, uint32(os.Getuid()))
			if e != nil {
				t.Fatal(e)
			}
			defer next.Close()
			resumed := fixtureJournalGeneration(t, next, &raw)
			called := false
			code := resumed.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" })
			if mode == "intact" || mode == "joint-old-pair" {
				if code != "" || !called || generationIncidentCount(t, next) != 0 {
					t.Fatal("consistent local pair denied", code, called)
				}
				return
			}
			if code != "generation_source_fenced" || called || generationIncidentCount(t, next) != 1 {
				t.Fatal("incomplete anchor commit admitted", code, called)
			}
			if mode != "journal-only" && !bytes.Equal(before, read(anchorPath)) {
				t.Fatal("damaged anchor repaired")
			}
			if mode == "journal-only" {
				if _, e := os.Lstat(anchorPath); !os.IsNotExist(e) {
					t.Fatal("missing anchor recreated", e)
				}
			}
		})
	}
}
