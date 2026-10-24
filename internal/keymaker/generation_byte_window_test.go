//go:build linux

package keymaker

import (
	"context"
	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Delay actual durability without altering the write or Sync result. This is
// local fixture latency, not collector/source or host storage qualification.
type generationByteSyncDelay struct {
	durableFile
	calls int
}

func (w *generationByteSyncDelay) Sync() error {
	w.calls++
	time.Sleep(300 * time.Millisecond)
	return w.durableFile.Sync()
}

// Semantic intact/corrupt byte fixtures must survive a real 300ms audit Sync
// before testing anchor continuity. The explicit 250ms control finishes durable
// publication but rejects its callback, then admits with the delay removed.
func TestGenerationByteAnchorSyncDelay(t *testing.T) {
	for _, mode := range []string{"intact", "corrupt", "default-250ms"} {
		t.Run(mode, func(t *testing.T) {
			s, dir := generationStore(t)
			raw := generationBytes(t, "active")
			w := byteGenerationWindow(&raw)
			if mode == "default-250ms" {
				original := w
				w = generationWindowFunc(func(ctx context.Context, path string, floor gj.Floor, fn func(gj.View, time.Time) error) error {
					return original.WithEvidence(ctx, path, floor, func(v gj.View, _ time.Time) error { return fn(v, time.Now().Add(gj.ReaderHold)) })
				})
			}
			g := newJournalGeneration(w, s, "/protected/generations", gj.Floor{Hash: gj.ZeroHash})
			writer := s.journal.writer
			delayed := &generationByteSyncDelay{durableFile: writer}
			s.journal.writer = delayed
			called := false
			code := g.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" })
			s.journal.writer = writer
			if delayed.calls == 0 {
				t.Fatal("300ms Sync not exercised")
			}
			if mode == "default-250ms" {
				if code != "request_deadline_exceeded" || called {
					t.Fatal("default window released callback", code, called)
				}
				loaded, damaged := loadGenerationAnchor(s, "/protected/generations", gj.Floor{Hash: gj.ZeroHash})
				if damaged || !g.enrolled || loaded != g.anchor || generationIncidentCount(t, s) != 0 {
					t.Fatal("expiry lost durable publication or fabricated fence", loaded, damaged)
				}
				if code = g.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" }); code != "" || !called {
					t.Fatal("unblocked control", code, called)
				}
				return
			}
			if code != "" || !called {
				t.Fatal("semantic setup depended on 250ms storage latency", code, called)
			}
			if mode == "corrupt" {
				if e := os.WriteFile(filepath.Join(dir.Name(), "generation.anchor"), []byte(`{}`), 0600); e != nil {
					t.Fatal(e)
				}
			}
			called = false
			code = g.withWindow(context.Background(), func(context.Context, gj.View) Code { called = true; return "" })
			want := Code("")
			incidents := 0
			if mode == "corrupt" {
				want = "generation_source_fenced"
				incidents = 1
			}
			if code != want || called != (want == "") || generationIncidentCount(t, s) != incidents {
				t.Fatal("anchor semantics", code, called, generationIncidentCount(t, s))
			}
		})
	}
}
