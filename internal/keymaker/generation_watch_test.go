//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// Idle watchers read new windows instead of caching authority. A healthy poll
// leaves the connection lifetime open; retirement or uncertain source evidence
// closes it, and cancellation terminates the polling goroutine. The window is
// a byte-validating fake with the semantic fixture budget, not a filesystem
// notification qualification. The production watcher still bounds each poll.
func TestGenerationWatchLifetime(t *testing.T) {
	for _, mode := range []string{"retirement", "unavailable", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			s, _ := generationStore(t)
			active, retiring := generationBytes(t, "active"), generationBytes(t, "retiring")
			var changed atomic.Bool
			polled := make(chan struct{}, 1)
			window := generationWindowFunc(func(ctx context.Context, path string, floor gj.Floor, commit func(gj.View, time.Time) error) error {
				raw := active
				if changed.Load() {
					if mode == "unavailable" {
						return &gj.Refusal{Code: "journal_missing"}
					}
					raw = retiring
				}
				e := byteGenerationWindow(&raw).WithEvidence(ctx, path, floor, commit)
				select {
				case polled <- struct{}{}:
				default:
				}
				return e
			})
			g := newJournalGeneration(window, s, "/protected/generations", gj.Floor{Hash: gj.ZeroHash})
			v, e := gj.Verify(bytes.NewReader(active), gj.Floor{Hash: gj.ZeroHash})
			if e != nil {
				t.Fatal(e)
			}
			r := v.Rows[0]
			if _, c := g.Lookup(context.Background(), uint32(r.UID)); c != "" {
				t.Fatal(c)
			}
			<-polled
			lifetime, cancel := g.Watch(uint32(r.UID), r.Generation)
			defer cancel()
			select {
			case <-polled:
			case <-time.After(time.Second):
				t.Fatal("healthy watcher never polled")
			}
			select {
			case <-lifetime:
				t.Fatal("healthy poll closed authority")
			default:
			}
			if mode == "cancel" {
				cancel()
			} else {
				changed.Store(true)
			}
			select {
			case <-lifetime:
			case <-time.After(time.Second):
				t.Fatal("watcher failed to close", mode)
			}
		})
	}
}
