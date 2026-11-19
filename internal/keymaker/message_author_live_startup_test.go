//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
	"github.com/relux-works/swarma-keymaker/messageauthor"
)

type maLiveReadyWriter chan struct{}

func (w maLiveReadyWriter) Write(p []byte) (int, error) {
	if string(p) == "ready\n" {
		w <- struct{}{}
	}
	return len(p), nil
}

// The actual composed service is started over test-owned files and SO_PEERCRED.
// Only time/head/generation are fixture inputs; the production current provider
// and absence of a production root loader remain unchanged in the negative.
func TestMALiveProductionRole(t *testing.T) {
	for _, positive := range []bool{false, true} {
		t.Run(map[bool]string{false: "refusing-production", true: "injected-control"}[positive], func(t *testing.T) {
			f := newMALiveFixture(t, uint32(os.Getuid()))
			expected := maLiveExpected(t, f.h.store)
			f.h.store.Close()
			socketDir, e := os.MkdirTemp(os.Getenv("TMPDIR"), "mas-")
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { os.RemoveAll(socketDir) })
			if e = os.Chmod(socketDir, 0755); e != nil {
				t.Fatal(e)
			}
			raw, e := os.ReadFile("../../packaging/message-author.example.json")
			if e != nil {
				t.Fatal(e)
			}
			var o map[string]any
			if e = json.Unmarshal(raw, &o); e != nil {
				t.Fatal(e)
			}
			o["instance_id"] = f.h.store.maLive.Instance
			o["service_uid"] = os.Getuid()
			o["service_gid"] = os.Getgid()
			o["master_epoch"] = f.b.Epoch
			o["registry_revision"] = f.b.RegistryRevision
			state := o["state"].(map[string]any)
			state["path"] = f.dir.Name()
			state["head_file"] = filepath.Join(socketDir, "..", "fixture-head")
			socket := o["socket"].(map[string]any)
			socket["dir"] = socketDir
			socket["group"] = os.Getgid()
			raw, e = json.Marshal(o)
			if e != nil {
				t.Fatal(e)
			}
			cfg, e := ParseConfig(bytes.NewReader(raw))
			if e != nil {
				t.Fatal(e)
			}
			d := productionMALiveDeps()
			d.clock = func(*timeconf.Policy) (*timeconf.Provider, error) {
				p, _, _ := fixtureTimeProvider(t, helperNow)
				return p, nil
			}
			d.head = func(string) (j7Expectation, error) { return expected, nil }
			d.generation = func(*Store, generationJournalConfig) GenerationSource { return newGenerations(f.b.UID, f.b.Generation) }
			var calls atomic.Int32
			if positive {
				f.source.from = helperNow.Add(-time.Hour)
				f.source.until = helperNow.Add(time.Hour)
				d.current = f.source
				d.key = f.h.key
				d.invoke = func(s *Store, b Binding, p *messageAuthorPlan, before func() Code) ([]byte, Code) {
					return f.h.key.selectedHeld(s, b, p, func() Code {
						c := before()
						if c == "" {
							calls.Add(1)
						}
						return c
					})
				}
			}
			ready := make(maLiveReadyWriter, 1)
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan error, 1)
			go func() { done <- serveMALive(ctx, cfg, ready, d) }()
			t.Cleanup(func() {
				cancel()
				select {
				case e := <-done:
					if e != nil {
						t.Error(e)
					}
				case <-time.After(3 * time.Second):
					t.Error("service did not stop")
				}
			})
			select {
			case <-ready:
			case e := <-done:
				done <- nil
				t.Fatal("healthy service setup refused", e)
			case <-time.After(3 * time.Second):
				t.Fatal("service readiness timeout")
			}
			conn, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(socketDir, "control.sock"), Net: "unix"})
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			hello, e := maLiveFrame(control.Object{"method": "hello", "request_id": f.request().ID, "versions": []any{int64(1)}})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = conn.Write(hello); e != nil {
				t.Fatal(e)
			}
			if frame, c := maLiveRead(conn); c != "" || !bytes.Contains(frame, []byte(`"version":1`)) {
				t.Fatal("service hello", c)
			}
			for _, method := range []messageauthor.Method{messageauthor.IdentityMethod, messageauthor.SignMethod} {
				r := f.request()
				r.Method = method
				if method == messageauthor.IdentityMethod {
					r.Preimage = nil
				}
				out := maLiveSocketCall(t, conn, r)
				if !positive {
					if out.Refusal == nil || out.Refusal.Code != "message_author_unqualified" || calls.Load() != 0 {
						t.Fatal("production manufactured currentness")
					}
				} else if method == messageauthor.IdentityMethod {
					if out.Identity == nil || calls.Load() != 0 {
						t.Fatal("identity control")
					}
				} else {
					if out.Signature == nil || calls.Load() != 1 || record.VerifySignature(f.v.Key, out.Signature.Signature, r.Preimage) != nil {
						t.Fatal("service signature control")
					}
				}
			}
			cancel()
			conn.Close()
			select {
			case e := <-done:
				if e != nil {
					t.Fatal(e)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("service stop timeout")
			}
			// Supply an already completed receipt to cleanup instead of waiting twice.
			done <- nil
			s, c := openMALive(f.dir, uint32(os.Getuid()), fixtureAuditClock{}, expected)
			if !positive {
				if c != "" || len(s.maLive.Attempts) != 0 {
					t.Fatal("production refusal retained an attempt", c)
				}
				s.Close()
			}
			t.Logf("actual composed role: positive=%v invocation_count=%d", positive, calls.Load())
		})
	}
}

// Unknown CLI actions refuse before any config file, input or state is read.
func TestMALiveOperatorClosedCommands(t *testing.T) {
	for _, command := range []string{"sign", "export", "issue", "migrate", "reconcile-wire"} {
		if c := RunMessageAuthorOperator(t.Context(), command, "", 0, nil, io.Discard); c != "request_malformed" {
			t.Fatal("operator command union widened", c)
		}
	}
}

// Real shared time-provider qualification feeds this holder's clock seam. Aged
// sync and uncertainty failures refuse without a fence; restored evidence does
// not clear an already persisted holder fence. No host time source is consulted.
func TestMALiveTimeProviderBounds(t *testing.T) {
	for _, fault := range []string{"sync-age", "uncertainty"} {
		t.Run(fault, func(t *testing.T) {
			f := newMALiveFixture(t)
			p, _, collector := fixtureTimeProvider(t, helperNow)
			f.source.from = helperNow.Add(-time.Hour)
			f.source.until = helperNow.Add(time.Hour)
			f.h.clock = func(ctx context.Context) (j7GateTime, Code) {
				v, e := timeconfidence.Sample(ctx, p)
				if e != nil {
					return j7GateTime{}, "clock_untrusted"
				}
				lo, hi, ok := timeconfidence.Bounds(v)
				if !ok {
					return j7GateTime{}, "clock_untrusted"
				}
				return j7GateTime{Now: v.Now, Lower: lo, Upper: hi}, ""
			}
			good := collector.e
			if fault == "sync-age" {
				collector.e.Tracking.Reference = helperNow.Add(-2049 * time.Second)
			} else {
				collector.e.Tracking.RootDispersion = 2
			}
			f.refusal(t, f.request(), "clock_untrusted", 0)
			if f.h.store.maLive.Fenced {
				t.Fatal("time provider fault fenced holder")
			}
			collector.e = good
			f.control(t)
			f.h.store.maLive.Fenced = true
			f.refusal(t, f.request(), "message_author_unqualified", 1)
		})
	}
}
