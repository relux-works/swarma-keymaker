package keymaker

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// Real malformed reconnects and server-busy requests charge both work buckets
// before journaling. Exhaustion bounds further writes; fresh credit restores a
// valid identity response. Kernel admission costs are outside this work budget.
func TestFrameRefusalAccounting(t *testing.T) {
	for _, kind := range []string{"valid", "oversize", "busy"} {
		t.Run(kind, func(t *testing.T) {
			f := startRealFixture(t)
			// Hold the budget clock still; reconnects must drain the real burst,
			// independently of filesystem speed or scheduler delays.
			fixed := time.Now()
			f.engine.rateMu.Lock()
			f.engine.rateNow = func() time.Time { return fixed }
			f.engine.rateMu.Unlock()
			if kind == "busy" {
				for i := 0; i < cap(f.server.requests); i++ {
					f.server.requests <- struct{}{}
				}
			}
			send := func(attack bool) {
				t.Helper()
				c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: f.server.Path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if err = c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
					t.Fatal(err)
				}
				raw := Packet([]byte{11})
				if attack && kind == "oversize" {
					raw = []byte{0, 1, 0, 1}
				}
				if _, err = c.Write(raw); err != nil {
					t.Fatal(err)
				}
				body, code := ReadFrame(c)
				if code != "" || len(body) == 0 {
					t.Fatal("missing response", code)
				}
				if attack {
					if !bytes.Equal(body, []byte{5}) {
						t.Fatal("refusal released public data")
					}
				} else if body[0] != 12 {
					t.Fatal("valid identity control refused")
				}
			}
			send(kind != "valid")
			f.audit.mu.Lock()
			seq := f.audit.seq
			f.audit.mu.Unlock()
			if seq != 1 {
				t.Fatal("missing durable record", seq)
			}
			f.engine.rateMu.Lock()
			charged := !f.engine.global.last.IsZero() && len(f.engine.peers) == 1
			f.engine.rateMu.Unlock()
			if !charged {
				t.Fatal("refusal bypassed work buckets")
			}
			if kind == "valid" {
				return
			}
			for i := 0; i < 51; i++ {
				send(true)
			}
			f.audit.mu.Lock()
			seq = f.audit.seq
			last := f.audit.previous
			f.audit.mu.Unlock()
			if seq != 41 {
				t.Fatalf("overload amplified journal writes: %d, want burst 40 plus one indication", seq)
			}
			if f.engine.AggregatedRefusals() != 11 {
				t.Fatal("overload counter lost refusals", f.engine.AggregatedRefusals())
			}
			if last == "" {
				t.Fatal("missing audit chain")
			}
			if kind == "busy" {
				for i := 0; i < cap(f.server.requests); i++ {
					<-f.server.requests
				}
			}
			f.engine.rateMu.Lock()
			f.engine.global = bucket{}
			f.engine.peers = map[Principal]*bucket{}
			f.engine.rateMu.Unlock()
			send(false)
		})
	}
}

// Already framed overload is also bounded, with no parser/signing/release work;
// limiting only framing refusals would leave a second journal-amplification path.
func TestOverloadRefusalBudget(t *testing.T) {
	e, _, signer, a, s := fixtureEngine(t)
	fixed := time.Now()
	e.rateNow = func() time.Time { return fixed }
	e.global = bucket{last: time.Now().Add(time.Hour)}
	for i := 0; i < 100; i++ {
		if code := e.Handle(context.Background(), s, []byte{11}, func([]byte) error { t.Fatal("overload released"); return nil }); code != "rate_limited" {
			t.Fatal(code)
		}
	}
	if len(a.records) != 1 {
		t.Fatalf("overload amplified journal writes: %d, want 1", len(a.records))
	}
	if signer.calls.Load() != 0 {
		t.Fatal("overload signed")
	}
	if e.AggregatedRefusals() != 99 {
		t.Fatal("overload counter lost refusals", e.AggregatedRefusals())
	}
	e.global = bucket{}
	if code := e.Handle(context.Background(), s, []byte{11}, func([]byte) error { return nil }); code != "" {
		t.Fatal("positive control", code)
	}
}
