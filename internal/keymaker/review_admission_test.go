package keymaker

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

// A refused confirmation must remove its provisional watch before the first
// byte arrives; later restored authority must not turn that socket into success.
func TestReviewAdmissionConfirmationWait(t *testing.T) {
	f, g, calls := nativeAdmissionFixture(t, "generation_mismatch", true)
	before := nativeSnapshot(t, f)
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	select {
	case <-g.observed:
	case <-time.After(time.Second):
		t.Fatal("no confirmation refusal")
	}
	end := time.Now().Add(300 * time.Millisecond)
	for {
		f.generation.mu.Lock()
		n := len(f.generation.watchers[uint32(os.Getuid())])
		f.generation.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("confirmation watcher retained while waiting")
		}
		time.Sleep(time.Millisecond)
	}
	if len(f.server.requests) != 0 {
		t.Fatal("silent confirmation refusal held slot")
	}
	if !f.store.mu.TryLock() {
		t.Fatal("Store held while waiting")
	}
	f.store.mu.Unlock()
	nativeAdmissionUnchanged(t, f, g, calls, before)
	nativeAdmissionControl(t, f, g)
	nativeSend(t, c, nativeHello(1))
	nativeResponse(t, nativeReceive(t, c), nativeID(1), "generation_mismatch")
	nativeAdmissionClosed(t, c)
}

type reviewAdmissionDelay struct {
	GenerationSource
	once sync.Once
}

func (g *reviewAdmissionDelay) Lookup(ctx context.Context, uid uint32) (Generation, Code) {
	g.once.Do(func() {
		select {
		case <-time.After(1600 * time.Millisecond):
		case <-ctx.Done():
		}
	})
	return g.GenerationSource.Lookup(ctx, uid)
}

// Slow generation lookup consumes the original admission budget. A partial
// frame cannot obtain a fresh two seconds, and active admission still works.
func TestReviewAdmissionRemainingDeadline(t *testing.T) {
	f, g, _ := nativeAdmissionFixture(t, "generation_inactive", false)
	f.engine.Generations = &reviewAdmissionDelay{GenerationSource: g}
	before := len(nativeAudit(t, f.store.journal))
	f.start()
	start := time.Now()
	c := nativeDial(t, f.server.ControlPath)
	select {
	case <-g.observed:
	case <-time.After(1800 * time.Millisecond):
		t.Fatal("delayed lookup failed")
	}
	if _, e := c.Write([]byte{0}); e != nil {
		t.Fatal(e)
	}
	nativeAdmissionClosed(t, c)
	if elapsed := time.Since(start); elapsed < 1800*time.Millisecond || elapsed > 2500*time.Millisecond {
		t.Fatal("admission deadline reset", elapsed)
	}
	if n := len(nativeAudit(t, f.store.journal)); n != before {
		t.Fatal("silent deadline started audit", n-before)
	}
	nativeAdmissionControl(t, f, g)
}

type reviewAdmissionAudit struct {
	Auditor
	entered chan struct{}
	once    sync.Once
}

func (a *reviewAdmissionAudit) Append(r AuditRecord) Code {
	a.once.Do(func() { close(a.entered) })
	return a.Auditor.Append(r)
}

func (a *reviewAdmissionAudit) AppendContext(ctx context.Context, r AuditRecord) Code {
	a.once.Do(func() { close(a.entered) })
	return a.Auditor.AppendContext(ctx, r)
}

// A refusal queued behind another journal user must not keep a request slot or
// begin a durable append after its admission deadline. Journal contention is
// injected only in this isolated fixture; the native socket/observer are real.
func TestReviewAdmissionQueuedAuditDeadline(t *testing.T) {
	f, g, _ := nativeAdmissionFixture(t, "generation_inactive", false)
	before := len(nativeAudit(t, f.store.journal))
	beforeState := nativeSnapshot(t, f)
	a := &reviewAdmissionAudit{Auditor: f.store.journal, entered: make(chan struct{})}
	f.engine.Audit = a
	f.store.journal.mu.Lock()
	locked := true
	defer func() {
		if locked {
			f.store.journal.mu.Unlock()
		}
	}()
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeSend(t, c, nativeHello(1))
	select {
	case <-a.entered:
	case <-time.After(time.Second):
		t.Fatal("did not reach actual journal append")
	}
	nativeAdmissionClosed(t, c)
	// Allow scheduling after the socket deadline; no late success is accepted.
	time.Sleep(100 * time.Millisecond)
	held := len(f.server.requests)
	f.store.journal.mu.Unlock()
	locked = false
	end := time.Now().Add(time.Second)
	for len(f.server.requests) != 0 && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	delta := len(nativeAudit(t, f.store.journal)) - before
	t.Logf("after socket deadline: active slots=%d; after unlocking journal: late durable records=%d", held, delta)
	nativeAdmissionUnchanged(t, f, g, &nativeAdmissionCalls{}, beforeState)
	nativeAdmissionControl(t, f, g)
	if held != 0 || delta != 0 {
		t.Fatalf("expired refusal retained slot and appended after deadline: slots=%d late_records=%d", held, delta)
	}
}

// Refusal flood traffic consumes the real shared rate budget, aggregates
// overload audit, returns no result, and releases every connection/request slot.
// Restored credit plus an active principal then succeeds through the same daemon.
func TestReviewAdmissionFlood(t *testing.T) {
	f, g, _ := nativeAdmissionFixture(t, "generation_inactive", false)
	instant := time.Now()
	f.engine.rateNow = func() time.Time { return instant }
	before := len(nativeAudit(t, f.store.journal))
	f.start()
	for i := 1; i <= 60; i++ {
		c := nativeDial(t, f.server.ControlPath)
		nativeSend(t, c, nativeHello(i))
		code, id := Code("generation_inactive"), any(nativeID(i))
		if i > 40 {
			code, id = "rate_limited", nil
		}
		nativeResponse(t, nativeReceive(t, c), id, code)
		nativeAdmissionClosed(t, c)
		c.Close()
	}
	if n := len(nativeAudit(t, f.store.journal)) - before; n != 41 {
		t.Fatal("refusal audit escaped burst plus aggregate cap", n)
	}
	if n := f.engine.AggregatedRefusals(); n != 19 {
		t.Fatal("wrong aggregate", n)
	}
	end := time.Now().Add(time.Second)
	for {
		f.server.mu.Lock()
		n := len(f.server.connections)
		counts := len(f.server.counts)
		f.server.mu.Unlock()
		if n == 0 && counts == 0 && len(f.server.requests) == 0 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("refusal connection/slot leak", n, counts, len(f.server.requests))
		}
		time.Sleep(time.Millisecond)
	}
	f.engine.rateMu.Lock()
	f.engine.global = bucket{}
	f.engine.peers = map[Principal]*bucket{}
	f.engine.rateMu.Unlock()
	nativeAdmissionControl(t, f, g)
}

// Invalid IDs stay null even when supplied by a refused kernel-authenticated
// caller; valid IDs survive unrelated envelope errors, with one durable audit.
func TestReviewAdmissionIDShapes(t *testing.T) {
	for _, kind := range []string{"uppercase", "short", "null", "number", "extra"} {
		t.Run(kind, func(t *testing.T) {
			f, g, _ := nativeAdmissionFixture(t, "generation_inactive", false)
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			obj := nativeHello(10)
			var id any
			switch kind {
			case "uppercase":
				obj["request_id"] = "ABCDEF00000000000000000000000000"
			case "short":
				obj["request_id"] = "a"
			case "null":
				obj["request_id"] = nil
			case "number":
				obj["request_id"] = int64(1)
			case "extra":
				obj["uid"] = int64(os.Getuid())
				id = nativeID(10)
			}
			nativeSend(t, c, obj)
			nativeResponse(t, nativeReceive(t, c), id, "request_malformed")
			nativeAdmissionClosed(t, c)
			nativeAdmissionControl(t, f, g)
		})
	}
}

// A real refusal journal sync fault closes both surfaces without success; the
// healthy fixture's typed refusal and subsequent active request are controls.
func TestReviewAdmissionAuditFailure(t *testing.T) {
	for _, fault := range []bool{false, true} {
		name := "healthy"
		if fault {
			name = "sync-fault"
		}
		t.Run(name, func(t *testing.T) {
			f, g, _ := nativeAdmissionFixture(t, "generation_inactive", false)
			if fault {
				f.store.journal.mu.Lock()
				f.store.journal.writer = &faultFile{file: f.store.journal.file, syncFail: true}
				f.store.journal.mu.Unlock()
			}
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeSend(t, c, nativeHello(1))
			body, code := ReadFrame(c)
			if code != "" {
				t.Fatal("unexpected read failure", code)
			}
			if !fault {
				obj, e := control.Decode(body)
				if e != nil {
					t.Fatal(e)
				}
				nativeResponse(t, obj, nativeID(1), "generation_inactive")
				nativeAdmissionControl(t, f, g)
				return
			}
			if body != nil {
				obj, e := control.Decode(body)
				if e != nil {
					t.Fatal(e)
				}
				nativeResponse(t, obj, nativeID(1), "audit_unavailable")
			}
			select {
			case e := <-f.done:
				if e != Code("audit_unavailable") {
					t.Fatal(e)
				}
				f.cancel()
				f.cancel = nil
				f.stopped = true
			case <-time.After(time.Second):
				t.Fatal("audit fault left daemon running")
			}
			for _, path := range []string{f.server.Path, f.server.ControlPath} {
				c, e := net.DialTimeout("unix", path, 100*time.Millisecond)
				if e == nil {
					c.Close()
					t.Fatal("listener survived refusal sync fault")
				}
			}
		})
	}
}

// Eight silent refused connections consume only the per-UID connection cap;
// the ninth closes, and closing one permits an active control. Cancellation
// then joins all refusal readers and watchers, so none remains in shutdown.
func TestReviewAdmissionConnectionCap(t *testing.T) {
	f, g, _ := nativeAdmissionFixture(t, "generation_inactive", true)
	f.start()
	var conns []*net.UnixConn
	for i := 0; i < 8; i++ {
		conns = append(conns, nativeDial(t, f.server.ControlPath))
	}
	end := time.Now().Add(time.Second)
	for {
		f.server.mu.Lock()
		n := f.server.counts[uint32(os.Getuid())]
		f.server.mu.Unlock()
		if n == 8 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("did not fill connection cap")
		}
		time.Sleep(time.Millisecond)
	}
	extra := nativeDial(t, f.server.ControlPath)
	nativeAdmissionClosed(t, extra)
	if len(f.server.requests) != 0 {
		t.Fatal("silent refused connections used active request slots")
	}
	conns[0].Close()
	for {
		f.server.mu.Lock()
		n := f.server.counts[uint32(os.Getuid())]
		f.server.mu.Unlock()
		if n == 7 {
			break
		}
		if time.Now().After(end) {
			t.Fatal("closed refusal retained connection slot")
		}
		time.Sleep(time.Millisecond)
	}
	nativeAdmissionControl(t, f, g)
	f.cancel()
	select {
	case e := <-f.done:
		if e != nil {
			t.Fatal(e)
		}
		f.cancel = nil
		f.stopped = true
	case <-time.After(time.Second):
		t.Fatal("refusal readers survived shutdown")
	}
	f.server.mu.Lock()
	n := len(f.server.connections)
	f.server.mu.Unlock()
	f.generation.mu.Lock()
	watchers := len(f.generation.watchers[uint32(os.Getuid())])
	f.generation.mu.Unlock()
	if n != 0 || watchers != 0 || len(f.server.requests) != 0 {
		t.Fatal("shutdown leaked refusal resources", n, watchers, len(f.server.requests))
	}
}
