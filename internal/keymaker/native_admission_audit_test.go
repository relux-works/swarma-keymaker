package keymaker

import (
	"bytes"
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

type admissionAuditBudget struct {
	Auditor
	entered chan context.Context
}

func (a *admissionAuditBudget) AppendContext(ctx context.Context, r AuditRecord) Code {
	a.entered <- ctx
	return a.Auditor.AppendContext(ctx, r)
}

type admissionSyncBarrier struct {
	durableFile
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
	writes  atomic.Int32
}

func (w *admissionSyncBarrier) Write(b []byte) (int, error) {
	w.writes.Add(1)
	return w.durableFile.Write(b)
}
func (w *admissionSyncBarrier) Sync() error {
	w.once.Do(func() { close(w.entered); <-w.resume })
	return w.durableFile.Sync()
}

func admissionSlotsReleased(t *testing.T, f *nativeFixture) {
	t.Helper()
	end := time.Now().Add(300 * time.Millisecond)
	for len(f.server.requests) != 0 {
		if time.Now().After(end) {
			t.Fatal("expired refusal retained request slot", len(f.server.requests))
		}
		time.Sleep(time.Millisecond)
	}
}

// Once the real append reaches sync just before the admission deadline, socket
// expiry must not cancel/tear it. It completes exactly once after sync resumes;
// only then does its slot release. Active hello/pubkey on the same daemon follows.
func TestNativeAdmissionStartedAuditDeadline(t *testing.T) {
	f, g, calls := nativeAdmissionFixture(t, "generation_inactive", false)
	before, records := nativeSnapshot(t, f), len(nativeAudit(t, f.store.journal))
	j := f.store.journal
	w := &admissionSyncBarrier{durableFile: j.writer, entered: make(chan struct{}), resume: make(chan struct{})}
	a := &admissionAuditBudget{Auditor: j, entered: make(chan context.Context, 1)}
	f.engine.Audit = a
	j.mu.Lock()
	j.writer = w
	locked := true
	defer func() {
		if locked {
			j.mu.Unlock()
		}
	}()
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(w.resume) }) })
	f.start()
	c := nativeDial(t, f.server.ControlPath)
	nativeSend(t, c, nativeHello(1))
	var ctx context.Context
	select {
	case ctx = <-a.entered:
	case <-time.After(time.Second):
		t.Fatal("refusal did not queue audit")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("missing admission deadline")
	}
	// Release the gate with 100ms left, then hold the actual durable sync across it.
	<-time.After(time.Until(deadline.Add(-100 * time.Millisecond)))
	j.mu.Unlock()
	locked = false
	select {
	case <-w.entered:
	case <-ctx.Done():
		t.Fatal("append did not begin before deadline")
	}
	<-ctx.Done()
	nativeAdmissionClosed(t, c)
	if w.writes.Load() != 1 || len(f.server.requests) != 1 {
		t.Fatal("started append was interrupted", w.writes.Load(), len(f.server.requests))
	}
	release.Do(func() { close(w.resume) })
	admissionSlotsReleased(t, f)
	out := nativeAudit(t, j)[records:]
	if len(out) != 1 || out[0].RefusalCode == nil || *out[0].RefusalCode != "generation_inactive" || w.writes.Load() != 1 {
		t.Fatal("started refusal audit lost or duplicated", out)
	}
	nativeAdmissionUnchanged(t, f, g, calls, before)
	// Restore the ordinary writer and observer after the once-only boundary probe.
	j.mu.Lock()
	j.writer = j.file
	j.mu.Unlock()
	nativeAdmissionControl(t, f, g)
}

// Ordinary B framing/schema/method refusals obey the same bounded pre-append
// rule as accept-time refusals. None emits an unaudited error or writes late;
// after unlock the same healthy journal serves an active request.
func TestNativeOrdinaryRefusalAuditDeadline(t *testing.T) {
	for _, kind := range []string{"framing", "canonical", "method"} {
		t.Run(kind, func(t *testing.T) {
			f, g, _ := nativeAdmissionFixture(t, "generation_inactive", false)
			g.refusing.Store(false)
			a := &admissionAuditBudget{Auditor: f.store.journal, entered: make(chan context.Context, 1)}
			f.engine.Audit = a
			f.start()
			c := nativeDial(t, f.server.ControlPath)
			nativeNegotiate(t, c, 1)
			before, records := nativeSnapshot(t, f), len(nativeAudit(t, f.store.journal))
			f.store.journal.mu.Lock()
			locked := true
			defer func() {
				if locked {
					f.store.journal.mu.Unlock()
				}
			}()
			switch kind {
			case "framing":
				if err := writeResponse(c, []byte{0, 0, 0, 0}); err != nil {
					t.Fatal(err)
				}
			case "canonical":
				if err := writeResponse(c, Packet([]byte("{} "))); err != nil {
					t.Fatal(err)
				}
			case "method":
				nativeSend(t, c, nativeRequest(2, "sign", control.Object{}))
			}
			select {
			case <-a.entered:
			case <-time.After(time.Second):
				t.Fatal("ordinary refusal did not reach audit")
			}
			nativeAdmissionClosed(t, c)
			admissionSlotsReleased(t, f)
			f.store.journal.mu.Unlock()
			locked = false
			if delta := len(nativeAudit(t, f.store.journal)) - records; delta != 0 {
				t.Fatal("ordinary expired refusal appended late", delta)
			}
			if !bytes.Equal(before, nativeSnapshot(t, f)) || f.engine.closed.Load() {
				t.Fatal("abandoned audit changed state or fenced healthy journal")
			}
			nativeAdmissionControl(t, f, g)
		})
	}
}

// Expiry/cancellation with a free gate does not consume sequence, reserve or
// failure state. A succeeding ordinary durable append proves the journal is usable.
func TestJournalCancelledBeforeAppend(t *testing.T) {
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
	j := f.store.journal
	before := len(nativeAudit(t, j))
	seq, total, previous := j.seq, j.total, j.previous
	for _, expired := range []bool{false, true} {
		var ctx context.Context
		var cancel context.CancelFunc
		if expired {
			ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		} else {
			ctx, cancel = context.WithCancel(context.Background())
			cancel()
		}
		if code := j.AppendContext(ctx, AuditRecord{Surface: "control", Operation: "hello", Result: "refused"}); code != "request_deadline_exceeded" {
			t.Fatal("cancelled append admitted", code)
		}
		cancel()
	}
	if j.seq != seq || j.total != total || j.previous != previous || j.failed || len(nativeAudit(t, j)) != before {
		t.Fatal("cancelled append changed journal")
	}
	if code := j.Append(AuditRecord{Surface: "control", Operation: "hello", Result: "success"}); code != "" {
		t.Fatal("healthy append after cancellation", code)
	}
	if len(nativeAudit(t, j)) != before+1 {
		t.Fatal("positive append control absent")
	}
}

type admissionPrepareClock struct {
	AuditClock
	entered, resume chan struct{}
	once            sync.Once
}

func (c *admissionPrepareClock) UTC() (time.Time, bool) {
	c.once.Do(func() { close(c.entered); <-c.resume })
	return c.AuditClock.UTC()
}

// Holding read-only record preparation across expiry must not begin write or
// rotation afterward. This tests the durable-action boundary beyond acquisition;
// a later non-cancellable append is the positive control.
func TestJournalDeadlineDuringPreparation(t *testing.T) {
	f := nativeBase(t, Principal{uint32(os.Getuid()), nativeToken}, nil, nil)
	j := f.store.journal
	before := len(nativeAudit(t, j))
	clock := &admissionPrepareClock{AuditClock: j.clock, entered: make(chan struct{}), resume: make(chan struct{})}
	j.clock = clock
	w := &admissionSyncBarrier{durableFile: j.writer, entered: make(chan struct{}), resume: make(chan struct{})}
	close(w.resume)
	j.writer = w
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(clock.resume) }) })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan Code, 1)
	go func() {
		done <- j.AppendContext(ctx, AuditRecord{Surface: "control", Operation: "hello", Result: "refused"})
	}()
	select {
	case <-clock.entered:
	case <-time.After(time.Second):
		t.Fatal("audit preparation not reached")
	}
	<-ctx.Done()
	release.Do(func() { close(clock.resume) })
	if code := <-done; code != "request_deadline_exceeded" {
		t.Fatal("expired preparation began append", code)
	}
	if w.writes.Load() != 0 || j.failed || len(nativeAudit(t, j)) != before {
		t.Fatal("expired preparation wrote or poisoned journal")
	}
	if code := j.Append(AuditRecord{Surface: "control", Operation: "hello", Result: "success"}); code != "" {
		t.Fatal(code)
	}
	if w.writes.Load() != 1 || len(nativeAudit(t, j)) != before+1 {
		t.Fatal("durable append control missing")
	}
}
