package enrollment

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Done is evaluated after RLock registers its waiter and releases the mutex.
// This observes real queue entry without polling, delays or scheduling yields.
type gateQueuedContext struct {
	context.Context
	queued chan struct{}
	once   sync.Once
}

func (c *gateQueuedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.queued) })
	return c.Context.Done()
}

func gateAwait(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("admission gate did not progress")
	}
}

// At GOMAXPROCS=1 a writer immediately trying another pause must first hand
// admission to its finite published cohort, including cancellation on either
// side of publication. An unpaused control admits the same valid readers.
func TestAdmissionGatePublicationHandoff(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	for _, mode := range []string{"control", "cancel-before", "cancel-after"} {
		t.Run(mode, func(t *testing.T) {
			const count, canceled = 32, 8
			var g admissionGate
			if mode != "control" {
				g.pause()
			}
			release := make(chan struct{})
			var workers sync.WaitGroup
			var cancels []context.CancelFunc
			var entered atomic.Int32
			defer func() {
				for _, cancel := range cancels {
					cancel()
				}
				close(release)
				// Failure cleanup releases the isolated fixture's blocked readers.
				g.mu.Lock()
				g.paused = false
				g.notify()
				g.mu.Unlock()
				workers.Wait()
			}()
			for i := 0; i < count; i++ {
				ctx, cancel := context.WithCancel(context.Background())
				cancels = append(cancels, cancel)
				queued := &gateQueuedContext{Context: ctx, queued: make(chan struct{})}
				admitted := make(chan struct{})
				workers.Add(1)
				go func() {
					defer workers.Done()
					if err := g.RLock(queued); err == nil {
						entered.Add(1)
						close(admitted)
						<-release
						g.RUnlock()
					}
				}()
				if mode == "control" {
					gateAwait(t, admitted)
				} else {
					gateAwait(t, queued.queued)
				}
			}
			if mode == "control" {
				if entered.Load() != count {
					t.Fatal("unpaused control did not admit all readers")
				}
				return
			}
			if mode == "cancel-before" {
				for _, cancel := range cancels[:canceled] {
					cancel()
				}
			}
			g.Lock()
			g.Unlock()
			if mode == "cancel-after" {
				for _, cancel := range cancels[:canceled] {
					cancel()
				}
			}
			g.pause() // No yield: the next writer challenges the handoff directly.
			g.mu.Lock()
			readers, pending := g.readers, g.handoff
			g.mu.Unlock()
			if readers != count-canceled || pending != 0 {
				t.Fatalf("next pause overtook published readers: admitted=%d pending=%d", readers, pending)
			}
		})
	}
}

// A sustained valid reader stream cannot prevent bounded writer publication.
// All readers hold an initial admission before the writer starts; later reads
// continue until its 40 publications finish, without sleeps or yields.
func TestAdmissionGateWriterProgress(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	var g admissionGate
	ctx, cancel := context.WithCancel(context.Background())
	var readers sync.WaitGroup
	var reads atomic.Int32
	start := make(chan struct{})
	defer func() { cancel(); readers.Wait() }()
	for i := 0; i < 8; i++ {
		ready := make(chan struct{})
		readers.Add(1)
		go func() {
			defer readers.Done()
			if g.RLock(ctx) != nil {
				return
			}
			reads.Add(1)
			close(ready)
			<-start
			g.RUnlock()
			for g.RLock(ctx) == nil {
				reads.Add(1)
				g.RUnlock()
			}
		}()
		gateAwait(t, ready)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 40; i++ {
			g.pause()
			g.Lock()
			g.Unlock()
		}
	}()
	close(start)
	gateAwait(t, done)
	if reads.Load() <= 8 {
		t.Fatal("continuous reader traffic control absent")
	}
}

// The published failure fence is what queued readers observe, even when a
// valid recovery reload immediately follows. Recovery is the positive control;
// a next-publication success cannot erase the failure for the waiting cohort.
func TestAdmissionGateFailedPublication(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	a.mu.pause()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	const count = 16
	results := make(chan Code, count)
	for i := 0; i < count; i++ {
		queued := &gateQueuedContext{Context: ctx, queued: make(chan struct{})}
		go func() {
			key, code := a.Authorize(queued, 30001, testGeneration, public(2), testName, testAudience, testNow, testNow)
			if key != (EnrolledKey{}) {
				t.Error("failed publication disclosed old enrollment")
			}
			results <- code
		}()
		gateAwait(t, queued.queued)
	}
	// Use the fixture's protected pin write while retaining its valid recovery.
	valid := f.config
	f.config = PinConfig{}
	f.writeConfig()
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	f.config = valid
	f.writeConfig()
	expectCode(t, OK, a.Reload(context.Background()))
	for i := 0; i < count; i++ {
		expectCode(t, EnrollmentUnverified, <-results)
	}
	_, code := authorize(a)
	expectCode(t, OK, code)
}
