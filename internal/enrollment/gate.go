package enrollment

import (
	"context"
	"sync"
)

// admissionGate separates pending reload work from exclusive publication. A
// pending reload blocks new readers, never existing releases. No goroutine is
// created to wait for a lock, so a canceled caller leaves no abandoned waiter.
// Writers are serialized by Authority.reloadMu; the zero value is usable.
type admissionGate struct {
	mu      sync.Mutex
	readers int
	paused  bool
	changed chan struct{}
}

func (g *admissionGate) notify() {
	if g.changed != nil {
		close(g.changed)
	}
	g.changed = make(chan struct{})
}

func (g *admissionGate) pause() {
	g.mu.Lock()
	g.paused = true
	g.mu.Unlock()
}

func (g *admissionGate) RLock(ctx context.Context) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !g.paused {
			g.readers++
			return nil
		}
		if g.changed == nil {
			g.changed = make(chan struct{})
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-changed:
		}
		g.mu.Lock()
	}
}

func (g *admissionGate) RUnlock() {
	g.mu.Lock()
	g.readers--
	if g.readers == 0 {
		g.notify()
	}
	g.mu.Unlock()
}

// Lock drains admitted releases. Only the short publication holds exclusivity;
// reload I/O happens between pause and Lock. Failure must also publish its fence,
// even if the reload context expired while building the candidate.
func (g *admissionGate) Lock() {
	g.mu.Lock()
	g.paused = true
	for g.readers != 0 {
		if g.changed == nil {
			g.changed = make(chan struct{})
		}
		changed := g.changed
		g.mu.Unlock()
		<-changed
		g.mu.Lock()
	}
	g.mu.Unlock()
}

func (g *admissionGate) Unlock() {
	g.mu.Lock()
	g.paused = false
	g.notify()
	g.mu.Unlock()
}
