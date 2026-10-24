package keymaker

import (
	"context"
	"sync"
	"time"
)

// auditGate is a zero-value exclusive journal gate. Waiters select directly on
// cancellation; no goroutine or polling loop can acquire it after abandonment.
// The order remains generation -> Store -> enrollment -> journal.
type auditGate struct {
	once sync.Once
	held chan struct{}
}

func (g *auditGate) init() { g.once.Do(func() { g.held = make(chan struct{}, 1) }) }

func auditContextExpired(ctx context.Context) bool {
	if ctx.Err() != nil {
		return true
	}
	deadline, bounded := ctx.Deadline()
	return bounded && !time.Now().Before(deadline)
}

func (g *auditGate) LockContext(ctx context.Context) bool {
	g.init()
	if auditContextExpired(ctx) {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	case g.held <- struct{}{}:
		// A ready gate can race a ready deadline. Never start from expired authority.
		if auditContextExpired(ctx) {
			g.Unlock()
			return false
		}
		return true
	}
}

func (g *auditGate) Lock()   { g.LockContext(context.Background()) }
func (g *auditGate) Unlock() { <-g.held }

// TryLock supports nonblocking admission probes without creating a waiter.
func (g *auditGate) TryLock() bool {
	g.init()
	select {
	case g.held <- struct{}{}:
		return true
	default:
		return false
	}
}
