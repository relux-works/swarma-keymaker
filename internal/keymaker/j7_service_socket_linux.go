//go:build linux

package keymaker

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

// j7ServiceAdapter is the complete landed adapter surface the request role
// serves. The wrapper below preserves every optional capability and marker.
type j7ServiceAdapter interface {
	control.Handler
	control.PeerSource
	control.RequestIDs
	control.ReleaseFence
	control.Observer
	control.ConnectionScope
	control.BoundChannelSource
	control.RunLifecycleHandler
	control.RunRequestHandler
}

// j7Latch is the one-way fatal latch. The first Store or audit failure records
// its cause and synchronously stops admission before the failing call returns.
type j7Latch struct {
	once sync.Once
	mu   sync.Mutex
	code Code
	stop func()
}

func newJ7Latch() *j7Latch { return &j7Latch{} }

func (l *j7Latch) cause() Code {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.code
}

func (l *j7Latch) fail(code Code) {
	l.once.Do(func() {
		l.mu.Lock()
		l.code = code
		stop := l.stop
		l.mu.Unlock()
		if stop != nil {
			stop()
		}
	})
}

// attach registers the listener stop. A failure latched earlier stops at once.
func (l *j7Latch) attach(stop func()) {
	l.mu.Lock()
	l.stop = stop
	failed := l.code != ""
	l.mu.Unlock()
	if failed {
		stop()
	}
}

// j7StoreHealth reports a failed audit journal or Store. Both flags are read
// under their own gates, in the Store-then-journal order, never nested.
func j7StoreHealth(s *Store) Code {
	s.mu.Lock()
	failed := s.failed
	journal := s.journal
	s.mu.Unlock()
	if journal == nil {
		return "audit_unavailable"
	}
	journal.mu.Lock()
	audit := journal.failed
	journal.mu.Unlock()
	if audit {
		return "audit_unavailable"
	}
	if failed {
		return "j7_state_fenced"
	}
	return ""
}

// j7ServiceHandler adds only the fatal latch around the landed adapter: it
// grants nothing, changes no result and refuses everything once latched.
type j7ServiceHandler struct {
	inner  j7ServiceAdapter
	latch  *j7Latch
	health func() Code
}

func (*j7ServiceHandler) RunLifecycleOnly()  {}
func (*j7ServiceHandler) RunRequestSigning() {}

func (h *j7ServiceHandler) observe(code control.Code) {
	if code == "audit_unavailable" {
		h.latch.fail("audit_unavailable")
		return
	}
	if c := h.health(); c != "" {
		h.latch.fail(c)
	}
}
func (h *j7ServiceHandler) Scope(ctx context.Context, conn net.Conn) (context.Context, func()) {
	scoped, close := h.inner.Scope(ctx, conn)
	return scoped, func() { close(); h.observe("") }
}
func (h *j7ServiceHandler) BoundChannel(ctx context.Context, conn net.Conn, peer control.Peer) bool {
	return h.latch.cause() == "" && h.inner.BoundChannel(ctx, conn, peer)
}
func (h *j7ServiceHandler) Identify(ctx context.Context, conn net.Conn) (control.Peer, control.Code) {
	if c := h.latch.cause(); c != "" {
		return control.Peer{}, control.Code(c)
	}
	return h.inner.Identify(ctx, conn)
}
func (h *j7ServiceHandler) Enter(ctx context.Context, conn net.Conn) (func(), control.Code) {
	if c := h.latch.cause(); c != "" {
		return nil, control.Code(c)
	}
	return h.inner.Enter(ctx, conn)
}
func (h *j7ServiceHandler) Refuse(ctx context.Context, conn net.Conn, peer *control.Peer, r control.Request, body []byte, refusal control.Code) control.Code {
	if c := h.latch.cause(); c != "" {
		return control.Code(c)
	}
	code := h.inner.Refuse(ctx, conn, peer, r, body, refusal)
	h.observe(code)
	return code
}
func (h *j7ServiceHandler) Admit(ctx context.Context, peer control.Peer, r control.Request) control.Code {
	if c := h.latch.cause(); c != "" {
		return control.Code(c)
	}
	code := h.inner.Admit(ctx, peer, r)
	h.observe(code)
	return code
}
func (h *j7ServiceHandler) Handle(ctx context.Context, peer control.Peer, r control.Request) (control.Object, control.Code) {
	if c := h.latch.cause(); c != "" {
		return nil, control.Code(c)
	}
	result, code := h.inner.Handle(ctx, peer, r)
	h.observe(code)
	return result, code
}
func (h *j7ServiceHandler) WithActive(ctx context.Context, peer control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	if c := h.latch.cause(); c != "" {
		return control.Code(c)
	}
	code := h.inner.WithActive(ctx, peer, r, result, release)
	h.observe(code)
	return code
}

// j7Socket owns the request role's only listener. It has no Engine: admission
// bounds are the 128 global and 8 per peer UID connection limits, and request
// authority stays with the adapter's per-request peer check. Rate buckets are
// not applied on this socket; that limit is stated in the specification.
type j7Socket struct {
	dir         *os.File
	listener    *net.UnixListener
	inode       uint64
	device      uint64
	mu          sync.Mutex
	connections map[*net.UnixConn]uint32
	counts      map[uint32]int
	closed      bool
	wg          sync.WaitGroup
}

// atCapacity is called under mu before tracking a newly accepted connection.
func (s *j7Socket) atCapacity(uid uint32) bool {
	return len(s.connections) >= 128 || s.counts[uid] >= 8
}

// openJ7Socket locks the service-owned 0755 socket directory and publishes
// control.sock through the staged 0660 creation. An existing entry, a leftover
// staging directory or a held directory lock refuses; nothing is unlinked.
func openJ7Socket(path string, uid, gid uint32, listen func(*os.File, uint32) (*net.UnixListener, uint64, uint64, error)) (*j7Socket, error) {
	dir, err := OpenDirectory(path, uid, 0755)
	if err != nil {
		return nil, err
	}
	if syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		dir.Close()
		return nil, failure("socket directory already locked")
	}
	listener, inode, device, err := listen(dir, gid)
	if err != nil {
		dir.Close()
		return nil, err
	}
	s := &j7Socket{dir: dir, listener: listener, inode: inode, device: device, connections: map[*net.UnixConn]uint32{}, counts: map[uint32]int{}}
	st, err := os.Lstat(fmt.Sprintf("/proc/self/fd/%d/control.sock", dir.Fd()))
	if err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0660 {
		s.remove()
		return nil, failure("unsafe control socket")
	}
	stat := st.Sys().(*syscall.Stat_t)
	if stat.Uid != uid || stat.Gid != gid || stat.Ino != inode || uint64(stat.Dev) != device {
		s.remove()
		return nil, failure("unsafe control socket")
	}
	return s, nil
}

// stop ends admission and closes every accepted connection. It is idempotent.
func (s *j7Socket) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.listener.Close()
	for c := range s.connections {
		c.Close()
	}
}

// remove unlinks control.sock only while the entry is still the socket inode
// this process published, then releases the directory lock.
func (s *j7Socket) remove() {
	s.stop()
	anchor := fmt.Sprintf("/proc/self/fd/%d/control.sock", s.dir.Fd())
	st, err := os.Lstat(anchor)
	if err == nil && st.Mode()&os.ModeSocket != 0 {
		stat := st.Sys().(*syscall.Stat_t)
		if stat.Ino == s.inode && uint64(stat.Dev) == s.device && stat.Uid == uint32(os.Getuid()) {
			syscall.Unlinkat(int(s.dir.Fd()), "control.sock")
		}
	}
	s.dir.Close()
}

// serve runs until cancellation or the fatal latch: stop accepting, then wait
// for every connection handler. The caller unlinks and closes custody after.
func (s *j7Socket) serve(ctx context.Context, wire *control.Server, latch *j7Latch, health func() Code) error {
	latch.attach(s.stop)
	// Lifecycle withdrawal can commit in a background watcher. Detect a
	// failure even with no later request; handler failures also latch directly.
	watch, end := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			if health != nil {
				if c := health(); c != "" {
					latch.fail(c)
					return
				}
			}
			select {
			case <-watch.Done():
				return
			case <-tick.C:
			}
		}
	}()
	defer func() { end(); <-watchDone }()
	cancel := context.AfterFunc(ctx, s.stop)
	defer cancel()
	err := s.accept(ctx, wire)
	s.stop()
	s.wg.Wait()
	if c := latch.cause(); c != "" {
		return c
	}
	return err
}

func (s *j7Socket) accept(ctx context.Context, wire *control.Server) error {
	for {
		c, err := s.listener.AcceptUnix()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return failure("accept failed")
		}
		// The kernel peer check is immediate; a peer without credentials never
		// reaches the wire. Per-UID bounds apply before generation resolution.
		peer, code := kernelPeer(c)
		s.mu.Lock()
		if code != "" || s.closed || s.atCapacity(peer.UID) {
			s.mu.Unlock()
			c.Close()
			continue
		}
		s.connections[c] = peer.UID
		s.counts[peer.UID]++
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() {
				c.Close()
				s.mu.Lock()
				delete(s.connections, c)
				s.counts[peer.UID]--
				if s.counts[peer.UID] == 0 {
					delete(s.counts, peer.UID)
				}
				s.mu.Unlock()
			}()
			wire.ServeConn(ctx, c)
		}()
	}
}
