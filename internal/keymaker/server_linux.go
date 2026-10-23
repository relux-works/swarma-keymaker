//go:build linux

package keymaker

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Server struct {
	Engine        *Engine
	Peers         PeerSource
	Path          string
	dir           *os.File
	listener      *net.UnixListener
	inode, device uint64
	mu            sync.Mutex
	connections   map[*net.UnixConn]uint32
	counts        map[uint32]int
	closed        bool
	requests      chan struct{}
	wg            sync.WaitGroup
}

func LockState(dir *os.File, uid uint32) (*os.File, error) {
	f, e := openRelative(dir, "keymaker.lock", syscall.O_RDWR|syscall.O_CREAT, uid, 0600)
	if e != nil {
		return nil, e
	}
	if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, failure("state already locked")
	}
	return f, nil
}
func NewServer(socketDir string, engine *Engine, peers PeerSource) (*Server, error) {
	dir, e := OpenDirectory(socketDir, uint32(os.Getuid()), 0755)
	if e != nil {
		return nil, e
	}
	fail := func(err error) (*Server, error) { dir.Close(); return nil, err }
	if syscall.Flock(int(dir.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return fail(failure("socket directory already locked"))
	}
	// Bind relative to the retained directory inode. Existing entries, including
	// stale sockets, refuse; restart never unlinks another process's path.
	anchor := fmt.Sprintf("/proc/self/fd/%d/agent.sock", dir.Fd())
	if _, err := os.Lstat(anchor); !os.IsNotExist(err) {
		return fail(failure("socket path already exists"))
	}
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: anchor, Net: "unix"})
	if e != nil {
		return fail(failure("socket creation failed"))
	}
	l.SetUnlinkOnClose(false)
	if syscall.Fchmodat(int(dir.Fd()), "agent.sock", 0666, 0) != nil {
		l.Close()
		syscall.Unlinkat(int(dir.Fd()), "agent.sock")
		return fail(failure("socket permissions failed"))
	}
	st, e := os.Lstat(anchor)
	if e != nil {
		l.Close()
		return fail(failure("socket identity unavailable"))
	}
	stat := st.Sys().(*syscall.Stat_t)
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0666 || stat.Uid != uint32(os.Getuid()) {
		l.Close()
		return fail(failure("unsafe socket"))
	}
	return &Server{Engine: engine, Peers: peers, Path: filepath.Join(socketDir, "agent.sock"), dir: dir, listener: l, inode: stat.Ino, device: uint64(stat.Dev), connections: map[*net.UnixConn]uint32{}, counts: map[uint32]int{}, requests: make(chan struct{}, 16)}, nil
}
func (s *Server) Close() {
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
func (s *Server) cleanup() {
	anchor := fmt.Sprintf("/proc/self/fd/%d/agent.sock", s.dir.Fd())
	st, e := os.Lstat(anchor)
	if e == nil && st.Mode()&os.ModeSocket != 0 {
		v := st.Sys().(*syscall.Stat_t)
		if v.Ino == s.inode && uint64(v.Dev) == s.device && v.Uid == uint32(os.Getuid()) {
			syscall.Unlinkat(int(s.dir.Fd()), "agent.sock")
		}
	}
	s.dir.Close()
}
func (s *Server) Serve(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-s.Engine.Failed():
			s.Close()
		case <-done:
		}
	}()
	defer func() { close(done); s.Close(); s.wg.Wait(); s.cleanup() }()
	for {
		c, e := s.listener.AcceptUnix()
		if e != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return failure("accept failed")
		}
		peer, code := s.Peers.Credentials(c)
		s.mu.Lock()
		if s.closed || len(s.connections) >= 128 || code == "" && s.counts[peer.UID] >= 8 {
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
			s.handle(ctx, c, peer, code)
		}()
	}
}
func writeResponse(c *net.UnixConn, b []byte) error {
	for len(b) > 0 {
		n, e := c.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func fatalCode(c Code) bool {
	switch c {
	case "identity_revoked", "generation_inactive", "generation_mismatch", "generation_source_unavailable", "audit_unavailable", "binding_conflict", "binding_not_found", "peer_identity_unavailable":
		return true
	}
	return false
}
func (s *Server) handle(parent context.Context, c *net.UnixConn, peer Peer, peerCode Code) {
	session := Session{Admission: peerCode}
	if peerCode == "" {
		ctx, cancel := context.WithTimeout(parent, 2*time.Second)
		session = s.Engine.OpenSession(ctx, peer)
		cancel()
	}
	connectionDone := make(chan struct{})
	defer close(connectionDone)
	if session.Admission == "" {
		bindingChange, cancelBinding := s.Engine.Store.Watch(session.Binding.Number)
		defer cancelBinding()
		generationChange, cancelGeneration := s.Engine.Generations.Watch(peer.UID, session.Generation)
		defer cancelGeneration()
		// Subscribe, then re-read, so an update between admission and subscription
		// cannot leave an idle connection alive under an obsolete snapshot.
		ctx, cancel := context.WithTimeout(parent, 2*time.Second)
		check := s.Engine.OpenSession(ctx, peer)
		cancel()
		if check.Admission != "" || check.Generation != session.Generation || check.Binding.Number != session.Binding.Number {
			c.Close()
			return
		}
		go func() {
			select {
			case <-bindingChange:
				c.Close()
			case <-generationChange:
				c.Close()
			case <-connectionDone:
			}
		}()
	}
	for {
		frameDeadline := time.Now().Add(2 * time.Second)
		c.SetReadDeadline(frameDeadline)
		body, code := ReadFrame(c)
		if body == nil && code == "" {
			return
		}
		if code != "" {
			if !time.Now().Before(frameDeadline) {
				code = "request_deadline_exceeded"
			}
			s.Engine.RejectFrame(session, code)
			c.SetWriteDeadline(time.Now().Add(2 * time.Second))
			writeResponse(c, AgentFailure)
			return
		}
		ctx, cancel := context.WithTimeout(parent, 2*time.Second)
		c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		select {
		case s.requests <- struct{}{}:
			code = s.Engine.Handle(ctx, session, body, func(b []byte) error { return writeResponse(c, b) })
			<-s.requests
		default:
			q, _ := parseAgent(body)
			code = s.Engine.refuse(session, q, body, "busy")
		}
		cancel()
		if code != "" {
			if writeResponse(c, AgentFailure) != nil || fatalCode(code) || session.Admission != "" {
				return
			}
		}
	}
}
