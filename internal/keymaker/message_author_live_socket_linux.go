//go:build linux

package keymaker

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-keymaker/messageauthor"
)

type maLiveServer struct {
	holder      *maLiveHolder
	write       func(context.Context, net.Conn, []byte) Code
	mu          sync.Mutex
	listener    *net.UnixListener
	connections map[*net.UnixConn]uint32
	counts      map[uint32]int
	slots       chan struct{}
	closed      bool
	wg          sync.WaitGroup
}

func (s *maLiveServer) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.listener != nil {
		s.listener.Close()
	}
	for conn := range s.connections {
		conn.Close()
	}
}
func (s *maLiveServer) serve(ctx context.Context, l *net.UnixListener) error {
	s.mu.Lock()
	s.listener = l
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, s.close)
	defer stop()
	defer func() { s.close(); s.wg.Wait() }()
	for {
		conn, e := l.AcceptUnix()
		if e != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return Code("audit_unavailable")
			}
			return failure("socket accept failed")
		}
		accepted := time.Now()
		peer, c := kernelPeer(conn)
		if c != "" {
			conn.Close()
			continue
		}
		s.mu.Lock()
		admit := !s.closed && maLiveConnectionRoom(len(s.connections), s.counts[peer.UID])
		if admit {
			s.connections[conn] = peer.UID
			s.counts[peer.UID]++
		}
		s.mu.Unlock()
		if !admit {
			c := s.holder.charge(Principal{UID: peer.UID}, false)
			if c == "" {
				c = "busy"
			}
			s.refuse(ctx, conn, Principal{}, "", c, accepted.Add(2*time.Second))
			conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			defer func() { s.mu.Lock(); delete(s.connections, conn); s.counts[peer.UID]--; s.mu.Unlock() }()
			s.connection(ctx, conn, peer, accepted)
		}()
	}
}
func maLiveRead(r io.Reader) ([]byte, Code) {
	var header [4]byte
	n, e := io.ReadFull(r, header[:])
	if n == 0 && e == io.EOF {
		return nil, ""
	}
	if e != nil {
		return nil, "frame_truncated"
	}
	size, e := messageauthor.FrameLength(header)
	if e != nil {
		if errors.Is(e, messageauthor.ErrFrameTooLarge) {
			return nil, "frame_too_large"
		}
		return nil, "frame_malformed"
	}
	frame := make([]byte, 4+size)
	copy(frame, header[:])
	if _, e = io.ReadFull(r, frame[4:]); e != nil {
		return nil, "frame_truncated"
	}
	return frame, ""
}
func maLiveFrame(object control.Object) ([]byte, error) {
	body, e := control.Marshal(object)
	if e != nil {
		return nil, e
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	return frame, nil
}
func maLiveWrite(ctx context.Context, conn net.Conn, frame []byte) Code {
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || !time.Now().Before(deadline) {
		return "request_deadline_exceeded"
	}
	if conn.SetWriteDeadline(deadline) != nil {
		return "request_deadline_exceeded"
	}
	for len(frame) > 0 {
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return "request_deadline_exceeded"
		}
		n, e := conn.Write(frame)
		if e != nil || n <= 0 {
			return "request_deadline_exceeded"
		}
		frame = frame[n:]
	}
	return ""
}
func (s *maLiveServer) refuse(ctx context.Context, conn net.Conn, p Principal, id string, c Code, deadline time.Time) bool {
	if !control.ValidRefusal(control.Code(c), maLiveRefusal(id, c).Refusal.Retryable) {
		return false
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if ctx.Err() != nil {
		return false
	}
	domain := "control"
	r := AuditRecord{Surface: "control", Domain: &domain, Operation: "unparsed", Result: "refused", RefusalCode: &c}
	if p.Generation != "" {
		r.PeerUID = &p.UID
		r.Generation = &p.Generation
	}
	if id != "" {
		r.RequestID = &id
	}
	// Custody failures without a captured cause are not emitted as unaudited
	// diagnostics. The held path supplies a cause for any such refusal.
	cause, _ := ctx.Value(maLiveCauseKey{}).(*custodyCause)
	if c == "custody_unavailable" || c == "message_author_unqualified" && cause != nil && cause.valid() {
		if cause == nil || !cause.valid() {
			return false
		}
		r.CustodyCause = cause
	}
	if s.holder.store.journal.AppendContext(ctx, r) != "" {
		s.close()
		return false
	}
	var correlation any
	if id != "" {
		correlation = id
	}
	frame, e := maLiveFrame(control.Object{"request_id": correlation, "error": control.Object{"code": string(c), "retryable": maLiveRefusal(id, c).Refusal.Retryable}})
	return e == nil && maLiveWrite(ctx, conn, frame) == ""
}
func maLiveHello(object control.Object) (string, Code) {
	id, _ := object["request_id"].(string)
	if !maLiveID(id) {
		return "", "request_malformed"
	}
	if len(object) != 3 || object["method"] != "hello" {
		return id, "request_malformed"
	}
	versions, ok := object["versions"].([]any)
	if !ok || len(versions) == 0 {
		return id, "request_malformed"
	}
	seen := map[int64]bool{}
	supported := false
	for _, v := range versions {
		n, ok := v.(int64)
		if !ok || n <= 0 || seen[n] {
			return id, "request_malformed"
		}
		seen[n] = true
		supported = supported || n == 1
	}
	if !supported {
		return id, "version_unsupported"
	}
	return id, ""
}

type maLiveCauseKey struct{}

func (s *maLiveServer) connection(ctx context.Context, conn *net.UnixConn, peer Peer, accepted time.Time) {
	probe, cancel := context.WithDeadline(ctx, accepted.Add(2*time.Second))
	g, c := s.holder.generations.Lookup(probe, peer.UID)
	cancel()
	if c != "" || !g.Verified || g.Fenced || g.State != "active" || g.Generation == "" {
		if c == "" {
			c = "generation_source_unavailable"
		}
		s.refuse(ctx, conn, Principal{}, "", c, accepted.Add(2*time.Second))
		return
	}
	p := Principal{peer.UID, g.Generation}
	ended, unwatch := s.holder.generations.Watch(p.UID, p.Generation)
	defer unwatch()
	scoped, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		select {
		case <-ended:
			conn.Close()
		case <-scoped.Done():
		}
	}()
	// Pin a binding watch atomically with selection, without holding metadata
	// locks over socket reads. Retirement uses the same Store barrier and wakes
	// this connection even while it is idle between requests.
	var binding uint64
	cancelBinding := func() {}
	defer func() { cancelBinding() }()
	pinBinding := func(ctx context.Context) Code {
		store := s.holder.store
		if !store.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		defer store.mu.Unlock()
		b, code := store.lookup(p.UID, p.Generation)
		if code != "" {
			return ""
		} // The held request path classifies no binding.
		if binding != 0 {
			if binding != b.Number {
				return "message_author_unqualified"
			}
			return ""
		}
		ended, cancel := store.watchLocked(b.Number)
		cancelBinding, binding = cancel, b.Number
		go func() {
			select {
			case <-ended:
				conn.Close()
			case <-scoped.Done():
			}
		}()
		return ""
	}
	if pinBinding(scoped) != "" {
		return
	}
	negotiated := false
	for {
		readUntil := time.Now().Add(2 * time.Second)
		if !negotiated {
			readUntil = accepted.Add(2 * time.Second)
		}
		if conn.SetReadDeadline(readUntil) != nil {
			return
		}
		frame, c := maLiveRead(conn)
		completed := time.Now()
		if frame == nil && c == "" {
			return
		}
		deadline := completed.Add(2 * time.Second)
		if c != "" {
			if rate := s.holder.charge(p, false); rate != "" {
				c = rate
			}
			s.refuse(scoped, conn, p, "", c, deadline)
			return
		}
		if c := s.holder.charge(p, false); c != "" {
			s.refuse(scoped, conn, p, "", c, deadline)
			return
		}
		select {
		case s.slots <- struct{}{}:
		default:
			s.refuse(scoped, conn, p, "", "busy", deadline)
			return
		}
		keep := func() bool {
			defer func() { <-s.slots }()
			object, e := control.Decode(frame[4:])
			if object["method"] == string(messageauthor.SignMethod) {
				if c := s.holder.chargeSign(p); c != "" {
					return s.refuse(scoped, conn, p, "", c, deadline)
				}
			}
			if e != nil {
				return s.refuse(scoped, conn, p, "", "ccj_noncanonical", deadline)
			}
			id, _ := object["request_id"].(string)
			if !maLiveID(id) {
				id = ""
			}
			if !negotiated {
				if object["method"] != "hello" {
					s.refuse(scoped, conn, p, id, "hello_required", readUntil)
					return false
				}
				id, c := maLiveHello(object)
				if c != "" {
					s.refuse(scoped, conn, p, id, c, readUntil)
					return false
				}
				helloCtx, stop := context.WithDeadline(scoped, readUntil)
				defer stop()
				c = s.holder.generations.WithActive(helloCtx, p.UID, p.Generation, func(ctx context.Context) Code {
					if c := s.holder.store.journal.AppendContext(ctx, AuditRecord{Surface: "control", Operation: "hello", Domain: maLiveControlDomain(), RequestID: &id, PeerUID: &p.UID, Generation: &p.Generation, Result: "success"}); c != "" {
						return c
					}
					frame, e := maLiveFrame(control.Object{"request_id": id, "result": control.Object{"version": int64(1)}})
					if e != nil {
						return "request_malformed"
					}
					return maLiveWrite(ctx, conn, frame)
				})
				if c != "" {
					s.refuse(scoped, conn, p, id, c, readUntil)
					return false
				}
				negotiated = true
				return true
			}
			if object["method"] == "hello" {
				return s.refuse(scoped, conn, p, id, "hello_already_negotiated", deadline)
			}
			// Check the encoded cap before the typed decoder allocates P.
			if object["method"] == string(messageauthor.SignMethod) {
				if params, ok := object["params"].(control.Object); ok {
					if p64, ok := params["preimage"].(string); ok && len(p64) > 32768 {
						return s.refuse(scoped, conn, p, id, "signer_preimage_too_large", deadline)
					}
				}
			}
			r, e := messageauthor.DecodeRequestFrame(frame)
			if e != nil {
				code := Code("request_malformed")
				if method, ok := object["method"].(string); ok && method != string(messageauthor.IdentityMethod) && method != string(messageauthor.SignMethod) {
					code = "operation_unsupported"
				}
				return s.refuse(scoped, conn, p, id, code, deadline)
			}
			deadline = completed.Add(time.Duration(r.TimeoutMS) * time.Millisecond)
			requestCtx, stop := context.WithDeadline(scoped, deadline)
			defer stop()
			if pinBinding(requestCtx) != "" {
				return false
			}
			var cause custodyCause
			requestCtx = context.WithValue(requestCtx, maLiveCauseKey{}, &cause)
			requestCtx = context.WithValue(requestCtx, maLiveChargedKey{}, true)
			disclosing := false
			c = s.holder.handle(requestCtx, p, r, func(ctx context.Context, out messageauthor.Response) Code {
				raw, e := messageauthor.EncodeResponseFrame(r, out)
				if e != nil {
					return "message_author_unqualified"
				}
				disclosing = true
				if s.write != nil {
					return s.write(ctx, conn, raw)
				}
				return maLiveWrite(ctx, conn, raw)
			})
			if c != "" {
				// Once response framing starts, a refusal frame cannot be appended
				// to a possibly partial success frame. Close and retain unknown.
				if disclosing {
					return false
				}
				if c == "audit_unavailable" {
					s.close()
					return false
				}
				if !s.refuse(requestCtx, conn, p, r.ID, c, deadline) {
					return false
				}
				if c == "generation_inactive" || c == "generation_mismatch" || c == "generation_source_fenced" || c == "identity_revoked" {
					return false
				}
			}
			return true
		}()
		if !keep {
			return
		}
	}
}
func maLiveControlDomain() *string { s := "control"; return &s }

func maLiveConnectionRoom(global, uid int) bool { return global < 32 && uid < 4 }
func newMALiveServer(h *maLiveHolder) *maLiveServer {
	return &maLiveServer{holder: h, connections: map[*net.UnixConn]uint32{}, counts: map[uint32]int{}, slots: make(chan struct{}, 16)}
}
