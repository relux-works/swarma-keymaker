package control

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

const frameBudget = 2 * time.Second

// Peer contains authority supplied by PeerSource, never request fields.
type Peer struct {
	UID        uint32
	Generation string
}

// PeerSource obtains the opener's kernel identity and checks its current active
// generation on every request, including hello. It must honor ctx. No binding is
// required for hello. Implementations must not infer authority from request data.
type PeerSource interface {
	Identify(ctx context.Context, conn net.Conn) (Peer, Code)
}

// Handler executes only pubkey, register, revoke and sign_registration. It must
// validate the exact method-specific schema and current authority, honor ctx,
// prepare audited results and recover durable results for admitted retries.
// The ReleaseFence, rather than this return boundary, covers actual wire release.
// It must not implement a generic signing operation behind these method names.
type Handler interface {
	Handle(ctx context.Context, peer Peer, request Request) (Object, Code)
}

// RequestIDs admits IDs in the caller's UID+generation scope, including hello.
// It must be atomic across connections, bounded and fail closed. Exact effect
// retries may be admitted for Handler recovery; changed method/arguments must
// return request_conflict. It must not treat a timeout change as new authority.
// This interface does not provide an in-memory substitute for durable replay.
type RequestIDs interface {
	Admit(ctx context.Context, peer Peer, request Request) Code
}

// ReleaseFence serializes successful response release against generation retirement
// for the exact peer tuple. It must honor ctx, synchronously call release exactly
// once only while current authoritative evidence permits it, and hold the barrier
// until release returns. Refusal must not call release. No cached lookup suffices.
//
// The core adapter can use GenerationSource.WithActive(uid, generation, callback),
// then perform its final binding/result checks and durable audit inside that
// callback before invoking release. Request and result identify that final work;
// they must not be modified or retained. Hello needs generation/audit, no binding.
// Transport deadline setup and encoding precede the barrier; actual writes are
// exclusively inside it. Refusals carry no result and can report a failed fence.
type ReleaseFence interface {
	WithActive(ctx context.Context, peer Peer, request Request, result Object, release func() Code) Code
}

// Observer supplies shared workload admission and durable refusal reporting.
// Enter returns a release function for the active-request slot. Refuse must
// establish durable audit or return audit_unavailable and close admission.
// A nil peer means authority was not established; conn still carries kernel
// credentials. Raw body bytes may be digested, never retained in audit.
type Observer interface {
	Enter(context.Context, net.Conn) (func(), Code)
	Refuse(context.Context, net.Conn, *Peer, Request, []byte, Code) Code
}

// Server owns no listeners, socket paths, peer credentials or global budgets.
// Its dependencies must be safe for concurrent calls and honor cancellation.
type Server struct {
	handler  Handler
	peers    PeerSource
	ids      RequestIDs
	fence    ReleaseFence
	observer Observer
}

func New(handler Handler, peers PeerSource, ids RequestIDs, fence ReleaseFence, observer Observer) (*Server, error) {
	if handler == nil || peers == nil || ids == nil || fence == nil || observer == nil {
		return nil, errors.New("control dependencies are required")
	}
	return &Server{handler: handler, peers: peers, ids: ids, fence: fence, observer: observer}, nil
}

// Serve accepts from a supplied listener and runs one goroutine per connection.
// Cancellation closes that listener and all its accepted connections; it waits
// for their context-cooperative handlers. The caller supplies bounded admission
// and socket ownership/permissions. It returns the context error on cancellation.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		wg.Go(func() { s.ServeConn(ctx, conn) })
	}
}

// ServeConn owns and closes conn. It reads and executes strictly sequentially:
// clients must await each response before sending the next request. There is no
// read-ahead, parallel dispatch or unbounded request queue on a connection.
func (s *Server) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	state := connectionState{helloDeadline: time.Now().Add(frameBudget)}
	for s.serveOne(ctx, conn, &state) {
	}
}

type connectionState struct {
	negotiated    bool
	accepted      Peer
	helloDeadline time.Time
}

func (s *Server) serveOne(ctx context.Context, conn net.Conn, state *connectionState) bool {
	readDeadline := time.Now().Add(frameBudget)
	if !state.negotiated {
		readDeadline = state.helloDeadline
	}
	if parent, ok := ctx.Deadline(); ok && parent.Before(readDeadline) {
		readDeadline = parent
	}
	if conn.SetReadDeadline(readDeadline) != nil {
		return false
	}
	body, code := readFrame(conn)
	completed := time.Now()
	if ctx.Err() != nil {
		return false
	}
	if body == nil && code == "" {
		return false
	}
	done, limit := s.observer.Enter(ctx, conn)
	if done != nil {
		defer done()
	}
	if limit != "" {
		code = limit
	}
	report := func(peer *Peer, request Request, refusal Code) Code {
		return s.observer.Refuse(ctx, conn, peer, request, body, refusal)
	}
	if code != "" {
		s.replyError(conn, nil, report(nil, Request{}, code), time.Now().Add(frameBudget))
		return false
	}
	if done == nil {
		return false
	}
	obj, err := Decode(body)
	if err != nil {
		s.replyError(conn, nil, report(nil, Request{}, CCJNoncanonical), time.Now().Add(frameBudget))
		return false
	}
	req, id, code := envelope(obj)
	closeAfter := false
	switch {
	case code == RequestMalformed:
	case !state.negotiated && req.Method != "hello":
		code = HelloRequired
	case state.negotiated && req.Method == "hello":
		code = HelloAlreadyNegotiated
	case code == VersionUnsupported:
		closeAfter = true
	}
	deadline := completed.Add(req.Timeout)
	if !state.negotiated {
		deadline = state.helloDeadline
	}
	if req.Timeout == 0 {
		deadline = completed.Add(frameBudget)
	}
	requestCtx, cancel := context.WithDeadline(ctx, deadline)
	var result Object
	var peer Peer
	var established *Peer
	if code == "" && requestCtx.Err() == nil {
		peer, code = s.peers.Identify(requestCtx, conn)
		if code == "" {
			established = &peer
		}
		if code == "" && peer.Generation == "" {
			code = "generation_source_unavailable"
		}
		if code == "" && state.negotiated && peer != state.accepted {
			code = "generation_mismatch"
		}
		if code == "" {
			switch req.Method {
			case "hello", "pubkey", "register", "revoke", "sign_registration":
			default:
				code = OperationUnsupported
			}
		}
		if code == "" && requestCtx.Err() == nil {
			code = s.ids.Admit(requestCtx, peer, req)
		}
		if code == "" && requestCtx.Err() == nil {
			if req.Method == "hello" {
				result = Object{"version": int64(1)}
			} else {
				result, code = s.handler.Handle(requestCtx, peer, req)
			}
		}
	}
	closeAfter = closeAfter || generationFailure(code)
	if requestCtx.Err() != nil || !time.Now().Before(deadline) {
		code = DeadlineExceeded
		result = nil
	}
	if !state.negotiated && code == DeadlineExceeded {
		closeAfter = true
	}
	if ctx.Err() != nil {
		cancel()
		return false
	}
	if code == "" {
		var err error
		code, err = s.release(requestCtx, conn, peer, req, result, deadline)
		cancel()
		if err != nil {
			return false
		}
		if code == "" {
			if req.Method == "hello" {
				state.accepted = peer
				state.negotiated = true
			}
			return true
		}
		// The authoritative fence refused before any success byte was written.
		// A result-free error may be sent, then this authority lifetime ends.
		closeAfter = true
	} else {
		cancel()
	}
	if ctx.Err() != nil {
		return false
	}
	code = report(established, req, code)
	closeAfter = closeAfter || code == "audit_unavailable"
	if !s.replyError(conn, id, code, time.Now().Add(frameBudget)) {
		return false
	}
	if closeAfter {
		return false
	}
	return true
}

func generationFailure(code Code) bool {
	switch code {
	case "generation_inactive", "generation_mismatch", "generation_source_unavailable", "peer_identity_unavailable":
		return true
	}
	return false
}

// release prepares transport state before entering the authoritative barrier.
// Returning a refusal is possible only before success emission; a partial write
// or a broken dependency contract closes without appending a second response.
func (s *Server) release(ctx context.Context, conn net.Conn, peer Peer, req Request, result Object, deadline time.Time) (Code, error) {
	if result == nil {
		return "", errors.New("control result is required")
	}
	frame, err := marshalFrame(Object{"request_id": req.ID, "result": result})
	if err != nil {
		return "", err
	}
	if err = conn.SetWriteDeadline(deadline); err != nil {
		return "", err
	}
	started := false
	var writeErr error
	release := func() Code {
		if started {
			return RequestConflict
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			return DeadlineExceeded
		}
		started = true
		writeErr = writeAll(conn, frame)
		if writeErr != nil {
			return DeadlineExceeded
		}
		return ""
	}
	code := s.fence.WithActive(ctx, peer, req, result, release)
	if writeErr != nil {
		return "", writeErr
	}
	if code != "" && started {
		return "", errors.New("control release failed after write")
	}
	if code == "" && !started {
		return "", errors.New("control release was not invoked")
	}
	return code, nil
}

func (s *Server) replyError(conn net.Conn, id any, code Code, deadline time.Time) bool {
	if !validCode(code) {
		return false
	}
	response := Object{"request_id": id, "error": Object{"code": string(code), "retryable": retryable(code)}}
	if conn.SetWriteDeadline(deadline) != nil {
		return false
	}
	return writeFrame(conn, response) == nil
}
