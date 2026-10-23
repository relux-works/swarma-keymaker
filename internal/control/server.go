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
// fence release, audit durably, and recover durable results for admitted retries.
// It must not implement a generic signing operation behind these method names.
type Handler interface {
	Handle(ctx context.Context, peer Peer, method string, params Object) (Object, Code)
}

// RequestIDs admits IDs in the caller's UID+generation scope, including hello.
// It must be atomic across connections, bounded and fail closed. Exact effect
// retries may be admitted for Handler recovery; changed method/arguments must
// return request_conflict. It must not treat a timeout change as new authority.
// This interface does not provide an in-memory substitute for durable replay.
type RequestIDs interface {
	Admit(ctx context.Context, peer Peer, request Request) Code
}

// Server owns no listeners, socket paths, peer credentials or global budgets.
// Its dependencies must be safe for concurrent calls and honor cancellation.
type Server struct {
	handler Handler
	peers   PeerSource
	ids     RequestIDs
}

func New(handler Handler, peers PeerSource, ids RequestIDs) (*Server, error) {
	if handler == nil || peers == nil || ids == nil {
		return nil, errors.New("control dependencies are required")
	}
	return &Server{handler: handler, peers: peers, ids: ids}, nil
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
	negotiated := false
	helloDeadline := time.Now().Add(frameBudget)
	for {
		readDeadline := time.Now().Add(frameBudget)
		if !negotiated {
			readDeadline = helloDeadline
		}
		if parent, ok := ctx.Deadline(); ok && parent.Before(readDeadline) {
			readDeadline = parent
		}
		if conn.SetReadDeadline(readDeadline) != nil {
			return
		}
		body, code := readFrame(conn)
		completed := time.Now()
		if ctx.Err() != nil {
			return
		}
		if code != "" {
			s.reply(conn, nil, nil, code, time.Now().Add(frameBudget))
			return
		}
		if body == nil {
			return
		}
		obj, err := Decode(body)
		if err != nil {
			s.reply(conn, nil, nil, CCJNoncanonical, time.Now().Add(frameBudget))
			return
		}
		req, id, code := envelope(obj)
		closeAfter := false
		switch {
		case code == RequestMalformed:
		case !negotiated && req.Method != "hello":
			code = HelloRequired
		case negotiated && req.Method == "hello":
			code = HelloAlreadyNegotiated
		case code == VersionUnsupported:
			closeAfter = true
		}
		deadline := completed.Add(req.Timeout)
		if !negotiated {
			deadline = helloDeadline
		}
		if req.Timeout == 0 {
			deadline = completed.Add(frameBudget)
		}
		requestCtx, cancel := context.WithDeadline(ctx, deadline)
		var result Object
		if code == "" && requestCtx.Err() == nil {
			var peer Peer
			peer, code = s.peers.Identify(requestCtx, conn)
			if code == "" && peer.Generation == "" {
				code = "generation_source_unavailable"
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
					result, code = s.handler.Handle(requestCtx, peer, req.Method, req.Params)
				}
			}
		}
		if requestCtx.Err() != nil || !time.Now().Before(deadline) {
			code = DeadlineExceeded
			result = nil
		}
		if !negotiated && code == DeadlineExceeded {
			closeAfter = true
		}
		cancel()
		if ctx.Err() != nil {
			return
		}
		if code != "" {
			result = nil
		}
		writeDeadline := deadline
		if code != "" {
			writeDeadline = time.Now().Add(frameBudget)
		}
		if !s.reply(conn, id, result, code, writeDeadline) {
			return
		}
		if closeAfter {
			return
		}
		if code == "" && req.Method == "hello" {
			negotiated = true
		}
	}
}
func (s *Server) reply(conn net.Conn, id any, result Object, code Code, deadline time.Time) bool {
	response := Object{"request_id": id}
	if code != "" {
		if !validCode(code) {
			return false
		}
		response["error"] = Object{"code": string(code), "retryable": retryable(code)}
	} else {
		if result == nil {
			return false
		}
		response["result"] = result
	}
	if conn.SetWriteDeadline(deadline) != nil {
		return false
	}
	return writeFrame(conn, response) == nil
}
