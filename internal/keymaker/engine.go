package keymaker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

type Session struct {
	PeerKnown  bool
	Peer       Peer
	Generation string
	Binding    Binding
	Admission  Code
}
type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) take(now time.Time, rate, burst float64) bool {
	if b.last.IsZero() {
		b.tokens = burst
	} else {
		b.tokens += now.Sub(b.last).Seconds() * rate
		if b.tokens > burst {
			b.tokens = burst
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type Engine struct {
	Store       *Store
	Generations GenerationSource
	Signer      Signer
	Audit       Auditor
	closed      atomic.Bool
	failed      chan struct{}
	failOnce    sync.Once
	rateMu      sync.Mutex
	global      bucket
	peers       map[Principal]*bucket
	overload    bucket
	aggregated  uint64
	rateNow     func() time.Time
}

func NewEngine(s *Store, g GenerationSource, k Signer, a Auditor) *Engine {
	return &Engine{Store: s, Generations: g, Signer: k, Audit: a, failed: make(chan struct{}), peers: map[Principal]*bucket{}, rateNow: time.Now}
}
func (e *Engine) Failed() <-chan struct{} { return e.failed }
func (e *Engine) fail()                   { e.closed.Store(true); e.failOnce.Do(func() { close(e.failed) }) }
func (e *Engine) OpenSession(ctx context.Context, peer Peer) Session {
	s := Session{Peer: peer, PeerKnown: true}
	g, c := e.Generations.Lookup(ctx, peer.UID)
	if c != "" {
		s.Admission = c
		return s
	}
	s.Generation = g.Generation
	e.Store.mu.Lock()
	s.Binding, c = e.Store.lookup(peer.UID, g.Generation)
	e.Store.mu.Unlock()
	if c != "" {
		s.Admission = c
		return s
	}
	s.Admission = authorize(peer, s.Generation, g, s.Binding)
	return s
}
func (e *Engine) charge(s Session) Code {
	e.rateMu.Lock()
	defer e.rateMu.Unlock()
	now := e.rateNow()
	if !e.global.take(now, 200, 256) {
		return "rate_limited"
	}
	p := Principal{s.Peer.UID, s.Generation}
	b := e.peers[p]
	if b == nil {
		if len(e.peers) >= 4096 { // Evict only expired buckets; UID churn cannot grow memory indefinitely.
			for key, v := range e.peers {
				if now.Sub(v.last) > 2*time.Second {
					delete(e.peers, key)
				}
			}
			if len(e.peers) >= 4096 {
				return "busy"
			}
		}
		b = &bucket{}
		e.peers[p] = b
	}
	if !b.take(now, 20, 40) {
		return "rate_limited"
	}
	return ""
}
func (e *Engine) record(s Session, q agentRequest, body []byte, c Code) AuditRecord {
	r := AuditRecord{Surface: "agent", Operation: q.operation, Result: "success"}
	if s.PeerKnown {
		r.PeerUID = &s.Peer.UID
	}
	if r.Operation == "" {
		r.Operation = "unparsed"
	}
	if s.Generation != "" {
		r.Generation = &s.Generation
	}
	if s.Binding.Number != 0 {
		r.Path = &s.Binding.Path
		r.Epoch = &s.Binding.Epoch
	}
	if q.namespace != "" {
		r.Domain = &q.namespace
	}
	if body != nil {
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])
		r.PayloadDigest = &digest
	}
	if c != "" {
		r.Result = "refused"
		r.RefusalCode = &c
	}
	return r
}
func (e *Engine) refuse(s Session, q agentRequest, body []byte, c Code) Code {
	if e.closed.Load() {
		return "audit_unavailable"
	}
	if e.Audit.Append(e.record(s, q, body, c)) != "" {
		e.fail()
		return "audit_unavailable"
	}
	return c
}

// overloadRefusal does no parsing, hashing or signing. Over-budget traffic gets
// one aggregate journal indication/second (burst one); further refusals consume
// only a fixed, saturating in-memory counter. No request can execute on this path.
func (e *Engine) overloadRefusal(s Session, c Code) Code {
	e.rateMu.Lock()
	emit := e.overload.take(e.rateNow(), 1, 1)
	if !emit && e.aggregated < 9007199254740991 {
		e.aggregated++
	}
	e.rateMu.Unlock()
	if emit {
		return e.refuse(s, agentRequest{operation: "overload"}, nil, c)
	}
	if e.closed.Load() {
		return "audit_unavailable"
	}
	return c
}

// AggregatedRefusals counts suppressed overload journal writes for this process;
// it is bounded telemetry, not durable operation evidence or binding authority.
func (e *Engine) AggregatedRefusals() uint64 {
	e.rateMu.Lock()
	defer e.rateMu.Unlock()
	return e.aggregated
}

// RejectFrame charges bounded framing errors before journal work or input hashes.
func (e *Engine) RejectFrame(s Session, c Code) Code {
	if e.closed.Load() {
		return "audit_unavailable"
	}
	if limit := e.charge(s); limit != "" {
		return e.overloadRefusal(s, limit)
	}
	return e.refuse(s, agentRequest{}, nil, c)
}

// RejectBusy shares the same accounting as dispatched requests and framing
// errors. Saturated dispatch cannot become a separate audit-write budget.
func (e *Engine) RejectBusy(s Session, body []byte) Code {
	if e.closed.Load() {
		return "audit_unavailable"
	}
	if c := e.charge(s); c != "" {
		return e.overloadRefusal(s, c)
	}
	q, _ := parseAgent(body)
	return e.refuse(s, q, body, "busy")
}

// Handle releases a complete response only inside both the generation barrier and
// the binding lock, after durable audit. The network callback must be deadline-
// bounded. No state mutex is held while waiting for the generation dependency.
func (e *Engine) Handle(ctx context.Context, s Session, body []byte, release func([]byte) error) Code {
	if e.closed.Load() {
		return "audit_unavailable"
	}
	if c := e.charge(s); c != "" {
		return e.overloadRefusal(s, c)
	}
	q, parseCode := parseAgent(body)
	if s.Admission != "" {
		return e.refuse(s, q, body, s.Admission)
	}
	g, c := e.Generations.Lookup(ctx, s.Peer.UID)
	if c != "" {
		return e.refuse(s, q, body, c)
	}
	e.Store.mu.Lock()
	current, bc := e.Store.lookup(s.Peer.UID, s.Generation)
	e.Store.mu.Unlock()
	if bc != "" {
		return e.refuse(s, q, body, bc)
	}
	if c = authorize(s.Peer, s.Generation, g, current); c != "" {
		return e.refuse(s, q, body, c)
	}
	if current.Number != s.Binding.Number || current.Path != s.Binding.Path || current.Epoch != s.Binding.Epoch {
		return e.refuse(s, q, body, "binding_conflict")
	}
	if parseCode != "" {
		return e.refuse(s, q, body, parseCode)
	}
	if q.operation == "sign" {
		if q.flags != 0 {
			return e.refuse(s, q, body, "sign_flags_unsupported")
		}
		q.namespace, c = validatePreimage(q.data)
		if c != "" {
			return e.refuse(s, q, body, c)
		}
	}
	public, c := e.Signer.Public(current.Path)
	if c != "" {
		return e.refuse(s, q, body, c)
	}
	if len(public) != 32 {
		return e.refuse(s, q, body, "sign_key_mismatch")
	}
	blob := PublicBlob(public)
	var response []byte
	if q.operation == "pubkey" {
		payload := append([]byte{12, 0, 0, 0, 1}, SSHString(blob)...)
		payload = append(payload, SSHString([]byte("keymaker"))...)
		response = Packet(payload)
	} else {
		if !bytes.Equal(q.key, blob) {
			return e.refuse(s, q, body, "sign_key_mismatch")
		}
		if ctx.Err() != nil {
			return e.refuse(s, q, body, "request_deadline_exceeded")
		}
		sig, code := e.Signer.Sign(current.Path, q.data)
		if code != "" {
			return e.refuse(s, q, body, code)
		}
		if len(sig) != 64 {
			erase(sig)
			return e.refuse(s, q, body, "request_malformed")
		}
		signed := append(SSHString([]byte("ssh-ed25519")), SSHString(sig)...)
		response = Packet(append([]byte{14}, SSHString(signed)...))
		erase(sig)
	}
	defer erase(response)
	c = e.Generations.WithActive(ctx, s.Peer.UID, s.Generation, func() Code {
		e.Store.mu.Lock()
		defer e.Store.mu.Unlock()
		if e.closed.Load() {
			return "audit_unavailable"
		}
		if ctx.Err() != nil {
			return "request_deadline_exceeded"
		}
		b, code := e.Store.lookup(s.Peer.UID, s.Generation)
		if code != "" {
			return code
		}
		if b.Number != s.Binding.Number || b.Path != s.Binding.Path || b.Epoch != s.Binding.Epoch {
			return "binding_conflict"
		}
		if b.UID != s.Peer.UID {
			return "peer_binding_mismatch"
		}
		if e.Audit.Append(e.record(s, q, body, "")) != "" {
			e.fail()
			return "audit_unavailable"
		}
		if ctx.Err() != nil {
			return "request_deadline_exceeded"
		}
		if release(response) != nil {
			return "request_deadline_exceeded"
		}
		return ""
	})
	if c != "" {
		if c == "audit_unavailable" {
			e.fail()
			return c
		}
		return e.refuse(s, q, body, c)
	}
	return ""
}
