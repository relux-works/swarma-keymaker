package keymaker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

// OperatorActVerifier is trusted injected authority. Production supplies nil
// until the signed-act format, pins and replay rules are published. No wire
// boolean or document member can instantiate a verifier.
type OperatorActVerifier interface {
	Verify(context.Context, Principal, Binding, []byte) Code
}
type NativeConfig struct {
	Helper                  *RegistrationHelper
	Operator                Principal
	Registry                Registry
	Epoch, RegistryRevision string
}
type Native struct {
	Engine    *Engine
	Config    NativeConfig
	verifier  OperatorActVerifier
	slots     chan struct{}
	rateMu    sync.Mutex
	mutations map[Principal]*bucket
	helperMu  sync.Mutex
	helpers   map[string]*bucket
}

// Connection state is private to one sequential control loop. It is never wire
// data or shared across connections. Mutations pin no station identity; pubkey
// pins the first self binding and subscribes while the Store lock is held.
type nativeConnectionKey struct{}
type nativeConnection struct {
	custodyCause  custodyCause
	conn          net.Conn
	done          <-chan struct{}
	binding       uint64
	cancelBinding func()
	requestID     string
	conditions    []GenerationCondition
	prepared      bool
}

func (c *nativeConnection) close() {
	if c.cancelBinding != nil {
		c.cancelBinding()
	}
}
func connectionFrom(ctx context.Context) *nativeConnection {
	c, _ := ctx.Value(nativeConnectionKey{}).(*nativeConnection)
	return c
}
func (c *nativeConnection) pin(s *Store, b Binding) Code {
	if c.binding != 0 && c.binding != b.Number {
		return "identity_revoked"
	}
	if c.binding == 0 {
		c.binding = b.Number
		change, cancel := s.watchLocked(b.Number)
		c.cancelBinding = cancel
		go func() {
			select {
			case <-change:
				c.conn.Close()
			case <-c.done:
			}
		}()
	}
	return ""
}
func (c *nativeConnection) bindingActive(s *Store) Code {
	if c.binding == 0 {
		return ""
	}
	for _, b := range s.records {
		if b.Number == c.binding && b.Status == "active" {
			return ""
		}
	}
	return "identity_revoked"
}

func NewNative(e *Engine, cfg NativeConfig, v OperatorActVerifier, slots chan struct{}) (*Native, error) {
	if e == nil {
		return nil, failure("native dependencies unavailable")
	}
	audit, paired := e.Audit.(*Journal)
	if !paired || e.Store == nil || e.Store.dir == nil || e.Store.journal == nil || audit != e.Store.journal || e.Generations == nil || e.Signer == nil || !validGeneration(cfg.Operator.Generation) || cfg.Epoch == "" || cfg.RegistryRevision == "" || cfg.Registry.Validate() != "" || slots == nil {
		return nil, failure("native dependencies unavailable")
	}
	return &Native{Engine: e, Config: cfg, verifier: v, slots: slots, mutations: map[Principal]*bucket{}, helpers: map[string]*bucket{}}, nil
}
func nativePrincipal(p control.Peer) Principal { return Principal{p.UID, p.Generation} }
func generationCode(g Generation, uid uint32) Code {
	if g.UID != uid || !g.Verified || g.Fenced || g.Provenance == "" || g.Revision == "" || !validGeneration(g.Generation) {
		return "generation_source_unavailable"
	}
	if g.State != "active" {
		return "generation_inactive"
	}
	return ""
}
func (n *Native) Identify(ctx context.Context, conn net.Conn) (control.Peer, control.Code) {
	p, c := kernelPeer(conn)
	if c != "" {
		return control.Peer{}, control.Code(c)
	}
	g, c := n.Engine.Generations.Lookup(ctx, p.UID)
	if c == "" {
		c = generationCode(g, p.UID)
	}
	if c != "" {
		return control.Peer{}, control.Code(c)
	}
	return control.Peer{UID: p.UID, Generation: g.Generation}, ""
}
func (n *Native) operator(p Principal) Code {
	if p != n.Config.Operator {
		return "role_not_permitted"
	}
	return ""
}
func (n *Native) Enter(ctx context.Context, conn net.Conn) (func(), control.Code) {
	if n.Engine.closed.Load() {
		return nil, "audit_unavailable"
	}
	p, c := kernelPeer(conn)
	if c != "" {
		return nil, control.Code(c)
	}
	// Evidence here scopes workload only; Identify and the final barrier establish
	// authority independently. Unavailable evidence never grants execution.
	g, _ := n.Engine.Generations.Lookup(ctx, p.UID)
	if c = n.Engine.charge(Session{Peer: p, Generation: g.Generation}); c != "" {
		return nil, control.Code(c)
	}
	select {
	case n.slots <- struct{}{}:
		return func() { <-n.slots }, ""
	default:
		return nil, "busy"
	}
}
func (n *Native) record(p *control.Peer, r control.Request, body []byte, c Code) AuditRecord {
	domain := "control"
	if r.Method == "sign_registration" {
		domain = "registration/1"
	}
	out := AuditRecord{Surface: "control", Operation: r.Method, Domain: &domain, Result: "success"}
	switch out.Operation {
	case "hello", "pubkey", "register", "revoke", "sign_registration", "sign", "decrypt", "overload":
	default:
		out.Operation = "unparsed"
	}
	if r.ID != "" {
		out.RequestID = &r.ID
	}
	if p != nil {
		out.PeerUID = &p.UID
		if p.Generation != "" {
			out.Generation = &p.Generation
		}
	}
	if body != nil {
		sum := sha256.Sum256(body)
		digest := hex.EncodeToString(sum[:])
		out.PayloadDigest = &digest
	}
	if c != "" {
		out.Result = "refused"
		out.RefusalCode = &c
	}
	return out
}
func (n *Native) audit(record AuditRecord) Code {
	return n.auditContext(context.Background(), record)
}
func (n *Native) auditContext(ctx context.Context, record AuditRecord) Code {
	if n.Engine.closed.Load() {
		return "audit_unavailable"
	}
	if auditContextExpired(ctx) {
		return "request_deadline_exceeded"
	}
	c := n.Engine.Audit.AppendContext(ctx, record)
	if c == "request_deadline_exceeded" {
		return c
	}
	if n.Engine.closed.Load() || c != "" {
		n.Engine.fail()
		return "audit_unavailable"
	}
	return ""
}
func (n *Native) Refuse(ctx context.Context, conn net.Conn, p *control.Peer, r control.Request, body []byte, refusal control.Code) control.Code {
	// The wire supplies the remaining admission budget or a separate bounded
	// refusal-report budget. An append already begun still owns its durable sync.
	if auditContextExpired(ctx) {
		return control.DeadlineExceeded
	}
	if p == nil {
		if kernel, c := kernelPeer(conn); c == "" {
			p = &control.Peer{UID: kernel.UID}
		}
	}
	if refusal == "rate_limited" || refusal == "busy" {
		e := n.Engine
		e.rateMu.Lock()
		emit := e.overload.take(e.rateNow(), 1, 1)
		if !emit && e.aggregated < 9007199254740991 {
			e.aggregated++
		}
		e.rateMu.Unlock()
		if !emit {
			if e.closed.Load() {
				return "audit_unavailable"
			}
			return refusal
		}
		r = control.Request{Method: "overload"}
		body = nil
	}
	if n.Engine.closed.Load() {
		return "audit_unavailable"
	}
	record := n.record(p, r, body, Code(refusal))
	if connection := connectionFrom(ctx); connection != nil {
		record.CustodyCause = auditCustodyCause(Code(refusal), connection.custodyCause)
	}
	c := n.Engine.Audit.AppendContext(ctx, record)
	if c == "request_deadline_exceeded" {
		// No append began. Caller closes without a result; a healthy journal stays
		// usable. Actual write/sync failures below still fence both surfaces.
		return control.Code(c)
	}
	if c != "" {
		n.Engine.fail()
		return "audit_unavailable"
	}
	return refusal
}

// Admit consults durable state. The coordinator repeats this check atomically
// with intent/result persistence; concurrent connections cannot race the hint.
func (n *Native) Admit(ctx context.Context, p control.Peer, r control.Request) control.Code {
	if auditContextExpired(ctx) {
		return control.DeadlineExceeded
	}
	principal := nativePrincipal(p)
	connection := connectionFrom(ctx)
	if connection == nil {
		return "peer_identity_unavailable"
	}
	connection.requestID, connection.prepared = r.ID, false
	connection.custodyCause = ""
	connection.conditions = []GenerationCondition{{Principal: principal}}
	if mutation(r.Method) {
		if c := n.operator(principal); c != "" {
			return control.Code(c)
		}
		if c := n.mutationCredit(principal); c != "" {
			return control.Code(c)
		}
	}
	n.Engine.Store.mu.Lock()
	defer n.Engine.Store.mu.Unlock()
	if c := connection.bindingActive(n.Engine.Store); c != "" {
		return control.Code(c)
	}
	prior, c := n.Engine.Store.retained(principal, r)
	if c != "" {
		return control.Code(c)
	}
	if prior != nil && !mutation(r.Method) && r.Method != "sign_registration" {
		return control.RequestConflict
	}
	return ""
}
func exactMembers(obj control.Object, keys ...string) bool {
	if len(obj) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := obj[k]; !ok {
			return false
		}
	}
	return true
}
func resultFor(public []byte, b Binding) control.Object {
	return control.Object{"public_key": base64.StdEncoding.EncodeToString(public), "path": b.Path, "registration_number": int64(b.Number), "master_epoch": b.Epoch}
}
func (n *Native) Handle(ctx context.Context, peer control.Peer, r control.Request) (control.Object, control.Code) {
	connection := connectionFrom(ctx)
	if connection == nil || connection.requestID != r.ID {
		return nil, "peer_identity_unavailable"
	}
	if r.Method == "sign_registration" {
		return n.signRegistration(ctx, peer, r)
	}
	if r.Method == "pubkey" {
		if len(r.Params) != 0 {
			return nil, control.RequestMalformed
		}
		n.Engine.Store.mu.Lock()
		defer n.Engine.Store.mu.Unlock()
		b, c := n.Engine.Store.lookup(peer.UID, peer.Generation)
		if c != "" {
			return nil, control.Code(c)
		}
		if c := connection.pin(n.Engine.Store, b); c != "" {
			return nil, control.Code(c)
		}
		public, c, cause := publicForAudit(n.Engine.Signer, b.Path)
		connection.custodyCause = cause
		if c != "" {
			return nil, control.Code(c)
		}
		if len(public) != 32 {
			return nil, "sign_key_mismatch"
		}
		return resultFor(public, b), ""
	}
	if !mutation(r.Method) {
		return nil, control.OperationUnsupported
	}
	p := nativePrincipal(peer)
	if c := n.operator(p); c != "" {
		return nil, control.Code(c)
	}
	// A replay needs current caller authority, not a still-unbound target. It
	// returns the original result even if later transactions changed that target.
	var replay control.Object
	c := n.Engine.Generations.WithActive(ctx, p.UID, p.Generation, func(ctx context.Context) Code {
		s := n.Engine.Store
		if !s.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		defer s.mu.Unlock()
		if c := connection.bindingActive(s); c != "" {
			return c
		}
		old, c := s.retained(p, r)
		if c != "" {
			return c
		}
		if old != nil {
			replay, c = s.resultObject(old)
			return c
		}
		return ""
	})
	if c != "" || replay != nil {
		connection.prepared = c == "" && replay != nil
		return replay, control.Code(c)
	}
	plan, planCode := n.plan(ctx, p, r)
	conditions := []GenerationCondition{{Principal: p}}
	if plan.target != nil {
		conditions = append(conditions, *plan.target)
	}
	// Observe the target predicate under the same generation barrier as the
	// caller, but defer its refusal until after retained-result selection. An
	// earlier lookup is only a fast replay path: it cannot decide that execution
	// is fresh. Another connection can commit that ID while this one waits for
	// the barrier. The authoritative lookup and fresh-target gate below both
	// hold Store.mu inside that barrier, with no intervening commit possible.
	effectConditions := append([]GenerationCondition(nil), conditions...)
	targetCode := Code("generation_source_unavailable")
	if plan.target != nil {
		effectConditions[1].Verdict = &targetCode
	}
	var result control.Object
	c = n.Engine.Generations.WithEvidence(ctx, effectConditions, func(ctx context.Context) Code {
		s := n.Engine.Store
		if !s.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		defer s.mu.Unlock()
		if c := connection.bindingActive(s); c != "" {
			return c
		}
		old, c := s.retained(p, r)
		if c != "" {
			return c
		}
		if old != nil {
			result, c = s.resultObject(old)
			connection.prepared = c == ""
			return c
		}
		if planCode != "" {
			return planCode
		}
		if plan.target != nil && targetCode != "" {
			return targetCode
		}
		if auditContextExpired(ctx) {
			return "request_deadline_exceeded"
		}
		records := append([]Binding(nil), s.records...)
		next := s.next
		b := plan.binding
		if r.Method == "register" {
			for _, old := range records {
				if old.Epoch == b.Epoch && old.Path == b.Path && old.Status == "revoked" {
					return "identity_revoked"
				}
			}
			b.Number = next
			b.Status = "active"
			b.Registrar = p
			next++
			records = append(records, b)
		} else {
			found := false
			for i, old := range records {
				if old.Number == b.Number {
					if old != b {
						return "binding_conflict"
					}
					records[i].Status = "revoked"
					found = true
					break
				}
			}
			if !found {
				return "binding_not_found"
			}
		}
		if c := validateBindings(records, next); c != "" {
			return c
		}
		if r.Method == "register" {
			public, c, cause := publicForAudit(n.Engine.Signer, b.Path)
			connection.custodyCause = cause
			if c != "" {
				return c
			}
			if len(public) != 32 {
				return "sign_key_mismatch"
			}
			result = resultFor(public, b)
		} else {
			result = control.Object{"registration_number": int64(b.Number), "status": "revoked"}
		}
		args, _ := requestArguments(r)
		encoded, err := control.Marshal(result)
		if err != nil {
			return "request_malformed"
		}
		entry := retainedRequest{Caller: p, ID: r.ID, Method: r.Method, Arguments: string(args), Status: "committed", Result: encoded}
		prospective := append(append([]retainedRequest(nil), s.requests...), entry)
		if !s.fitsState(records, next, prospective) {
			return "state_capacity_exceeded"
		}
		// Operation evidence precedes the intent. The two following cross-bound
		// commits either retain an unresolved intent (startup fences) or bind the
		// effect and result together. Raw arguments stay in protected result state.
		audit := n.record(&peer, r, args, "")
		audit.Result = "unknown"
		audit.Path = &b.Path
		audit.Epoch = &b.Epoch
		if c := n.auditContext(ctx, audit); c != "" {
			return c
		}
		entry.Status = "pending"
		entry.Result = json.RawMessage("null")
		s.appendRequest(entry)
		if c := s.persistContext(ctx); c != "" {
			s.failed = true
			n.Engine.fail()
			return c
		}
		if auditContextExpired(ctx) {
			s.failed = true
			n.Engine.fail()
			return "audit_unavailable"
		}
		s.records, s.next = records, next
		entry.Status = "committed"
		entry.Result = encoded
		s.requests[len(s.requests)-1] = entry
		if c := s.persistContext(ctx); c != "" {
			s.failed = true
			n.Engine.fail()
			return c
		}
		if r.Method == "revoke" {
			s.notify(b.Number)
		}
		// Only this fresh effect carries target evidence to its first release.
		// An exact historical replay retains caller-only authority conditions.
		connection.conditions = conditions
		connection.prepared = true
		return ""
	})
	return result, control.Code(c)
}
func (n *Native) mutationCredit(p Principal) Code {
	n.rateMu.Lock()
	defer n.rateMu.Unlock()
	now := n.Engine.rateNow()
	b := n.mutations[p]
	if b == nil {
		if len(n.mutations) >= 4096 {
			for key, v := range n.mutations {
				if now.Sub(v.last) > 2*time.Second {
					delete(n.mutations, key)
				}
			}
			if len(n.mutations) >= 4096 {
				return "busy"
			}
		}
		b = &bucket{}
		n.mutations[p] = b
	}
	if !b.take(now, 2, 4) {
		return "rate_limited"
	}
	return ""
}

type nativePlan struct {
	binding Binding
	target  *GenerationCondition
}

func (n *Native) plan(ctx context.Context, p Principal, r control.Request) (nativePlan, Code) {
	if r.Method == "register" {
		if !exactMembers(r.Params, "target_uid", "target_generation", "owner", "names", "lifetime") {
			return nativePlan{}, "request_malformed"
		}
		uid, uok := r.Params["target_uid"].(int64)
		gen, gok := r.Params["target_generation"].(string)
		owner, ook := r.Params["owner"].(string)
		life, lok := r.Params["lifetime"].(string)
		names, nok := r.Params["names"].(control.Object)
		if !uok || uid < 0 || uid > 4294967295 || !gok || gen == "" || !ook || owner == "" || !lok || (life != "ephemeral" && life != "persistent") || !nok || !exactMembers(names, "purpose", "product", "project", "agent") {
			return nativePlan{}, "request_malformed"
		}
		var resolved Names
		fields := []*string{&resolved.Purpose, &resolved.Product, &resolved.Project, &resolved.Agent}
		for i, key := range []string{"purpose", "product", "project", "agent"} {
			value, ok := names[key].(string)
			if !ok {
				return nativePlan{}, "request_malformed"
			}
			*fields[i] = value
		}
		if resolved.Purpose != "agent-identity" {
			return nativePlan{}, "purpose_unknown"
		}
		path, c := n.Config.Registry.Resolve(resolved)
		if c != "" {
			return nativePlan{}, c
		}
		b := Binding{UID: uint32(uid), Generation: gen, Owner: owner, Lifetime: life, Path: path, Epoch: n.Config.Epoch, RegistryRevision: n.Config.RegistryRevision}
		return nativePlan{binding: b, target: &GenerationCondition{Principal: Principal{b.UID, gen}}}, ""
	}
	if !exactMembers(r.Params, "registration_number", "mode", "operator_record") {
		return nativePlan{}, "request_malformed"
	}
	number, ok := r.Params["registration_number"].(int64)
	mode, mok := r.Params["mode"].(string)
	if !ok || number < 1 || !mok || (mode != "ephemeral" && mode != "operator") {
		return nativePlan{}, "request_malformed"
	}
	s := n.Engine.Store
	s.mu.Lock()
	var b Binding
	for _, candidate := range s.records {
		if candidate.Number == uint64(number) {
			b = candidate
			break
		}
	}
	s.mu.Unlock()
	if b.Number == 0 {
		return nativePlan{}, "binding_not_found"
	}
	if b.Status == "revoked" {
		return nativePlan{}, "identity_revoked"
	}
	if b.Lifetime == "persistent" && mode == "ephemeral" {
		return nativePlan{}, "persistent_revoke_requires_operator"
	}
	if mode == "ephemeral" {
		if r.Params["operator_record"] != nil {
			return nativePlan{}, "request_malformed"
		}
		if b.Registrar != p {
			return nativePlan{}, "role_not_permitted"
		}
		return nativePlan{binding: b, target: &GenerationCondition{Principal: Principal{b.UID, b.Generation}, Retired: true}}, ""
	}
	if _, ok := r.Params["operator_record"].(control.Object); r.Params["operator_record"] != nil && !ok {
		return nativePlan{}, "request_malformed"
	}
	if n.verifier == nil || r.Params["operator_record"] == nil {
		return nativePlan{}, "operator_record_unavailable"
	}
	args, c := requestArguments(r)
	if c != "" {
		return nativePlan{}, c
	}
	if c = n.verifier.Verify(ctx, p, b, args); c != "" {
		return nativePlan{}, c
	}
	return nativePlan{binding: b}, ""
}

// The actual write remains inside one authority barrier and the Store lock. No lookup
// outside that barrier authorizes release; hello deliberately needs no binding.
func (n *Native) WithActive(ctx context.Context, peer control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	p := nativePrincipal(peer)
	connection := connectionFrom(ctx)
	if connection == nil || connection.requestID != r.ID {
		return "peer_identity_unavailable"
	}
	var conditions []GenerationCondition
	if mutation(r.Method) {
		if !connection.prepared {
			return "audit_unavailable"
		}
		conditions = connection.conditions
	}
	c := n.releaseFence(ctx, p, conditions, func(ctx context.Context) Code {
		s := n.Engine.Store
		if !s.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		defer s.mu.Unlock()
		if s.failed || n.Engine.closed.Load() {
			return "audit_unavailable"
		}
		if auditContextExpired(ctx) {
			return "request_deadline_exceeded"
		}
		if c := connection.bindingActive(s); c != "" {
			return c
		}
		if mutation(r.Method) {
			if c := n.operator(p); c != "" {
				return c
			}
		}
		if r.Method == "pubkey" {
			b, c := s.lookup(p.UID, p.Generation)
			if c != "" {
				return c
			}
			if result["path"] != b.Path || result["master_epoch"] != b.Epoch || result["registration_number"] != int64(b.Number) {
				return "binding_conflict"
			}
		}
		if r.Method == "sign_registration" {
			return n.releaseRegistration(ctx, peer, r, result, release)
		}
		prior, c := s.retained(p, r)
		if c != "" {
			return c
		}
		encoded, err := control.Marshal(result)
		if err != nil {
			return "request_malformed"
		}
		if mutation(r.Method) {
			if prior == nil || !bytes.Equal(prior.Result, encoded) {
				return "audit_unavailable"
			}
		} else {
			if prior != nil {
				return "request_conflict"
			}
			args, c := requestArguments(r)
			if c != "" {
				return c
			}
			entry := retainedRequest{Caller: p, ID: r.ID, Method: r.Method, Arguments: string(args), Status: "committed", Result: encoded}
			prospective := append(append([]retainedRequest(nil), s.requests...), entry)
			if !s.fitsState(s.records, s.next, prospective) {
				return "state_capacity_exceeded"
			}
			s.appendRequest(entry)
			if c := s.persistContext(ctx); c != "" {
				s.failed = true
				n.Engine.fail()
				return c
			}
		}
		args, _ := requestArguments(r)
		record := n.record(&peer, r, args, "")
		if path, ok := result["path"].(string); ok {
			record.Path = &path
		}
		if epoch, ok := result["master_epoch"].(string); ok {
			record.Epoch = &epoch
		}
		if c := n.auditContext(ctx, record); c != "" {
			return c
		}
		if auditContextExpired(ctx) {
			return "request_deadline_exceeded"
		}
		return Code(release(ctx))
	})
	return control.Code(c)
}

func (n *Native) releaseFence(ctx context.Context, p Principal, conditions []GenerationCondition, release func(context.Context) Code) Code {
	if conditions != nil {
		return n.Engine.Generations.WithEvidence(ctx, conditions, release)
	}
	return n.Engine.Generations.WithActive(ctx, p.UID, p.Generation, release)
}
