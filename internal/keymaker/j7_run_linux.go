//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"reflect"
	"sync"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

type j7ChannelKey struct{}
type j7Channel struct {
	conn     net.Conn
	run      string // all selection/assignment accesses are under Store's gate
	ever     bool
	ctx      context.Context
	cancel   context.CancelFunc
	watchMu  sync.Mutex
	stops    []func()
	closed   bool
	endReply *retainedRequest // Store gate; one exact self-end release, no mutation authority
}

func (c *j7Channel) active() bool { return c.ctx.Err() == nil }

// Wire lifetime outlasts self-end authority only for its committed acknowledgement.
// The permit belongs to this accepted connection and is consumed at final release.
// EOF/Scope cleanup invalidates it even if an internal caller retained the scope.
func (c *j7Channel) releasePermitted(peer Principal, r control.Request) bool {
	c.watchMu.Lock()
	closed := c.closed
	c.watchMu.Unlock()
	if closed {
		return false
	}
	if c.active() {
		return true
	}
	end := c.endReply
	if end == nil || r.Method != "j7_run_end" || end.Caller != peer || end.ID != r.ID {
		return false
	}
	args, code := requestArguments(r)
	return code == "" && end.Arguments == string(args)
}

func (c *j7Channel) stop() {
	c.cancel()
	c.watchMu.Lock()
	c.closed = true
	stops := c.stops
	c.stops = nil
	c.watchMu.Unlock()
	for _, stop := range stops {
		stop()
	}
}
func (c *j7Channel) addStop(stop func()) {
	c.watchMu.Lock()
	closed := c.closed
	if !closed {
		c.stops = append(c.stops, stop)
	}
	c.watchMu.Unlock()
	if closed {
		stop()
	}
}
func j7ChannelFrom(ctx context.Context) *j7Channel {
	c, _ := ctx.Value(j7ChannelKey{}).(*j7Channel)
	return c
}
func j7LifecycleMethod(method string) bool {
	return method == "j7_run_bind" || method == "j7_run_end" || method == "j7_run_rebind"
}

// j7Lifecycle is a lifecycle-only native adapter: no Master, Signer, private key,
// typed signing handler or enrollment service is required or constructed.
// Production startup remains closed until the external broker is qualified.
type j7Lifecycle struct {
	store       *Store
	policy      *j7Policy
	generations GenerationSource
	launcher    Principal
	channels    map[string]*j7Channel // indexed by protected retained ID, never UID
	slots       chan struct{}
	entropy     io.Reader
}

func (*j7Lifecycle) RunLifecycleOnly() {}

func newJ7Lifecycle(s *Store, p *j7Policy, g GenerationSource, launcher Principal) (*j7Lifecycle, error) {
	if s == nil || s.journal == nil || s.dir == nil || s.schema != j7Schema || s.validateJ7() != nil || p == nil || p.store != s || g == nil || !validGeneration(launcher.Generation) {
		return nil, failure("J7 lifecycle unavailable")
	}
	return &j7Lifecycle{store: s, policy: p, generations: g, launcher: launcher, channels: map[string]*j7Channel{}, slots: make(chan struct{}, 8), entropy: rand.Reader}, nil
}
func (l *j7Lifecycle) Scope(ctx context.Context, conn net.Conn) (context.Context, func()) {
	runCtx, cancel := context.WithCancel(ctx)
	c := &j7Channel{conn: conn, ctx: runCtx, cancel: cancel}
	// Keep the wire context alive for the current self-end reply. Every adapter
	// boundary separately checks authority; only its exact one-use reply survives.
	return context.WithValue(ctx, j7ChannelKey{}, c), func() {
		l.store.mu.Lock()
		if c.run != "" && l.channels[c.run] == c {
			delete(l.channels, c.run)
		}
		c.endReply = nil
		c.cancel()
		l.store.mu.Unlock()
		c.stop()
	}
}
func (l *j7Lifecycle) Identify(ctx context.Context, conn net.Conn) (control.Peer, control.Code) {
	p, code := kernelPeer(conn)
	if code != "" {
		return control.Peer{}, control.Code(code)
	}
	g, code := l.generations.Lookup(ctx, p.UID)
	if code == "" {
		code = generationCode(g, p.UID)
	}
	return control.Peer{UID: p.UID, Generation: g.Generation}, control.Code(code)
}
func (l *j7Lifecycle) Enter(ctx context.Context, conn net.Conn) (func(), control.Code) {
	if _, code := kernelPeer(conn); code != "" {
		return nil, control.Code(code)
	}
	select {
	case <-ctx.Done():
		return nil, control.DeadlineExceeded
	case l.slots <- struct{}{}:
		return func() { <-l.slots }, ""
	default:
		return nil, "busy"
	}
}
func (l *j7Lifecycle) Refuse(ctx context.Context, conn net.Conn, peer *control.Peer, r control.Request, body []byte, refusal control.Code) control.Code {
	cause := Code(refusal)
	domain := "control"
	digest := messageHash(body)
	record := AuditRecord{Surface: "control", Operation: "j7_lifecycle", Domain: &domain, PayloadDigest: &digest, Result: "refused", RefusalCode: &cause}
	if r.ID != "" {
		record.RequestID = &r.ID
	}
	if peer != nil {
		record.PeerUID = &peer.UID
		if peer.Generation != "" {
			record.Generation = &peer.Generation
		}
	}
	if code := l.store.journal.AppendContext(ctx, record); code != "" {
		return control.Code(code)
	}
	return refusal
}
func (l *j7Lifecycle) Admit(ctx context.Context, peer control.Peer, r control.Request) control.Code {
	ch := j7ChannelFrom(ctx)
	if ch == nil || !ch.active() {
		return "run_identity_unavailable"
	}
	if r.Method != "hello" && !j7LifecycleMethod(r.Method) {
		return control.OperationUnsupported
	}
	if nativePrincipal(peer) != l.launcher {
		return "role_not_permitted"
	}
	if !l.store.mu.LockContext(ctx) {
		return control.DeadlineExceeded
	}
	defer l.store.mu.Unlock()
	if !ch.active() {
		return "run_identity_unavailable"
	}
	_, code := l.store.retained(nativePrincipal(peer), r)
	return control.Code(code)
}

type j7BindArguments struct {
	Identity uint64    `json:"identity_registration_number"`
	Origin   *j7Origin `json:"origin"`
	Parent   string    `json:"parent_run"`
	Input    Principal `json:"input_principal"`
}

func (l *j7Lifecycle) run(id string) *j7Run {
	for i := range l.store.j7.Runs {
		if l.store.j7.Runs[i].ID == id {
			return &l.store.j7.Runs[i]
		}
	}
	return nil
}
func j7DecodeArgs(params control.Object, v any) Code {
	raw, err := canonical(params)
	if err != nil || messageRequired(raw, reflect.TypeOf(v).Elem()) != nil || StrictJSON(bytes.NewReader(raw), v) != nil {
		return "request_malformed"
	}
	return ""
}
func (l *j7Lifecycle) Handle(ctx context.Context, peer control.Peer, r control.Request) (control.Object, control.Code) {
	ch := j7ChannelFrom(ctx)
	if ch == nil || !ch.active() {
		return nil, "run_identity_unavailable"
	}
	if !j7LifecycleMethod(r.Method) {
		return nil, control.OperationUnsupported
	}
	if nativePrincipal(peer) != l.launcher {
		return nil, "role_not_permitted"
	}
	var args j7BindArguments
	var id string
	var selected Binding
	var saved j7Run
	if r.Method == "j7_run_bind" {
		if code := j7DecodeArgs(r.Params, &args); code != "" {
			return nil, control.Code(code)
		}
		if args.Identity != l.policy.identity || args.Input.UID == 0 || !validGeneration(args.Input.Generation) || args.Input.UID == l.launcher.UID || (args.Parent == "") != (args.Origin != nil) || args.Origin != nil && !args.Origin.valid() {
			return nil, control.RequestMalformed
		}
	} else {
		var arg struct {
			ID string `json:"run_id"`
		}
		if code := j7DecodeArgs(r.Params, &arg); code != "" || !messageID(arg.ID) {
			return nil, control.RequestMalformed
		}
		id = arg.ID
	}
	if !l.store.mu.LockContext(ctx) {
		return nil, control.DeadlineExceeded
	}
	if !ch.active() {
		l.store.mu.Unlock()
		return nil, "run_identity_unavailable"
	}
	if l.store.failed || l.store.j7 == nil {
		l.store.mu.Unlock()
		return nil, "j7_state_fenced"
	}
	if r.Method == "j7_run_bind" {
		for _, b := range l.store.records {
			if b.Number == args.Identity {
				selected = b
			}
		}
	} else if row := l.run(id); row != nil {
		saved = *row
		selected = row.Binding
	}
	var priorExists bool
	if prior, code := l.store.retained(nativePrincipal(peer), r); code != "" {
		l.store.mu.Unlock()
		return nil, control.Code(code)
	} else {
		priorExists = prior != nil
	}
	l.store.mu.Unlock()
	if selected.Number == 0 {
		return nil, "binding_not_found"
	}
	if r.Method == "j7_run_bind" && args.Input.UID == selected.UID {
		return nil, "run_identity_unavailable"
	}
	conditions := []GenerationCondition{{Principal: l.launcher}}
	if r.Method != "j7_run_end" {
		conditions = append(conditions, GenerationCondition{Principal: Principal{selected.UID, selected.Generation}})
		input := args.Input
		if r.Method != "j7_run_bind" {
			input = saved.Input
		}
		conditions = append(conditions, GenerationCondition{Principal: input})
	}
	var nonce [16]byte
	if r.Method == "j7_run_bind" && !priorExists {
		if l.entropy == nil {
			return nil, "entropy_unavailable"
		}
		if _, err := io.ReadFull(l.entropy, nonce[:]); err != nil {
			return nil, "entropy_unavailable"
		}
		id = hex.EncodeToString(nonce[:])
	}
	var result control.Object
	var bound *j7Run
	var ended *j7Channel
	code := l.generations.WithEvidence(ctx, conditions, func(ctx context.Context) Code {
		effect := func(_ *j7PolicyTable) Code {
			s := l.store
			if !ch.active() {
				return "run_identity_unavailable"
			}
			if s.failed || s.j7 == nil || s.j7.Pending {
				return "j7_state_fenced"
			}
			prior, code := s.retained(nativePrincipal(peer), r)
			if code != "" {
				return code
			}
			if prior != nil {
				obj, code := s.resultObject(prior)
				if code != "" {
					return code
				}
				rid, _ := obj["run_id"].(string)
				run := l.run(rid)
				if run == nil {
					return "j7_state_fenced"
				}
				if r.Method != "j7_run_end" && (run.State != "live" || ch.run != rid || l.channels[rid] != ch) {
					return "run_identity_unavailable"
				}
				result = obj
				return ""
			}
			previous := s.j7
			s.j7 = cloneJ7(s.j7)
			effectStarted := false
			defer func() {
				if !effectStarted {
					s.j7 = previous
				}
			}()
			switch r.Method {
			case "j7_run_bind":
				if ch.ever || ch.run != "" || l.run(id) != nil || len(s.j7.Runs) >= j7HistoryLimit {
					return "run_identity_unavailable"
				}
				current, c := s.lookup(selected.UID, selected.Generation)
				if c != "" {
					return c
				}
				if current != selected {
					return "binding_conflict"
				}
				for _, run := range s.j7.Runs {
					if run.State == "live" && run.Input.UID == args.Input.UID {
						return "run_identity_unavailable"
					}
				}
				var origin j7Origin
				if args.Origin != nil {
					origin = *args.Origin
				} else {
					parent := l.run(args.Parent)
					if parent == nil || parent.State != "live" || parent.Binding != selected {
						return "run_identity_unavailable"
					}
					origin = parent.Origin
				}
				row := j7Run{ID: id, Binding: selected, Origin: origin, Launcher: l.launcher, Input: args.Input, Parent: args.Parent, State: "live"}
				s.j7.Runs = append(s.j7.Runs, row)
				bound = &row
			case "j7_run_rebind":
				row := l.run(id)
				if row == nil || row.State != "live" || row.Launcher != l.launcher || ch.ever || l.channels[id] != nil {
					return "run_identity_unavailable"
				}
				current, c := s.lookup(row.Binding.UID, row.Binding.Generation)
				if c != "" {
					return c
				}
				if current != row.Binding {
					return "binding_conflict"
				}
				copy := *row
				bound = &copy
			case "j7_run_end":
				// The currently configured launcher may retire old history after
				// an operator-approved launcher incarnation change. This grants
				// no rebind/adoption and never rewrites the original principal.
				row := l.run(id)
				if row == nil {
					return "run_identity_unavailable"
				}
				row.State = "ended"
				ended = l.channels[id]
			}
			state := "live"
			if r.Method == "j7_run_end" {
				state = "ended"
			}
			result = control.Object{"run_id": id, "state": state}
			encoded, err := control.Marshal(result)
			if err != nil {
				return "j7_state_fenced"
			}
			arguments, c := requestArguments(r)
			if c != "" {
				return c
			}
			entry := retainedRequest{Caller: l.launcher, ID: r.ID, Method: r.Method, Arguments: string(arguments), Status: "committed", Result: encoded}
			prospective := append(append([]retainedRequest{}, s.requests...), entry)
			if !s.fitsState(s.records, s.next, prospective) {
				return "state_capacity_exceeded"
			}
			effectStarted = true
			s.appendRequest(entry)
			if c := s.commitJ7(ctx); c != "" {
				return c
			}
			if bound != nil {
				ch.run = id
				ch.ever = true
				l.channels[id] = ch
			}
			if ended != nil {
				delete(l.channels, id)
				ended.cancel()
				if ended == ch {
					ch.endReply = &entry
				} else {
					_ = ended.conn.Close()
				}
			}
			return ""
		}
		if r.Method == "j7_run_end" {
			return l.policy.locked(ctx, func() Code {
				if !l.store.mu.LockContext(ctx) {
					return "request_deadline_exceeded"
				}
				defer l.store.mu.Unlock()
				return effect(nil)
			})
		}
		return l.policy.withTable(ctx, effect)
	})
	if code != "" {
		return nil, control.Code(code)
	}
	if bound != nil {
		l.watch(ch, *bound)
	}
	return result, ""
}
func (l *j7Lifecycle) watch(ch *j7Channel, run j7Run) {
	// Register identity withdrawal under the same Store gate as exact selection.
	// Stop callbacks run after releasing that gate to avoid recursive acquisition.
	l.store.mu.Lock()
	current, code := l.store.lookup(run.Binding.UID, run.Binding.Generation)
	if code != "" || current != run.Binding {
		l.store.mu.Unlock()
		ch.cancel()
		_ = ch.conn.Close()
		return
	}
	bindingChange, bindingStop := l.store.watchLocked(run.Binding.Number)
	l.store.mu.Unlock()
	ch.addStop(bindingStop)
	go func() {
		select {
		case <-bindingChange:
			ch.cancel()
			_ = ch.conn.Close()
		case <-ch.ctx.Done():
		}
	}()

	for _, p := range []Principal{run.Launcher, run.Input, {run.Binding.UID, run.Binding.Generation}} {
		change, stop := l.generations.Watch(p.UID, p.Generation)
		ch.addStop(stop)
		go func() {
			select {
			case <-change:
				ch.cancel()
				_ = ch.conn.Close()
			case <-ch.ctx.Done():
			}
		}()
	}
}
func (l *j7Lifecycle) WithActive(ctx context.Context, peer control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	ch := j7ChannelFrom(ctx)
	if ch == nil {
		return "run_identity_unavailable"
	}
	conditions := []GenerationCondition{{Principal: nativePrincipal(peer)}}
	if !l.store.mu.LockContext(ctx) {
		return control.DeadlineExceeded
	}
	if !ch.releasePermitted(nativePrincipal(peer), r) {
		l.store.mu.Unlock()
		return "run_identity_unavailable"
	}
	selfEnd := ch.endReply != nil
	if r.Method != "hello" && (r.Method != "j7_run_end" || selfEnd) {
		id, _ := result["run_id"].(string)
		row := l.run(id)
		if row == nil {
			l.store.mu.Unlock()
			return "run_identity_unavailable"
		}
		conditions = append(conditions, GenerationCondition{Principal: row.Input}, GenerationCondition{Principal: Principal{row.Binding.UID, row.Binding.Generation}})
	}
	l.store.mu.Unlock()
	code := l.generations.WithEvidence(ctx, conditions, func(ctx context.Context) Code {
		return l.policy.locked(ctx, func() Code {
			s := l.store
			if !s.mu.LockContext(ctx) {
				return "request_deadline_exceeded"
			}
			defer s.mu.Unlock()
			if !ch.releasePermitted(nativePrincipal(peer), r) {
				return "run_identity_unavailable"
			}
			if s.failed || s.j7 == nil || s.j7.Pending {
				return "j7_state_fenced"
			}
			p := nativePrincipal(peer)
			if p != l.launcher {
				return "role_not_permitted"
			}
			if r.Method != "hello" {
				if p != l.launcher {
					return "role_not_permitted"
				}
				id, _ := result["run_id"].(string)
				row := l.run(id)
				if row == nil {
					return "run_identity_unavailable"
				}
				if r.Method != "j7_run_end" || selfEnd {
					if !selfEnd && (row.State != "live" || ch.run != id || l.channels[id] != ch || !ch.active()) {
						return "run_identity_unavailable"
					}
					b, c := s.lookup(row.Binding.UID, row.Binding.Generation)
					if c != "" {
						return c
					}
					if b != row.Binding {
						return "binding_conflict"
					}
				}
				prior, c := s.retained(p, r)
				if c != "" || prior == nil {
					return "j7_state_fenced"
				}
				encoded, err := control.Marshal(result)
				if err != nil || string(prior.Result) != string(encoded) {
					return "request_conflict"
				}
				if selfEnd {
					// Consumption precedes the callback, including its error path.
					// Input/station generation and binding checks above also prevent
					// this reply permit from surviving subsequent retirement.
					ch.endReply = nil
					defer ch.conn.Close()
				}
			} else {
				args, c := requestArguments(r)
				if c != "" {
					return c
				}
				encoded, err := control.Marshal(result)
				if err != nil {
					return "request_malformed"
				}
				prior, c := s.retained(p, r)
				if c != "" {
					return c
				}
				if prior != nil {
					return "request_conflict"
				}
				entry := retainedRequest{Caller: p, ID: r.ID, Method: r.Method, Arguments: string(args), Status: "committed", Result: encoded}
				prospective := append(append([]retainedRequest{}, s.requests...), entry)
				if !s.fitsState(s.records, s.next, prospective) {
					return "state_capacity_exceeded"
				}
				s.appendRequest(entry)
				if c := s.commitJ7(ctx); c != "" {
					return c
				}
			}
			domain := "control"
			operation := "j7_lifecycle"
			request := r.ID
			if c := s.journal.AppendContext(ctx, AuditRecord{Surface: "control", Operation: operation, Domain: &domain, RequestID: &request, PeerUID: &peer.UID, Generation: &peer.Generation, Result: "success"}); c != "" {
				s.failed = true
				return c
			}
			return Code(release(ctx))
		})
	})
	return control.Code(code)
}
