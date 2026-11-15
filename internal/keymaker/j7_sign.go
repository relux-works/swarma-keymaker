//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-keymaker/internal/control"
)

// Node and policy pins come from trusted construction, never request evidence.
// Check performs the adopted complete v3 verifier, not caller-supplied liveness.
// The receiver must still repeat its own admission; observation is not atomic
// with a later chain effect. No production startup constructs this adapter.
type j7RentalAuthority struct {
	node     su.Node
	policies map[string]rental.Policy
}

func (a *j7RentalAuthority) check(ctx context.Context, g rental.SignedGrant, e j7Evidence, now int64) Code {
	if a == nil || a.node == nil {
		return "delegation_evidence_unavailable"
	}
	p, ok := a.policies[g.Grant.AgentName]
	if !ok || p.AgentName != g.Grant.AgentName || p.LandlordName != g.Grant.LandlordName || p.Network != g.Grant.Network || p.Genesis != g.Grant.Genesis || p.IssuerPubkey != g.Grant.IssuerKey {
		return "delegation_evidence_unavailable"
	}
	raw, err := json.Marshal(rental.GrantPresentation{SignedGrant: g, Issuance: rental.IssuanceProof{TxID: e.Issuance}})
	if err != nil {
		return "request_malformed"
	}
	receipt := rental.Check(ctx, a.node, p, raw, g.Grant.AgentName, g.Grant.GranteeKey, now)
	if receipt.Verdict != "live" || receipt.Reason != "LIVE" || receipt.Closed || receipt.GrantID != g.ID() || receipt.CheckedAt != now || !validDigest(receipt.TipHash) {
		return "delegation_evidence_unavailable"
	}
	return ""
}

type j7RequestCustody struct {
	*j7Lifecycle
	key      *j7Key
	clock    AuditClock
	evidence *j7RentalAuthority
	entropy  io.Reader
}

func (*j7RequestCustody) RunRequestSigning() {}
func newJ7RequestCustody(l *j7Lifecycle, k *j7Key, clock AuditClock, evidence *j7RentalAuthority) (*j7RequestCustody, error) {
	if l == nil || k == nil || k.role != j7RequestRole || k.instance != l.store.j7.Instance || clock == nil || !j7SigningStateSchema(l.store.schema) || l.store.validateJ7() != nil {
		return nil, failure("J7 request custody unavailable")
	}
	return &j7RequestCustody{j7Lifecycle: l, key: k, clock: clock, evidence: evidence, entropy: rand.Reader}, nil
}
func (a *j7RequestCustody) now(ctx context.Context) (int64, Code) {
	if ctx.Err() != nil {
		return 0, "request_deadline_exceeded"
	}
	var at time.Time
	var ok bool
	if c, yes := a.clock.(interface {
		UTCContext(context.Context) (time.Time, bool)
	}); yes {
		at, ok = c.UTCContext(ctx)
	} else {
		at, ok = a.clock.UTC()
	}
	if !ok || at.Unix() < 1 || at.Unix() > j7MaxTime {
		return 0, "clock_untrusted"
	}
	return at.Unix(), ""
}

type j7Plan struct {
	operation   string
	contract    j7Contract
	contractRaw []byte
	grant       *rental.SignedGrant
	evidence    j7Evidence
	envelope    *j7EnvelopeInput
	instruction []byte
	consent     j7ConsentPermission
	delegation  *j7DelegationPlan
}

func j7ParseRequest(r control.Request) (j7Plan, Code) {
	var p j7Plan
	if r.Method == "j7_pubkey" {
		if len(r.Params) != 0 {
			return p, "request_malformed"
		}
		return p, ""
	}
	var object, ev string
	if r.Method == "j7_enroll" {
		var v j7EnrollParams
		if c := j7DecodeArgs(r.Params, &v); c != "" {
			return p, c
		}
		object, ev = v.Object, v.Evidence
		p.operation = "enroll"
	} else {
		var v j7SignParams
		if c := j7DecodeArgs(r.Params, &v); c != "" {
			return p, c
		}
		object, ev = v.Object, v.Evidence
		p.operation = v.Operation
		if p.operation != "consent_v3" && p.operation != "envelope_v3" {
			// Only the generic bounded object/evidence transport is decoded.
			// An unavailable operation has no object parser or signing branch.
			raw, c := j7Decode64(object, j7ObjectLimit)
			var opaque map[string]json.RawMessage
			if c != "" || len(raw) == 0 || StrictJSON(bytes.NewReader(raw), &opaque) != nil || opaque == nil {
				return p, "request_malformed"
			}
			evidence, c := j7Decode64(ev, 1024)
			var bundle j7Evidence
			if c != "" || j7StrictObject(evidence, &bundle) != "" || bundle.Format != "keymaker-j7-evidence/1" || bundle.Issuance != "" && !validDigest(bundle.Issuance) {
				return p, "request_malformed"
			}
			return p, "operation_unsupported"
		}
	}
	raw, c := j7Decode64(object, j7ObjectLimit)
	if c != "" {
		return p, c
	}
	var contract, grant string
	switch p.operation {
	case "consent_v3":
		var v j7ConsentInput
		if c = j7StrictObject(raw, &v); c != "" {
			return p, c
		}
		contract = v.Contract
	case "enroll":
		var v j7GrantInput
		if c = j7StrictObject(raw, &v); c != "" {
			return p, c
		}
		contract, grant = v.Contract, v.Grant
	case "envelope_v3":
		var v j7EnvelopeInput
		if c = j7StrictObject(raw, &v); c != "" {
			return p, c
		}
		contract, grant = v.Contract, v.Grant
		p.envelope = &v
		p.instruction, c = j7Decode64(v.Instruction, 8192)
		if c != "" || len(p.instruction) == 0 {
			return p, "request_malformed"
		}
	}
	p.contractRaw, c = j7Decode64(contract, 8192)
	if c != "" {
		return p, c
	}
	p.contract, c = parseJ7Contract(p.contractRaw)
	if c != "" {
		return p, c
	}
	p.consent = j7ConsentTriple(p.contractRaw)
	p.evidence, c = j7DecodeEvidence(ev, p.operation != "consent_v3")
	if c != "" {
		return p, c
	}
	if grant != "" {
		graw, c := j7Decode64(grant, 16384)
		if c != "" {
			return p, c
		}
		g, e := rental.ParseSignedGrant(graw)
		if e != nil {
			return p, "request_malformed"
		}
		p.grant = &g
		if c = j7BindContract(p.contractRaw, p.contract, g.Grant); c != "" {
			return p, c
		}
	}
	if p.operation != "consent_v3" && p.grant == nil {
		return p, "request_malformed"
	}
	if v := p.envelope; v != nil {
		if v.Transport != "matrix" || v.To != p.contract.Agent || !j7MatrixID(v.Room, '!', false) || !j7MatrixID(v.MXID, '@', true) || !j7Listed(p.contract.Actions, v.Action) {
			return p, "request_malformed"
		}
		switch v.Action {
		case "land":
			if v.Amount != 0 || !j7Repo(v.Repo) || !j7Listed(p.contract.Repos, v.Repo) {
				return p, "request_malformed"
			}
		case "spend":
			if v.Repo != "" || v.Amount <= 0 || v.Amount > p.contract.Budget {
				return p, "request_malformed"
			}
		case "instruct", "review":
			if v.Repo != "" || v.Amount != 0 {
				return p, "request_malformed"
			}
		default:
			return p, "request_malformed"
		}
	}
	return p, ""
}
func (a *j7RequestCustody) Admit(ctx context.Context, peer control.Peer, r control.Request) control.Code {
	if !j7SigningMethod(r.Method) {
		return a.j7Lifecycle.Admit(ctx, peer, r)
	}
	if !a.store.mu.LockContext(ctx) {
		return control.DeadlineExceeded
	}
	defer a.store.mu.Unlock()
	ch := j7ChannelFrom(ctx)
	if _, c := a.selectedLocked(ch, nativePrincipal(peer)); c != "" {
		return control.Code(c)
	}
	if prior, c := a.store.retained(nativePrincipal(peer), r); c != "" {
		return control.Code(c)
	} else if prior != nil {
		record := a.store.j7SigningRecord(nativePrincipal(peer), r.ID)
		if record == nil || record.Run != ch.run {
			return control.RequestConflict
		}
	}
	return ""
}
func (a *j7RequestCustody) selectedLocked(ch *j7Channel, peer Principal) (j7Run, Code) {
	if ch == nil || !ch.active() || ch.run == "" || a.channels[ch.run] != ch {
		return j7Run{}, "run_identity_unavailable"
	}
	if peer != a.launcher {
		return j7Run{}, "role_not_permitted"
	}
	s := a.store
	if s.failed || s.j7Signing == nil || !j7SigningStateSchema(s.schema) || s.j7UnknownHandoff() {
		return j7Run{}, "j7_state_fenced"
	}
	row := a.run(ch.run)
	if row == nil || row.State != "live" || row.Launcher != peer {
		return j7Run{}, "run_identity_unavailable"
	}
	b, c := s.lookup(row.Binding.UID, row.Binding.Generation)
	if c != "" {
		return j7Run{}, c
	}
	if b != row.Binding {
		return j7Run{}, "binding_conflict"
	}
	return *row, ""
}
func (a *j7RequestCustody) withKeyLocked(ctx context.Context, id string, b Binding, fn func(string, func(*[32]byte) ([]byte, error)) Code) (code Code) {
	cause := custodyProtectionFailed
	defer func() {
		if code == "custody_unavailable" {
			if evidence, ok := ctx.Value(j7AuditKey{}).(*j7RequestAudit); ok {
				evidence.mu.Lock()
				evidence.id = id
				evidence.cause = cause
				evidence.mu.Unlock()
			}
		}
	}()
	k := a.key
	if k == nil {
		cause = custodyUnloaded
		return "custody_unavailable"
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		cause = custodyClosed
		return "custody_unavailable"
	}
	if len(k.seed) == 0 {
		cause = custodyUnloaded
		return "custody_unavailable"
	}
	if k.role != j7RequestRole || k.instance != a.store.j7.Instance || k.epoch != b.Epoch || k.registry != b.RegistryRevision || ValidatePath(b.Path, "agent-identity") != "" {
		return "custody_unavailable"
	}
	path := "m/7'" + strings.TrimPrefix(b.Path, "m/1'")
	public, e := k.withPathLocked(path, nil)
	if e != nil {
		return "custody_unavailable"
	}
	return fn(hex.EncodeToString(public), func(id *[32]byte) ([]byte, error) { return k.withPathLocked(path, id) })
}
func (a *j7RequestCustody) withRun(ctx context.Context, peer control.Peer, r control.Request, p j7Plan, fn func(j7Run, *j7PolicyTable, string, func(*[32]byte) ([]byte, error)) Code) Code {
	s := a.store
	ch := j7ChannelFrom(ctx)
	if !s.mu.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	selected, c := a.selectedLocked(ch, nativePrincipal(peer))
	s.mu.Unlock()
	if c != "" {
		return c
	}
	conditions := []GenerationCondition{{Principal: selected.Launcher}, {Principal: selected.Input}, {Principal: Principal{selected.Binding.UID, selected.Binding.Generation}}}
	code := a.generations.WithEvidence(ctx, conditions, func(ctx context.Context) Code {
		return a.policy.withTable(ctx, func(table *j7PolicyTable) Code {
			current, c := a.selectedLocked(ch, nativePrincipal(peer))
			if c != "" {
				return c
			}
			if current != selected {
				return "run_identity_unavailable"
			}
			if _, c := s.retained(nativePrincipal(peer), r); c != "" {
				return c
			}
			if c = a.permissionLocked(table, current, p); c != "" {
				return c
			}
			return a.withKeyLocked(ctx, r.ID, current.Binding, func(public string, sign func(*[32]byte) ([]byte, error)) Code {
				if p.operation != "" && p.contract.Grantee != public {
					return "peer_binding_mismatch"
				}
				now, c := a.now(ctx)
				if c != "" {
					return c
				}
				if p.operation != "" && (now >= p.contract.NotAfter || p.grant != nil && now < p.contract.NotBefore) {
					return "delegation_evidence_unavailable"
				}
				return fn(current, table, public, sign)
			})
		})
	})
	if p.operation == "consent_v3" && code == "GRANT_NOT_FOR_RUN" {
		return "CONSENT_NOT_FOR_RUN"
	}
	return code
}
func (a *j7RequestCustody) permissionLocked(table *j7PolicyTable, run j7Run, p j7Plan) Code {
	if p.operation == "" {
		return ""
	}
	row := j7PolicyRowFor(table, run.Origin.key())
	if p.operation == "consent_v3" {
		if row != nil {
			for _, c := range row.Consent {
				if c.Contract == p.consent.Contract && c.Booking == p.consent.Booking && c.Privacy == p.consent.Privacy {
					return ""
				}
			}
		}
		return "CONSENT_NOT_FOR_RUN"
	}
	if p.grant == nil {
		return "request_malformed"
	}
	id := p.grant.ID()
	if p.operation == "delegation_request_v3" {
		if row == nil || !j7Listed(row.Delegate, id) {
			return "GRANT_NOT_FOR_RUN"
		}
		return ""
	}
	for _, d := range a.store.j7.Denials {
		if d.Origin == run.Origin.key() && d.Grant == id {
			return "GRANT_NOT_FOR_RUN"
		}
	}
	if p.operation == "enroll" {
		_, c := a.enrollmentLocked(run, p, table)
		return c
	}
	if row == nil || !j7Listed(row.Use, id) && !a.store.j7Enrolled(run.Origin.key(), run.Binding.Number, id) {
		return "GRANT_NOT_FOR_RUN"
	}
	return ""
}
func (a *j7RequestCustody) enrollmentLocked(run j7Run, p j7Plan, table *j7PolicyTable) (j7Enrollment, Code) {
	if p.grant == nil {
		return j7Enrollment{}, "request_malformed"
	}
	for _, e := range a.store.j7Signing.Enrollments {
		if e.Origin == run.Origin.key() && e.Identity == run.Binding.Number && e.Grant == p.grant.ID() {
			return e, ""
		}
	}
	current := false
	if row := j7PolicyRowFor(table, run.Origin.key()); row != nil {
		for _, c := range row.Consent {
			if c.AndUse && c.Contract == p.consent.Contract && c.Booking == p.consent.Booking && c.Privacy == p.consent.Privacy {
				current = true
			}
		}
	}
	if !current {
		return j7Enrollment{}, "GRANT_NOT_FOR_RUN"
	}
	want, _ := j7Compact(p.grant.Grant.Consent.ConsentEvent)
	for _, r := range a.store.j7Signing.Records {
		if r.Operation != "consent_v3" || r.Release != "released" || r.Origin.key() != run.Origin.key() || r.Binding != run.Binding || !r.Consent.AndUse || r.Consent.Contract != p.consent.Contract || r.Consent.Booking != p.consent.Booking || r.Consent.Privacy != p.consent.Privacy {
			continue
		}
		index, ok := a.store.requestIndex[requestKey{r.Caller, r.ID}]
		if !ok {
			return j7Enrollment{}, "j7_state_fenced"
		}
		prior := a.store.requests[index]
		obj, e := control.Decode(prior.Result)
		if e != nil {
			return j7Enrollment{}, "j7_state_fenced"
		}
		encoded, _ := obj["signed_object_b64"].(string)
		actual, c := j7Decode64(encoded, 16384)
		if c != "" {
			return j7Enrollment{}, "j7_state_fenced"
		}
		if bytes.Equal(want, actual) {
			return j7Enrollment{Origin: run.Origin.key(), Identity: run.Binding.Number, Grant: p.grant.ID(), ConsentID: r.EventID, ConsentResultHash: r.ResultHash, Consent: r.Consent}, ""
		}
	}
	return j7Enrollment{}, "GRANT_NOT_FOR_RUN"
}
func (a *j7RequestCustody) Handle(ctx context.Context, peer control.Peer, r control.Request) (control.Object, control.Code) {
	if !j7SigningMethod(r.Method) {
		return a.j7Lifecycle.Handle(ctx, peer, r)
	}
	p, c := j7ParseRequestForSchema(r, a.store.schema)
	if c != "" {
		return nil, control.Code(c)
	}
	// Authorization precedes potentially journal-writing node validation.
	c = a.withRun(ctx, peer, r, p, func(j7Run, *j7PolicyTable, string, func(*[32]byte) ([]byte, error)) Code { return "" })
	if c != "" {
		return nil, control.Code(c)
	}
	if p.grant != nil {
		now, c := a.now(ctx)
		if c != "" {
			return nil, control.Code(c)
		}
		if c = a.evidence.check(ctx, *p.grant, p.evidence, now); c != "" {
			return nil, control.Code(c)
		}
	}
	if c = p.childFits(); c != "" {
		return nil, control.Code(c)
	}
	var result control.Object
	c = a.withRun(ctx, peer, r, p, func(run j7Run, table *j7PolicyTable, public string, sign func(*[32]byte) ([]byte, error)) Code {
		s := a.store
		prior, c := s.retained(nativePrincipal(peer), r)
		if c != "" {
			return c
		}
		if prior != nil {
			rec := s.j7SigningRecord(nativePrincipal(peer), r.ID)
			if rec == nil || rec.Run != run.ID || rec.Binding != run.Binding || rec.Origin != run.Origin {
				return "request_conflict"
			}
			result, c = s.resultObject(prior)
			return c
		}
		if len(s.j7Signing.Records) >= j7HistoryLimit {
			return "state_capacity_exceeded"
		}
		result = control.Object{"profile": "j7-request-public/1", "public_key": public}
		rec := j7SigningRecord{Caller: nativePrincipal(peer), ID: r.ID, Run: run.ID, Binding: run.Binding, Origin: run.Origin, Method: r.Method, Operation: p.operation, Grants: []string{}, Release: "prepared"}
		if p.grant != nil {
			rec.Grants = []string{p.grant.ID()}
		}
		if r.Method == "j7_enroll" {
			result = control.Object{"grant_id": p.grant.ID()}
		}
		var event rental.Event
		profile := ""
		if r.Method == "j7_sign" {
			now, c := a.now(ctx)
			if c != "" {
				return c
			}
			event = rental.Event{Pubkey: public, CreatedAt: now, Content: ""}
			switch p.operation {
			case "consent_v3":
				event.Kind = 8181
				event.Tags = [][]string{{"t", "swarma-rental-consent-v1"}, {"contract", p.consent.Contract}, {"booking", p.consent.Booking}, {"privacy", p.consent.Privacy}}
				profile = "swarma-rental-consent-v1"
				row := j7PolicyRowFor(table, run.Origin.key())
				for _, v := range row.Consent {
					if v.Contract == p.consent.Contract && v.Booking == p.consent.Booking && v.Privacy == p.consent.Privacy {
						rec.Consent = v
					}
				}
			case "delegation_request_v3":
				var nonce [32]byte
				if a.entropy == nil {
					return "entropy_unavailable"
				}
				if _, e := io.ReadFull(a.entropy, nonce[:]); e != nil {
					return "entropy_unavailable"
				}
				event = p.delegationEvent(public, now, nonce[:])
				profile = "swarma-delegation-request-v1/draft"
			case "envelope_v3":
				var nonce [32]byte
				if a.entropy == nil {
					return "entropy_unavailable"
				}
				if _, e := io.ReadFull(a.entropy, nonce[:]); e != nil {
					return "entropy_unavailable"
				}
				v := p.envelope
				event.Kind = 8185
				event.Tags = [][]string{{"t", "swarma-instruction-v1"}, {"to", v.To}, {"grant", p.grant.ID()}, {"action", v.Action}, {"body", j7Hash(p.instruction)}, {"room", v.Room}, {"mxid", v.MXID}, {"nonce", hex.EncodeToString(nonce[:])}}
				if v.Action == "land" {
					event.Tags = append(event.Tags, []string{"repo", v.Repo})
				}
				if v.Action == "spend" {
					event.Tags = append(event.Tags, []string{"amount", strconv.FormatInt(v.Amount, 10)})
				}
				profile = "swarma-instruction-v1/draft"
			}
			event.ID = j7EventID(event)
			event.Sig = strings.Repeat("0", 128)
			result = j7SignedResult(event, profile)
		}
		args, c := requestArguments(r)
		if c != "" {
			return c
		}
		rec.InputHash = j7Hash(args)
		encoded, e := control.Marshal(result)
		if e != nil {
			return "request_malformed"
		}
		rec.ResultHash = j7Hash(encoded)
		rec.EventID = event.ID
		previous := s.j7Signing
		s.j7Signing = cloneJ7Signing(previous)
		s.j7Signing.Records = append(s.j7Signing.Records, rec)
		entry := retainedRequest{Caller: nativePrincipal(peer), ID: r.ID, Method: r.Method, Arguments: string(args), Status: "committed", Result: encoded}
		// Reserve the largest handoff spelling and boolean before signing,
		// not merely the shorter prepared snapshot. A later entry downgrade
		// and unknown commit must not consume unreserved participant bytes.
		at := len(s.j7Signing.Records) - 1
		s.j7Signing.Records[at].Release = "handoff_unknown"
		s.j7Signing.Records[at].Consent.AndUse = false
		fits := s.fitsState(s.records, s.next, append(append([]retainedRequest{}, s.requests...), entry))
		s.j7Signing.Records[at] = rec
		if !fits {
			s.j7Signing = previous
			return "state_capacity_exceeded"
		}
		if r.Method == "j7_sign" {
			id, e := hex.DecodeString(event.ID)
			if e != nil {
				s.j7Signing = previous
				return "request_malformed"
			}
			var digest [32]byte
			copy(digest[:], id)
			sig, e := sign(&digest)
			if e != nil {
				s.j7Signing = previous
				return "custody_unavailable"
			}
			event.Sig = hex.EncodeToString(sig)
			erase(sig)
			result = j7SignedResult(event, profile)
			entry.Result, e = control.Marshal(result)
			if e != nil {
				s.j7Signing = previous
				return "j7_state_fenced"
			}
			s.j7Signing.Records[len(s.j7Signing.Records)-1].ResultHash = j7Hash(entry.Result)
		}
		s.appendRequest(entry)
		if c := s.commitJ7(ctx); c != "" {
			return c
		}
		if c := s.j7Point("signing-prepared"); c != "" {
			s.failed = true
			return "j7_state_fenced"
		}
		return ""
	})
	if c != "" {
		return nil, control.Code(c)
	}
	return result, ""
}

// Evidence belongs to this serialized connection/request only, never a shared
// last-error slot. It is captured under the custody gate and consumed by audit.
type j7AuditKey struct{}
type j7RequestAudit struct {
	mu    sync.Mutex
	id    string
	cause custodyCause
}

func (a *j7RequestCustody) Scope(ctx context.Context, conn net.Conn) (context.Context, func()) {
	ctx, stop := a.j7Lifecycle.Scope(ctx, conn)
	return context.WithValue(ctx, j7AuditKey{}, &j7RequestAudit{}), stop
}
func (a *j7RequestCustody) Refuse(ctx context.Context, conn net.Conn, peer *control.Peer, r control.Request, body []byte, refusal control.Code) control.Code {
	var cause custodyCause
	if evidence, ok := ctx.Value(j7AuditKey{}).(*j7RequestAudit); ok {
		evidence.mu.Lock()
		if evidence.id == r.ID {
			cause = evidence.cause
		}
		evidence.id = ""
		evidence.cause = ""
		evidence.mu.Unlock()
	}
	return a.j7Lifecycle.refuseWithCustodyCause(ctx, conn, peer, r, body, refusal, cause)
}
