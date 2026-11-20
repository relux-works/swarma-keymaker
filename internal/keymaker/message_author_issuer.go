package keymaker

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

// maIssuer is an internal capability, never an RPC or a caller-body signer.
// Production does not construct it while G-A7A2-RETENTION-SCALING is closed.
// Its mutex excludes renewal/current selection through the disclosure callback;
// the order is generation -> issuer -> Store -> custody -> audit.
type maIssuer struct {
	mu          sync.Mutex
	store       *Store
	subject     *messageAuthorKey
	custody     *maIssuerKey
	generations GenerationSource
	clock       func(context.Context) (j7GateTime, Code)
}
type maIssuerCertificate struct {
	Key   string `json:"key"`
	T     string `json:"t"`
	A     []byte `json:"a"`
	From  string `json:"from"`
	Until string `json:"until"`
	Seq   uint64 `json:"audit_seq"`
	Hash  string `json:"audit_hash"`
}
type maIssuerRecord struct {
	Binding    Binding              `json:"binding"`
	Phase      string               `json:"phase"`
	Current    *maIssuerCertificate `json:"current"`
	Pending    *maIssuerCertificate `json:"pending"`
	Tombstones []string             `json:"tombstones"`
	// A paired cancellation snapshot is durable proof, never a caller Boolean.
	CancelSeq  uint64 `json:"cancel_seq"`
	CancelHash string `json:"cancel_hash"`
}

func (r *maIssuerRecord) UnmarshalJSON(raw []byte) error {
	f, e := objectMembers(raw, []string{"binding", "phase", "tombstones", "cancel_seq", "cancel_hash"}, "current", "pending")
	if e != nil {
		return e
	}
	for _, k := range []string{"current", "pending"} {
		if _, ok := f[k]; !ok {
			return failure("missing issuer evidence")
		}
	}
	type plain maIssuerRecord
	return StrictJSON(bytes.NewReader(raw), (*plain)(r))
}
func (c *maIssuerCertificate) UnmarshalJSON(raw []byte) error {
	if _, e := objectMembers(raw, []string{"key", "t", "a", "from", "until", "audit_seq", "audit_hash"}); e != nil {
		return e
	}
	type plain maIssuerCertificate
	return StrictJSON(bytes.NewReader(raw), (*plain)(c))
}
func maIssuerBinding(b Binding) messageBinding {
	return messageBinding{b.UID, b.Generation, b.Number, b.Epoch, b.Owner, "m/9'" + strings.TrimPrefix(b.Path, "m/1'")}
}
func maIssuerWireBinding(b Binding) map[string]any {
	v := maIssuerBinding(b)
	return map[string]any{"uid": int64(v.UID), "generation": v.Generation, "registration_number": int64(v.Number), "master_epoch": v.Epoch, "owner": v.Owner, "path": v.Path}
}
func (i *maIssuer) body(b Binding, key string, at j7GateTime, lifetime time.Duration) (map[string]any, Code) {
	if !at.startBoundsValid() {
		return nil, "clock_untrusted"
	}
	if lifetime <= 0 || lifetime > 86400*time.Second || lifetime%time.Second != 0 {
		return nil, "key_not_valid_now"
	}
	if b.Status != "active" || ValidatePath(b.Path, "agent-identity") != "" || !messageText(b.Owner) || !messageText(b.Generation) || b.Number == 0 || b.Number >= j7SafeInteger {
		return nil, "binding_conflict"
	}
	if record.ValidateKey(key) != nil || !strings.HasPrefix(key, "bip340:") {
		return nil, "sign_key_mismatch"
	}
	issuer, c := i.custody.public()
	if c != "" {
		return nil, c
	}
	from := at.Lower.UTC().Truncate(time.Second)
	until := from.Add(lifetime)
	if from.Year() < 1970 || until.Year() > 9999 || !at.Upper.Before(until) {
		return nil, "key_not_valid_now"
	}
	return map[string]any{"type": "attestation/1", "issuer": issuer, "subject": map[string]any{"algorithm": "BIP-340", "key_id": key, "public_bytes": strings.TrimPrefix(key, "bip340:")}, "key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"}, "iat": messageStamp(from), "exp": messageStamp(until), "binding": maIssuerWireBinding(b)}, ""
}
func maIssuerTimes(c *maIssuerCertificate, at j7GateTime) bool {
	if c == nil {
		return false
	}
	from, e := time.Parse(time.RFC3339, c.From)
	until, e2 := time.Parse(time.RFC3339, c.Until)
	return e == nil && e2 == nil && until.After(from) && until.Sub(from) <= 86400*time.Second && maLiveInterval(at, from, until)
}
func maIssuerEnvelope(c *maIssuerCertificate, b Binding) bool {
	if c == nil || len(c.A) == 0 || len(c.A) > 8192 || record.ValidateKey(c.Key) != nil || !strings.HasPrefix(c.Key, "bip340:") {
		return false
	}
	x, e := record.Parse(c.A, 8192, 16)
	if e != nil {
		return false
	}
	a, ok := x.(map[string]any)
	if !ok {
		return false
	}
	ab, ok := a["body"].(map[string]any)
	if !ok {
		return false
	}
	// The entire internal body is closed, including binding, not just its tag.
	issuer, ok := ab["issuer"].(string)
	if !ok || !strings.HasPrefix(issuer, "ed25519:") {
		return false
	}
	expected := map[string]any{"type": "attestation/1", "issuer": issuer, "subject": map[string]any{"algorithm": "BIP-340", "key_id": c.Key, "public_bytes": strings.TrimPrefix(c.Key, "bip340:")}, "key_class": "agent", "purpose": "swarma-msg", "roles": []any{"author"}, "actions": []any{"message.sign"}, "iat": c.From, "exp": c.Until, "binding": maIssuerWireBinding(b)}
	want, _ := canonical(expected)
	got, _ := canonical(ab)
	if !bytes.Equal(want, got) {
		return false
	}
	id, e := record.ContentID("attestation/1", ab)
	if e != nil || id != c.T || a["id"] != id || a["version"] != "swarm-envelope/2" || len(a) != 4 {
		return false
	}
	sigs, ok := a["signatures"].([]any)
	if !ok || len(sigs) != 1 {
		return false
	}
	sig, ok := sigs[0].(map[string]any)
	if !ok || len(sig) != 3 || sig["key"] != issuer || sig["role"] != "author" {
		return false
	}
	text, ok := sig["sig"].(string)
	if !ok {
		return false
	}
	signature, e := base64.RawURLEncoding.DecodeString(text)
	if e != nil {
		return false
	}
	pre, e := record.SigningPreimage("attestation/1", issuer, "author", ab)
	from, e1 := time.Parse(time.RFC3339, c.From)
	until, e2 := time.Parse(time.RFC3339, c.Until)
	return e == nil && e1 == nil && e2 == nil && messageStamp(from) == c.From && messageStamp(until) == c.Until && until.After(from) && until.Sub(from) <= 86400*time.Second && record.VerifySignature(issuer, signature, pre) == nil
}
func maIssuerSignedBy(c *maIssuerCertificate, key string) bool {
	if c == nil {
		return false
	}
	x, e := record.Parse(c.A, 8192, 16)
	if e != nil {
		return false
	}
	a, ok := x.(map[string]any)
	if !ok {
		return false
	}
	b, ok := a["body"].(map[string]any)
	return ok && b["issuer"] == key
}
func (s *Store) maIssuerIndex(b Binding) int {
	for n, r := range s.maLive.Issuers {
		if r.Binding == b {
			return n
		}
	}
	return -1
}
func (s *Store) validateMAIssuers() error {
	seen := map[uint64]bool{}
	for _, r := range s.maLive.Issuers {
		if seen[r.Binding.Number] || r.Tombstones == nil {
			return failure("invalid issuer history")
		}
		seen[r.Binding.Number] = true
		found := false
		for _, b := range s.records {
			if b == r.Binding || b.Number == r.Binding.Number && b.Status == "revoked" && (r.Phase == "withdrawn" || r.Phase == "fenced") {
				found = true
			}
		}
		if !found {
			return failure("issuer binding absent")
		}
		switch r.Phase {
		case "bound", "pending", "current", "withdrawn", "fenced", "cancelled":
		default:
			return failure("invalid issuer phase")
		}
		for _, c := range []*maIssuerCertificate{r.Current, r.Pending} {
			if c != nil && !maIssuerEnvelope(c, r.Binding) {
				return failure("invalid issuer certificate")
			}
		}
		if r.Phase == "current" && (r.Current == nil || r.Pending != nil || r.CancelSeq != 0 || r.Current.Seq == 0 || r.Current.Seq > s.auditSeq || !validDigest(r.Current.Hash)) {
			return failure("invalid issuer current")
		}
		if r.Phase == "cancelled" && (r.CancelSeq == 0 || !validDigest(r.CancelHash)) {
			return failure("invalid issuer cancellation")
		}
		if r.Phase != "cancelled" && r.Phase != "fenced" && (r.CancelSeq != 0 || r.CancelHash != "") {
			return failure("unexpected cancellation proof")
		}
		for _, t := range r.Tombstones {
			if !strings.HasPrefix(t, "sha256:") || !validDigest(strings.TrimPrefix(t, "sha256:")) || r.Phase == "current" && r.Current.T == t {
				return failure("invalid issuer tombstone")
			}
		}
	}
	return nil
}
func (i *maIssuer) active(ctx context.Context, b Binding, fn func(*Store, j7GateTime) Code) Code {
	if i == nil || i.store == nil || i.generations == nil || i.clock == nil {
		return "message_author_unqualified"
	}
	return i.generations.WithActive(ctx, b.UID, b.Generation, func(ctx context.Context) Code {
		i.mu.Lock()
		defer i.mu.Unlock()
		s := i.store
		if !s.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		defer s.mu.Unlock()
		if s.failed || s.maLive == nil || s.maLive.Fenced {
			return "message_author_unqualified"
		}
		now, c := s.lookup(b.UID, b.Generation)
		if c != "" || now != b || b.Epoch != s.maLive.Epoch || b.RegistryRevision != s.maLive.Registry {
			return "binding_conflict"
		}
		at, c := i.clock(ctx)
		if c != "" || !at.startBoundsValid() {
			return "clock_untrusted"
		}
		return fn(s, at)
	})
}
func (s *Store) maIssuerPersist(ctx context.Context) Code { return s.persistMALiveAdmission(ctx) }

// issue is internal enrollment/renewal work. No caller can supply body/preimage.
func (i *maIssuer) issue(ctx context.Context, b Binding) Code {
	return i.active(ctx, b, func(s *Store, at j7GateTime) Code {
		if i.subject == nil || i.custody == nil {
			return "custody_unavailable"
		}
		i.subject.mu.Lock()
		defer i.subject.mu.Unlock()
		if !i.subject.mapped || i.subject.instance != s.maLive.Instance || i.subject.epoch != b.Epoch || i.subject.registry != b.RegistryRevision {
			return "custody_unavailable"
		}
		public, c := i.subject.selectedHeld(s, b, nil, nil)
		if c != "" {
			return c
		}
		key := "bip340:" + base64.RawURLEncoding.EncodeToString(public)
		body, c := i.body(b, key, at, 86400*time.Second)
		if c != "" {
			return c
		}
		n := s.maIssuerIndex(b)
		created := n < 0
		durable := false
		defer func() {
			if created && !durable && !s.failed {
				s.maLive.Issuers = s.maLive.Issuers[:len(s.maLive.Issuers)-1]
			}
		}()
		if n < 0 {
			s.maLive.Issuers = append(s.maLive.Issuers, maIssuerRecord{Binding: b, Phase: "bound", Tombstones: []string{}})
			n = len(s.maLive.Issuers) - 1
		}
		r := &s.maLive.Issuers[n]
		if r.Phase != "bound" && r.Phase != "current" {
			return "message_author_unqualified"
		}
		nextT, err := record.ContentID("attestation/1", body)
		if err != nil {
			return "message_author_unqualified"
		}
		if r.Current != nil && r.Current.T == nextT {
			return "message_author_unqualified"
		}
		for _, old := range r.Tombstones {
			if old == nextT {
				return "message_author_unqualified"
			}
		}
		oldPhase := r.Phase
		// Reserve both raw envelopes, base64 expansion, evidence and one tombstone
		// before pending or crypto. The shared three-copy budget includes this row.
		before := s.maLiveBodySize(j7SafeInteger, len(s.maLive.Attempts), s.maLiveCache.total) + maLiveReceiptBound
		if !maLiveStateRoom(before + 2*((8192+2)/3*4) + 2048 + maLiveRetireReserve) {
			return "state_capacity_exceeded"
		}
		r.Phase = "pending"
		r.Pending = nil
		if c = s.maIssuerPersist(ctx); c != "" {
			if !s.failed {
				r.Phase = oldPhase
			}
			return c
		}
		durable = true
		if c = s.messagePoint("mai-pending"); c != "" {
			return c
		}
		envelope, c := i.custody.attest(body)
		if c != "" {
			return c
		}
		t, e := record.ContentID("attestation/1", body)
		if e != nil {
			return "message_author_unqualified"
		}
		candidate := &maIssuerCertificate{Key: key, T: t, A: envelope, From: body["iat"].(string), Until: body["exp"].(string)}
		if r.Current != nil && r.Current.T == t {
			return "message_author_unqualified"
		}
		r.Pending = candidate
		if c = s.maIssuerPersist(ctx); c != "" {
			return c
		}
		if c = s.messagePoint("mai-candidate"); c != "" {
			return c
		}
		fresh, c := i.clock(ctx)
		if c != "" || !maIssuerTimes(candidate, fresh) {
			return "clock_untrusted"
		}
		issuerKey, cc := i.custody.public()
		if cc != "" || !maIssuerSignedBy(candidate, issuerKey) {
			return "custody_unavailable"
		}
		op := "message_author_attestation_issue"
		if r.Current != nil {
			op = "message_author_attestation_renew"
		}
		digest := maLiveHash(envelope)
		seq, hash, c := s.maLiveAppend(ctx, Principal{b.UID, b.Generation}, "", op, &digest)
		if c != "" {
			return c
		}
		candidate.Seq, candidate.Hash = seq, hash
		if c = s.messagePoint("mai-success-audit"); c != "" {
			return c
		}
		if r.Current != nil {
			r.Tombstones = append(r.Tombstones, r.Current.T)
		}
		r.Current, r.Pending, r.Phase = candidate, nil, "current"
		c = s.maIssuerPersist(context.WithoutCancel(ctx))
		if c != "" {
			return c
		}
		return s.messagePoint("mai-commit")
	})
}
func (s *Store) maIssuerProof(c *maIssuerCertificate, op string) bool {
	if c == nil || s.journal == nil || c.Seq == 0 || !validDigest(c.Hash) {
		return false
	}
	s.journal.mu.Lock()
	r, ok := s.journal.maIssuerEvents[c.Seq]
	s.journal.mu.Unlock()
	return ok && r.Digest == c.Hash && r.Operation == op && r.PayloadDigest != nil && *r.PayloadDigest == maLiveHash(c.A)
}
func (s *Store) maIssuerCommitted(c *maIssuerCertificate) bool {
	return s.maIssuerProof(c, "message_author_attestation_issue") || s.maIssuerProof(c, "message_author_attestation_renew")
}

// A readable issuance audit beyond the paired snapshot cannot prove whether its
// commit completed. Neither expiry nor cancellation may erase that uncertainty.
func (s *Store) maIssuerUnpaired() bool {
	s.journal.mu.Lock()
	defer s.journal.mu.Unlock()
	for _, a := range s.journal.maIssuerEvents {
		if a.Seq > s.auditSeq && (a.Operation == "message_author_attestation_issue" || a.Operation == "message_author_attestation_renew") {
			return true
		}
	}
	return false
}
func (i *maIssuer) WithCurrent(ctx context.Context, b Binding, at j7GateTime, fn func(maLiveTuple) Code) Code {
	if i == nil || i.store == nil {
		return "message_author_unqualified"
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	s := i.store
	if !s.mu.LockContext(ctx) {
		return "request_deadline_exceeded"
	}
	if s.maLive == nil {
		s.mu.Unlock()
		return "message_author_unqualified"
	}
	n := s.maIssuerIndex(b)
	var out maLiveTuple
	c := Code("message_author_unqualified")
	now, bc := s.lookup(b.UID, b.Generation)
	if !s.failed && !s.maLive.Fenced && bc == "" && now == b && n >= 0 {
		r := s.maLive.Issuers[n]
		pub, pc := i.custody.public()
		if r.Phase == "current" && pc == "" && maIssuerSignedBy(r.Current, pub) && maIssuerTimes(r.Current, at) && s.maIssuerCommitted(r.Current) {
			until, _ := time.Parse(time.RFC3339, r.Current.Until)
			// Renewal is internal work; reads never issue under a release callback.
			if at.Upper.Before(until.Add(-time.Hour)) {
				out = maLiveTuple{r.Current.Key, r.Current.T, append([]byte(nil), r.Current.A...)}
				c = ""
			}
		}
	}
	s.mu.Unlock()
	if c != "" {
		return c
	}
	return fn(out)
}

// cancel proves cancellation by writing its own durable audit+snapshot before
// restoration; it accepts no externally asserted proof flag. Unpaired evidence
// cannot restore, and a committed replacement cannot enter this transition.
func (i *maIssuer) cancel(ctx context.Context, b Binding) Code {
	return i.active(ctx, b, func(s *Store, at j7GateTime) Code {
		n := s.maIssuerIndex(b)
		if n < 0 {
			return "message_author_unqualified"
		}
		r := &s.maLive.Issuers[n]
		if r.Phase == "cancelled" || r.Phase == "fenced" && r.CancelSeq != 0 {
			return s.maIssuerRestore(r, at, ctx)
		}
		if r.Phase != "pending" {
			return "message_author_unqualified"
		}
		// A success audit beyond the snapshot means issuance outcome is unknown.
		if s.maIssuerUnpaired() {
			return "message_author_unqualified"
		}
		if r.Current != nil && !maIssuerTimes(r.Current, at) {
			return "key_not_valid_now"
		}
		raw, _ := canonical(r)
		digest := maLiveHash(raw)
		seq, hash, c := s.maLiveAppend(ctx, Principal{b.UID, b.Generation}, "", "message_author_attestation_fence", &digest)
		if c != "" {
			return c
		}
		r.Phase, r.CancelSeq, r.CancelHash = "cancelled", seq, hash
		if c = s.maIssuerPersist(ctx); c != "" {
			return c
		}
		if c = s.messagePoint("mai-cancel"); c != "" {
			return c
		}
		return s.maIssuerRestore(r, at, ctx)
	})
}
func (s *Store) maIssuerRestore(r *maIssuerRecord, at j7GateTime, ctx context.Context) Code {
	s.journal.mu.Lock()
	a, ok := s.journal.maIssuerEvents[r.CancelSeq]
	s.journal.mu.Unlock()
	proof := *r
	proof.Phase = "pending"
	proof.CancelSeq = 0
	proof.CancelHash = ""
	raw, _ := canonical(proof)
	if a.PayloadDigest == nil || *a.PayloadDigest != maLiveHash(raw) {
		return "message_author_unqualified"
	}
	if (r.Phase != "cancelled" && r.Phase != "fenced") || !ok || a.Digest != r.CancelHash || a.Operation != "message_author_attestation_fence" {
		return "message_author_unqualified"
	}
	if r.Current != nil && (!maIssuerTimes(r.Current, at) || !s.maIssuerCommitted(r.Current)) {
		return "message_author_unqualified"
	}
	if r.Pending != nil {
		r.Tombstones = append(r.Tombstones, r.Pending.T)
	}
	r.Pending = nil
	r.CancelSeq = 0
	r.CancelHash = ""
	r.Phase = "bound"
	if r.Current != nil {
		r.Phase = "current"
	}
	return s.maIssuerPersist(ctx)
}

// Recovery validates evidence but performs no issuance or renewal. Cancellation
// restoration requires fresh exact authority and both trusted bounds, via cancel
// reconciliation, rather than startup manufacturing a current certificate.
func (s *Store) recoverMAIssuers() bool {
	changed := false
	for n := range s.maLive.Issuers {
		r := &s.maLive.Issuers[n]
		if r.Phase == "current" && !s.maIssuerCommitted(r.Current) || r.Phase == "pending" && s.maIssuerUnpaired() {
			r.Phase = "fenced"
			changed = true
		}
	}
	return changed
}

// resolve can only reconcile retained, already committed evidence. It never
// constructs, signs, issues, or guesses a replacement T. Unknown proof stays S5.
func (i *maIssuer) resolve(ctx context.Context, b Binding) Code {
	return i.active(ctx, b, func(s *Store, at j7GateTime) Code {
		n := s.maIssuerIndex(b)
		if n < 0 {
			return ""
		}
		r := &s.maLive.Issuers[n]
		if r.Phase != "fenced" {
			return ""
		}
		if r.CancelSeq != 0 {
			return s.maIssuerRestore(r, at, ctx)
		}
		pub, c := i.custody.public()
		if c != "" || r.Pending != nil || r.Current == nil || !maIssuerEnvelope(r.Current, b) || !s.maIssuerCommitted(r.Current) || !maIssuerSignedBy(r.Current, pub) {
			return "message_author_unqualified"
		}
		if !maIssuerTimes(r.Current, at) {
			return s.maIssuerExpire(ctx, r, at)
		}
		raw, _ := canonical(r)
		digest := maLiveHash(raw)
		if _, _, c := s.maLiveAppend(ctx, Principal{b.UID, b.Generation}, "", "message_author_attestation_fence", &digest); c != "" {
			return c
		}
		r.Phase = "current"
		return s.maIssuerPersist(context.WithoutCancel(ctx))
	})
}

// Expiry is fresh holder-local work, never evidence-only startup recovery. Both
// bounds must prove expiry, and no unpaired issuance commit may be forgotten.
func (s *Store) maIssuerExpire(ctx context.Context, r *maIssuerRecord, at j7GateTime) Code {
	selected := r.Current
	if r.Phase == "pending" {
		selected = r.Pending
	}
	if selected == nil {
		return "message_author_unqualified"
	}
	until, e := time.Parse(time.RFC3339, selected.Until)
	if e != nil || !at.startBoundsValid() || at.Lower.Before(until) {
		return "key_not_valid_now"
	}
	if s.maIssuerUnpaired() || r.Current != nil && !s.maIssuerCommitted(r.Current) {
		return "message_author_unqualified"
	}
	raw, _ := canonical(r)
	digest := maLiveHash(raw)
	if _, _, c := s.maLiveAppend(ctx, Principal{r.Binding.UID, r.Binding.Generation}, "", "message_author_attestation_fence", &digest); c != "" {
		return c
	}
	for _, c := range []*maIssuerCertificate{r.Current, r.Pending} {
		if c != nil {
			r.Tombstones = append(r.Tombstones, c.T)
		}
	}
	r.Current, r.Pending, r.Phase = nil, nil, "bound"
	if c := s.maIssuerPersist(context.WithoutCancel(ctx)); c != "" {
		return c
	}
	return s.messagePoint("mai-expired")
}

// maintain is holder-local enrollment/renewal work, never a release callback or
// a production factory. The scheduler must call it before exp-1h; selection
// refuses overdue authority even if scheduling or qualified time is unavailable.
func (i *maIssuer) maintain(ctx context.Context, b Binding) Code {
	issue := false
	c := i.active(ctx, b, func(s *Store, at j7GateTime) Code {
		n := s.maIssuerIndex(b)
		if n < 0 {
			issue = true
			return ""
		}
		r := &s.maLive.Issuers[n]
		if r.Phase == "pending" || r.Phase == "current" {
			selected := r.Current
			if r.Phase == "pending" {
				selected = r.Pending
			}
			if selected != nil {
				until, e := time.Parse(time.RFC3339, selected.Until)
				if e == nil && !at.Lower.Before(until) {
					if c := s.maIssuerExpire(ctx, r, at); c != "" {
						return c
					}
				}
			}
		}
		if r.Phase == "cancelled" {
			if c := s.maIssuerRestore(r, at, ctx); c != "" {
				return c
			}
		}
		if r.Phase == "bound" {
			issue = true
			return ""
		}
		if r.Phase != "current" {
			return "message_author_unqualified"
		}
		until, e := time.Parse(time.RFC3339, r.Current.Until)
		if e != nil {
			return "message_author_unqualified"
		}
		if !at.Upper.Before(until.Add(-time.Hour)) {
			issue = true
		}
		return ""
	})
	if c != "" || !issue {
		return c
	}
	return i.issue(ctx, b)
}
