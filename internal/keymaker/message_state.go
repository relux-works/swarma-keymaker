package keymaker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"syscall"

	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
	"github.com/relux-works/waggle/verifier"
)

const messageHistoryLimit = 65536
const messageProofReserve = 4 << 20

type messageArtifact struct {
	Hash  string `json:"hash"`
	Bytes int64  `json:"bytes"`
}
type messageAssociation struct {
	Binding messageBinding `json:"binding"`
	Current *string        `json:"current"`
	Pending *string        `json:"pending"`
}
type messageIntent struct {
	Binding         Binding             `json:"binding"`
	Policy          messageIssuerPolicy `json:"issuer_policy"`
	KeyID           string              `json:"key_id"`
	IssuedAt        string              `json:"issued_at"`
	ReservedBytes   int64               `json:"reserved_bytes"`
	BaseVersion     uint64              `json:"base_version"`
	BaseDigest      string              `json:"base_digest"`
	PreviousCurrent *string             `json:"previous_current"`
}
type messageCandidate struct {
	Certificate messageCertificate     `json:"certificate"`
	Intent      messageArtifact        `json:"intent"`
	Effect      messageCandidateEffect `json:"effect"`
}
type messageCandidateEffect struct {
	Binding     messageBinding   `json:"binding"`
	BaseVersion uint64           `json:"base_version"`
	BaseDigest  string           `json:"base_digest"`
	Current     *string          `json:"current"`
	Pending     string           `json:"pending"`
	Phase       string           `json:"phase"`
	Publication *messageArtifact `json:"publication"`
}

func messageEffectMatches(effect messageCandidateEffect, tx messageTransaction, intent messageIntent) bool {
	return effect.Binding == messageBindingOf(intent.Binding) && effect.BaseVersion == tx.BaseVersion && effect.BaseDigest == tx.BaseDigest && sameMessageString(effect.Current, tx.PreviousCurrent) && effect.Pending == tx.ID && effect.Phase == "issued" && effect.Publication == nil
}

type messageResolution struct {
	Outcome   string           `json:"outcome"`
	Intent    messageArtifact  `json:"intent"`
	Candidate *messageArtifact `json:"candidate"`
	Version   uint64           `json:"version"`
	Digest    string           `json:"digest"`
}
type messageTransaction struct {
	ID              string           `json:"id"`
	Kind            string           `json:"kind"`
	BaseVersion     uint64           `json:"base_version"`
	BaseDigest      string           `json:"base_digest"`
	PreviousCurrent *string          `json:"previous_current"`
	Intent          messageArtifact  `json:"intent"`
	Candidate       *messageArtifact `json:"candidate"`
	Phase           string           `json:"phase"`
	Resolution      *messageArtifact `json:"resolution"`
}

// PENDING S4: original evidence carriers/validation/WC1 projection must be
// rechecked against the accepted freshness-aware interface. S2 cannot populate
// these slots and never calls VerifyJournal or accepts an availability Boolean.
type messagePublication struct {
	Transaction string          `json:"transaction"`
	ContentID   string          `json:"content_id"`
	Entry       string          `json:"entry"`
	Suffix      []string        `json:"suffix"`
	Checkpoint  string          `json:"checkpoint"`
	Conflict    *string         `json:"conflict"`
	Snapshot    string          `json:"snapshot"`
	Validation  json.RawMessage `json:"validation"`
	Witness     json.RawMessage `json:"witness"`
}
type messageInventory struct {
	Certificates  []messageCertificate `json:"certificates"`
	Associations  []messageAssociation `json:"associations"`
	Transactions  []messageTransaction `json:"transactions"`
	Publications  []messagePublication `json:"publications"`
	artifactBytes int64
}

func newMessageInventory() *messageInventory {
	return &messageInventory{Certificates: []messageCertificate{}, Associations: []messageAssociation{}, Transactions: []messageTransaction{}, Publications: []messagePublication{}}
}

// All internal schema members are required, including nullable references. The
// reflection walks only our closed persisted types; it is not a wire codec.
func messageRequired(raw json.RawMessage, t reflect.Type) error {
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		return messageRequired(raw, t.Elem())
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return failure("null message state")
	}
	if t == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var names []string
		types := map[string]reflect.Type{}
		for x := 0; x < t.NumField(); x++ {
			f := t.Field(x)
			if !f.IsExported() {
				continue
			}
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				return failure("invalid message type")
			}
			names = append(names, name)
			types[name] = f.Type
		}
		fields, e := objectMembers(raw, nil, names...)
		if e != nil {
			return e
		}
		for _, name := range names {
			v, ok := fields[name]
			if !ok {
				return failure("missing message member")
			}
			if e := messageRequired(v, types[name]); e != nil {
				return e
			}
		}
	case reflect.Slice:
		var rows []json.RawMessage
		if json.Unmarshal(raw, &rows) != nil || rows == nil {
			return failure("invalid message array")
		}
		if len(rows) > messageHistoryLimit {
			return failure("message history exceeded")
		}
		for _, r := range rows {
			if e := messageRequired(r, t.Elem()); e != nil {
				return e
			}
		}
	}
	return nil
}
func (m *messageInventory) UnmarshalJSON(raw []byte) error {
	if e := messageRequired(raw, reflect.TypeFor[messageInventory]()); e != nil {
		return e
	}
	type plain messageInventory
	return StrictJSON(bytes.NewReader(raw), (*plain)(m))
}
func messageHash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func messageID(id string) bool {
	if len(id) != 32 {
		return false
	}
	_, e := hex.DecodeString(id)
	return e == nil && strings.ToLower(id) == id
}
func messageRef(raw []byte) messageArtifact {
	return messageArtifact{messageHash(raw), int64(len(raw))}
}
func (s *Store) messageAssociation(b messageBinding) *messageAssociation {
	if s.messages != nil {
		for x := range s.messages.Associations {
			if s.messages.Associations[x].Binding == b {
				return &s.messages.Associations[x]
			}
		}
	}
	return nil
}
func (s *Store) messageTx(id string) *messageTransaction {
	if s.messages != nil {
		for x := range s.messages.Transactions {
			if s.messages.Transactions[x].ID == id {
				return &s.messages.Transactions[x]
			}
		}
	}
	return nil
}

// Until separately qualified publication/activation is implemented, every
// message-authority selection is closed. A readable prior T never bypasses a
// pending fence, including after restart or for retained-result disclosure.
func (s *Store) messageCurrent(b Binding) (messageCertificate, Code) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, c := s.lookup(b.UID, b.Generation); c != "" {
		return messageCertificate{}, c
	}
	if a := s.messageAssociation(messageBindingOf(b)); a != nil && a.Pending != nil {
		return messageCertificate{}, "key_not_enrolled"
	}
	return messageCertificate{}, "key_not_enrolled"
}

func (m *messageInventory) reservation() int64 {
	var total int64
	for _, a := range m.Associations {
		if a.Pending != nil {
			total += messageProofReserve
		}
	}
	return total
}

// messageCapacity charges every byte that coexists on disk, plus unspent proof
// reservations. Callers supply future immutable artifacts, recovery copies and
// install staging separately; installed bindings.json is measured, not inferred
// from a prospective state which may shrink. No write is needed for this check.
func (s *Store) messageCapacity(artifacts, recovery, staging int64) bool {
	if s.messages == nil || s.dir == nil {
		return false
	}
	f, err := openRelative(s.dir, "bindings.json", syscall.O_RDONLY, s.uid, 0600)
	if err != nil {
		return false
	}
	st, err := f.Stat()
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return false
	}
	total := int64(0)
	for _, n := range []int64{st.Size(), s.messages.artifactBytes, s.messages.reservation(), artifacts, recovery, staging} {
		if n < 0 || n > stateBudget-total {
			return false
		}
		total += n
	}
	return true
}
func (s *Store) messageFits(rawBytes int) bool {
	return s.messageFitsTransitions(rawBytes, 1, 0)
}

// Each transition retains a new recovery body. At a later transition the prior
// installed snapshot may itself have grown to rawBytes. Reserving its upper
// bound as well covers the peak across a native intent/effect pair.
func (s *Store) messageFitsTransitions(rawBytes, transitions int, artifacts int64) bool {
	if rawBytes < 0 || rawBytes > stateBudget || transitions < 1 || transitions > 3 {
		return false
	}
	recovery := int64(rawBytes) * int64(transitions)
	staging := int64(rawBytes)
	if transitions > 1 {
		staging += int64(rawBytes)
	}
	return s.messageCapacity(artifacts, recovery, staging)
}

// messagePreview deliberately copies only sizing/serialization inputs, never
// the Store gate, watchers or request index. Caller already holds Store's gate.
func (s *Store) messagePreview() *Store {
	return &Store{dir: s.dir, uid: s.uid, schema: s.schema, messages: s.messages,
		records: s.records, requests: s.requests, next: s.next, version: s.version, journal: s.journal}
}

// Audit linkage is not known until commit. Bound its complete encoded form
// before creating the recovery file or appending anything to the journal.
func (s *Store) messageSnapshotBound(version uint64) ([]byte, error) {
	return canonical(s.disk(version, bindingCommit{Seq: 9007199254740991, Hash: strings.Repeat("0", 64)}))
}

// Store/generation checks are held through preparation and each durable phase.
// PENDING: production scheduling, root policy provisioning and provider latency
// qualification. Clock/audit collection in this internal path is not qualified
// for generation windows; production needs separately reviewed bounded authority
// preparation/rechecks. No non-message production file constructs this service.
type messageCertification struct {
	store       *Store
	issuer      *messageIssuer
	generations GenerationSource
	entropy     io.Reader
	facts       func(context.Context, Binding) (verifier.Context, Code)
}

func (c *messageCertification) issue(ctx context.Context, selected Binding) (string, Code) {
	if c == nil || c.store == nil || c.issuer == nil || c.generations == nil || c.facts == nil {
		return "", "key_not_enrolled"
	}
	var id string
	code := c.generations.WithActive(ctx, selected.UID, selected.Generation, func(ctx context.Context) Code {
		s := c.store
		if !s.mu.LockContext(ctx) {
			return "request_deadline_exceeded"
		}
		defer s.mu.Unlock()
		b, code := s.lookup(selected.UID, selected.Generation)
		if code != "" {
			return code
		}
		if b != selected {
			return "binding_conflict"
		}
		if s.schema != 2 || s.messages == nil || s.dir == nil {
			return "key_not_enrolled"
		}
		mb := messageBindingOf(b)
		association := s.messageAssociation(mb)
		if association != nil && association.Pending != nil {
			return "key_not_enrolled"
		}
		if len(s.messages.Transactions) >= messageHistoryLimit || len(s.messages.Certificates) >= messageHistoryLimit || association == nil && len(s.messages.Associations) >= messageHistoryLimit {
			return "state_capacity_exceeded"
		}
		body, e := s.messageBody(s.version + 1)
		if e != nil || !s.messageFits(len(body)*4+messageProofReserve) {
			return "state_capacity_exceeded"
		}
		if c.issuer.clock == nil {
			return "clock_untrusted"
		}
		sample, e := c.issuer.clock.Sample(ctx)
		if e != nil || !timeconfidence.Valid(sample) {
			return "clock_untrusted"
		}
		public, key, code := messagePublicLocked(c.issuer.master, s, b, c.issuer.policy.Epoch, c.issuer.policy.RegistryRevision)
		if code != "" {
			return code
		}
		if _, code = c.issuer.body(b, public, sample.Now); code != "" {
			return code
		}
		if code = c.issuer.validateRoot(); code != "" {
			return code
		}
		facts, code := c.facts(ctx, b)
		if code != "" {
			return code
		}
		ctx, releaseAudit, code := s.journal.reserveMessageAudit(ctx)
		if code != "" {
			return code
		}
		defer releaseAudit()
		entropy := c.entropy
		if entropy == nil {
			entropy = rand.Reader
		}
		var nonce [16]byte
		if _, e = io.ReadFull(entropy, nonce[:]); e != nil {
			return "key_not_enrolled"
		}
		id = hex.EncodeToString(nonce[:])
		if s.messageTx(id) != nil {
			return "request_conflict"
		}
		base, e := s.contentDigest(s.version)
		if e != nil {
			return "audit_unavailable"
		}
		var previous *string
		kind := "issue"
		if association != nil && association.Current != nil {
			v := *association.Current
			previous = &v
			kind = "renew"
		}
		intent := messageIntent{b, c.issuer.policy, key, messageStamp(sample.Now), int64(len(body))*8 + messageProofReserve, s.version, base, previous}
		ref, code := s.writeMessageArtifact(ctx, id, intent)
		if code != "" {
			s.failed = true
			return code
		}
		s.messages.Transactions = append(s.messages.Transactions, messageTransaction{ID: id, Kind: kind, BaseVersion: s.version, BaseDigest: base, PreviousCurrent: previous, Intent: ref, Phase: "intent"})
		if association == nil {
			s.messages.Associations = append(s.messages.Associations, messageAssociation{Binding: mb})
			association = &s.messages.Associations[len(s.messages.Associations)-1]
		}
		association.Pending = &id
		if code = s.messagePhase(ctx, id, "message_certification_fence", ref); code != "" {
			s.failed = true
			return code
		}
		cert, code := c.issuer.prepareAt(ctx, id, b, public, facts, sample.Now)
		if code != "" {
			return code
		} // Durable intent remains closed; offline abort needs exact proof.
		if code = s.messagePoint("signed"); code != "" {
			s.failed = true
			return code
		}
		candidate := messageCandidate{Certificate: cert, Intent: ref, Effect: messageCandidateEffect{messageBindingOf(b), intent.BaseVersion, intent.BaseDigest, previous, id, "issued", nil}}
		candidateRef, code := s.writeMessageArtifact(ctx, id, candidate)
		if code != "" {
			s.failed = true
			return code
		}
		tx := s.messageTx(id)
		tx.Candidate = &candidateRef
		tx.Phase = "prepared"
		if code = s.messagePhase(ctx, id, "", candidateRef); code != "" {
			s.failed = true
			return code
		}
		tx.Phase = "issued"
		s.messages.Certificates = append(s.messages.Certificates, cert)
		operation := "message_attestation_issue"
		if tx.Kind == "renew" {
			operation = "message_attestation_renew"
		}
		if code = s.messagePhase(ctx, id, operation, candidateRef); code != "" {
			s.failed = true
			return code
		}
		// Candidate commitment is not current-T promotion. Publication and activation
		// have no S2 transition, even if the caller can read the exact certificate.
		return ""
	})
	return id, code
}
func (s *Store) messagePoint(point string) Code {
	if s.messageFault != nil {
		return s.messageFault(point)
	}
	return ""
}
func (s *Store) messagePhase(ctx context.Context, id, operation string, ref messageArtifact) Code {
	if operation != "" {
		tx := s.messageTx(id)
		if tx == nil {
			return "audit_unavailable"
		}
		intent, code := s.readMessageIntent(tx)
		if code != "" {
			return code
		}
		phase := tx.Phase
		if operation == "message_certification_reconcile" {
			phase = "reconcile"
		}
		if code = s.messageAudit(ctx, id, phase, operation, ref.Hash, intent.Binding); code != "" {
			return code
		}
	}
	return s.persistMessagesContext(ctx, id)
}
func (s *Store) messageAudit(ctx context.Context, id, phase, operation, digest string, b Binding) Code {
	if s.journal == nil {
		return "audit_unavailable"
	}
	request, domain := "msg:"+id+":"+phase, "control"
	r := AuditRecord{Surface: "control", RequestID: &request, Operation: operation, Domain: &domain, PayloadDigest: &digest, Result: "success"}
	if b.Generation != "" {
		r.PeerUID, r.Generation, r.Path, r.Epoch = &b.UID, &b.Generation, &b.Path, &b.Epoch
	}
	return s.journal.AppendContext(ctx, r)
}
func (s *Store) messageBody(version uint64) ([]byte, error) {
	d := s.disk(version, bindingCommit{})
	raw, e := json.Marshal(d)
	if e != nil {
		return nil, e
	}
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if e = dec.Decode(&obj); e != nil {
		return nil, e
	}
	delete(obj, "audit_seq")
	delete(obj, "audit_hash")
	return canonical(obj)
}
func (s *Store) disk(version uint64, commit bindingCommit) bindingDisk {
	return bindingDisk{Next: s.next, Records: s.records, Requests: s.requests, Version: version, AuditSeq: commit.Seq, AuditHash: commit.Hash, SchemaVersion: s.schema, Messages: s.messages}
}
func (s *Store) readMessageIntent(tx *messageTransaction) (messageIntent, Code) {
	var i messageIntent
	code := s.readMessageArtifact(tx.ID, tx.Intent, &i)
	return i, code
}

func (s *Store) persistMessagesContext(ctx context.Context, ids ...string) Code {
	if auditContextExpired(ctx) {
		return "request_deadline_exceeded"
	}
	if s.dir == nil || s.journal == nil || s.schema != 2 || s.messages == nil || s.version >= 9007199254740991 {
		return "audit_unavailable"
	}
	id := "migration"
	if len(ids) > 0 {
		id = ids[0]
	} else if len(s.messages.Transactions) > 0 {
		id = s.messages.Transactions[len(s.messages.Transactions)-1].ID
	}
	version := s.version + 1
	body, e := s.messageBody(version)
	bound, boundErr := s.messageSnapshotBound(version)
	if e != nil || boundErr != nil || !s.messageFits(len(bound)) {
		return "state_capacity_exceeded"
	}
	if code := s.writeMessageFile(ctx, id, "snapshot-"+strconv.FormatUint(version, 10), body); code != "" {
		return code
	}
	if code := s.messagePoint("before-commit"); code != "" {
		return code
	}
	commit, code := s.journal.commitBindingContext(ctx, version, messageHash(body))
	if code != "" {
		return code
	}
	if code = s.messagePoint("after-commit"); code != "" {
		return code
	}
	raw, e := canonical(s.disk(version, commit))
	if e != nil || len(raw) > len(bound) {
		// A violated encoder bound is an internal failure, never a capacity refusal
		// after a journal commit. The preflight already reserved both future copies.
		return "audit_unavailable"
	}
	if code = s.installMessageSnapshot(ctx, raw); code != "" {
		return code
	}
	s.version, s.auditSeq, s.auditHash = version, commit.Seq, commit.Hash
	return ""
}
func (s *Store) installMessageSnapshot(ctx context.Context, raw []byte) Code {
	if auditContextExpired(ctx) {
		return "request_deadline_exceeded"
	}
	f, e := openRelative(s.dir, "bindings.next", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, s.uid, 0600)
	if e != nil {
		return "audit_unavailable"
	}
	_, e = f.Write(raw)
	if e == nil {
		e = s.messagePointError("snapshot-write")
	}
	if e == nil {
		e = f.Sync()
	}
	if e == nil {
		e = s.messagePointError("snapshot-sync")
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return "audit_unavailable"
	}
	if e = syscall.Renameat(int(s.dir.Fd()), "bindings.next", int(s.dir.Fd()), "bindings.json"); e != nil {
		return "audit_unavailable"
	}
	if code := s.messagePoint("snapshot-rename"); code != "" {
		return code
	}
	if s.dir.Sync() != nil {
		return "audit_unavailable"
	}
	return s.messagePoint("snapshot-directory-sync")
}
func (s *Store) messagePointError(point string) error {
	if code := s.messagePoint(point); code != "" {
		return code
	}
	return nil
}
