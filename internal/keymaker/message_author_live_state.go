package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-envelope/record"
)

const maLiveSchema = 8
const maLiveAttemptLimit = 2304
const maLiveStateLimit = 11796480

// Fresh attempts and enrollments leave a fixed 64 KiB of encoded state for
// retirement. Each canonical binding exceeds 64 bytes, so the absolute snapshot
// ceiling permits fewer than 65536 bindings; active -> revoked adds one byte
// each, while terminal attempt tombstones never grow their reserved rows.
const maLiveRetireReserve = 64 << 10

// Two existing generation anchors are each capped at 4096 bytes. Snapshot
// commits can retain the old, staging and new copies at the same time.
const maLiveStateOverhead = 8192

// The six states record effect knowledge, not connection state. Fenced is a
// separate continuity overlay; neither startup nor a healthy provider clears it.
type maLiveInventory struct {
	Format   string           `json:"format"`
	Instance string           `json:"instance"`
	Epoch    string           `json:"master_epoch"`
	Registry string           `json:"registry_revision"`
	Fenced   bool             `json:"fenced"`
	Attempts []maLiveAttempt  `json:"attempts"`
	Issuers  []maIssuerRecord `json:"issuers"`
}
type maLiveAttempt struct {
	Caller      Principal `json:"caller"`
	ID          string    `json:"id"`
	Method      string    `json:"method"`
	Preimage    []byte    `json:"preimage"`
	Binding     Binding   `json:"binding"`
	Instance    string    `json:"instance"`
	Key         string    `json:"key"`
	Attestation string    `json:"author_attestation"`
	Status      string    `json:"status"`
	Signature   []byte    `json:"signature"`
	SuccessSeq  uint64    `json:"success_audit_seq"`
	SuccessHash string    `json:"success_audit_hash"`
}

func (m *maLiveInventory) UnmarshalJSON(raw []byte) error {
	if _, e := objectMembers(raw, []string{"format", "instance", "master_epoch", "registry_revision", "fenced", "attempts", "issuers"}); e != nil {
		return e
	}
	type plain maLiveInventory
	return StrictJSON(bytes.NewReader(raw), (*plain)(m))
}
func (a *maLiveAttempt) UnmarshalJSON(raw []byte) error {
	fields, e := objectMembers(raw, []string{"caller", "id", "method", "preimage", "binding", "instance", "key", "author_attestation", "status", "success_audit_seq", "success_audit_hash"}, "signature")
	if e != nil {
		return e
	}
	if _, ok := fields["signature"]; !ok {
		return failure("missing signature knowledge")
	}
	if e = messageRequired(fields["caller"], reflect.TypeFor[Principal]()); e != nil {
		return e
	}
	if e = messageRequired(fields["binding"], reflect.TypeFor[Binding]()); e != nil {
		return e
	}
	type plain maLiveAttempt
	return StrictJSON(bytes.NewReader(raw), (*plain)(a))
}
func maLiveStatus(status string) bool {
	switch status {
	case "intent", "invoking", "result", "handoff_unknown", "released", "dead":
		return true
	}
	return false
}

// The cache contains canonical bytes, never a second authority. Full load validation
// builds it; runtime writers name every changed row while holding Store. Immutable
// caller/id keys cannot be reassigned and result room is reserved before invocation.
type maLiveStateCache struct {
	rows     [][]byte
	reserved []int
	total    int
	actual   int
	ids      map[requestKey]int
	bindings map[uint64]Binding
	records  []byte
}

func (s *Store) maLiveHeader() error {
	m := s.maLive
	if s.schema != maLiveSchema || m == nil || m.Format != "keymaker-message-author-state/2" || !validJ7Instance(m.Instance) || m.Epoch == "" || m.Registry == "" || m.Attempts == nil || m.Issuers == nil || len(m.Attempts) > maLiveAttemptLimit || s.j7 != nil || s.j7Signing != nil || s.messages != nil || len(s.requests) != 0 {
		return failure("invalid message-author state")
	}
	return nil
}
func (s *Store) maLiveRefreshBindings() error {
	if s.maLiveHeader() != nil || s.validate() != "" {
		return failure("invalid message-author bindings")
	}
	paths := map[string]bool{}
	bindings := map[uint64]Binding{}
	for _, b := range s.records {
		if b.Epoch != s.maLive.Epoch || b.RegistryRevision != s.maLive.Registry || paths[b.Epoch+":"+b.Path] {
			return failure("invalid message-author binding history")
		}
		paths[b.Epoch+":"+b.Path] = true
		bindings[b.Number] = b
	}
	raw, e := canonical(s.records)
	if e != nil {
		return e
	}
	s.maLiveCache.bindings = bindings
	s.maLiveCache.records = raw
	return nil
}
func (s *Store) validateMALiveAttempt(a maLiveAttempt) error {
	m := s.maLive
	if !maLiveID(a.ID) || !maLiveStatus(a.Status) || a.Method != "sign_message_author" || len(a.Preimage) > 24576 || a.Caller != (Principal{a.Binding.UID, a.Binding.Generation}) || a.Instance != m.Instance || a.Binding.Epoch != m.Epoch || a.Binding.RegistryRevision != m.Registry {
		return failure("invalid message-author attempt")
	}
	if _, c := prepareMessageAuthor(a.Preimage, a.Key, a.Attestation); c != "" {
		return failure("invalid message-author intent")
	}
	b, found := s.maLiveCache.bindings[a.Binding.Number]
	b.Status = a.Binding.Status
	if !found || b != a.Binding || a.Binding.Status != "active" {
		return failure("lost message-author binding")
	}
	if len(a.Signature) > 0 && record.VerifySignature(a.Key, a.Signature, a.Preimage) != nil {
		return failure("invalid message-author signature")
	}
	hasResult := a.Status == "result" || a.Status == "handoff_unknown" || a.Status == "released" || a.Status == "dead" && len(a.Signature) > 0
	if hasResult && (len(a.Signature) != 64 || a.SuccessSeq == 0 || !validDigest(a.SuccessHash)) || !hasResult && (len(a.Signature) != 0 || a.SuccessSeq != 0 || a.SuccessHash != "") {
		return failure("invalid message-author result proof")
	}
	return nil
}
func maLiveRowBytes(a maLiveAttempt) ([]byte, int, error) {
	raw, e := canonical(a)
	if e != nil {
		return nil, 0, e
	}
	reserved := len(raw)
	if a.Status == "intent" || a.Status == "invoking" {
		a.Signature = make([]byte, 64)
		a.SuccessSeq = j7SafeInteger
		a.SuccessHash = strings.Repeat("0", 64)
	}
	if a.Status != "dead" {
		// Replays need room for the longer handoff marker even after release.
		a.Status = "handoff_unknown"
		v, e := canonical(a)
		if e != nil {
			return nil, 0, e
		}
		reserved = len(v)
	}
	return raw, reserved, nil
}
func (s *Store) validateMALive() error {
	if e := s.maLiveHeader(); e != nil {
		return e
	}
	if e := s.validateMAIssuers(); e != nil {
		return e
	}
	old := s.maLiveCache
	s.maLiveCache = &maLiveStateCache{ids: map[requestKey]int{}}
	ok := false
	defer func() {
		if !ok {
			s.maLiveCache = old
		}
	}()
	if e := s.maLiveRefreshBindings(); e != nil {
		return e
	}
	for i, a := range s.maLive.Attempts {
		key := requestKey{Caller: a.Caller, ID: a.ID}
		if _, exists := s.maLiveCache.ids[key]; exists {
			return failure("duplicate message-author attempt")
		}
		if e := s.validateMALiveAttempt(a); e != nil {
			return e
		}
		raw, n, e := maLiveRowBytes(a)
		if e != nil {
			return e
		}
		s.maLiveCache.ids[key] = i
		s.maLiveCache.rows = append(s.maLiveCache.rows, raw)
		s.maLiveCache.reserved = append(s.maLiveCache.reserved, n)
		s.maLiveCache.total += n
		s.maLiveCache.actual += len(raw)
	}
	if !maLiveStateRoom(s.maLiveBodySize(j7SafeInteger, len(s.maLive.Attempts), s.maLiveCache.total) + maLiveReceiptBound) {
		return failure("message-author state capacity")
	}
	ok = true
	return nil
}
func (s *Store) maLiveIndex(p Principal, id string) int {
	for i := range s.maLive.Attempts {
		a := &s.maLive.Attempts[i]
		if a.Caller == p && a.ID == id {
			return i
		}
	}
	return -1
}

// All callers hold Store. Journal-first pair commits preserve the existing
// snapshot protocol. Once a durable effect starts its commit is completed even
// if the request expires; the delivery barrier separately suppresses late bytes.
func (s *Store) persistMALive(ctx context.Context, changed ...int) Code {
	return s.persistMALiveReserved(ctx, 0, changed...)
}

func (s *Store) persistMALiveAdmission(ctx context.Context, changed ...int) Code {
	return s.persistMALiveReserved(ctx, maLiveRetireReserve, changed...)
}

func (s *Store) persistMALiveReserved(ctx context.Context, reserve int, changed ...int) Code {
	if auditContextExpired(ctx) {
		return "request_deadline_exceeded"
	}
	if s.failed || s.journal == nil || s.dir == nil || s.version >= j7SafeInteger || s.maLiveHeader() != nil {
		return "message_author_unqualified"
	}
	// Only explicit initialization lacks a cache. Load always validates all rows.
	if s.maLiveCache == nil {
		if s.validateMALive() != nil {
			return "message_author_unqualified"
		}
	}
	cache := s.maLiveCache
	if len(s.maLive.Attempts) < len(cache.rows) {
		return "message_author_unqualified"
	}
	updates := map[int][]byte{}
	sizes := map[int]int{}
	keys := map[requestKey]int{}
	total := cache.total
	actual := cache.actual
	for _, i := range changed {
		if i < 0 || i >= len(s.maLive.Attempts) {
			return "message_author_unqualified"
		}
		if _, duplicate := updates[i]; duplicate {
			continue
		}
		a := s.maLive.Attempts[i]
		key := requestKey{Caller: a.Caller, ID: a.ID}
		if previous, exists := cache.ids[key]; exists && previous != i {
			return "message_author_unqualified"
		}
		if previous, exists := keys[key]; exists && previous != i {
			return "message_author_unqualified"
		}
		if i < len(cache.rows) {
			if previous, exists := cache.ids[key]; !exists || previous != i {
				return "message_author_unqualified"
			}
		}
		if i < len(cache.rows) {
			var previous maLiveAttempt
			if json.Unmarshal(cache.rows[i], &previous) != nil || previous.Caller != a.Caller || previous.ID != a.ID || previous.Method != a.Method || !bytes.Equal(previous.Preimage, a.Preimage) || previous.Binding != a.Binding || previous.Instance != a.Instance || previous.Key != a.Key || previous.Attestation != a.Attestation {
				return "message_author_unqualified"
			}
		}
		if s.validateMALiveAttempt(a) != nil {
			return "message_author_unqualified"
		}
		raw, n, e := maLiveRowBytes(a)
		if e != nil {
			return "message_author_unqualified"
		}
		updates[i] = raw
		sizes[i] = n
		keys[key] = i
		total += n
		actual += len(raw)
		if i < len(cache.rows) {
			total -= cache.reserved[i]
			actual -= len(cache.rows[i])
		}
	}
	for i := len(cache.rows); i < len(s.maLive.Attempts); i++ {
		if _, ok := updates[i]; !ok {
			return "message_author_unqualified"
		}
	}
	version := s.version + 1
	// Account incrementally before allocating the complete snapshot body.
	bound := s.maLiveBodySize(j7SafeInteger, len(s.maLive.Attempts), total) + maLiveReceiptBound
	if !maLiveStateRoom(bound + reserve) {
		return "state_capacity_exceeded"
	}
	body := s.maLiveBody(version, updates, actual)
	digest := messageHash(body)
	commit, c := s.journal.commitBindingContext(ctx, version, digest)
	if c != "" {
		if c == "request_deadline_exceeded" {
			return c
		}
		s.failed = true
		s.maLive.Fenced = true
		return c
	}
	// This is the same CCJ1 snapshot and journal-first protocol. Reuse the body
	// that was hashed rather than canonicalizing the retained inventory again.
	raw := make([]byte, 0, len(body)+maLiveReceiptBound)
	raw = append(raw, `{"audit_hash":"`...)
	raw = append(raw, commit.Hash...)
	raw = append(raw, `","audit_seq":`...)
	raw = strconv.AppendUint(raw, commit.Seq, 10)
	raw = append(raw, ',')
	raw = append(raw, body[1:]...)
	if len(raw) > bound || s.installMessageSnapshot(context.WithoutCancel(ctx), raw) != "" {
		s.failed = true
		s.maLive.Fenced = true
		return "message_author_unqualified"
	}
	for i := len(cache.rows); i < len(s.maLive.Attempts); i++ {
		cache.rows = append(cache.rows, nil)
		cache.reserved = append(cache.reserved, 0)
	}
	for i, raw := range updates {
		cache.rows[i] = raw
		cache.reserved[i] = sizes[i]
	}
	for key, i := range keys {
		cache.ids[key] = i
	}
	cache.total = total
	cache.actual = actual
	s.version, s.auditSeq, s.auditHash = version, commit.Seq, commit.Hash
	return ""
}

const maLiveReceiptBound = len(`"audit_hash":"",`) + 64 + len(`"audit_seq":,`) + 16

// The fields are emitted in CCJ1 key order. Row/record fragments have already
// passed canonical encoding; only small metadata is encoded per transition.
func (s *Store) maLiveMetadata() []byte {
	m := s.maLive
	meta, _ := canonical(struct {
		Fenced   bool             `json:"fenced"`
		Format   string           `json:"format"`
		Instance string           `json:"instance"`
		Epoch    string           `json:"master_epoch"`
		Registry string           `json:"registry_revision"`
		Issuers  []maIssuerRecord `json:"issuers"`
	}{m.Fenced, m.Format, m.Instance, m.Epoch, m.Registry, m.Issuers})
	return meta
}
func (s *Store) maLiveBodySize(version uint64, rows, rowBytes int) int {
	return len(`{"message_author":{"attempts":[`) + rowBytes + max(0, rows-1) + len(`],`) + len(s.maLiveMetadata()) - 1 + len(`,"next_registration_number":`) + len(strconv.FormatUint(s.next, 10)) + len(`,"records":`) + len(s.maLiveCache.records) + len(`,"requests":[],"schema_version":8,"version":`) + len(strconv.FormatUint(version, 10)) + 1
}
func (s *Store) maLiveBody(version uint64, updates map[int][]byte, actual int) []byte {
	m := s.maLive
	meta := s.maLiveMetadata()
	raw := make([]byte, 0, s.maLiveBodySize(version, len(m.Attempts), actual))
	raw = append(raw, `{"message_author":{"attempts":[`...)
	for i := range m.Attempts {
		if i > 0 {
			raw = append(raw, ',')
		}
		row, ok := updates[i]
		if !ok {
			row = s.maLiveCache.rows[i]
		}
		raw = append(raw, row...)
	}
	raw = append(raw, ']', ',')
	raw = append(raw, meta[1:]...)
	raw = append(raw, `,"next_registration_number":`...)
	raw = strconv.AppendUint(raw, s.next, 10)
	raw = append(raw, `,"records":`...)
	raw = append(raw, s.maLiveCache.records...)
	raw = append(raw, `,"requests":[],"schema_version":8,"version":`...)
	raw = strconv.AppendUint(raw, version, 10)
	return append(raw, '}')
}
func maLiveStateRoom(bytes int) bool {
	return bytes >= 0 && bytes <= (maLiveStateLimit-maLiveStateOverhead)/3
}
