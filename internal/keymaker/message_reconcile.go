package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// messageSchemaFloor is obtained only from protected owner policy. There is no
// service-writable floor, automatic downgrade or production configuration hook.
// PENDING: deployment must exclude older/restored serving instances independently
// of this local lock; complete-store rollback detection still needs Option C.
type messageSchemaFloor struct{ minimum int }
type messageFloorDocument struct {
	Minimum int `json:"minimum_reader_schema"`
}

func validMessageFloorStat(uid uint32, mode uint32) bool { return uid == 0 && mode == 0600 }
func loadMessageSchemaFloor(path string) (messageSchemaFloor, error) {
	var document messageFloorDocument
	if e := ProtectedConfig(path, &document); e != nil {
		return messageSchemaFloor{}, e
	}
	st, e := os.Lstat(path)
	if e != nil || !validMessageFloorStat(st.Sys().(*syscall.Stat_t).Uid, uint32(st.Mode().Perm())) || document.Minimum != 2 {
		return messageSchemaFloor{}, failure("invalid minimum reader floor")
	}
	return messageSchemaFloor{minimum: document.Minimum}, nil
}
func openMessageStore(dir *os.File, uid uint32, floor messageSchemaFloor, clock AuditClock) (*Store, error) {
	if floor.minimum != 2 {
		return nil, failure("minimum reader floor unavailable")
	}
	lock, e := LockState(dir, uid)
	if e != nil {
		return nil, e
	}
	s, _, _, e := openCustodyStateMessage(dir, uid, clock, floor.minimum, false)
	if e != nil {
		lock.Close()
		return nil, e
	}
	s.messageLock = lock
	return s, nil
}

type messageMaintenance struct {
	store *Store
	lock  *os.File
	floor messageSchemaFloor
}

func openMessageMaintenance(dir *os.File, uid uint32, floor messageSchemaFloor, clock AuditClock) (*messageMaintenance, error) {
	if floor.minimum != 2 {
		return nil, failure("minimum reader floor unavailable")
	}
	lock, e := LockState(dir, uid)
	if e != nil {
		return nil, e
	}
	s, _, _, e := openCustodyStateMessage(dir, uid, clock, 2, true)
	if e != nil {
		lock.Close()
		return nil, e
	}
	return &messageMaintenance{store: s, lock: lock, floor: floor}, nil
}
func (m *messageMaintenance) Close() error {
	e := m.store.Close()
	ce := m.lock.Close()
	if e != nil {
		return e
	}
	return ce
}

type messageMigrationDecision struct {
	From        int    `json:"from_schema"`
	To          int    `json:"to_schema"`
	BaseVersion uint64 `json:"base_version"`
	BaseDigest  string `json:"base_digest"`
}

func (m *messageMaintenance) migrate(ctx context.Context) Code {
	s := m.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.floor.minimum != 2 || s.schema != 0 || !s.matchesCommit(s.journal.binding) {
		return "audit_unavailable"
	}
	ctx, release, code := s.journal.reserveMessageAudit(ctx)
	if code != "" {
		return code
	}
	defer release()
	fd, pendingErr := syscall.Openat(int(s.dir.Fd()), "bindings.next", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if pendingErr == nil {
		syscall.Close(fd)
	}
	if pendingErr != syscall.ENOENT {
		return "audit_unavailable"
	}
	fd, stagingErr := syscall.Openat(int(s.dir.Fd()), "message-tx", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if stagingErr == nil {
		syscall.Close(fd)
	}
	if stagingErr != syscall.ENOENT {
		return "audit_unavailable"
	}
	old, e := messageRead(s.dir, "bindings.json", s.uid, stateBudget)
	if e != nil {
		return "audit_unavailable"
	}
	base, e := s.contentDigest(s.version)
	if e != nil {
		return "audit_unavailable"
	}
	decision := messageMigrationDecision{1, 2, s.version, base}
	raw, e := canonical(decision)
	if e != nil {
		return "audit_unavailable"
	}
	preview := s.messagePreview()
	preview.schema, preview.messages = 2, newMessageInventory()
	bound, e := preview.messageSnapshotBound(s.version + 1)
	if e != nil || !preview.messageFitsTransitions(len(bound), 1, int64(len(old))+int64(len(raw))) {
		return "state_capacity_exceeded"
	}
	s.schema, s.messages = preview.schema, preview.messages
	if code := s.writeMessageFile(ctx, "migration", "base", old); code != "" {
		s.failed = true
		return code
	}
	if code := s.writeMessageFile(ctx, "migration", "decision", raw); code != "" {
		s.failed = true
		return code
	}
	if code := s.messageAudit(ctx, strings.Repeat("0", 32), "migrate", "message_state_migrate", messageHash(raw), Binding{}); code != "" {
		s.failed = true
		return code
	}
	if code := s.persistMessagesContext(ctx, "migration"); code != "" {
		s.failed = true
		return code
	}
	return ""
}

type messageRecoveryExpectation struct {
	Transaction     string
	BaseDigest      string
	CandidateDigest string
	Outcome         string
}

// reconcile has no issuer, master, entropy, publisher or cryptographic-signing
// dependency. An operator invocation selects an expected retained transaction;
// only exact replayed evidence determines whether abort/commit is provable.
// It never activates a certificate or clears an issued-candidate fence in S2.
func (m *messageMaintenance) reconcile(ctx context.Context, expected messageRecoveryExpectation) Code {
	s := m.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.floor.minimum != 2 || !messageID(expected.Transaction) || !validDigest(expected.BaseDigest) || (expected.Outcome != "commit" && expected.Outcome != "abort") {
		return "audit_unavailable"
	}
	ctx, release, code := s.journal.reserveMessageAudit(ctx)
	if code != "" {
		return code
	}
	defer release()
	if !s.matchesCommit(s.journal.binding) {
		candidate, raw, code := s.messageRecoverySnapshot(s.journal.binding, expected.Transaction)
		if code != "" {
			return code
		}
		tx := candidate.messageTx(expected.Transaction)
		if !messageRecoveryMatches(tx, expected) || !messageRecoveryOutcome(tx, expected.Outcome) {
			return "audit_unavailable"
		}
		// Establish the surviving journal tail's durability before installing its exact
		// already retained body. The commit supplies only audit linkage, no lost bytes.
		if s.journal.file.Sync() != nil || s.auditDir.Sync() != nil {
			return "audit_unavailable"
		}
		pending, e := messageRead(s.dir, "bindings.next", s.uid, stateBudget)
		if e == nil {
			if !bytes.Equal(pending, raw) {
				return "audit_unavailable"
			}
			// A complete write may have survived before its original fsync. Reassert
			// file durability before the rename; directory sync alone is insufficient.
			staging, e := openRelative(s.dir, "bindings.next", syscall.O_RDWR, s.uid, 0600)
			if e != nil {
				return "audit_unavailable"
			}
			e = staging.Sync()
			closeErr := staging.Close()
			if e != nil || closeErr != nil || s.messagePoint("recovery-staging-sync") != "" {
				return "audit_unavailable"
			}
			if syscall.Renameat(int(s.dir.Fd()), "bindings.next", int(s.dir.Fd()), "bindings.json") != nil || s.dir.Sync() != nil {
				return "audit_unavailable"
			}
		} else {
			// Only genuine absence permits creating a fresh install staging file; unsafe
			// or unreadable existing entries are never removed or overwritten.
			fd, err := syscall.Openat(int(s.dir.Fd()), "bindings.next", syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
			if err != syscall.ENOENT {
				if err == nil {
					syscall.Close(fd)
				}
				return "audit_unavailable"
			}
			if code := s.installMessageSnapshot(ctx, raw); code != "" {
				return code
			}
		}
		s.records, s.requests, s.next, s.version, s.auditSeq, s.auditHash, s.schema, s.messages = candidate.records, candidate.requests, candidate.next, candidate.version, candidate.auditSeq, candidate.auditHash, candidate.schema, candidate.messages
		s.requestIndex = candidate.requestIndex
	}
	tx := s.messageTx(expected.Transaction)
	if !messageRecoveryMatches(tx, expected) {
		return "audit_unavailable"
	}
	// Extra/unmatched artifacts and later snapshots make an abort unknown; normal
	// validation must succeed before a resolution can change any state.
	if e := s.validateMessages(); e != nil {
		return "audit_unavailable"
	}
	if tx.Resolution != nil {
		var prior messageResolution
		if s.readMessageArtifact(tx.ID, *tx.Resolution, &prior) != "" {
			return "audit_unavailable"
		}
		if expected.Outcome == "commit" && prior.Outcome == "issued" || expected.Outcome == "abort" && prior.Outcome == "aborted" {
			return ""
		}
		return "audit_unavailable"
	}
	association := s.messageAssociationOfTransaction(tx)
	if association == nil || association.Pending == nil || *association.Pending != tx.ID {
		return "audit_unavailable"
	}
	switch expected.Outcome {
	case "abort":
		if tx.Phase != "intent" && tx.Phase != "prepared" {
			return "audit_unavailable"
		}
	case "commit":
		if tx.Phase != "issued" {
			return "audit_unavailable"
		}
	}
	resolution := messageResolution{Outcome: "issued", Intent: tx.Intent, Candidate: tx.Candidate, Version: s.version, Digest: s.journal.binding.Digest}
	if expected.Outcome == "abort" {
		resolution.Outcome = "aborted"
	}
	// Size the complete proposed resolution, its artifact, recovery copy and
	// install staging before retaining any new evidence or appending its audit.
	resolutionBytes, e := canonical(resolution)
	if e != nil {
		return "audit_unavailable"
	}
	preview := s.messagePreview()
	inventory := *s.messages
	inventory.Transactions = append([]messageTransaction(nil), inventory.Transactions...)
	inventory.Associations = append([]messageAssociation(nil), inventory.Associations...)
	preview.messages = &inventory
	proposed := preview.messageTx(tx.ID)
	proposedRef := messageRef(resolutionBytes)
	proposed.Resolution = &proposedRef
	if expected.Outcome == "abort" {
		proposed.Phase = "aborted"
		preview.messageAssociationOfTransaction(proposed).Pending = nil
	}
	bound, e := preview.messageSnapshotBound(s.version + 1)
	if e != nil || !preview.messageFitsTransitions(len(bound), 1, int64(len(resolutionBytes))) {
		return "state_capacity_exceeded"
	}
	ref, code := s.writeMessageArtifact(ctx, tx.ID, resolution)
	if code != "" {
		s.failed = true
		return code
	}
	tx.Resolution = &ref
	operation := "message_certification_reconcile"
	if expected.Outcome == "abort" {
		tx.Phase = "aborted"
		association.Pending = nil
		operation = "message_certification_abort"
	}
	s.failed = false
	if code = s.messagePhase(ctx, tx.ID, operation, ref); code != "" {
		s.failed = true
		return code
	}
	return ""
}
func messageRecoveryMatches(tx *messageTransaction, e messageRecoveryExpectation) bool {
	if tx == nil || tx.ID != e.Transaction || tx.BaseDigest != e.BaseDigest {
		return false
	}
	return tx.Candidate == nil && e.CandidateDigest == "" || tx.Candidate != nil && tx.Candidate.Hash == e.CandidateDigest
}
func messageRecoveryOutcome(tx *messageTransaction, outcome string) bool {
	return tx != nil && (outcome == "commit" && tx.Phase == "issued" || outcome == "abort" && (tx.Phase == "intent" || tx.Phase == "prepared" || tx.Phase == "aborted"))
}
func (s *Store) messageAssociationOfTransaction(tx *messageTransaction) *messageAssociation {
	intent, code := s.readMessageIntent(tx)
	if code != "" {
		return nil
	}
	return s.messageAssociation(messageBindingOf(intent.Binding))
}
func (s *Store) messageRecoverySnapshot(commit bindingCommit, id string) (*Store, []byte, Code) {
	if !messageID(id) {
		return nil, nil, "audit_unavailable"
	}
	dir, e := s.messageDirectory(id, false)
	if e != nil {
		return nil, nil, "audit_unavailable"
	}
	defer dir.Close()
	raw, e := messageRead(dir, "snapshot-"+strconv.FormatUint(commit.Version, 10), s.uid, stateBudget)
	if e != nil || messageHash(raw) != commit.Digest {
		return nil, nil, "audit_unavailable"
	}
	var body map[string]json.RawMessage
	if StrictJSON(bytes.NewReader(raw), &body) != nil {
		return nil, nil, "audit_unavailable"
	}
	body["audit_seq"], _ = json.Marshal(commit.Seq)
	body["audit_hash"], _ = json.Marshal(commit.Hash)
	installed, e := canonical(body)
	if e != nil {
		return nil, nil, "audit_unavailable"
	}
	var disk bindingDisk
	if StrictJSON(bytes.NewReader(installed), &disk) != nil {
		return nil, nil, "audit_unavailable"
	}
	candidate := NewStore()
	candidate.dir, candidate.uid, candidate.journal = s.dir, s.uid, s.journal
	candidate.schema, candidate.messages = disk.SchemaVersion, disk.Messages
	candidate.records, candidate.requests, candidate.next = disk.Records, disk.Requests, disk.Next
	candidate.version, candidate.auditSeq, candidate.auditHash = disk.Version, disk.AuditSeq, disk.AuditHash
	if candidate.validate() != "" || candidate.validateRequests() != nil || !candidate.matchesCommit(commit) || candidate.validateMessages() != nil {
		return nil, nil, "audit_unavailable"
	}
	return candidate, installed, ""
}
