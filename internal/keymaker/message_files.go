package keymaker

import (
	"bytes"
	"context"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/waggle/record"
)

func messageSubdir(parent *os.File, name string, uid uint32, create bool) (*os.File, error) {
	if name != "message-tx" && name != "migration" && !messageID(name) {
		return nil, failure("invalid message directory")
	}
	if create {
		if e := syscall.Mkdirat(int(parent.Fd()), name, 0700); e != nil && e != syscall.EEXIST {
			return nil, e
		}
		if e := parent.Sync(); e != nil {
			return nil, e
		}
	}
	fd, e := syscall.Openat(int(parent.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), name)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&07777 != 0700 {
		f.Close()
		return nil, failure("unsafe message directory")
	}
	return f, nil
}
func messageEntries(dir *os.File) ([]os.DirEntry, error) {
	fd, e := syscall.Openat(int(dir.Fd()), ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "message inventory")
	defer f.Close()
	return f.ReadDir(-1)
}
func (s *Store) messageDirectory(id string, create bool) (*os.File, error) {
	root, e := messageSubdir(s.dir, "message-tx", s.uid, create)
	if e != nil {
		return nil, e
	}
	defer root.Close()
	return messageSubdir(root, id, s.uid, create)
}
func messageRead(dir *os.File, name string, uid uint32, max int64) ([]byte, error) {
	f, e := openRelative(dir, name, syscall.O_RDONLY, uid, 0600)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max {
		return nil, failure("message artifact exceeded")
	}
	return raw, nil
}
func (s *Store) writeMessageFile(ctx context.Context, id, name string, raw []byte) Code {
	if auditContextExpired(ctx) {
		return "request_deadline_exceeded"
	}
	if !s.messageCapacity(int64(len(raw)), 0, 0) {
		return "state_capacity_exceeded"
	}
	dir, e := s.messageDirectory(id, true)
	if e != nil {
		return "audit_unavailable"
	}
	defer dir.Close()
	f, e := openRelative(dir, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, s.uid, 0600)
	if e != nil {
		return "audit_unavailable"
	}
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = s.messagePointError("artifact-write")
	}
	if e == nil {
		e = f.Sync()
	}
	if e == nil {
		e = s.messagePointError("artifact-sync")
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return "audit_unavailable"
	}
	if dir.Sync() != nil {
		return "audit_unavailable"
	}
	s.messages.artifactBytes += int64(len(raw))
	return s.messagePoint("artifact-directory-sync")
}
func (s *Store) writeMessageArtifact(ctx context.Context, id string, v any) (messageArtifact, Code) {
	raw, e := canonical(v)
	if e != nil {
		return messageArtifact{}, "binding_conflict"
	}
	ref := messageRef(raw)
	return ref, s.writeMessageFile(ctx, id, ref.Hash, raw)
}
func (s *Store) readMessageArtifact(id string, ref messageArtifact, v any) Code {
	if !validDigest(ref.Hash) || ref.Bytes < 1 || ref.Bytes > stateBudget {
		return "audit_unavailable"
	}
	dir, e := s.messageDirectory(id, false)
	if e != nil {
		return "audit_unavailable"
	}
	defer dir.Close()
	raw, e := messageRead(dir, ref.Hash, s.uid, ref.Bytes)
	if e != nil || int64(len(raw)) != ref.Bytes || messageHash(raw) != ref.Hash || messageRequired(raw, reflectMessageType(v)) != nil || StrictJSON(bytes.NewReader(raw), v) != nil {
		return "audit_unavailable"
	}
	encoded, e := canonical(v)
	if e != nil || !bytes.Equal(encoded, raw) {
		return "audit_unavailable"
	}
	return ""
}

// validateMessages checks S2's complete closed state and immutable referenced
// artifacts. There is deliberately no published/active acceptance path here.
func (s *Store) validateMessages() error {
	m := s.messages
	if s.schema != 2 || m == nil || len(m.Transactions) > messageHistoryLimit || len(m.Associations) > messageHistoryLimit || len(m.Certificates) > messageHistoryLimit || len(m.Publications) != 0 {
		return failure("invalid message state")
	}
	txs := map[string]bool{}
	refs := map[string]map[string]bool{}
	issued := map[string]messageCertificate{}
	for _, cert := range m.Certificates {
		if issued[cert.Transaction].Transaction != "" || !messageID(cert.Transaction) {
			return failure("duplicate message certificate")
		}
		if e := validateMessageCertificate(cert); e != nil {
			return e
		}
		issued[cert.Transaction] = cert
	}
	for _, tx := range m.Transactions {
		if !messageID(tx.ID) || txs[tx.ID] || tx.BaseVersion < 1 || tx.BaseVersion >= s.version || !validDigest(tx.BaseDigest) || (tx.Kind != "issue" && tx.Kind != "renew") {
			return failure("invalid message transaction")
		}
		txs[tx.ID] = true
		if digest, ok := s.journalCommitDigest(tx.BaseVersion); s.journal != nil && (!ok || digest != tx.BaseDigest) {
			return failure("unmatched message intent base")
		}
		if (tx.Kind == "issue") != (tx.PreviousCurrent == nil) {
			return failure("message kind disagrees with predecessor")
		}
		refs[tx.ID] = map[string]bool{tx.Intent.Hash: true}
		intent, code := s.readMessageIntent(&tx)
		if code != "" || intent.BaseVersion != tx.BaseVersion || intent.BaseDigest != tx.BaseDigest || intent.ReservedBytes < messageProofReserve || !sameMessageString(intent.PreviousCurrent, tx.PreviousCurrent) {
			return failure("invalid message intent")
		}
		if code := ValidatePath(intent.Binding.Path, "agent-identity"); code != "" {
			return failure("invalid message intent binding")
		}
		if _, ok := s.messageStoredBinding(intent.Binding); !ok {
			return failure("missing message binding")
		}
		if intent.ReservedBytes > stateBudget || validateMessageIntent(intent) != nil {
			return failure("invalid retained issuance plan")
		}
		association := s.messageAssociation(messageBindingOf(intent.Binding))
		if association == nil {
			return failure("missing message association")
		}
		if tx.PreviousCurrent != nil && issued[*tx.PreviousCurrent].Transaction == "" {
			return failure("missing previous certificate")
		}
		var candidate messageCandidate
		if tx.Candidate != nil {
			refs[tx.ID][tx.Candidate.Hash] = true
			if s.readMessageArtifact(tx.ID, *tx.Candidate, &candidate) != "" || !messageEffectMatches(candidate.Effect, tx, intent) || candidate.Intent != tx.Intent || candidate.Certificate.Transaction != tx.ID || candidate.Certificate.Binding != messageBindingOf(intent.Binding) || candidate.Certificate.KeyID != intent.KeyID || candidate.Certificate.IssuerPolicy != intent.Policy || validateMessageCertificate(candidate.Certificate) != nil {
				return failure("invalid message candidate")
			}
		}
		if tx.Candidate != nil {
			raw, _ := record.DecodeBase64(candidate.Certificate.Envelope, -1)
			value, e := record.Parse(raw, 8192, 16)
			if e != nil {
				return failure("invalid candidate plan")
			}
			if value.(map[string]any)["body"].(map[string]any)["iat"] != intent.IssuedAt {
				return failure("changed candidate lifetime")
			}
		}
		switch tx.Phase {
		case "intent":
			if tx.Candidate != nil {
				return failure("premature message candidate")
			}
		case "prepared":
			if tx.Candidate == nil {
				return failure("missing prepared candidate")
			}
		case "issued":
			if tx.Candidate == nil || issued[tx.ID] != candidate.Certificate {
				return failure("unmatched issued candidate")
			}
		case "aborted":
			if issued[tx.ID].Transaction != "" || tx.Resolution == nil {
				return failure("invalid message abort")
			}
		default:
			return failure("unqualified message phase")
		}
		if tx.Phase == "intent" || tx.Phase == "prepared" || tx.Phase == "issued" {
			if association.Pending == nil || *association.Pending != tx.ID {
				return failure("missing message fence")
			}
		}
		if tx.Phase != "issued" && issued[tx.ID].Transaction != "" {
			return failure("premature committed certificate")
		}
		if tx.Resolution != nil {
			refs[tx.ID][tx.Resolution.Hash] = true
			var resolution messageResolution
			if s.readMessageArtifact(tx.ID, *tx.Resolution, &resolution) != "" || resolution.Intent != tx.Intent || !sameMessageArtifact(resolution.Candidate, tx.Candidate) || resolution.Version <= tx.BaseVersion || resolution.Version >= s.version || !validDigest(resolution.Digest) || (resolution.Outcome != "aborted" && resolution.Outcome != "issued") || (resolution.Outcome == "aborted") != (tx.Phase == "aborted") {
				return failure("invalid message resolution")
			}
			if digest, ok := s.journalCommitDigest(resolution.Version); s.journal != nil && (!ok || digest != resolution.Digest) {
				return failure("unmatched resolution base")
			}
		}
		if e := s.validateMessageEvents(tx, intent); e != nil {
			return e
		}
	}
	for id := range issued {
		if !txs[id] {
			return failure("orphan certificate")
		}
	}
	seen := map[messageBinding]bool{}
	for _, a := range m.Associations {
		if seen[a.Binding] || a.Current != nil {
			return failure("unqualified current certificate")
		}
		seen[a.Binding] = true
		if a.Pending != nil && !txs[*a.Pending] {
			return failure("missing pending transaction")
		}
		if a.Pending != nil {
			tx := s.messageTx(*a.Pending)
			intent, code := s.readMessageIntent(tx)
			if code != "" || tx.Phase == "aborted" || messageBindingOf(intent.Binding) != a.Binding {
				return failure("foreign association fence")
			}
		}
		found := false
		for _, b := range s.records {
			if messageBindingOf(b) == a.Binding {
				found = true
				break
			}
		}
		if !found {
			return failure("orphan message association")
		}
	}
	return s.validateMessageFiles(refs)
}
func sameMessageString(a, b *string) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func sameMessageArtifact(a, b *messageArtifact) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func (s *Store) messageStoredBinding(b Binding) (Binding, bool) {
	for _, v := range s.records {
		x := v
		x.Status = b.Status
		if x == b {
			return v, true
		}
	}
	return Binding{}, false
}

func validateMessageCertificate(c messageCertificate) error {
	raw, e := record.DecodeBase64(c.Envelope, -1)
	if e != nil {
		return failure("invalid certificate bytes")
	}
	value, e := record.Parse(raw, 8192, 16)
	if e != nil {
		return failure("invalid certificate profile")
	}
	env, ok := value.(map[string]any)
	if !ok {
		return failure("invalid certificate envelope")
	}
	body, ok := env["body"].(map[string]any)
	if !ok || len(env) != 4 || len(body) != 10 || env["version"] != "swarm-envelope/2" || body["issuer"] != c.IssuerPolicy.Key || body["type"] != "attestation/1" {
		return failure("invalid certificate envelope")
	}
	id, e := record.ContentID("attestation/1", body)
	if e != nil || id != c.ContentID || env["id"] != id {
		return failure("invalid certificate id")
	}
	sigs, ok := env["signatures"].([]any)
	if !ok || len(sigs) != 1 {
		return failure("invalid certificate signature")
	}
	sig, ok := sigs[0].(map[string]any)
	if !ok || len(sig) != 3 || sig["role"] != "author" || sig["key"] != c.IssuerPolicy.Key {
		return failure("invalid certificate signature")
	}
	encoded, ok := sig["sig"].(string)
	if !ok {
		return failure("invalid certificate signature")
	}
	signature, e := record.DecodeBase64(encoded, 64)
	pre, e2 := record.SigningPreimage("attestation/1", c.IssuerPolicy.Key, "author", body)
	if e != nil || e2 != nil || record.VerifySignature(c.IssuerPolicy.Key, signature, pre) != nil {
		return failure("invalid certificate signature")
	}
	// Rebuild the exact closed body from its independently retained policy/binding.
	// This historical check verifies bytes/math, not current status or freshness.
	b := Binding{UID: c.Binding.UID, Generation: c.Binding.Generation, Number: c.Binding.Number, Epoch: c.Binding.Epoch, Owner: c.Binding.Owner, Path: "m/1'" + strings.TrimPrefix(c.Binding.Path, "m/4'"), RegistryRevision: c.IssuerPolicy.RegistryRevision, Status: "active"}
	if ValidatePath(c.Binding.Path, "swarma-msg") != "" || ValidatePath(c.IssuerPolicy.Path, "root-attestation") != "" {
		return failure("invalid certificate path")
	}
	at, ok := body["iat"].(string)
	if !ok {
		return failure("invalid certificate time")
	}
	instant, e := parseMessageStamp(at)
	if e != nil {
		return e
	}
	algorithm, public, e := record.KeyBytes(c.KeyID)
	if e != nil || algorithm != "ed25519" {
		return failure("invalid certificate key")
	}
	rebuilt, code := (&messageIssuer{policy: c.IssuerPolicy}).body(b, public, instant)
	if code != "" {
		return failure("invalid certificate selection")
	}
	expected, e := record.Canonical(rebuilt)
	actual, e2 := record.Canonical(body)
	if e != nil || e2 != nil || !bytes.Equal(expected, actual) {
		return failure("certificate selection mismatch")
	}
	return nil
}
func (s *Store) validateMessageFiles(refs map[string]map[string]bool) error {
	root, e := messageSubdir(s.dir, "message-tx", s.uid, false)
	if e != nil {
		return failure("missing message artifacts")
	}
	defer root.Close()
	entries, e := messageEntries(root)
	if e != nil {
		return e
	}
	var total int64
	var migrationBase, migrationDecision []byte
	copies := map[uint64]bool{}
	for _, entry := range entries {
		id := entry.Name()
		if id != "migration" && refs[id] == nil {
			return failure("orphan message directory")
		}
		dir, e := messageSubdir(root, id, s.uid, false)
		if e != nil {
			return e
		}
		files, e := messageEntries(dir)
		if e != nil {
			dir.Close()
			return e
		}
		for _, file := range files {
			name := file.Name()
			raw, e := messageRead(dir, name, s.uid, stateBudget-total)
			if e != nil {
				dir.Close()
				return e
			}
			total += int64(len(raw))
			if total > stateBudget {
				dir.Close()
				return failure("message state capacity exceeded")
			}
			switch {
			case strings.HasPrefix(name, "snapshot-"):
				version, e := strconv.ParseUint(strings.TrimPrefix(name, "snapshot-"), 10, 64)
				if e != nil || version > s.version || strconv.FormatUint(version, 10) != strings.TrimPrefix(name, "snapshot-") {
					dir.Close()
					return failure("unresolved message snapshot")
				}
				if copies[version] {
					dir.Close()
					return failure("duplicate message snapshot copy")
				}
				copies[version] = true
				if expected, ok := s.journalCommitDigest(version); s.journal != nil && (!ok || expected != messageHash(raw)) {
					dir.Close()
					return failure("message snapshot hash mismatch")
				}
			case id == "migration" && name == "base":
				migrationBase = raw
			case id == "migration" && name == "decision":
				migrationDecision = raw
			case refs[id][name] && validDigest(name) && messageHash(raw) == name:
			default:
				dir.Close()
				return failure("unreferenced message artifact")
			}
		}
		dir.Close()
	}

	var decision messageMigrationDecision
	if messageRequired(migrationDecision, reflect.TypeFor[messageMigrationDecision]()) != nil || StrictJSON(bytes.NewReader(migrationDecision), &decision) != nil || decision.From != 1 || decision.To != 2 || decision.BaseVersion < 1 || !validDigest(decision.BaseDigest) {
		return failure("invalid migration evidence")
	}
	var base bindingDisk
	if StrictJSON(bytes.NewReader(migrationBase), &base) != nil || base.SchemaVersion != 0 || base.Version != decision.BaseVersion {
		return failure("invalid migration base")
	}
	prior := NewStore()
	prior.records, prior.requests, prior.next = base.Records, base.Requests, base.Next
	digest, e := prior.contentDigest(base.Version)
	if e != nil || digest != decision.BaseDigest {
		return failure("migration base mismatch")
	}
	if s.journal != nil {
		expected, ok := s.journalCommitDigest(decision.BaseVersion)
		if !ok || expected != digest || s.journal.messageMigrationDigest == nil || *s.journal.messageMigrationDigest != messageHash(migrationDecision) {
			return failure("migration journal mismatch")
		}
		for version := range s.journal.messageCommits {
			if version > decision.BaseVersion && !copies[version] {
				return failure("missing message snapshot copy")
			}
		}
	}
	s.messages.artifactBytes = total
	if !s.messageCapacity(0, 0, 0) {
		return failure("message state capacity exceeded")
	}
	return nil
}

func reflectMessageType(v any) reflect.Type { return reflect.TypeOf(v).Elem() }
func parseMessageStamp(raw string) (time.Time, error) {
	t, e := time.Parse("2006-01-02T15:04:05Z", raw)
	if e != nil || messageStamp(t) != raw || t.Year() < 1970 {
		return time.Time{}, failure("invalid message timestamp")
	}
	return t, nil
}
func (s *Store) journalCommitDigest(version uint64) (string, bool) {
	if s.journal == nil {
		return "", false
	}
	c, ok := s.journal.messageCommits[version]
	return c.Digest, ok
}

func validateMessageIntent(intent messageIntent) error {
	at, e := parseMessageStamp(intent.IssuedAt)
	if e != nil {
		return e
	}
	algorithm, public, e := record.KeyBytes(intent.KeyID)
	if e != nil || algorithm != "ed25519" || ValidatePath(intent.Policy.Path, "root-attestation") != "" || record.ValidateKey(intent.Policy.Key) != nil {
		return failure("invalid issuance policy")
	}
	if _, code := (&messageIssuer{policy: intent.Policy}).body(intent.Binding, public, at); code != "" {
		return failure("invalid issuance selection")
	}
	return nil
}
