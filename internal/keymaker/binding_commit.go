package keymaker

import (
	"context"
	"strconv"
)

type bindingCommit struct {
	Version uint64
	Digest  string
	Seq     uint64
	Hash    string
}

// Internal lifecycle commits use existing typed audit fields, preserving the
// exact audit schema. The transaction ID is generated here, never client input.
func (j *Journal) observeBinding(r AuditRecord) error {
	if e := j.observeMessageEvent(r); e != nil {
		return e
	}
	if r.Operation == "message_state_migrate" {
		if j.messageHistory || j.binding.Version == 0 || r.Surface != "control" || r.Domain == nil || *r.Domain != "control" || r.RequestID == nil || *r.RequestID != "msg:00000000000000000000000000000000:migrate" || r.PayloadDigest == nil || !validDigest(*r.PayloadDigest) || r.RefusalCode != nil || (r.Result != "success" && r.Result != "unknown") || r.PeerUID != nil || r.Generation != nil || r.Path != nil || r.Epoch != nil {
			return failure("invalid message migration")
		}
		j.messageHistory = true
		j.messageMigrationDigest = r.PayloadDigest
		j.messageCommits = map[uint64]bindingCommit{j.binding.Version: j.binding}
	}
	if r.Operation != "binding_commit" {
		return nil
	}
	if r.Surface != "control" || r.Domain == nil || *r.Domain != "control" || r.RequestID == nil || r.PayloadDigest == nil || !validDigest(*r.PayloadDigest) || r.RefusalCode != nil || (r.Result != "success" && r.Result != "unknown") {
		return failure("invalid binding commit")
	}
	version := j.binding.Version + 1
	if version > 9007199254740991 || *r.RequestID != "binding:"+strconv.FormatUint(version, 10) {
		return failure("binding commit discontinuity")
	}
	j.binding = bindingCommit{Version: version, Digest: *r.PayloadDigest, Seq: r.Seq, Hash: r.Digest}
	if j.messageHistory {
		j.messageCommits[version] = j.binding
	}
	return nil
}

func (j *Journal) commitBinding(version uint64, digest string) (bindingCommit, Code) {
	return j.commitBindingContext(context.Background(), version, digest)
}
func (j *Journal) commitBindingContext(ctx context.Context, version uint64, digest string) (bindingCommit, Code) {
	if !j.mu.LockContext(ctx) {
		return bindingCommit{}, "request_deadline_exceeded"
	}
	defer j.mu.Unlock()
	if version != j.binding.Version+1 || !validDigest(digest) {
		return bindingCommit{}, "audit_unavailable"
	}
	id, domain := "binding:"+strconv.FormatUint(version, 10), "control"
	if c := j.appendContextLocked(ctx, AuditRecord{Surface: "control", Operation: "binding_commit", Domain: &domain, RequestID: &id, PayloadDigest: &digest, Result: "success"}); c != "" {
		return bindingCommit{}, c
	}
	return j.binding, ""
}
