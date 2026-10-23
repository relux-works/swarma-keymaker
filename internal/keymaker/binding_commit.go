package keymaker

import "strconv"

type bindingCommit struct {
	Version uint64
	Digest  string
	Seq     uint64
	Hash    string
}

// Internal lifecycle commits use existing typed audit fields, preserving the
// exact audit schema. The transaction ID is generated here, never client input.
func (j *Journal) observeBinding(r AuditRecord) error {
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
	return nil
}

func (j *Journal) commitBinding(version uint64, digest string) (bindingCommit, Code) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if version != j.binding.Version+1 || !validDigest(digest) {
		return bindingCommit{}, "audit_unavailable"
	}
	id, domain := "binding:"+strconv.FormatUint(version, 10), "control"
	if c := j.appendLocked(AuditRecord{Surface: "control", Operation: "binding_commit", Domain: &domain, RequestID: &id, PayloadDigest: &digest, Result: "success"}); c != "" {
		return bindingCommit{}, c
	}
	return j.binding, ""
}
