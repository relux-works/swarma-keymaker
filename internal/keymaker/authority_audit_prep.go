package keymaker

import "strconv"

type authorityAuditTail struct {
	Seq  uint64
	Hash string
}

// These are immutable observations/reservations supplied under the caller's
// audit serialization, not capabilities or independently authenticated tickets.
// This pure slice neither acquires that serialization nor consumes a live ticket.
type authorityAuditRotationReservation struct {
	Tail                       authorityAuditTail
	Segment, FirstSeq          uint64
	SegmentBytes, SegmentLimit int64
	SealBytes                  int64
	NewSegments                uint64
}

type authorityAuditMessageReservation struct {
	Tail                   authorityAuditTail
	Reserved, Remaining    int64
	TotalBytes, TotalLimit int64
}

type authorityAuditInput struct {
	// Body is exact closed B3, not a final Root or an arbitrary audit template.
	Body          []byte
	TransactionID string
	Tail          authorityAuditTail
	// The replayed binding version is observed with that same serialized tail.
	BindingVersion uint64
	Instance       string
	// Nil means already-collected unknown time. No clock/provider is accepted.
	Timestamp *string
	Rotation  *authorityAuditRotationReservation
	Message   *authorityAuditMessageReservation
}

type authorityPreparedRotation struct {
	Seal        []byte
	NextSegment uint64
}

type authorityPreparedAudit struct {
	Frames                            [][]byte
	Tail                              authorityAuditTail
	Binding                           bindingCommit
	Root                              map[string]any
	Rotation                          *authorityPreparedRotation
	MessageRemaining, MessageReserved int64
}

// prepareAuthorityAudit follows G4's acyclic DAG, without locks, I/O, ambient
// time, providers or a serving caller. It prepares one binding frame and any
// preceding rotation seal; future message events require their own preparation.
//
// The allowed binding_commit payload_digest commits B3, which already contains
// the predecessor and revision. B3 fixes candidate and transaction_id. Validate
// that complete derivation here; retain the existing binding:<revision> request
// ID and body hash, without adding a transaction field or operation literal.
// Exact bytes alone establish no live reservation, currentness or authority.
func prepareAuthorityAudit(in authorityAuditInput) (authorityPreparedAudit, error) {
	if in.Tail.Seq >= uint64(authoritySafeInteger) || in.BindingVersion >= uint64(authoritySafeInteger) {
		return authorityPreparedAudit{}, authorityFail("audit_reservation_overflow")
	}
	if in.BindingVersion > in.Tail.Seq {
		return authorityPreparedAudit{}, authorityFail("audit_binding_mismatch")
	}
	if (in.Tail.Seq == 0 && in.Tail.Hash != "") || (in.Tail.Seq != 0 && (len(in.Tail.Hash) != 64 || !validDigest(in.Tail.Hash))) {
		return authorityPreparedAudit{}, authorityFail("audit_tail_mismatch")
	}
	if in.Rotation == nil || in.Message == nil {
		return authorityPreparedAudit{}, authorityFail("audit_reservation_missing")
	}
	r, m := *in.Rotation, *in.Message
	if r.Tail != in.Tail || m.Tail != in.Tail {
		return authorityPreparedAudit{}, authorityFail("audit_tail_mismatch")
	}
	if r.Segment == 0 || r.Segment > uint64(authoritySafeInteger) || r.FirstSeq == 0 || r.FirstSeq > in.Tail.Seq+1 || r.SegmentBytes < 0 || r.SegmentLimit <= 0 || r.SealBytes < 0 || r.NewSegments > 1 || m.Remaining < 0 || m.Reserved < m.Remaining || m.TotalBytes < 0 || m.TotalLimit < 0 {
		return authorityPreparedAudit{}, authorityFail("audit_reservation_invalid")
	}
	if (r.SegmentBytes == 0) != (r.FirstSeq == in.Tail.Seq+1) {
		return authorityPreparedAudit{}, authorityFail("audit_reservation_invalid")
	}
	if r.SegmentLimit > 64<<20 || m.TotalLimit > (1<<30)+(16<<20) || r.SegmentBytes > r.SegmentLimit || m.TotalBytes > m.TotalLimit || m.Remaining > messageAuditReserve || m.Reserved > m.TotalLimit-m.TotalBytes {
		return authorityPreparedAudit{}, authorityFail("audit_reservation_overflow")
	}
	// This input alone would exceed the global frame cap, before encoding.
	if len(in.Instance) > 8192 {
		return authorityPreparedAudit{}, authorityFail("audit_frame_limit")
	}
	// Keep this fixed-width lowercase-hex check direct: arID is a function
	// variable, which the construction guard deliberately forbids calling.
	if len(in.Instance) != 32 {
		return authorityPreparedAudit{}, authorityFail("field_format")
	}
	for _, c := range in.Instance {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return authorityPreparedAudit{}, authorityFail("field_format")
		}
	}
	if in.Timestamp != nil {
		if e := arStamp(*in.Timestamp); e != nil {
			return authorityPreparedAudit{}, e
		}
	}
	// The closed body contains one <=1 MiB authority object and its bounded
	// payload reference; refuse a large intake before the generic codec parses it.
	if len(in.Body) > 2*authorityRootLimit {
		return authorityPreparedAudit{}, authorityFail("total_limit")
	}
	body, e := decodeAuthority(in.Body, "keymaker-combined-body/3")
	if e != nil {
		return authorityPreparedAudit{}, e
	}
	a := body["authority"].(map[string]any)
	candidate, e := authorityCandidate(body)
	if e != nil {
		return authorityPreparedAudit{}, e
	}
	tx, e := authorityTransaction(a["previous_root_digest"], a["transaction_revision"].(int64), candidate)
	if e != nil {
		return authorityPreparedAudit{}, e
	}
	txBytes, e := encodeAuthority(tx, "keymaker-authority-tx/1")
	if e != nil {
		return authorityPreparedAudit{}, e
	}
	if authorityDigest(txBytes) != in.TransactionID {
		return authorityPreparedAudit{}, authorityFail("authority_transaction_mismatch")
	}
	version := uint64(a["transaction_revision"].(int64))
	if version != in.BindingVersion+1 {
		return authorityPreparedAudit{}, authorityFail("audit_binding_mismatch")
	}
	id, domain, digest := "binding:"+strconv.FormatUint(version, 10), "control", candidate["body_digest"].(string)[7:]
	record := AuditRecord{Seq: in.Tail.Seq + 1, Instance: in.Instance, Surface: "control", RequestID: &id, Operation: "binding_commit", Domain: &domain, PayloadDigest: &digest, Result: "success", Previous: in.Tail.Hash}
	if in.Timestamp == nil {
		record.Result = "unknown"
	} else {
		stamp := *in.Timestamp
		record.Time = &stamp
	}
	record.Digest, e = auditDigest(record)
	if e != nil {
		return authorityPreparedAudit{}, e
	}
	frame, e := canonical(record)
	if e != nil {
		return authorityPreparedAudit{}, e
	}
	frame = append(frame, '\n')
	n := int64(len(frame))
	if n > 8192 || n > r.SegmentLimit {
		return authorityPreparedAudit{}, authorityFail("audit_frame_limit")
	}
	// Subtraction after range checks avoids overflowing any sum, including a
	// malicious near-MaxInt64 census. Other message tickets remain reserved.
	if n > m.Remaining || n > m.TotalLimit-m.TotalBytes-(m.Reserved-m.Remaining) {
		return authorityPreparedAudit{}, authorityFail("audit_reservation_overflow")
	}
	var rotation *authorityPreparedRotation
	if n > r.SegmentLimit-r.SegmentBytes {
		seal, e := canonical(auditSeal{First: r.FirstSeq, Last: in.Tail.Seq, Digest: in.Tail.Hash})
		if e != nil {
			return authorityPreparedAudit{}, e
		}
		if r.NewSegments != 1 || r.Segment == uint64(authoritySafeInteger) || int64(len(seal)) > r.SealBytes {
			return authorityPreparedAudit{}, authorityFail("audit_reservation_overflow")
		}
		rotation = &authorityPreparedRotation{Seal: seal, NextSegment: r.Segment + 1}
	}
	commit := bindingCommit{Version: version, Digest: digest, Seq: record.Seq, Hash: record.Digest}
	root := authorityCopy(a)
	root["binding_commit"] = map[string]any{"version": int64(version), "digest": digest, "audit_seq": int64(commit.Seq), "audit_hash": commit.Hash}
	// The placeholder satisfies the closed shape; sealing excludes precisely
	// root_digest and replaces it only after C's exact audit pair is fixed.
	root["root_digest"] = in.TransactionID
	root, e = sealAuthorityRoot(root)
	if e != nil {
		return authorityPreparedAudit{}, e
	}
	return authorityPreparedAudit{Frames: [][]byte{frame}, Tail: authorityAuditTail{Seq: commit.Seq, Hash: commit.Hash}, Binding: commit, Root: root, Rotation: rotation, MessageRemaining: m.Remaining - n, MessageReserved: m.Reserved - n}, nil
}
