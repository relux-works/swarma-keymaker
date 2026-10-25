package keymaker

import "reflect"

// All functions here are byte/identity checks only. Callers in future slices
// must supply independently authenticated current inputs; a matching hash does
// not establish custody, genesis authority, committed reservation or eligibility.
func authorityDigest(b []byte) string { return "sha256:" + messageHash(b) }
func authorityCopy(o map[string]any) map[string]any {
	out := make(map[string]any, len(o))
	for k, v := range o {
		out[k] = v
	}
	return out
}
func authorityBindingPreimage(root map[string]any) (map[string]any, error) {
	if e := arRoot(authorityRootKind)(root); e != nil {
		return nil, e
	}
	a := authorityCopy(root)
	delete(a, "binding_commit")
	delete(a, "root_digest")
	return map[string]any{"type": "keymaker-combined-body/3", "schema_version": int64(3), "authority": a, "payload": root["payload"]}, nil
}
func authorityFinalPreimage(root map[string]any) (map[string]any, error) {
	if e := arRoot(authorityRootKind)(root); e != nil {
		return nil, e
	}
	p := authorityCopy(root)
	delete(p, "root_digest")
	return p, nil
}
func authorityCandidate(body map[string]any) (map[string]any, error) {
	b, e := encodeAuthority(body, "keymaker-combined-body/3")
	if e != nil {
		return nil, e
	}
	return map[string]any{"type": "keymaker-authority-candidate/1", "body_digest": authorityDigest(b)}, nil
}
func authorityTransaction(base any, next int64, candidate map[string]any) (map[string]any, error) {
	b, e := encodeAuthority(candidate, "keymaker-authority-candidate/1")
	if e != nil {
		return nil, e
	}
	o := map[string]any{"type": "keymaker-authority-tx/1", "base_root_digest": base, "next_revision": next, "candidate_root_digest": authorityDigest(b)}
	if e = authorityRuleFor("keymaker-authority-tx/1")(o); e != nil {
		return nil, e
	}
	return o, nil
}
func verifyAuthorityRoot(root map[string]any) error {
	p, e := authorityFinalPreimage(root)
	if e != nil {
		return e
	}
	b, e := marshalAuthorityCCJ(p, authorityRootLimit)
	if e != nil {
		return e
	}
	if root["root_digest"] != authorityDigest(b) {
		return authorityFail("digest_mismatch")
	}
	body, e := authorityBindingPreimage(root)
	if e != nil {
		return e
	}
	b, e = encodeAuthority(body, "keymaker-combined-body/3")
	if e != nil {
		return e
	}
	if root["binding_commit"].(map[string]any)["digest"] != messageHash(b) {
		return authorityFail("digest_mismatch")
	}
	return nil
}

// Seal computes only acyclic byte references, without committing anything.
// It never mutates the supplied map or grants authority to the returned root.
func sealAuthorityRoot(root map[string]any) (map[string]any, error) {
	if e := arRoot(authorityRootKind)(root); e != nil {
		return nil, e
	}
	root = authorityCopy(root)
	commit := authorityCopy(root["binding_commit"].(map[string]any))
	root["binding_commit"] = commit
	body, e := authorityBindingPreimage(root)
	if e != nil {
		return nil, e
	}
	b, e := encodeAuthority(body, "keymaker-combined-body/3")
	if e != nil {
		return nil, e
	}
	commit["digest"] = messageHash(b)
	p, e := authorityFinalPreimage(root)
	if e != nil {
		return nil, e
	}
	b, e = encodeAuthority(p, authorityRootPreimageKind)
	if e != nil {
		return nil, e
	}
	root["root_digest"] = authorityDigest(b)
	return root, nil
}
func authorityAttemptPreimage(attempt map[string]any) (map[string]any, error) {
	if e := authorityAttemptRule("pc2-activation-attempt/1")(attempt); e != nil {
		return nil, e
	}
	p := authorityCopy(attempt)
	delete(p, "attempt_id")
	delete(p, "disposition")
	delete(p, "evidence_digest")
	return p, nil
}
func authorityAttemptID(attempt map[string]any) (string, error) {
	p, e := authorityAttemptPreimage(attempt)
	if e != nil {
		return "", e
	}
	b, e := encodeAuthority(p, authorityAttemptPreimageKind)
	if e != nil {
		return "", e
	}
	return authorityDigest(b), nil
}
func authorityHold(kind string, originKind authorityKind, preimage []byte) (map[string]any, error) {
	want := authorityKind("keymaker-authority-tx/1")
	if kind == "activation" {
		want = authorityAttemptPreimageKind
	} else if kind != "authority" {
		return nil, authorityFail("wrong_domain")
	}
	if originKind != want {
		return nil, authorityFail("authority_hold_origin_domain")
	}
	if _, e := decodeAuthority(preimage, want); e != nil {
		return nil, authorityFail("authority_hold_origin_domain")
	}
	return map[string]any{"type": "pc2-hold/1", "kind": kind, "origin_id": authorityDigest(preimage)}, nil
}
func verifyAuthorityHold(hold map[string]any, resolve func(string) (authorityKind, []byte, error)) error {
	if e := authorityRuleFor("pc2-hold/1")(hold); e != nil {
		return e
	}
	k, b, e := resolve(hold["origin_id"].(string))
	if e != nil {
		return e
	}
	o, e := authorityHold(hold["kind"].(string), k, b)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(o, hold) {
		return authorityFail("authority_hold_origin_domain")
	}
	return nil
}
func authorityLink(root, guard map[string]any, epoch int64) (map[string]any, error) {
	if e := verifyAuthorityRoot(root); e != nil {
		return nil, e
	}
	b, e := encodeAuthority(guard, "pc2-recovery-guard/1")
	if e != nil {
		return nil, e
	}
	o := map[string]any{"type": "keymaker-authority-link/1", "root_digest": root["root_digest"], "transaction_revision": root["transaction_revision"], "authority_incarnation": root["authority_incarnation"], "withdrawal_counter": root["withdrawal_counter"], "journal": root["journal"], "guard_digest": authorityDigest(b), "minimum_reader_schema": int64(3), "floor_epoch": epoch}
	if e = authorityRuleFor("keymaker-authority-link/1")(o); e != nil {
		return nil, e
	}
	return o, nil
}
func checkAuthorityContinuity(rootValue, floorValue any) error {
	if e := arRoot(authorityRootKind)(rootValue); e != nil {
		return e
	}
	if e := authorityRuleFor("keymaker-authority-floor/1")(floorValue); e != nil {
		return e
	}
	r := rootValue.(map[string]any)
	f := floorValue.(map[string]any)
	if e := verifyAuthorityRoot(r); e != nil {
		return e
	}
	for _, k := range []string{"root_digest", "transaction_revision", "authority_incarnation", "withdrawal_counter", "journal"} {
		if !reflect.DeepEqual(r[k], f[k]) {
			return authorityFail("old_root_replay")
		}
	}
	return nil
}

// Genesis references here are already-authenticated caller inputs, never JSON
// authority. This verifies checkpoint domain/continuity only, not owner proofs.
func checkAuthorityJournal(checkpoint, protected, genesis any, activation bool) error {
	if e := arCheckpoint()(checkpoint); e != nil {
		return e
	}
	if e := arCheckpoint()(protected); e != nil {
		return e
	}
	c := checkpoint.(map[string]any)
	f := protected.(map[string]any)
	seq := c["seq"].(int64)
	if seq < f["seq"].(int64) || seq == f["seq"].(int64) && c["hash"] != f["hash"] {
		return authorityFail("journal_rollback")
	}
	if activation && seq == 0 {
		return authorityFail("activation_requires_positive_tail")
	}
	if seq == 0 {
		if genesis == nil {
			return authorityFail("genesis_unavailable")
		}
		if e := arObject(map[string]authorityRule{"kind": arEnum("first_enrollment", "unused_writer_genesis"), "authorization": arBlob(65536)})(genesis); e != nil {
			return authorityFail("genesis_unavailable")
		}
	}
	return nil
}

// The owner verifier supplies whether the signed proof advances; this codec
// cannot infer journal progress from unverified opaque envelope references.
func checkAuthorityJournalPrior(row any, advancing bool) error {
	if e := authorityJournalRule()(row); e != nil {
		return e
	}
	if advancing && row.(map[string]any)["prior_checkpoint"] == nil {
		return authorityFail("journal_unavailable")
	}
	return nil
}

// Match the already independently committed Q0/C0 inputs to M0. This is not a
// capacity engine, C0 authentication protocol, or permission to consume credit.
func checkAuthoritySlot(inventory, commit, reservation map[string]any) error {
	for _, x := range []struct {
		k authorityKind
		o map[string]any
	}{{"pc2-manager-inventory/1", inventory}, {"keymaker-capacity-genesis/1", commit}, {"keymaker-reservation/1", reservation}} {
		if e := authorityRuleFor(x.k)(x.o); e != nil {
			return e
		}
	}
	b, e := encodeAuthority(reservation, "keymaker-reservation/1")
	if e != nil {
		return e
	}
	ref := commit["reservation"].(map[string]any)
	if ref["digest"] != authorityDigest(b) || ref["bytes"] != int64(len(b)) || inventory["slot_reservation"] != ref["digest"] {
		return authorityFail("uncommitted_reservation")
	}
	return nil
}
