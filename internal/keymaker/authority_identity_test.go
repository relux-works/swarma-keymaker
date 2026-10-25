package keymaker

import (
	"bytes"
	"strings"
	"testing"
)

// Each stage is compared with independent G4 bytes; omitting authority or
// feeding the final self-hash back into its own preimage must fail here.
func TestPC2PreimageDomains(t *testing.T) {
	_, all := pc2Fixtures(t)
	for _, prefix := range []string{"", "journal-genesis-"} {
		t.Run(prefix, func(t *testing.T) {
			rootName := prefix + "root"
			bodyName := prefix + "body"
			if prefix == "" {
				rootName = "minimal-root"
				bodyName = "binding-body"
			}
			root := pc2Object(t, all[rootName])
			body, e := authorityBindingPreimage(root)
			if e != nil {
				t.Fatal(e)
			}
			b, e := encodeAuthority(body, "keymaker-combined-body/3")
			if e != nil || !bytes.Equal(b, all[bodyName]) {
				t.Fatal("P-PC2_OMIT_AUTHORITY_PREIMAGE: binding body", e)
			}
			candidate, e := authorityCandidate(body)
			if e != nil {
				t.Fatal(e)
			}
			b, e = encodeAuthority(candidate, "keymaker-authority-candidate/1")
			name := prefix + "candidate"
			if e != nil || !bytes.Equal(b, all[name]) {
				t.Fatal("candidate preimage", e)
			}
			tx, e := authorityTransaction(root["previous_root_digest"], root["transaction_revision"].(int64), candidate)
			if e != nil {
				t.Fatal(e)
			}
			b, e = encodeAuthority(tx, "keymaker-authority-tx/1")
			if e != nil || !bytes.Equal(b, all[prefix+"transaction"]) {
				t.Fatal("transaction preimage", e)
			}
			p, e := authorityFinalPreimage(root)
			if e != nil {
				t.Fatal(e)
			}
			b, e = encodeAuthority(p, authorityRootPreimageKind)
			name = prefix + "root-preimage"
			if prefix == "" {
				name = "minimal-root-preimage"
			}
			if e != nil || !bytes.Equal(b, all[name]) || authorityDigest(b) != root["root_digest"] {
				t.Fatal("P-PC2_ROOT_SELF_HASH: final preimage", e)
			}
			sealed, e := sealAuthorityRoot(root)
			if e != nil {
				t.Fatal(e)
			}
			b, e = encodeAuthority(sealed, authorityRootKind)
			if e != nil || !bytes.Equal(b, all[rootName]) {
				t.Fatal("seal independent root", e)
			}
		})
	}
	original := pc2Object(t, all["minimal-root"])
	before, e := authorityBindingPreimage(original)
	if e != nil {
		t.Fatal(e)
	}
	baseline := pc2Bytes(t, before)
	for _, field := range []string{"master_epoch", "withdrawal_counter", "custody_ready", "registry_digest", "pin_policy_digest", "instance_id", "authority_incarnation", "boot_id", "transaction_revision", "previous_root_digest", "journal", "entries", "payload", "participants", "provenance", "reservation", "manager_baseline"} {
		r := pc2Object(t, all["minimal-root"])
		switch field {
		case "master_epoch":
			r[field] = "changed"
		case "withdrawal_counter":
			r[field] = int64(3)
		case "custody_ready":
			r[field] = true
		case "boot_id":
			r[field] = "00000000-0000-4000-8000-000000000002"
		case "transaction_revision":
			r[field] = int64(3)
			r["binding_commit"].(map[string]any)["version"] = int64(3)
		case "journal":
			r[field].(map[string]any)["seq"] = int64(2)
		case "entries":
			_, all := pc2Fixtures(t)
			max := pc2Object(t, all["maximal-root"])
			r[field] = []any{max["entries"].([]any)[0]}
		case "payload", "participants", "provenance", "reservation":
			r[field].(map[string]any)["digest"] = "sha256:" + strings.Repeat("a", 64)
		case "manager_baseline":
			r[field].(map[string]any)["revision"] = int64(2)
		case "registry_digest", "pin_policy_digest", "previous_root_digest":
			r[field] = "sha256:" + strings.Repeat("a", 64)
		default:
			r[field] = strings.Repeat("a", 32)
		}
		body, e := authorityBindingPreimage(r)
		if e != nil || bytes.Equal(pc2Bytes(t, body), baseline) {
			t.Fatal("authority field unbound", field, e)
		}
	}
	r := pc2Object(t, all["minimal-root"])
	r["root_digest"] = "sha256:" + strings.Repeat("a", 64)
	r["binding_commit"].(map[string]any)["audit_hash"] = strings.Repeat("a", 64)
	body, e := authorityBindingPreimage(r)
	if e != nil || !bytes.Equal(pc2Bytes(t, body), baseline) {
		t.Fatal("future hashes entered binding preimage", e)
	}
}

// Immutable A2 fields determine one identity; mutable disposition/evidence do
// not create a new origin. A restart retains the original instance bytes.
func TestPC2AttemptIdentity(t *testing.T) {
	_, all := pc2Fixtures(t)
	a := pc2Object(t, all["attempt"])
	id, e := authorityAttemptID(a)
	if e != nil || id != a["attempt_id"] {
		t.Fatal("attempt golden", e)
	}
	pre, e := authorityAttemptPreimage(a)
	if e != nil {
		t.Fatal(e)
	}
	b, e := encodeAuthority(pre, authorityAttemptPreimageKind)
	if e != nil || !bytes.Equal(b, all["attempt-preimage"]) {
		t.Fatal("attempt immutable preimage", e)
	}
	changed := pc2Object(t, all["attempt"])
	changed["disposition"] = "absent"
	changed["evidence_digest"] = "sha256:" + strings.Repeat("a", 64)
	newID, e := authorityAttemptID(changed)
	if e != nil || newID != id {
		t.Fatal("P-PC2_ATTEMPT_NEW_ORIGIN: mutable resolution changed identity", e)
	}
	for _, field := range []string{"manager_id", "effect_digest", "ordinal", "owner", "boot_id", "instance_id", "target", "source", "prepared_tail", "active_record_hash", "provision_effect"} {
		t.Run(field, func(t *testing.T) {
			a := pc2Object(t, all["attempt"])
			switch field {
			case "ordinal":
				a[field] = int64(2)
			case "owner":
				a[field] = "other"
			case "effect_digest":
				a[field] = "sha256:" + strings.Repeat("a", 64)
			case "active_record_hash":
				a[field] = strings.Repeat("a", 64)
			case "boot_id":
				a[field] = "00000000-0000-4000-8000-000000000002"
			case "target":
				a[field].(map[string]any)["uid"] = int64(11)
			case "source":
				a[field].(map[string]any)["withdrawal_counter"] = int64(3)
			case "prepared_tail":
				a[field].(map[string]any)["seq"] = int64(2)
			case "provision_effect":
				a[field].(map[string]any)["request_id"] = strings.Repeat("a", 32)
			default:
				a[field] = strings.Repeat("a", 32)
			}
			newID, e := authorityAttemptID(a)
			if e != nil || newID == id {
				t.Fatal("immutable field omitted", field, e)
			}
			if _, e = decodeAuthority(pc2Bytes(t, a), "pc2-activation-attempt/1"); e == nil {
				t.Fatal("changed immutable bytes retained old ID")
			}
		})
	}
	for _, x := range []struct {
		kind       string
		k          authorityKind
		name, want string
	}{{"activation", authorityAttemptPreimageKind, "attempt-preimage", "hold"}, {"authority", "keymaker-authority-tx/1", "journal-genesis-transaction", "journal-genesis-authority-hold"}} {
		h, e := authorityHold(x.kind, x.k, all[x.name])
		if e != nil {
			t.Fatal(e)
		}
		b, e := encodeAuthority(h, "pc2-hold/1")
		if e != nil || !bytes.Equal(b, all[x.want]) {
			t.Fatal("hold identity", e)
		}
		if _, e = authorityHold(x.kind, "keymaker-capacity-genesis/1", all["capacity-genesis-commit"]); e == nil || authorityCode(e) != "authority_hold_origin_domain" {
			t.Fatal("P-PC2_C0_HOLD_ORIGIN: C0 originated hold", e)
		}
	}
	root := pc2Object(t, all["minimal-root"])
	guard := pc2Object(t, all["guard-clear"])
	link, e := authorityLink(root, guard, 1)
	if e != nil {
		t.Fatal(e)
	}
	b, e = encodeAuthority(link, "keymaker-authority-link/1")
	if e != nil || !bytes.Equal(b, all["logical-link"]) {
		t.Fatal("logical link", e)
	}
}

// A private payload change flows through its immutable Ref into both binding
// and final-root digests; private bytes are never copied into the logical root.
func TestPC2PayloadPreimageBinding(t *testing.T) {
	_, all := pc2Fixtures(t)
	base := pc2Object(t, all["minimal-root"])
	for _, field := range []string{"next_registration_number", "transaction_revision", "records", "requests", "messages", "message_authority"} {
		t.Run(field, func(t *testing.T) {
			p := pc2Object(t, all["private-payload"])
			switch field {
			case "next_registration_number":
				p[field] = int64(2)
			case "transaction_revision":
				p[field] = int64(3)
			case "records":
				p["next_registration_number"] = int64(2)
				p[field] = []any{pc2Binding()}
			case "requests":
				r := pc2Request()
				r["status"] = "committed"
				r["result"] = map[string]any{"envelope": "returned-envelope-private-marker"}
				p[field] = []any{r}
			case "messages":
				p[field].(map[string]any)["associations"] = []any{map[string]any{"binding": map[string]any{"uid": int64(10), "generation": strings.Repeat("1", 32), "registration_number": int64(1), "master_epoch": "e", "owner": "o", "path": "m/4'/1'/1'/1'"}, "current": nil, "pending": nil}}
			case "message_authority":
				p = pc2Object(t, all["freshness-payload"])
			}
			raw, e := encodeAuthority(p, "keymaker-private/3")
			if e != nil {
				t.Fatal(e)
			}
			r := pc2Object(t, all["minimal-root"])
			r["payload"].(map[string]any)["digest"] = authorityDigest(raw)
			r["payload"].(map[string]any)["bytes"] = int64(len(raw))
			r, e = sealAuthorityRoot(r)
			if e != nil {
				t.Fatal(e)
			}
			if r["root_digest"] == base["root_digest"] || r["binding_commit"].(map[string]any)["digest"] == base["binding_commit"].(map[string]any)["digest"] {
				t.Fatal("private field unbound", field)
			}
			logical, e := encodeAuthority(r, authorityRootKind)
			if e != nil || bytes.Contains(logical, []byte("returned-envelope-private-marker")) {
				t.Fatal("private bytes entered logical root", e)
			}
		})
	}
}
