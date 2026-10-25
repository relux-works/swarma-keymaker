package keymaker

import "sort"

// S2a only: inputs are independently prepared complete inventories and qualified
// future encoded-size bounds. This pure calculation performs no I/O and has no
// Store, audit, intent, floor, or provider handle. A ticket is sizing evidence,
// not a committed reservation or permission to mutate authority. S2b must bind
// the prepared census to its transaction and run this before its first intent.
type authorityCapacityClass struct {
	Inventory     map[string]any
	ReservedBytes int64
}
type authorityCapacityBound struct{ Bytes, IntegrityBytes int64 }
type authorityCapacityInput struct {
	Classes                                    []authorityCapacityClass
	BaseRoot                                   any // nil for genesis, otherwise an S1 digest
	InstalledID                                string
	InstalledBytes                             int64 // actual independently measured installed file, not a new bound
	Root, NativeIntent, NativeEffect, Metadata authorityCapacityBound
	PendingProofs                              int64
	ProofIntegrityBytes                        int64 // qualified future tree/descriptor overhead for all proof slots
	// Integrity overhead for the fixed manager attempt, hold, guard, recovery slot.
	ManagerSlotsInUse int64 // independently authenticated pending-slot count; refuse a second
	ManagerIntegrity  [4]int64
}
type authorityCapacityTicket struct {
	encoded string
	peak    int64
}

func (t authorityCapacityTicket) Bytes() []byte { return []byte(t.encoded) }
func (t authorityCapacityTicket) Peak() int64   { return t.peak }

func authorityCapacityAdd(a, b int64) (int64, error) {
	// A budget cap also bounds intermediate arithmetic before machine overflow.
	if a < 0 || b < 0 || a > stateBudget || b > stateBudget-a {
		return 0, authorityFail("capacity_exceeded")
	}
	return a + b, nil
}
func authorityCapacityPreflight(in authorityCapacityInput) (authorityCapacityTicket, error) {
	fail := func() (authorityCapacityTicket, error) {
		return authorityCapacityTicket{}, authorityFail("capacity_exceeded")
	}
	if in.ManagerSlotsInUse != 0 || len(in.Classes) != 14 || in.InstalledID == "" || in.InstalledBytes <= 0 || in.InstalledBytes > stateBudget || in.PendingProofs < 0 || in.PendingProofs > stateBudget/messageProofReserve {
		return fail()
	}
	rows := map[string]map[string]any{}
	installed := false
	for _, class := range in.Classes {
		raw, e := encodeAuthority(class.Inventory, "keymaker-capacity-inventory/1")
		if e != nil {
			return authorityCapacityTicket{}, e
		}
		// Work from the validated canonical copy, without retaining mutable caller maps.
		inv, e := decodeAuthority(raw, "keymaker-capacity-inventory/1")
		if e != nil {
			return authorityCapacityTicket{}, e
		}
		key := inv["owner"].(string) + "/" + inv["kind"].(string)
		if rows[key] != nil {
			return fail()
		}
		var materialized, integrity int64
		objects := inv["objects"].([]any)
		for _, v := range objects {
			o := v.(map[string]any)
			materialized, e = authorityCapacityAdd(materialized, o["bytes"].(int64))
			if e != nil {
				return fail()
			}
			integrity, e = authorityCapacityAdd(integrity, o["integrity_bytes"].(int64))
			if e != nil {
				return fail()
			}
			if key == "keymaker/installed" && o["id"] == in.InstalledID {
				if o["bytes"] != in.InstalledBytes {
					return fail()
				}
				installed = true
			}
		}
		if _, e = authorityCapacityAdd(0, class.ReservedBytes); e != nil {
			return fail()
		}
		rows[key] = map[string]any{"owner": inv["owner"], "kind": inv["kind"], "inventory_digest": authorityDigest(raw), "materialized_bytes": materialized, "integrity_bytes": integrity, "reserved_bytes": class.ReservedBytes, "objects": int64(len(objects))}
	}
	if !installed {
		return fail()
	}
	charge := func(key string, n int64) error {
		r := rows[key]
		if r == nil {
			return authorityFail("capacity_exceeded")
		}
		v, e := authorityCapacityAdd(r["reserved_bytes"].(int64), n)
		if e == nil {
			r["reserved_bytes"] = v
		}
		return e
	}
	bound := func(b authorityCapacityBound) (int64, error) {
		if b.Bytes <= 0 {
			return 0, authorityFail("capacity_exceeded")
		}
		return authorityCapacityAdd(b.Bytes, b.IntegrityBytes)
	}
	root, e := bound(in.Root)
	if e != nil {
		return fail()
	}
	intent, e := bound(in.NativeIntent)
	if e != nil {
		return fail()
	}
	effect, e := bound(in.NativeEffect)
	if e != nil {
		return fail()
	}
	metadata, e := bound(in.Metadata)
	if e != nil {
		return fail()
	}
	// Metadata covers all future auxiliary bodies, including rewritten class and
	// manager inventories, participants, provenance and the reservation itself.
	// The fixed record maxima below are a minimum; the prepared bound must also
	// cover inventory/other metadata growth and its encoded expansion.
	// Reserve the worst-case bounded reservation itself, participants, provenance.
	// Those metadata bodies must not consume their own unaccounted output bytes.
	if in.Metadata.Bytes < 65536+65536+4096 {
		return fail()
	}
	// Keep S2's conservative two-transition rule: two retained recovery bodies
	// plus two simultaneous installation copies, each at least the larger bound.
	// Existing retained snapshots remain in their materialized inventory as well.
	native := intent
	if effect > native {
		native = effect
	}
	for _, c := range []struct {
		key string
		n   int64
	}{
		{"keymaker/root_history", root}, // future logical root, alongside every old root
		{"keymaker/staging", root},
		{"keymaker/recovery", native}, // native intent snapshot
		{"keymaker/recovery", native}, // native effect snapshot
		{"keymaker/staging", native},
		{"keymaker/staging", native},
		{"keymaker/reservation_metadata", metadata},
	} {
		if charge(c.key, c.n) != nil {
			return fail()
		}
	}
	// Existing unspent proof tickets cannot be released by this pure calculation.
	proof, e := authorityCapacityAdd(in.PendingProofs*messageProofReserve, in.ProofIntegrityBytes)
	if e != nil {
		return fail()
	}
	r := rows["keymaker/pending_proofs"]
	if r["reserved_bytes"].(int64) < proof {
		r["reserved_bytes"] = proof
	}
	managerKeys := []string{"manager/attempts", "manager/holds", "manager/staging", "manager/recovery"}
	managerBytes := []int64{4096, 4096, 65536, 65536}
	for i, key := range managerKeys {
		n, e := authorityCapacityAdd(managerBytes[i], in.ManagerIntegrity[i])
		if e != nil || charge(key, n) != nil {
			return fail()
		}
	}
	keys := make([]string, 0, 14)
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	groups := make([]any, 0, 14)
	var total int64
	for _, key := range keys {
		r := rows[key]
		for _, field := range []string{"materialized_bytes", "integrity_bytes", "reserved_bytes"} {
			total, e = authorityCapacityAdd(total, r[field].(int64))
			if e != nil {
				return fail()
			}
		}
		groups = append(groups, r)
	}
	reservation := map[string]any{"version": "keymaker-reservation/1", "base_root_digest": in.BaseRoot, "limit_bytes": int64(stateBudget), "groups": groups, "total_bytes": total, "audit_records_reserved": int64(8), "manager_slots": map[string]any{"slots": int64(1), "attempt_bytes": int64(4096), "hold_bytes": int64(4096), "guard_bytes": int64(65536), "recovery_bytes": int64(65536)}}
	encoded, e := encodeAuthority(reservation, "keymaker-reservation/1")
	if e != nil {
		return authorityCapacityTicket{}, e
	}
	return authorityCapacityTicket{encoded: string(encoded), peak: total}, nil
}
