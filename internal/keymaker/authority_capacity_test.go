package keymaker

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func pc2CapacityInput() authorityCapacityInput {
	in := authorityCapacityInput{InstalledID: "bindings.json", InstalledBytes: 5000, Root: authorityCapacityBound{700, 3}, NativeIntent: authorityCapacityBound{800, 5}, NativeEffect: authorityCapacityBound{900, 7}, Metadata: authorityCapacityBound{135168, 11}, PendingProofs: 1, ManagerIntegrity: [4]int64{13, 17, 19, 23}}
	for _, key := range strings.Fields("keymaker/artifacts keymaker/installed keymaker/migration_history keymaker/pending_proofs keymaker/policy_history keymaker/recovery keymaker/reservation_metadata keymaker/root_history keymaker/staging manager/attempts manager/holds manager/inventory manager/recovery manager/staging") {
		parts := strings.Split(key, "/")
		id := "retained"
		n := int64(29)
		if key == "keymaker/installed" {
			id = in.InstalledID
			n = in.InstalledBytes
		}
		in.Classes = append(in.Classes, authorityCapacityClass{Inventory: map[string]any{"version": "keymaker-capacity-inventory/1", "owner": parts[0], "kind": parts[1], "objects": []any{map[string]any{"id": id, "bytes": n, "integrity_bytes": int64(2)}}}, ReservedBytes: 31})
	}
	return in
}
func pc2CapacityClass(in *authorityCapacityInput, key string) *authorityCapacityClass {
	for i := range in.Classes {
		c := &in.Classes[i]
		if c.Inventory["owner"].(string)+"/"+c.Inventory["kind"].(string) == key {
			return c
		}
	}
	panic("missing fixture class " + key)
}

// This independent ledger follows G4's simultaneous copies, not the preflight's
// returned total. It enables exact-fit and one-byte-over controls for every row.
func pc2CapacityExpected(in authorityCapacityInput) int64 {
	var total int64
	for _, c := range in.Classes {
		for _, v := range c.Inventory["objects"].([]any) {
			o := v.(map[string]any)
			total += o["bytes"].(int64) + o["integrity_bytes"].(int64)
		}
		reserved := c.ReservedBytes
		if c.Inventory["kind"] == "pending_proofs" && reserved < (in.PendingProofs*4194304+in.ProofIntegrityBytes) {
			reserved = in.PendingProofs*4194304 + in.ProofIntegrityBytes
		}
		total += reserved
	}
	native := in.NativeIntent.Bytes + in.NativeIntent.IntegrityBytes
	if b := in.NativeEffect.Bytes + in.NativeEffect.IntegrityBytes; b > native {
		native = b
	}
	total += 2*(in.Root.Bytes+in.Root.IntegrityBytes) + 4*native + in.Metadata.Bytes + in.Metadata.IntegrityBytes
	total += 4096 + 4096 + 65536 + 65536
	for _, n := range in.ManagerIntegrity {
		total += n
	}
	return total
}
func pc2CapacityFill(in *authorityCapacityInput, want int64) {
	c := pc2CapacityClass(in, "keymaker/artifacts")
	objects := c.Inventory["objects"].([]any)
	objects = append(objects, map[string]any{"id": "zz-filler", "bytes": want - pc2CapacityExpected(*in), "integrity_bytes": int64(0)})
	c.Inventory["objects"] = objects
}
func pc2CapacityRefused(t *testing.T, in authorityCapacityInput, claim string) {
	t.Helper()
	ticket, e := authorityCapacityPreflight(in)
	if authorityCode(e) != "capacity_exceeded" || ticket.Peak() != 0 || len(ticket.Bytes()) != 0 {
		t.Fatalf("%s: expected capacity_exceeded with no ticket, got %v peak=%d", claim, e, ticket.Peak())
	}
}

// The independently balanced ledgers fail by exactly one byte when any retained
// class or future obligation is counted. Exact fit and fresh admission prevent
// rejection-only implementations from satisfying the negative cases.
func TestPC2AggregateCapacityBeforeIntent(t *testing.T) {
	for _, name := range []string{"root_copy", "manager_hold", "actual_installed", "installed_bound_not_proposed", "native_intent", "native_effect", "old_new", "staging", "proof", "integrity", "proof_integrity", "attempt"} {
		t.Run(name, func(t *testing.T) {
			in := pc2CapacityInput()
			switch name {
			case "installed_bound_not_proposed":
				in.InstalledBytes = 400
				pc2CapacityClass(&in, "keymaker/installed").Inventory["objects"].([]any)[0].(map[string]any)["bytes"] = in.InstalledBytes
			case "native_intent":
				in.NativeIntent.Bytes = 9001
			case "native_effect":
				in.NativeEffect.Bytes = 10003
			case "old_new":
				pc2CapacityClass(&in, "keymaker/root_history").Inventory["objects"].([]any)[0].(map[string]any)["bytes"] = int64(6000)
			case "staging":
				pc2CapacityClass(&in, "keymaker/staging").Inventory["objects"].([]any)[0].(map[string]any)["bytes"] = int64(7000)
			case "proof":
				in.PendingProofs = 2
			case "integrity":
				in.Root.IntegrityBytes = 1007
			case "proof_integrity":
				in.ProofIntegrityBytes = 109
			case "attempt":
				pc2CapacityClass(&in, "manager/attempts").ReservedBytes = 999
			}
			pc2CapacityFill(&in, stateBudget+1)
			pc2CapacityRefused(t, in, name)
			filler := pc2CapacityClass(&in, "keymaker/artifacts").Inventory["objects"].([]any)[1].(map[string]any)
			filler["bytes"] = filler["bytes"].(int64) - 1
			ticket, e := authorityCapacityPreflight(in)
			if e != nil || ticket.Peak() != stateBudget {
				t.Fatalf("%s exact_fit_after_refusal: %v peak=%d", name, e, ticket.Peak())
			}
			o, e := decodeAuthority(ticket.Bytes(), "keymaker-reservation/1")
			if e != nil {
				t.Fatal(e)
			}
			if o["audit_records_reserved"] != int64(8) {
				t.Fatal("separate audit headroom lost")
			}
			// Returned bytes and subsequent caller mutations cannot change the ticket.
			saved := ticket.Bytes()
			changed := ticket.Bytes()
			changed[0] = '!'
			filler["bytes"] = int64(1)
			if !bytes.Equal(saved, ticket.Bytes()) {
				t.Fatal("mutable reservation ticket")
			}
		})
	}
	// Every one of the fourteen retained classes is included, independently of
	// reservations. Missing/duplicate inventories fail closed, including empty ones.
	for _, class := range pc2CapacityInput().Classes {
		key := class.Inventory["owner"].(string) + "/" + class.Inventory["kind"].(string)
		t.Run("class/"+key, func(t *testing.T) {
			in := pc2CapacityInput()
			c := pc2CapacityClass(&in, key)
			c.Inventory["objects"].([]any)[0].(map[string]any)["bytes"] = int64(10001)
			if key == "keymaker/installed" {
				in.InstalledBytes = 10001
			}
			pc2CapacityFill(&in, stateBudget+1)
			pc2CapacityRefused(t, in, "retained "+key)
			in = pc2CapacityInput()
			for i, c := range in.Classes {
				if c.Inventory["owner"].(string)+"/"+c.Inventory["kind"].(string) == key {
					in.Classes = append(in.Classes[:i], in.Classes[i+1:]...)
					break
				}
			}
			pc2CapacityRefused(t, in, "missing "+key)
		})
	}
	for _, name := range []string{"overflow", "negative", "proof_overflow", "reserved_overflow", "proof_integrity_overflow", "negative_manager_integrity", "installed_mismatch", "missing_installed", "missing_root", "missing_intent", "missing_effect", "missing_metadata", "duplicate_class", "second_manager_slot"} {
		t.Run(name, func(t *testing.T) {
			in := pc2CapacityInput()
			switch name {
			case "overflow":
				in.NativeEffect.IntegrityBytes = math.MaxInt64
			case "negative":
				in.Root.IntegrityBytes = -1
			case "proof_overflow":
				in.PendingProofs = math.MaxInt64
			case "proof_integrity_overflow":
				in.ProofIntegrityBytes = math.MaxInt64
			case "negative_manager_integrity":
				in.ManagerIntegrity[1] = -1
			case "reserved_overflow":
				in.Classes[0].ReservedBytes = math.MaxInt64
			case "installed_mismatch":
				in.InstalledBytes++
			case "missing_installed":
				in.InstalledID = "absent"
			case "missing_root":
				in.Root.Bytes = 0
			case "missing_intent":
				in.NativeIntent.Bytes = 0
			case "missing_effect":
				in.NativeEffect.Bytes = 0
			case "missing_metadata":
				in.Metadata.Bytes = 135167
			case "duplicate_class":
				in.Classes[0] = in.Classes[1]
			case "second_manager_slot":
				in.ManagerSlotsInUse = 1
			}
			pc2CapacityRefused(t, in, name)
		})
	}
	// Empty rows are explicit inventories rather than missing classes. New copies
	// still reserve credit, while only the independently measured install exists.
	t.Run("explicit_empty_classes", func(t *testing.T) {
		in := pc2CapacityInput()
		in.PendingProofs = 0
		for i := range in.Classes {
			in.Classes[i].ReservedBytes = 0
			if in.Classes[i].Inventory["kind"] != "installed" {
				in.Classes[i].Inventory["objects"] = []any{}
			}
		}
		ticket, e := authorityCapacityPreflight(in)
		if e != nil || ticket.Peak() != pc2CapacityExpected(in) {
			t.Fatal("explicit zero rows refused", e)
		}
		o, e := decodeAuthority(ticket.Bytes(), "keymaker-reservation/1")
		if e != nil || len(o["groups"].([]any)) != 14 {
			t.Fatal("zero inventory rows lost", e)
		}
	})
	t.Run("inventory_and_carried_tickets", func(t *testing.T) {
		in := pc2CapacityInput()
		pc2CapacityClass(&in, "keymaker/pending_proofs").ReservedBytes = 2 * 4194304
		ticket, e := authorityCapacityPreflight(in)
		if e != nil {
			t.Fatal(e)
		}
		o, e := decodeAuthority(ticket.Bytes(), "keymaker-reservation/1")
		if e != nil {
			t.Fatal(e)
		}
		rows := o["groups"].([]any)
		for i, v := range rows {
			row := v.(map[string]any)
			raw, e := encodeAuthority(in.Classes[i].Inventory, "keymaker-capacity-inventory/1")
			if e != nil {
				t.Fatal(e)
			}
			if row["inventory_digest"] != authorityDigest(raw) || row["objects"] != int64(1) {
				t.Fatal("inventory digest/count lost")
			}
		}
		if rows[3].(map[string]any)["reserved_bytes"] != int64(2*4194304) {
			t.Fatal("unspent proof ticket released")
		}
		if ticket.Peak() != pc2CapacityExpected(in) {
			t.Fatal("independent ledger mismatch")
		}
	})
	t.Run("retained_store_unchanged", pc2CapacityRetainedStore)
}

func pc2CapacityFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	e := filepath.WalkDir(root, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if !d.IsDir() {
			raw, e := os.ReadFile(p)
			if e != nil {
				return e
			}
			rel, e := filepath.Rel(root, p)
			if e != nil {
				return e
			}
			out[rel] = authorityDigest(raw)
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}

// Refusal of this pure primitive cannot append an intent or successful audit or
// mutate a real retained S2 Store. Reopen confirms its committed retained state.
// This does not qualify S2b transaction ordering/crashes or add refusal telemetry.
func pc2CapacityRetainedStore(t *testing.T) {
	f := messageStateSetup(t)
	beforeFiles := pc2CapacityFiles(t, f.path)
	bindings := f.store.Snapshot()
	before, e := f.store.messageSnapshotBound(f.store.version)
	if e != nil {
		t.Fatal(e)
	}
	state := fmt.Sprintf("%d/%d/%d/%s/%t/%v", f.store.version, f.store.next, f.store.auditSeq, f.store.auditHash, f.store.failed, f.store.requestIndex)
	st, e := os.Stat(filepath.Join(f.path, "bindings.json"))
	if e != nil {
		t.Fatal(e)
	}
	in := pc2CapacityInput()
	in.InstalledBytes = st.Size()
	pc2CapacityClass(&in, "keymaker/installed").Inventory["objects"].([]any)[0].(map[string]any)["bytes"] = st.Size()
	// The sizing census for this test also carries every real retained file, with
	// distinct IDs and its actual byte size, so recovery copies are not omitted.
	paths := make([]string, 0, len(beforeFiles))
	for p := range beforeFiles {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	recovery := pc2CapacityClass(&in, "keymaker/recovery")
	recovery.Inventory["objects"] = []any{}
	for _, p := range paths {
		if p == "bindings.json" {
			continue
		}
		st, e := os.Stat(filepath.Join(f.path, p))
		if e != nil {
			t.Fatal(e)
		}
		if st.Size() > 0 {
			recovery.Inventory["objects"] = append(recovery.Inventory["objects"].([]any), map[string]any{"id": p, "bytes": st.Size(), "integrity_bytes": int64(0)})
		}
	}
	pc2CapacityFill(&in, stateBudget+1)
	pc2CapacityRefused(t, in, "retained refusal")
	after, e := f.store.messageSnapshotBound(f.store.version)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) || !reflect.DeepEqual(bindings, f.store.Snapshot()) || state != fmt.Sprintf("%d/%d/%d/%s/%t/%v", f.store.version, f.store.next, f.store.auditSeq, f.store.auditHash, f.store.failed, f.store.requestIndex) {
		t.Fatal("refusal changed in-memory commit")
	}
	if !reflect.DeepEqual(beforeFiles, pc2CapacityFiles(t, f.path)) {
		t.Fatal("refusal wrote intent/root/snapshot")
	}
	// Audit bytes are unchanged separately: the preflight has no telemetry sink.
	for p, hash := range beforeFiles {
		if strings.Contains(p, "audit") && pc2CapacityFiles(t, f.path)[p] != hash {
			t.Fatal("unexpected refusal/success telemetry")
		}
	}
	s := f.reopen(t)
	reopened, e := s.messageSnapshotBound(s.version)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, reopened) || !reflect.DeepEqual(bindings, s.Snapshot()) {
		t.Fatal("reopen lost retained commit")
	}
	if !reflect.DeepEqual(beforeFiles, pc2CapacityFiles(t, f.path)) {
		t.Fatal("reopen changed retained bytes")
	}
	// Fresh valid sizing still admits after the over-budget refusal and reopen.
	filler := pc2CapacityClass(&in, "keymaker/artifacts").Inventory["objects"].([]any)[1].(map[string]any)
	filler["bytes"] = filler["bytes"].(int64) - 1
	if ticket, e := authorityCapacityPreflight(in); e != nil || ticket.Peak() != stateBudget {
		t.Fatal("fresh preflight after retained refusal", e)
	}
}
