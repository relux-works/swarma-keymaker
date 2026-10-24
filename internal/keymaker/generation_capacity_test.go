//go:build linux

package keymaker

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// Materialize exact capacity boundaries using only public Encode and Digest.
// Valid removed filler incarnations consume bytes; no padding bypasses CCJ.
func generationCapacityBytes(t *testing.T, target int) []byte {
	t.Helper()
	var rows []gj.Record
	total := 0
	add := func(uid int64, gen, state string) {
		r := gj.Record{Seq: int64(len(rows) + 1), Prev: gj.ZeroHash, UID: uid, Generation: gen, State: state, Writer: "user-manager", Time: "2026-01-01T00:00:00Z"}
		b, e := gj.Encode(r)
		if e != nil {
			t.Fatal(e)
		}
		rows = append(rows, r)
		total += len(b)
	}
	add(4294967294, strings.Repeat("f", 32), "creating")
	add(4294967294, strings.Repeat("f", 32), "active")
	for n := 1; ; n++ {
		old, totalBefore := len(rows), total
		add(1, fmt.Sprintf("%032x", n), "creating")
		add(1, fmt.Sprintf("%032x", n), "removed")
		if total > target || target-total == 1 {
			rows = rows[:old]
			total = totalBefore
			break
		}
	}
	gap := target - total
	if gap%2 != 0 {
		rows[2].Writer = "operator-manual"
		gap -= 3
	}
	for i := 2; gap > 0 && i < len(rows); i += 2 {
		digits := gap / 2
		if digits > 9 {
			digits = 9
		}
		uid := int64(1)
		for j := 0; j < digits; j++ {
			uid *= 10
		}
		rows[i].UID = uid
		rows[i+1].UID = uid
		gap -= digits * 2
	}
	if gap != 0 {
		t.Fatal("capacity fixture gap", gap)
	}
	var raw []byte
	prev := gj.ZeroHash
	for _, r := range rows {
		r.Prev = prev
		b, e := gj.Encode(r)
		if e != nil {
			t.Fatal(e)
		}
		raw = append(raw, b...)
		prev = gj.Digest(b)
	}
	if len(raw) != target {
		t.Fatal("capacity fixture size", len(raw), target)
	}
	return raw
}

// The generated valid history has the exact public byte budget. A one-byte
// reserve deficit and the hard ceiling remain valid diagnostic chains but
// refuse release capacity, beside the 529-byte valid control. No filesystem
// policy or locking is qualified by this fixture-construction check.
func TestGenerationCapacityFixtures(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		want string
	}{
		{"deficit", gj.MaxFile - 528, "journal_capacity_reserve"},
		{"ceiling", gj.MaxFile, "journal_capacity_reserve"},
		{"valid", gj.MaxFile - 529, "ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := generationCapacityBytes(t, tc.size)
			v, e := gj.Verify(bytes.NewReader(raw), gj.Floor{Hash: gj.ZeroHash})
			if e != nil {
				t.Fatal("invalid fixture chain", e)
			}
			e = v.Capacity()
			got := "ok"
			if e != nil {
				r, ok := e.(*gj.Refusal)
				if !ok {
					t.Fatal(e)
				}
				got = r.Code
			}
			if got != tc.want {
				t.Fatal("capacity verdict", got, tc.want)
			}
		})
	}
}
