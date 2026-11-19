package keymaker

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A changed row is validated before journal mutation; an unrelated malformed
// saved row is still rejected by the full loader, beside exact canonical bytes.
func TestMALiveIncrementalPersistence(t *testing.T) {
	f := newMALiveFixture(t)
	f.control(t)
	s := f.h.store
	a := maLiveIntent(f)
	a.ID = strings.Repeat("b", 32)
	s.maLive.Attempts = append(s.maLive.Attempts, a)
	if c := s.persistMALive(t.Context(), 1); c != "" {
		t.Fatal(c)
	}
	raw, e := os.ReadFile(filepath.Join(f.dir.Name(), "bindings.json"))
	if e != nil {
		t.Fatal(e)
	}
	want, e := canonical(s.disk(s.version, bindingCommit{Seq: s.auditSeq, Hash: s.auditHash}))
	if e != nil || !bytes.Equal(raw, want) {
		t.Fatal("incremental snapshot changed canonical format", e)
	}
	if _, e = loadStoreMessage(f.dir, s.uid, maLiveSchema, false); e != nil {
		t.Fatal("valid load", e)
	}
	before := s.journal.seq
	s.maLive.Attempts[1].ID = s.maLive.Attempts[0].ID
	if c := s.persistMALive(t.Context(), 1); c != "message_author_unqualified" || s.journal.seq != before {
		t.Fatal("duplicate identity persisted", c)
	}
	s.maLive.Attempts[1] = a
	s.maLive.Attempts[1].Preimage = []byte("invalid")
	if c := s.persistMALive(t.Context(), 1); c != "message_author_unqualified" || s.journal.seq != before {
		t.Fatal("changed corrupt intent persisted", c)
	}
	s.maLive.Attempts[1] = a
	fresh := a
	fresh.ID = strings.Repeat("c", 32)
	fresh.Preimage = []byte("invalid")
	s.maLive.Attempts = append(s.maLive.Attempts, fresh)
	if c := s.persistMALive(t.Context(), 2); c != "message_author_unqualified" || s.journal.seq != before {
		t.Fatal("corrupt new intent persisted", c)
	}
	s.maLive.Attempts = s.maLive.Attempts[:2]
	// A runtime writer cannot import an unmarked memory edit into the durable
	// inventory. It writes the validated canonical cached row, not that edit.
	s.maLive.Attempts[0].Signature[0] ^= 1
	s.maLive.Attempts[1].Status = "dead"
	if c := s.persistMALive(t.Context(), 1); c != "" {
		t.Fatal("unchanged row revalidated during transition", c)
	}
	s.maLive.Attempts[0].Signature[0] ^= 1
	raw, e = os.ReadFile(filepath.Join(f.dir.Name(), "bindings.json"))
	if e != nil {
		t.Fatal(e)
	}
	want, e = canonical(s.disk(s.version, bindingCommit{Seq: s.auditSeq, Hash: s.auditHash}))
	if e != nil || !bytes.Equal(raw, want) {
		t.Fatal("unmarked memory corruption reached snapshot", e)
	}
	s.maLive.Attempts[0].Signature[0] ^= 1
	bad, e := canonical(s.disk(s.version, bindingCommit{Seq: s.auditSeq, Hash: s.auditHash}))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(f.dir.Name(), "bindings.json"), bad, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = loadStoreMessage(f.dir, s.uid, maLiveSchema, false); e == nil {
		t.Fatal("corrupt unchanged row accepted at load")
	}
	if e = os.WriteFile(filepath.Join(f.dir.Name(), "bindings.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = loadStoreMessage(f.dir, s.uid, maLiveSchema, false); e != nil {
		t.Fatal("restored load", e)
	}
}

// At the peer-map bound, only naturally full idle buckets may disappear. Debt
// in either bucket survives; refilled principals and new traffic still work.
func TestMALiveIdlePeerReclamation(t *testing.T) {
	now := time.Unix(2000000000, 0)
	b := &maLiveBudget{now: func() time.Time { return now }, peers: map[Principal]*maLivePeerBudget{}}
	for i := range 65536 {
		b.peers[Principal{uint32(i), "1"}] = &maLivePeerBudget{all: bucket{0, now}, sign: bucket{0, now}}
	}
	fresh := Principal{70000, "1"}
	if c := b.charge(fresh, true); c != "rate_limited" || len(b.peers) != 65536 {
		t.Fatal("debt erased", c)
	}
	idle := Principal{0, "1"}
	debt := Principal{1, "1"}
	b.peers[idle] = &maLivePeerBudget{all: bucket{39, now.Add(-time.Second)}, sign: bucket{3, now.Add(-time.Second)}}
	// Traffic can be idle yet still owe a sign token: it must remain retained.
	b.peers[debt] = &maLivePeerBudget{all: bucket{40, now.Add(-time.Millisecond)}, sign: bucket{0, now.Add(-time.Millisecond)}}
	if c := b.charge(fresh, true); c != "" {
		t.Fatal("idle full control", c)
	}
	if _, ok := b.peers[idle]; ok {
		t.Fatal("idle full bucket not reclaimed")
	}
	if _, ok := b.peers[debt]; !ok {
		t.Fatal("sign debt erased")
	}
	if c := b.chargeSign(debt); c != "rate_limited" {
		t.Fatal("debt bypassed", c)
	}
	now = now.Add(20 * time.Second)
	if c := b.charge(debt, true); c != "" {
		t.Fatal("natural refill control", c)
	}
	t.Log(fmt.Sprintf("retained=%d; full idle reclaimed; debt preserved", len(b.peers)))
}
