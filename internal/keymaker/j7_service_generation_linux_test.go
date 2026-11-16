//go:build linux && genjournal_testseam

package keymaker

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	gj "github.com/relux-works/swarma-user-manager/tools/genjournal"
)

// Claim: the composed startup consumes the pinned source owner's real tagged
// reader and an independently carried anchor. Missing source refuses without
// effects; restoring the same source admits. Fixture ownership/reader duration
// are explicit test seams, not root-owned journal or timing qualification.
func TestJ7ServiceGenerationJournalStartup(t *testing.T) {
	launcher := Principal{uint32(os.Getuid()) + 1, strings.Repeat("1", 32)}
	station := Principal{uint32(os.Getuid()) + 100, strings.Repeat("2", 32)}
	var raw []byte
	prev := gj.ZeroHash
	seq := int64(0)
	for _, p := range []Principal{launcher, station} {
		for _, state := range []string{"creating", "active"} {
			seq++
			record := gj.Record{Seq: seq, Prev: prev, UID: int64(p.UID), Generation: p.Generation, State: state, Writer: "user-manager", Time: "2026-01-01T00:00:00Z"}
			line, e := gj.Encode(record)
			if e != nil {
				t.Fatal(e)
			}
			raw = append(raw, line...)
			prev = gj.Digest(line)
		}
	}
	view, e := gj.Verify(bytes.NewReader(raw), gj.Floor{Hash: gj.ZeroHash})
	if e != nil {
		t.Fatal(e)
	}
	path, anchor := generationFixture(t, raw)
	// The source fixture requires exact 0755/0644, independently of the
	// caller's restrictive umask. Only these freshly created fixture leaves
	// are adjusted; no shared ancestor or production policy is changed.
	if e := os.Chmod(path, 0755); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"gate.lock", "data.lock", "journal"} {
		if e := os.Chmod(filepath.Join(path, name), 0644); e != nil {
			t.Fatal(e)
		}
	}
	f := j7ServiceSetup(t, j7ServiceOptions{launcher: &launcher, prepare: func(t *testing.T, sf *j7StateFixture) {
		sf.store.mu.Lock()
		defer sf.store.mu.Unlock()
		sf.binding.Generation = station.Generation
		sf.store.records[0].Generation = station.Generation
		if c := sf.store.commitJ7(t.Context()); c != "" {
			t.Fatal(c)
		}
		if c := persistGenerationAnchor(t.Context(), sf.store, generationAnchor{Path: path, Floor: view.Tail}); c != "" {
			t.Fatal(c)
		}
	}})
	f.cfg.GenerationJournal.Path = path
	f.deps.generation = func(s *Store, c generationJournalConfig) GenerationSource {
		f.trace.add("generation")
		return newJournalGeneration(generationTestJournal(t, anchor), s, c.Path, c.InitialFloor)
	}
	moved := path + ".held"
	if e := os.Rename(path, moved); e != nil {
		t.Fatal(e)
	}
	f.refuses(t, "generation_source_unavailable", j7ServiceRefusal{absent: []string{"policy"}})
	if e := os.Rename(moved, path); e != nil {
		t.Fatal(e)
	}
	before := recoveryFiles(t, anchor)
	f.serves(t)
	if !reflect.DeepEqual(before, recoveryFiles(t, anchor)) {
		t.Fatal("service changed generation source")
	}
}
