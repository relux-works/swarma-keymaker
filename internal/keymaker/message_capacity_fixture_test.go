package keymaker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Only fixture construction batches audit syncs. The original writer is restored
// before any boundary operation; no production persist or refusal uses this.
type capacityFixtureJournal struct{ durableFile }

func (capacityFixtureJournal) Sync() error { return nil }

func capacityBinding(n int, native bool) Binding {
	uid, owner := 100000+n, "o"
	if native {
		uid, owner = 200000+n, "n"
	}
	b := fixtureBinding(uint32(uid))
	b.Path = fmt.Sprintf("m/1'/1'/%d'/1'", uid)
	b.Owner = strings.Repeat(owner, 512)
	return b
}

func capacityRequest(t *testing.T, n int, b Binding) retainedRequest {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"public_key": "fixture-public", "path": b.Path, "registration_number": b.Number, "master_epoch": b.Epoch})
	if err != nil {
		t.Fatal(err)
	}
	return retainedRequest{Caller: fixtureOperator, ID: fmt.Sprintf("%032x", n+1), Method: "register", Arguments: "{}", Status: "committed", Result: raw}
}

// Seed real encoded history, not a synthetic byte counter or smaller budget.
// messageBody and commitBinding are the production encoders. Historical bodies
// remain separate files with their exact journal digests. Only setup omits the
// repeated bound encodings, snapshot installs and sync per historical entry.
// count=-1 stops with 8 MiB free, leaving the actual last-fitting transitions,
// every refusal/retry and restart assertion on ordinary production persistence.
func seedMessageCapacity(t *testing.T, f *messageStateFixture, native bool, count int) int {
	t.Helper()
	s := f.store
	original := s.journal.writer
	s.journal.writer = capacityFixtureJournal{original}
	defer func() { s.journal.writer = original }()
	dir := filepath.Join(f.path, "message-tx", "migration")
	installed, err := os.ReadFile(filepath.Join(f.path, "bindings.json"))
	if err != nil {
		t.Fatal(err)
	}
	commit := func() {
		t.Helper()
		version := s.version + 1
		body, err := s.messageBody(version)
		if err != nil {
			t.Fatal(err)
		}
		// The installed encoding adds only these two sorted audit fields to the
		// canonical body. Bound their widest encoding before any fixture write.
		header, err := canonical(map[string]any{"audit_seq": 9007199254740991, "audit_hash": strings.Repeat("0", 64)})
		if err != nil {
			t.Fatal(err)
		}
		if peak := int64(len(installed)+len(body)+len(body)+len(header)-1) + s.messages.artifactBytes; peak > stateBudget {
			t.Fatalf("fixture exceeded real simultaneous-copy budget: %d", peak)
		}
		name := filepath.Join(dir, fmt.Sprintf("snapshot-%d", version))
		file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.Write(body)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatal(writeErr, closeErr)
		}
		s.messages.artifactBytes += int64(len(body))
		binding, code := s.journal.commitBinding(version, messageHash(body))
		if code != "" {
			t.Fatal("fixture journal encode", code)
		}
		header, err = canonical(map[string]any{"audit_seq": binding.Seq, "audit_hash": binding.Hash})
		if err != nil {
			t.Fatal(err)
		}
		installed = append(append(header[:len(header)-1], ','), body[1:]...)
		s.version, s.auditSeq, s.auditHash = version, binding.Seq, binding.Hash
	}
	filled := 0
	for ; filled < 2000; filled++ {
		if count >= 0 && filled == count || count < 0 && int64(len(installed))+s.messages.artifactBytes >= stateBudget-(8<<20) {
			break
		}
		b := capacityBinding(filled, native)
		b.Number, b.Status, b.Registrar = s.next, "active", fixtureOperator
		if native {
			entry := capacityRequest(t, filled, b)
			pending := entry
			pending.Status, pending.Result = "pending", json.RawMessage("null")
			s.appendRequest(pending)
			commit()
			s.requests[len(s.requests)-1] = entry
		}
		s.records, s.next = append(s.records, b), s.next+1
		commit()
	}
	if filled == 2000 {
		t.Fatal("fixture did not approach production capacity")
	}
	// Verify the composed installed encoding against the complete production
	// encoder, not just another fixture implementation or an expected length.
	want, err := canonical(s.disk(s.version, s.journal.binding))
	if err != nil || !bytes.Equal(installed, want) {
		t.Fatal("fixture installed bytes differ from production encoder", err)
	}
	s.journal.writer = original
	if err = original.Sync(); err != nil {
		t.Fatal(err)
	}
	if code := s.installMessageSnapshot(t.Context(), installed); code != "" {
		t.Fatal("fixture final install", code)
	}
	return filled
}

// A small real slow-path control proves byte identity of every retained body,
// installed snapshot and chained journal record for single and native pairs.
// Both branches start from the same copied initial files and audit instance.
// The large boundary tests additionally validate their entire seeded history on
// production reopen; this is not power-loss/durability qualification of setup.
func TestMsgCapacityFixtureMatchesProduction(t *testing.T) {
	for _, native := range []bool{false, true} {
		t.Run(fmt.Sprintf("native=%t", native), func(t *testing.T) {
			base := messageStateSetup(t)
			if err := base.store.Close(); err != nil {
				t.Fatal(err)
			}
			base.store = nil
			clone := func() *messageStateFixture {
				t.Helper()
				path := t.TempDir()
				if err := os.Chmod(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := filepath.WalkDir(base.path, func(source string, entry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					rel, err := filepath.Rel(base.path, source)
					if err != nil || rel == "." {
						return err
					}
					if entry.IsDir() {
						return os.Mkdir(filepath.Join(path, rel), 0700)
					}
					raw, err := os.ReadFile(source)
					if err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(path, rel), raw, 0600)
				}); err != nil {
					t.Fatal(err)
				}
				dir, err := OpenDirectory(path, uint32(os.Getuid()), 0700)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { dir.Close() })
				s, err := openMessageStore(dir, uint32(os.Getuid()), base.floor, fixtureAuditClock{})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { s.Close() })
				s.journal.instance = strings.Repeat("1", 32)
				return &messageStateFixture{path: path, dir: dir, floor: base.floor, store: s}
			}
			fast, slow := clone(), clone()
			const count = 4
			seedMessageCapacity(t, fast, native, count)
			for n := 0; n < count; n++ {
				s := slow.store
				b := capacityBinding(n, native)
				if !native {
					if _, code := s.Register(fixtureOperator, fixtureOperator, b); code != "" {
						t.Fatal(code)
					}
					continue
				}
				b.Number, b.Status, b.Registrar = s.next, "active", fixtureOperator
				entry := capacityRequest(t, n, b)
				pending := entry
				pending.Status, pending.Result = "pending", json.RawMessage("null")
				s.appendRequest(pending)
				if code := s.persist(); code != "" {
					t.Fatal(code)
				}
				s.records, s.next = append(s.records, b), s.next+1
				s.requests[len(s.requests)-1] = entry
				if code := s.persist(); code != "" {
					t.Fatal(code)
				}
			}
			files := func(path string) map[string]string {
				out := map[string]string{}
				for name, raw := range recoveryFiles(t, path) {
					rel, err := filepath.Rel(path, name)
					if err != nil {
						t.Fatal(err)
					}
					out[rel] = messageHash([]byte(raw))
				}
				return out
			}
			if !reflect.DeepEqual(files(fast.path), files(slow.path)) || fast.store.messages.artifactBytes != slow.store.messages.artifactBytes {
				t.Fatal("fixture files differ from slow production history")
			}
		})
	}
}
