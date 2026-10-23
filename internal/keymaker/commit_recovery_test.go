package keymaker

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func recoveryFiles(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[path] = string(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// Each one-sided restore or substituted body must fence before changing any
// evidence. The intact control admits later ordinary audit records; rollback of
// both complete stores is deliberately a control for the checkpoint limitation.
func TestBindingCommitRecovery(t *testing.T) {
	for _, mode := range []string{"one-mutation-earlier", "extra-later-mutation", "journal-truncated", "snapshot-only", "substituted-body", "wrong-reference", "intact", "complete-pair-rollback"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			if err := os.Chmod(d, 0700); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Getuid())
			dir, err := OpenDirectory(d, uid, 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			lock, err := LockState(dir, uid)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			s, err := OpenStore(dir, uid)
			if err != nil {
				t.Fatal(err)
			}
			b := fixtureBinding(uid)
			b.Lifetime = "persistent"
			if _, c := s.Register(fixtureOperator, fixtureOperator, b); c != "" {
				t.Fatal(c)
			}
			snapshot, journal := filepath.Join(d, "bindings.json"), filepath.Join(d, "audit", auditName(1))
			read := func(path string) []byte {
				t.Helper()
				value, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			write := func(path string, value []byte) {
				t.Helper()
				if err := os.WriteFile(path, value, 0600); err != nil {
					t.Fatal(err)
				}
			}
			oldSnapshot, oldJournal := read(snapshot), read(journal)
			if c := s.Unbind(fixtureOperator, fixtureOperator, uid, b.Generation); c != "" {
				t.Fatal(c)
			}
			if s.version != 3 || s.journal.binding.Version != 3 || !s.matchesCommit(s.journal.binding) {
				t.Fatal("mutation not committed")
			}
			if mode == "extra-later-mutation" {
				digest, err := s.contentDigest(s.version + 1)
				if err != nil {
					t.Fatal(err)
				}
				if _, c := s.journal.commitBinding(s.version+1, digest); c != "" {
					t.Fatal(c)
				}
			}
			if c := s.journal.Append(AuditRecord{Surface: "agent", Operation: "probe", Result: "success"}); c != "" {
				t.Fatal(c)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "one-mutation-earlier":
				write(snapshot, oldSnapshot)
			case "journal-truncated":
				value := read(journal)
				write(journal, value[:len(value)-1])
			case "snapshot-only":
				// The complementary crash image: the new snapshot survived,
				// but the journal contains only the earlier complete records.
				write(journal, oldJournal)
			case "complete-pair-rollback":
				write(snapshot, oldSnapshot)
				write(journal, oldJournal)
			case "substituted-body", "wrong-reference":
				var disk bindingDisk
				if err := json.Unmarshal(read(snapshot), &disk); err != nil {
					t.Fatal(err)
				}
				if mode == "substituted-body" {
					disk.Next++
				} else {
					disk.AuditHash = string(bytes.Repeat([]byte("0"), 64))
				}
				value, err := json.Marshal(disk)
				if err != nil {
					t.Fatal(err)
				}
				write(snapshot, value)
			}
			before := recoveryFiles(t, d)
			recovered, err := OpenStore(dir, uid)
			if mode != "intact" && mode != "complete-pair-rollback" {
				if err == nil || recovered != nil {
					if recovered != nil {
						recovered.Close()
					}
					t.Fatal("inconsistent pair admitted")
				}
				want := "keymaker: binding journal recovery mismatch"
				if mode == "journal-truncated" {
					want = "keymaker: incomplete audit record"
				}
				if err.Error() != want {
					t.Fatal("wrong recovery refusal", err, want)
				}
				if !reflect.DeepEqual(before, recoveryFiles(t, d)) {
					t.Fatal("rejected startup changed evidence")
				}
				return
			}
			if err != nil {
				t.Fatal("intact pair refused", err)
			}
			defer recovered.Close()
			want := Code("binding_not_found")
			if mode == "complete-pair-rollback" {
				want = ""
			}
			if _, c := recovered.lookup(uid, b.Generation); c != want {
				t.Fatal("wrong recovered authority", c, want)
			}
		})
	}
}

type commitSyncFault struct {
	file       *os.File
	beforeSync func()
}

func (f *commitSyncFault) Write(p []byte) (int, error) { return f.file.Write(p) }
func (f *commitSyncFault) Sync() error {
	f.beforeSync()
	if err := f.file.Sync(); err != nil {
		return err
	}
	return errors.New("injected crash after durable journal sync")
}

// Real journal I/O precedes snapshot I/O. A failure after durable journal sync
// or before snapshot creation leaves the running Store closed and restart
// fenced. The healthy control commits both and recovers the unbound identity.
func TestBindingCommitCrashWindows(t *testing.T) {
	for _, mode := range []string{"journal-only", "snapshot-write-failure", "intact"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			if err := os.Chmod(d, 0700); err != nil {
				t.Fatal(err)
			}
			uid := uint32(os.Getuid())
			dir, err := OpenDirectory(d, uid, 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			lock, err := LockState(dir, uid)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			s, err := OpenStore(dir, uid)
			if err != nil {
				t.Fatal(err)
			}
			b := fixtureBinding(uid)
			b.Lifetime = "persistent"
			if _, c := s.Register(fixtureOperator, fixtureOperator, b); c != "" {
				t.Fatal(c)
			}
			path := filepath.Join(d, "bindings.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "journal-only" {
				s.journal.writer = &commitSyncFault{file: s.journal.file, beforeSync: func() {
					now, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(before, now) {
						t.Fatal("snapshot changed before journal sync", err)
					}
				}}
			}
			if mode == "snapshot-write-failure" {
				if err := os.WriteFile(filepath.Join(d, "bindings.next"), []byte("retained intent"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			c := s.Unbind(fixtureOperator, fixtureOperator, uid, b.Generation)
			if mode != "intact" {
				if c != "audit_unavailable" {
					t.Fatal("wrong failure", c)
				}
				if _, c := s.lookup(uid, b.Generation); c != "audit_unavailable" {
					t.Fatal("failed store admitted lookup", c)
				}
				if _, c := s.Register(fixtureOperator, fixtureOperator, b); c != "audit_unavailable" {
					t.Fatal("failed store admitted mutation", c)
				}
				now, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, now) {
					t.Fatal("failed commit overwrote snapshot", err)
				}
			} else if c != "" {
				t.Fatal(c)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if mode != "intact" {
				journal, err := os.ReadFile(filepath.Join(d, "audit", auditName(1)))
				if err != nil {
					t.Fatal(err)
				}
				lines := bytes.Split(bytes.TrimSuffix(journal, []byte{'\n'}), []byte{'\n'})
				var last AuditRecord
				if err := json.Unmarshal(lines[len(lines)-1], &last); err != nil {
					t.Fatal(err)
				}
				if last.Operation != "binding_commit" || last.RequestID == nil || *last.RequestID != "binding:3" {
					t.Fatal("fault did not leave the newer journal commit")
				}
			}
			beforeFiles := recoveryFiles(t, d)
			recovered, err := OpenStore(dir, uid)
			if mode != "intact" {
				if err == nil || recovered != nil {
					if recovered != nil {
						recovered.Close()
					}
					t.Fatal("crashed pair admitted restart")
				}
				want := "keymaker: binding journal recovery mismatch"
				if mode == "snapshot-write-failure" {
					want = "keymaker: unresolved binding intent"
				}
				if err.Error() != want {
					t.Fatal("wrong crash refusal", err, want)
				}
				if !reflect.DeepEqual(beforeFiles, recoveryFiles(t, d)) {
					t.Fatal("restart changed crash evidence")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer recovered.Close()
			if _, c := recovered.lookup(uid, b.Generation); c != "binding_not_found" {
				t.Fatal("intact unbind lost", c)
			}
		})
	}
}
