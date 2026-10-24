package keymaker

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Rotation retains an unbroken hash/sequence chain; startup refuses corruption,
// truncated records, orphan seals and unsafe files instead of accepting a prefix.
func TestAuditRecoveryAndRotation(t *testing.T) {
	d := t.TempDir()
	os.Chmod(d, 0700)
	dir, e := OpenDirectory(d, uint32(os.Getuid()), 0700)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	j, e := fixtureOpenJournal(dir, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	j.segmentLimit = 1024
	for i := 0; i < 8; i++ {
		if c := j.Append(AuditRecord{Surface: "agent", Operation: "pubkey", Result: "success"}); c != "" {
			t.Fatal(c)
		}
	}
	last := j.previous
	j.Close()
	j, e = fixtureOpenJournal(dir, uint32(os.Getuid()))
	if e != nil {
		t.Fatal(e)
	}
	if j.seq != 8 || j.previous != last {
		t.Fatal("lost audit tail")
	}
	if c := j.Append(AuditRecord{Surface: "agent", Operation: "pubkey", Result: "success"}); c != "" {
		t.Fatal(c)
	}
	j.Close()
	p := filepath.Join(d, auditName(1))
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	b = bytes.Replace(b, []byte("pubkey"), []byte("revoke"), 1)
	if e = os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = fixtureOpenJournal(dir, uint32(os.Getuid())); e == nil {
		t.Fatal("tampered audit accepted")
	}
}

type uncertainAuditClock struct{}

func (uncertainAuditClock) UTC() (time.Time, bool) { return time.Time{}, false }

// Missing entropy refuses before creating a segment; uncertain time produces an
// explicit null/unknown record. Normal entropy/time are covered by recovery tests.
func TestAuditDependencyFailures(t *testing.T) {
	d := t.TempDir()
	os.Chmod(d, 0700)
	dir, e := OpenDirectory(d, uint32(os.Getuid()), 0700)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	if j, err := openJournal(dir, uint32(os.Getuid()), uncertainAuditClock{}, bytes.NewReader(nil)); err == nil || j != nil {
		t.Fatal("missing entropy admitted")
	}
	entries, e := os.ReadDir(d)
	if e != nil || len(entries) != 0 {
		t.Fatal("entropy failure changed journal")
	}
	j, e := openJournal(dir, uint32(os.Getuid()), uncertainAuditClock{}, bytes.NewReader(make([]byte, 16)))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if c := j.Append(AuditRecord{Surface: "agent", Operation: "pubkey", Result: "success"}); c != "" {
		t.Fatal(c)
	}
	b, e := os.ReadFile(filepath.Join(d, auditName(1)))
	if e != nil || !bytes.Contains(b, []byte(`"time":null`)) || !bytes.Contains(b, []byte(`"result":"unknown"`)) {
		t.Fatal("uncertain time invented evidence")
	}
}

// Incomplete, ambiguous and unsafe retained evidence fences replay. Every case
// begins from the same successfully appended journal, not an unrelated setup fault.
func TestAuditStartupRejectsIncompleteEvidence(t *testing.T) {
	for _, kind := range []string{"truncated", "empty-line", "orphan-seal", "unsafe-mode", "missing-first", "unsealed-history"} {
		t.Run(kind, func(t *testing.T) {
			d := t.TempDir()
			os.Chmod(d, 0700)
			dir, e := OpenDirectory(d, uint32(os.Getuid()), 0700)
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			j, e := fixtureOpenJournal(dir, uint32(os.Getuid()))
			if e != nil {
				t.Fatal(e)
			}
			j.segmentLimit = 600
			for i := 0; i < 2; i++ {
				if c := j.Append(AuditRecord{Surface: "agent", Operation: "pubkey", Result: "success"}); c != "" {
					t.Fatal(c)
				}
			}
			j.Close()
			p := filepath.Join(d, auditName(1))
			b, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "truncated":
				e = os.WriteFile(p, b[:len(b)-1], 0600)
			case "empty-line":
				e = os.WriteFile(p, append(b, '\n'), 0600)
			case "orphan-seal":
				e = os.WriteFile(filepath.Join(d, auditName(99)+".seal"), []byte("{}"), 0600)
			case "unsafe-mode":
				e = os.Chmod(p, 0666)
			case "missing-first":
				e = os.Remove(p)
			case "unsealed-history":
				e = os.Remove(p + ".seal")
			}
			if e != nil {
				t.Fatal(e)
			}
			if recovered, err := fixtureOpenJournal(dir, uint32(os.Getuid())); err == nil {
				recovered.Close()
				t.Fatal("unsafe journal admitted")
			}
		})
	}
}

// Failed append, short append or sync permanently closes the journal; a positive
// append control is exercised by TestAuditRecoveryAndRotation and audit vectors.
func TestAuditWriteFailures(t *testing.T) {
	for _, kind := range []string{"append", "short", "sync", "budget"} {
		t.Run(kind, func(t *testing.T) {
			d := t.TempDir()
			os.Chmod(d, 0700)
			dir, _ := OpenDirectory(d, uint32(os.Getuid()), 0700)
			defer dir.Close()
			j, e := fixtureOpenJournal(dir, uint32(os.Getuid()))
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			j.writer = &faultFile{file: j.file, writeFail: kind == "append", short: kind == "short", syncFail: kind == "sync"}
			if kind == "budget" {
				j.totalLimit = 1
				j.reserve = 0
			}
			if c := j.Append(AuditRecord{Operation: "sign", Result: "success"}); c != "audit_unavailable" {
				t.Fatal(c)
			}
			if c := j.Append(AuditRecord{Operation: "sign", Result: "success"}); c != "audit_unavailable" {
				t.Fatal("journal reopened after failure")
			}
		})
	}
}

// Metadata is exactly canonical, with null unknown fields; neither payloads nor
// key bytes are journal members. Unicode scalar strings use CCJ-1 literal encoding.
func TestAuditCanonicalSchema(t *testing.T) {
	r := AuditRecord{Operation: "sign", Surface: "agent", Result: "refused"}
	b, e := canonical(r)
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"request_id", "peer_uid", "generation", "path", "master_epoch", "domain", "payload_digest", "refusal_code"} {
		if !bytes.Contains(b, []byte(`"`+field+`":null`)) {
			t.Fatal("missing explicit unknown", field)
		}
	}
	out, e := canonical(map[string]any{"text": "<\u2028>", "control": "\x01"})
	if e != nil || strings.Contains(string(out), `\u2028`) || strings.Contains(string(out), `\u003c`) || !bytes.Contains(out, []byte(`\u0001`)) {
		t.Fatal("noncanonical string encoding")
	}
}
