package keymaker

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// These exact journal bytes were written and reopened by main 243a330 before
// custody_cause existed. Recovery must accept both custody and ordinary history,
// retain the original chain head, and never synthesize metadata or rewrite bytes.
// The fixed SHA256 values and record digests are independent of the new writer.
func TestCustodyLegacyRecovery(t *testing.T) {
	for _, row := range []struct{ name, hash, digest string }{
		{"custody", "aaaf0051d5ca4b4b17fb2fe0d906b3aa89e4cbf90fff21499bb34989540ac777", "f8f5f919560e0a99a3b5fc716c4bc226206cc8005026daed9c61a2804f4d990f"},
		{"ordinary", "a5a9334c7b71d703f4e25c69e80aa8325329853e885c1ef2bb4379d3f250f0f5", "88f572013d27746f99e6a635f6f5505e9af65f2f95bea94266f2dab182d71c1f"},
	} {
		t.Run(row.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "custody-legacy-243a330", row.name+".jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(raw)
			if hex.EncodeToString(sum[:]) != row.hash || bytes.Contains(raw, []byte("custody_cause")) {
				t.Fatal("pre-change fixture identity changed")
			}
			d := t.TempDir()
			if err := os.Chmod(d, 0700); err != nil {
				t.Fatal(err)
			}
			dir, err := OpenDirectory(d, uint32(os.Getuid()), 0700)
			if err != nil {
				t.Fatal(err)
			}
			defer dir.Close()
			path := filepath.Join(d, auditName(1))
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			j, recovery := OpenJournal(dir, uint32(os.Getuid()))
			if j != nil {
				if j.seq != 1 || j.previous != row.digest {
					t.Error("legacy chain head changed")
				}
				if err := j.Close(); err != nil {
					t.Fatal(err)
				}
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(raw, after) || sha256.Sum256(after) != sum {
				t.Fatal("legacy recovery rewrote bytes or hashes", err)
			}
			if recovery != nil || j == nil {
				t.Fatal("legacy custody history refused", recovery)
			}
		})
	}
}
