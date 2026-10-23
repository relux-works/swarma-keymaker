package keymaker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const generationFormatCommit = "33d0b941dcd4a7ee6d2b5b4ee03c4357056034df"
const generationManifestHash = "31d1ece06844337cfd8647c5226a920b56bbf61becf069281055447b32cce3c0"
const generationProvenanceHash = "c2dc3c486040f9dd0101f4b1db81d4697789ded098396360e00db43877ed348b"

func verifyGenerationVectors(dir string) error {
	raw, err := os.ReadFile(filepath.Join(dir, "provenance.json"))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != generationProvenanceHash {
		return fmt.Errorf("generation provenance hash mismatch")
	}
	var source struct {
		Repository, Commit string
		Files              []struct{ File, Path, SHA256 string }
	}
	if err := json.Unmarshal(raw, &source); err != nil {
		return err
	}
	if source.Repository != "https://github.com/relux-works/swarma-user-manager" || source.Commit != generationFormatCommit || len(source.Files) != 44 {
		return fmt.Errorf("generation source identity mismatch")
	}
	seen := map[string]bool{}
	for _, f := range source.Files {
		if f.File == "" || filepath.Base(f.File) != f.File || f.Path != "vectors/gen-journal/"+f.File || seen[f.File] {
			return fmt.Errorf("generation source path mismatch")
		}
		seen[f.File] = true
		b, err := os.ReadFile(filepath.Join(dir, f.File))
		if err != nil {
			return err
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != f.SHA256 {
			return fmt.Errorf("generation vector hash mismatch: %s", f.File)
		}
		if f.File == "manifest.json" && f.SHA256 != generationManifestHash {
			return fmt.Errorf("generation manifest hash mismatch")
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !seen[entry.Name()] && entry.Name() != "provenance.json" {
			return fmt.Errorf("untracked generation fixture: %s", entry.Name())
		}
	}
	var manifest struct {
		Format string
		Cases  []struct{ Name, Expect, Control string }
	}
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &manifest); err != nil {
		return err
	}
	if manifest.Format != "gen-journal-vectors/1" || len(manifest.Cases) != 67 {
		return fmt.Errorf("generation vector inventory mismatch")
	}
	names := map[string]string{}
	for _, c := range manifest.Cases {
		if _, ok := names[c.Name]; ok {
			return fmt.Errorf("duplicate generation vector")
		}
		names[c.Name] = c.Expect
	}
	for _, c := range manifest.Cases {
		if c.Expect != "ok" && names[c.Control] != "ok" {
			return fmt.Errorf("generation vector missing positive control")
		}
	}
	return nil
}

// The complete copied source inventory is byte-identical to the pinned public
// format head, and every negative in the 67-case manifest names a valid control.
// Adapter verdicts are a separate contract; hashes alone do not establish them.
func TestGenerationVectorProvenance(t *testing.T) {
	if err := verifyGenerationVectors("testdata/gen-journal"); err != nil {
		t.Fatal(err)
	}
}

// The drift checker accepts the exact copy, then rejects a changed fixture and
// changed provenance independently. Both plants are confined to private copies.
func TestGenerationVectorDriftControl(t *testing.T) {
	for _, file := range []string{"active.jsonl", "provenance.json"} {
		t.Run(file, func(t *testing.T) {
			d := t.TempDir()
			entries, err := os.ReadDir("testdata/gen-journal")
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				b, err := os.ReadFile(filepath.Join("testdata/gen-journal", e.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(d, e.Name()), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := verifyGenerationVectors(d); err != nil {
				t.Fatal("valid vector-copy control refused", err)
			}
			path := filepath.Join(d, file)
			f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.Write([]byte(" "))
			closeErr := f.Close()
			if err != nil || closeErr != nil {
				t.Fatal(err, closeErr)
			}
			err = verifyGenerationVectors(d)
			want := "generation vector hash mismatch: active.jsonl"
			if file == "provenance.json" {
				want = "generation provenance hash mismatch"
			}
			if err == nil || err.Error() != want {
				t.Fatalf("drift plant: got %v, want %s", err, want)
			}
		})
	}
}
