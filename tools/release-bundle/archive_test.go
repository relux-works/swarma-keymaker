package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func archiveFixture(t *testing.T, h *tar.Header) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(h); err != nil {
		t.Fatal(err)
	}
	if h.Typeflag == tar.TypeReg {
		if _, err := w.Write([]byte("test")); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// Malicious archive paths and link entries refuse before materialization. Even
// their potential escape destinations remain inside isolated test fixtures.
// An ordinary archived source file extracts with its exact bytes as control.
func TestReleaseArchiveFiles(t *testing.T) {
	for _, mode := range []string{"parent", "absolute", "backslash", "symlink", "hardlink"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			dest := filepath.Join(root, "source")
			if err := os.Mkdir(dest, 0700); err != nil {
				t.Fatal(err)
			}
			h := &tar.Header{Name: "source.go", Typeflag: tar.TypeReg, Mode: 0600, Size: 4}
			want := "source archive path refused"
			switch mode {
			case "parent":
				h.Name = "../escaped"
			case "absolute":
				h.Name = filepath.Join(root, "escaped")
			case "backslash":
				h.Name = "nested\\escaped"
			case "symlink":
				h.Typeflag = tar.TypeSymlink
				h.Size = 0
				h.Linkname = filepath.Join(root, "escaped")
				want = "source archive entry refused"
			case "hardlink":
				h.Typeflag = tar.TypeLink
				h.Size = 0
				h.Linkname = filepath.Join(root, "escaped")
				want = "source archive entry refused"
			}
			if err := extractTar(bytes.NewReader(archiveFixture(t, h)), dest); err == nil || err.Error() != want {
				t.Fatal("archive refusal differs", err)
			}
			entries, err := os.ReadDir(dest)
			if err != nil || len(entries) != 0 {
				t.Fatal("refused archive materialized entries", err)
			}
			absent(t, filepath.Join(root, "escaped"))
			h = &tar.Header{Name: "source.go", Typeflag: tar.TypeReg, Mode: 0600, Size: 4}
			if err := extractTar(bytes.NewReader(archiveFixture(t, h)), dest); err != nil {
				t.Fatal("valid archive control refused", err)
			}
			if raw, err := os.ReadFile(filepath.Join(dest, "source.go")); err != nil || string(raw) != "test" {
				t.Fatal("archive control bytes differ", err)
			}
		})
	}
}
