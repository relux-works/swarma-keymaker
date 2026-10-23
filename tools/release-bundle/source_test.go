package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func shippedUnit(t *testing.T) ([]byte, []byte) {
	t.Helper()
	unit, err := os.ReadFile("../../packaging/swarma-keymaker.service")
	if err != nil {
		t.Fatal(err)
	}
	spec, err := os.ReadFile("../../spec/keymaker.md")
	if err != nil {
		t.Fatal(err)
	}
	return unit, spec
}

// The shipped unit equals the complete ordered ini block in section 12.1.
// Added, removed, reordered or modified settings and missing blocks refuse.
func TestReleaseUnitMatchesSpec(t *testing.T) {
	unit, spec := shippedUnit(t)
	for _, mode := range []string{"added", "removed", "reordered", "modified", "no-section", "no-block"} {
		t.Run(mode, func(t *testing.T) {
			u, s := append([]byte(nil), unit...), append([]byte(nil), spec...)
			switch mode {
			case "added":
				u = append(u, []byte("ExecStartPre=/bin/true\n")...)
			case "removed":
				u = bytes.Replace(u, []byte("NoNewPrivileges=yes\n"), nil, 1)
			case "reordered":
				u = bytes.Replace(u, []byte("NoNewPrivileges=yes\nPrivateTmp=yes\n"), []byte("PrivateTmp=yes\nNoNewPrivileges=yes\n"), 1)
			case "modified":
				u = bytes.Replace(u, []byte("UMask=0077"), []byte("UMask=0000"), 1)
			case "no-section":
				s = bytes.Replace(s, []byte("### 12.1 "), []byte("### other "), 1)
			case "no-block":
				s = bytes.Replace(s, []byte("```ini\n"), []byte("```text\n"), 1)
			}
			if !errors.Is(unitMatchesSpec(u, s), errUnit) {
				t.Fatal("unit drift admitted")
			}
			if err := unitMatchesSpec(unit, spec); err != nil {
				t.Fatal("valid unit control refused", err)
			}
		})
	}
}

// Version inspection accepts the actual CLI constant and rejects missing,
// computed, non-string and malformed declarations without executing source.
func TestReleaseSourceVersion(t *testing.T) {
	raw, err := os.ReadFile("../../cmd/keymaker/main.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"package main", "package main; const version = 42", "package main; const version = string('x')", "not Go"} {
		if _, err := sourceVersion([]byte(bad)); !errors.Is(err, errVersion) {
			t.Fatal("bad source version admitted", err)
		}
		if got, err := sourceVersion(raw); err != nil || got == "" {
			t.Fatal("version control refused", err)
		}
	}
}

// Path policy refuses system/source targets lexically before target access.
// The valid target is absent inside a private temporary fixture directory.
func TestReleaseTargetPolicy(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "source")
	if err := os.Mkdir(repo, 0700); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"", "/", "/etc/release-fixture", "/usr/local/release-fixture", "/var/release-fixture", "/run/release-fixture", repo, filepath.Join(repo, "bundle")} {
		if _, err := targetPath(repo, target); !errors.Is(err, errTarget) {
			t.Fatal("unsafe target admitted")
		}
		if _, err := targetPath(repo, filepath.Join(root, "new-bundle")); err != nil {
			t.Fatal("valid target control refused", err)
		}
	}
	if _, err := os.Lstat(filepath.Join(root, "new-bundle")); !os.IsNotExist(err) {
		t.Fatal("preflight wrote target")
	}
}

// Canonical version parsing is independent of unrelated source declarations.
func TestReleaseSourceVersionControl(t *testing.T) {
	got, err := sourceVersion([]byte("package main\nconst unrelated = 2\nconst version = \"test-control\"\n"))
	if err != nil || strings.TrimSpace(got) != "test-control" {
		t.Fatal(got, err)
	}
}
