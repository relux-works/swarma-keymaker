package enrollment

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Unsafe pins never reach admission; each case is paired with an unchanged,
// protected configuration control. Ownership is injected, not changed on host.
func TestPinConfigurationRefusals(t *testing.T) {
	cases := []string{"owner", "group-write", "world-write", "symlink", "directory", "fifo", "parent-owner", "parent-write", "duplicate-json", "unknown-json", "relative-registry", "bad-revision", "bad-audience", "bad-generation", "bad-maintainer", "bad-publisher"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.config.Revision = f.commit(f.valid(), "", true)
			f.writeConfig()
			original, err := os.ReadFile(f.configPath)
			if err != nil {
				t.Fatal(err)
			}
			restore := func() {
				f.files.override = map[string]Metadata{}
				_ = os.Remove(f.configPath)
				if err = os.WriteFile(f.configPath, original, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch name {
			case "owner":
				f.files.override[f.configPath] = Metadata{Mode: 0600, UID: 42}
			case "group-write":
				f.files.override[f.configPath] = Metadata{Mode: 0620, UID: 0}
			case "world-write":
				f.files.override[f.configPath] = Metadata{Mode: 0602, UID: 0}
			case "symlink":
				if err = os.Rename(f.configPath, f.configPath+".real"); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(f.configPath+".real", f.configPath); err != nil {
					t.Fatal(err)
				}
			case "directory":
				f.files.override[f.configPath] = Metadata{Mode: fs.ModeDir | 0700, UID: 0}
			case "fifo":
				f.files.override[f.configPath] = Metadata{Mode: fs.ModeNamedPipe | 0600, UID: 0}
			case "parent-owner":
				f.files.override[filepath.Dir(f.configPath)] = Metadata{Mode: fs.ModeDir | 0700, UID: 42}
			case "parent-write":
				f.files.override[filepath.Dir(f.configPath)] = Metadata{Mode: fs.ModeDir | 0777, UID: 0}
			case "duplicate-json":
				if err = os.WriteFile(f.configPath, []byte(`{"revision":"a","revision":"b"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "unknown-json":
				if err = os.WriteFile(f.configPath, append([]byte(`{"extra":true,`), original[1:]...), 0600); err != nil {
					t.Fatal(err)
				}
			default:
				switch name {
				case "relative-registry":
					f.config.Registry = "relative"
				case "bad-revision":
					f.config.Revision = "main"
				case "bad-audience":
					f.config.Audience = "https://example.invalid"
				case "bad-generation":
					f.config.Generations["30001"] = "new"
				case "bad-maintainer":
					f.config.Maintainers = []string{public(2)}
				case "bad-publisher":
					f.config.Publisher = public(2) + "="
				}
				f.writeConfig()
			}
			a := New(f.configPath, f.files, nil)
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			if result, code := authorize(a); code != EnrollmentUnverified || result.Key != "" {
				t.Fatal("unsafe pins returned authority")
			}
			restore()
			a = f.reconciledAuthority()
			expectCode(t, OK, a.Reload(context.Background()))
			_, code := authorize(a)
			expectCode(t, OK, code)
		})
	}
}

// Canonical audience admission is independent of requested names or audiences.
func TestCanonicalAudience(t *testing.T) {
	for _, s := range []string{"", "https://example.invalid", "EXAMPLE.invalid", "a:", "a:0", "a:01", "a:65536", "a..b", "a.", "a/b", "[::1", "[::ffff:192.0.2.1]"} {
		if canonicalAudience(s) {
			t.Errorf("accepted %q", s)
		}
	}
	for _, s := range []string{"example.invalid", "example.invalid:8448", "127.0.0.1", "[::1]", "[2001:db8::1]:8448"} {
		if !canonicalAudience(s) {
			t.Errorf("rejected %q", s)
		}
	}
}
