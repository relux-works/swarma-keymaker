package enrollment

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-registrar/registry"
)

// A real OpenSSH-signed Git commit, not the embedded key or author metadata,
// establishes the positive control for the verifier and all fixture consumers.
func TestSignedGitFixture(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	f.writeConfig()
	_, policy, err := loadConfig(f.configPath, f.files)
	if err != nil {
		t.Fatalf("configuration: %v", err)
	}
	v := newGitVerifier(context.Background(), f.repo, f.config.Revision, f.config.ObjectFormat, f.config.Maintainers)
	entries, err := v.entries()
	if err != nil {
		t.Fatalf("entries: %v", err)
	}
	if err = v.Verify(f.config.Revision, entries); err != nil {
		t.Fatalf("signature: %v", err)
	}
	store := newFileStore(context.Background(), f.config.StateDir, f.files, f.config.ObjectFormat)
	_, _, err = (registry.Loader{ObjectFormat: f.config.ObjectFormat, Policy: policy, Verifier: v, Store: initialPublisher{store}}).Load(registry.Input{Revision: f.config.Revision, Entries: entries, FirstUse: true})
	if err != nil {
		t.Fatalf("loader: %v store_failed=%t", err, store.failed)
	}
}

// Refusals bind complete content/types and the exact pin. Each negative is
// followed by a valid independently signed control; no host keys are read.
func TestSignedCommitRefusals(t *testing.T) {
	for _, name := range []string{"unsigned", "foreign-signer", "wrong-revision", "symlink", "nonregular", "over-cap", "altered-bytes", "omitted-entry", "changed-type"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			entries := f.valid()
			revision := f.commit(entries, "", true)
			f.config.Revision = revision
			switch name {
			case "unsigned":
				f.config.Revision = f.commit(entries, "", false)
			case "foreign-signer":
				other := newFixture(t)
				f.config.Maintainers = []string{other.public}
			case "wrong-revision":
				f.config.Revision = strings.Repeat("a", 40)
			case "symlink":
				entries[0].Kind = registry.Symlink
				f.config.Revision = f.commit(entries, "", true)
			case "nonregular":
				entries[0].Kind = registry.Other
				f.config.Revision = f.commit(entries, "", true)
			case "over-cap":
				entries = nil
				for i := 0; i < 17; i++ {
					entries = append(entries, registry.Entry{Path: "enrollments/" + string(rune('a'+i)) + ".json", Bytes: []byte(strings.Repeat("x", 1<<20)), Kind: registry.Regular})
				}
				f.config.Revision = f.commit(entries, "", true)
			default:
				v := newGitVerifier(context.Background(), f.repo, revision, f.config.ObjectFormat, f.config.Maintainers)
				bound, err := v.entries()
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "altered-bytes":
					bound[0].Bytes[0] = ' '
				case "omitted-entry":
					bound = nil
				case "changed-type":
					bound[0].Kind = registry.Symlink
				}
				if v.Verify(revision, bound) == nil {
					t.Fatal("unbound entries accepted")
				}
				bound, err = v.entries()
				if err != nil || v.Verify(revision, bound) != nil {
					t.Fatal("bound positive control rejected")
				}
				return
			}
			a := f.authority()
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			result, code := authorize(a)
			expectCode(t, EnrollmentUnverified, code)
			if !reflect.DeepEqual(result, EnrolledKey{}) {
				t.Fatal("refusal released data")
			}
			f.config.Maintainers = []string{f.public}
			f.config.Revision = revision
			a = f.authority()
			expectCode(t, OK, a.Reload(context.Background()))
			_, code = authorize(a)
			expectCode(t, OK, code)
		})
	}
}

// An ancestry refusal cannot be bypassed by an equal enrollment body. A
// descendant commit with those same entries is the nearby accepted control.
func TestNonDescendantPin(t *testing.T) {
	f := newFixture(t)
	entries := f.valid()
	first := f.commit(entries, "", true)
	f.config.Revision = first
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	// Distinct commit metadata ensures this is an unrelated root, not the same OID.
	secondEntries := append([]registry.Entry{}, entries...)
	body := baseBody()
	body["seq"] = int64(2)
	secondEntries = append(secondEntries, registry.Entry{Path: "enrollments/2.json", Bytes: signedRecord(t, body, 1)})
	unrelated := f.commit(secondEntries, "", true)
	f.config.Revision = unrelated
	f.writeConfig()
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, EnrollmentUnverified, code)
	f.config.Revision = f.commit(secondEntries, first, true)
	f.writeConfig()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code = authorize(a)
	expectCode(t, OK, code)
}

// Inherited Git redirects/config/SSH-agent state cannot change selected objects.
// This tests environment isolation, not OS networking or hook invocation.
func TestGitEnvironmentIsolation(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	t.Setenv("GIT_DIR", "/missing/foreign.git")
	t.Setenv("GIT_OBJECT_DIRECTORY", "/missing/objects")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "alias.cat-file")
	t.Setenv("GIT_CONFIG_VALUE_0", "!exit 99")
	t.Setenv("SSH_AUTH_SOCK", "/missing/test-agent")
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, OK, code)
}

// A protected top-level Git directory cannot hide writable object storage or
// mutable alternates. Clearing the offending metadata restores the valid pin.
func TestProtectedGitStorage(t *testing.T) {
	for _, name := range []string{"writable-object-directory", "foreign-owner", "alternates", "symbolic-object-storage"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.config.Revision = f.commit(f.valid(), "", true)
			f.writeConfig()
			objectDir := filepath.Join(f.repo, "objects")
			switch name {
			case "writable-object-directory":
				f.files.override[objectDir] = Metadata{Mode: os.ModeDir | 0777, UID: 0}
			case "foreign-owner":
				f.files.override[objectDir] = Metadata{Mode: os.ModeDir | 0700, UID: 42}
			case "alternates":
				if err := os.WriteFile(filepath.Join(objectDir, "info", "alternates"), []byte("/foreign/objects\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symbolic-object-storage":
				f.files.override[objectDir] = Metadata{Mode: os.ModeSymlink | 0777, UID: 0}
			}
			a := New(f.configPath, f.files, nil)
			expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
			f.files.override = map[string]Metadata{}
			if name == "alternates" {
				if err := os.Remove(filepath.Join(objectDir, "info", "alternates")); err != nil {
					t.Fatal(err)
				}
			}
			a = f.authority()
			expectCode(t, OK, a.Reload(context.Background()))
			_, code := authorize(a)
			expectCode(t, OK, code)
		})
	}
}

// Malformed signature data, the wrong namespace and altered signed content
// cannot pass an allowlisted key. The control comes from OpenSSH's signer.
func TestSSHSigDomainsAndContent(t *testing.T) {
	f := newFixture(t)
	message := []byte("bounded test commit payload\n")
	path := filepath.Join(f.base, "payload")
	if err := os.WriteFile(path, message, 0600); err != nil {
		t.Fatal(err)
	}
	f.run("/usr/bin/ssh-keygen", nil, "-Y", "sign", "-f", f.key, "-n", "other", path)
	other, err := os.ReadFile(path + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	if verifySSHSig(other, message, []string{f.public}) == nil {
		t.Fatal("wrong namespace accepted")
	}
	if err = os.Remove(path + ".sig"); err != nil {
		t.Fatal(err)
	}
	f.run("/usr/bin/ssh-keygen", nil, "-Y", "sign", "-f", f.key, "-n", "git", path)
	valid, err := os.ReadFile(path + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{nil, []byte("bad armor"), append([]byte("leading junk\n"), valid...), append(valid, []byte("trailing")...)} {
		if verifySSHSig(input, message, []string{f.public}) == nil {
			t.Fatal("malformed signature accepted")
		}
	}
	if verifySSHSig(valid, []byte("changed"), []string{f.public}) == nil {
		t.Fatal("changed signed content accepted")
	}
	if verifySSHSig(valid, message, []string{f.public}) != nil {
		t.Fatal("OpenSSH positive control refused")
	}
}

// The cap must survive io.Copy's optional-interface optimizations, as used for
// subprocess pipes. A reader-only source prevents WriterTo from hiding a
// destination ReaderFrom bypass; exact-cap output is the positive control.
func TestGitOutputBound(t *testing.T) {
	limited := &boundedOutput{limit: 3}
	_, err := io.Copy(limited, struct{ io.Reader }{strings.NewReader("overflow")})
	if err == nil || len(limited.Bytes()) > 3 {
		t.Fatal("subprocess output escaped bound through io.Copy")
	}
	limited = &boundedOutput{limit: 3}
	_, err = io.Copy(limited, struct{ io.Reader }{strings.NewReader("fit")})
	if err != nil || string(limited.Bytes()) != "fit" {
		t.Fatal("exact-bound control failed")
	}
}

// A kernel read denial in otherwise protected Git storage is unavailable
// evidence, not a signature/schema verdict. Clearing that denial is the control.
func TestUnreadableGitEvidence(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	f.files.denyRead = map[string]error{filepath.Join(f.repo, "config"): os.ErrPermission}
	a.files = f.files
	expectCode(t, EnrollmentUnavailable, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, EnrollmentUnavailable, code)
	delete(f.files.denyRead, filepath.Join(f.repo, "config"))
	expectCode(t, OK, a.Reload(context.Background()))
	_, code = authorize(a)
	expectCode(t, OK, code)
}

// An explicit protected sha256 pin binds full signatures/trees/blobs;
// approval of a different 64-digit ID still refuses instead of following a ref.
func TestSHA256PinnedGit(t *testing.T) {
	f := newFixture(t)
	f.repo = filepath.Join(f.base, "registry-sha256.git")
	f.config.Registry = f.repo
	f.config.ObjectFormat = "sha256"
	f.run("/usr/bin/git", nil, "init", "--bare", "--quiet", "--object-format=sha256", f.repo)
	f.config.Revision = f.commit(f.valid(), "", true)
	if len(f.config.Revision) != 64 {
		t.Fatal("fixture did not create SHA-256 objects")
	}
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, OK, code)
	f.config.Revision = strings.Repeat("f", 64)
	f.writeConfig()
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	_, code = authorize(a)
	expectCode(t, EnrollmentUnverified, code)
}
