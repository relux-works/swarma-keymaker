//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Claim: all four commands refuse root effective UID and unequal real/effective UIDs before any filesystem effect, beside the same valid invocation.
func TestJ7OperatorProcessIdentity(t *testing.T) {
	for _, command := range []string{J7OperatorSeedInit, J7OperatorMigrate, J7OperatorPolicyPublish, J7OperatorHead} {
		for _, kind := range []string{"root", "real-root", "real-different"} {
			t.Run(command+"/"+kind, func(t *testing.T) {
				stage := "schema5"
				if command == J7OperatorMigrate {
					stage = "legacy"
				}
				f := j7OperatorSetup(t, stage)
				req := f.request(command)
				deps := j7OperatorFixtureDeps()
				ruid, euid := f.uid+1, f.uid
				if kind == "root" {
					ruid, euid, req.ServiceUID = 0, 0, 0
				}
				if kind == "real-root" {
					ruid = 0
				}
				deps.identity = func() (uint32, uint32) { return ruid, euid }
				before := j7OperatorTree(t, f.root)
				result := runJ7Operator(t.Context(), req, deps)
				if result.Outcome != "refused" || result.Refusal != "role_not_permitted" || result.Detail != "command runs only as the service user" || before != j7OperatorTree(t, f.root) {
					t.Fatal("identity refusal had effects or wrong code", result)
				}
				result = runJ7Operator(t.Context(), f.request(command), j7OperatorFixtureDeps())
				if result.Outcome != "ok" {
					t.Fatal("valid service identity refused", result)
				}
			})
		}
	}
}

// Claim: publish cannot replace seed, head, snapshot, symlink or foreign-policy targets; no bytes/head/audit change, while an absent or matching-policy target publishes.
func TestJ7OperatorPolicyTarget(t *testing.T) {
	for _, kind := range []string{"seed", "head", "snapshot", "symlink", "foreign-policy", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			f := j7OperatorSetup(t, "schema5")
			req := f.request(J7OperatorPolicyPublish)
			switch kind {
			case "seed":
				if err := InitializeJ7Seed(req.PolicyFile, f.uid, j7RequestRole, j7OperatorInstance); err != nil {
					t.Fatal(err)
				}
			case "head":
				os.WriteFile(req.PolicyFile, []byte("{\"expected_version\":7,\"expected_digest\":\"example\"}\n"), 0600)
			case "snapshot":
				raw, err := os.ReadFile(filepath.Join(f.state, "bindings.json"))
				if err != nil {
					t.Fatal(err)
				}
				os.WriteFile(req.PolicyFile, raw, 0600)
			case "symlink":
				if os.Symlink(f.input, req.PolicyFile) != nil {
					t.Fatal("target symlink")
				}
			case "foreign-policy":
				table := f.table(1)
				table.Identity++
				os.WriteFile(req.PolicyFile, j7PolicyRaw(t, table), 0600)
			case "malformed":
				os.WriteFile(req.PolicyFile, []byte("{}"), 0600)
			}
			before := j7OperatorTree(t, f.root)
			result := runJ7Operator(t.Context(), req, j7OperatorFixtureDeps())
			if result.Refusal != "j7_policy_target_invalid" || result.Outcome != "refused" || before != j7OperatorTree(t, f.root) {
				t.Fatal("non-policy target changed or wrong refusal", result)
			}
			if os.Remove(req.PolicyFile) != nil {
				t.Fatal("remove planted target")
			}
			result = runJ7Operator(t.Context(), req, j7OperatorFixtureDeps())
			if result.Outcome != "ok" {
				t.Fatal("absent target refused", result)
			}
			// The next version is allowed to replace a proven policy table.
			req.ExpectedVersion, req.ExpectedDigest = result.Version, result.Digest
			os.WriteFile(req.PolicyInput, j7PolicyRaw(t, f.table(2)), 0600)
			result = runJ7Operator(t.Context(), req, j7OperatorFixtureDeps())
			if result.Outcome != "ok" {
				t.Fatal("policy table replacement refused", result)
			}
		})
	}
}

// Claim: duplicate opened directory inodes refuse even when supplied as separate descriptors, and the production startup refuses before key or state changes.
func TestJ7ServiceDirectoryIdentity(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	a, err := os.Open(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := os.Open(f.statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if j7DistinctDirectoryIDs([]*os.File{a, b}) {
		t.Fatal("same directory inode admitted")
	}
	other, err := os.Open(f.policyDir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if !j7DistinctDirectoryIDs([]*os.File{a, other}) {
		t.Fatal("distinct directory inodes refused")
	}
	before := recoveryFiles(t, f.statePath)
	saved := f.cfg.J7Policy.Path
	f.cfg.J7Policy.Path = filepath.Join(f.statePath, "table.json")
	status := &j7ServiceStatus{}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	// Enter below the lexical step to isolate descriptor identity, as a
	// bind-mount alias would do without requiring a privileged mount fixture.
	if err := startJ7Request(ctx, f.cfg, f.static, status, f.deps); err != Code("j7_configuration_conflict") || f.trace.count("key") != 0 || status.String() != "" || !reflect.DeepEqual(before, recoveryFiles(t, f.statePath)) {
		t.Fatal("directory identity refusal", err)
	}
	f.cfg.J7Policy.Path = saved
	f.serves(t)
}

func j7FollowupACL(permission byte) []byte {
	return []byte{2, 0, 0, 0, 1, 0, 6, 0, 255, 255, 255, 255, 2, 0, permission, 0, 1, 0, 0, 0, 4, 0, permission, 0, 255, 255, 255, 255, 16, 0, permission, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255}
}

// Claim: a socket-directory default ACL refuses publication with no socket/state/audit effect; removing it permits the same service to start.
func TestJ7ServiceSocketDefaultACL(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	if err := unix.Setxattr(f.socketDir, "system.posix_acl_default", j7FollowupACL(6), 0); err != nil {
		t.Fatal(err)
	}
	f.refuses(t, "keymaker: unsafe socket directory ACL", j7ServiceRefusal{keyGate: true})
	if err := unix.Removexattr(f.socketDir, "system.posix_acl_default"); err != nil {
		t.Fatal(err)
	}
	f.serves(t)
}

// Claim: the shared native socket constructor refuses an inherited ACL before publication without leaving entries; removing the ACL permits exactly the normal socket.
func TestJ7SocketPrepublicationACL(t *testing.T) {
	path := t.TempDir()
	if os.Chmod(path, 0755) != nil {
		t.Fatal("socket fixture mode")
	}
	dir, err := OpenDirectory(path, uint32(os.Getuid()), 0755)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if err := unix.Setxattr(path, "system.posix_acl_default", j7FollowupACL(6), 0); err != nil {
		t.Fatal(err)
	}
	listener, _, _, err := createControlSocket(dir, uint32(os.Getgid()))
	if listener != nil {
		listener.Close()
	}
	if err == nil || err.Error() != "keymaker: unsafe socket directory ACL" || listener != nil || len(j7ServiceListing(t, path)) != 0 {
		t.Fatal("ACL socket publication was not refused", err)
	}
	if err := unix.Removexattr(path, "system.posix_acl_default"); err != nil {
		t.Fatal(err)
	}
	listener, _, _, err = createControlSocket(dir, uint32(os.Getgid()))
	if err != nil || listener == nil {
		t.Fatal("no-ACL socket refused", err)
	}
	listener.Close()
	if unix.Unlinkat(int(dir.Fd()), "control.sock", 0) != nil {
		t.Fatal("owned socket cleanup")
	}
}

// Claim: an extended ACL on a mode-0660 published socket refuses final admission, removes only its inode and leaves state/head/audit unchanged; the no-ACL constructor serves.
func TestJ7ServiceSocketAccessACL(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	before := recoveryFiles(t, f.statePath)
	head, _ := os.ReadFile(f.headFile)
	good := f.deps.listen
	f.deps.listen = func(dir *os.File, gid uint32) (*net.UnixListener, uint64, uint64, error) {
		l, i, d, err := good(dir, gid)
		if err == nil {
			if e := unix.Setxattr(fmt.Sprintf("/proc/self/fd/%d/control.sock", dir.Fd()), "system.posix_acl_access", j7FollowupACL(6), 0); e != nil {
				t.Fatal(e)
			}
		}
		return l, i, d, err
	}
	status := &j7ServiceStatus{}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if err := serveJ7Request(ctx, f.cfg, f.static, status, f.deps); err == nil || err.Error() != "keymaker: unsafe control socket" || status.String() != "" {
		t.Fatal("socket ACL admitted", err)
	}
	if _, err := os.Lstat(f.socketPath()); !os.IsNotExist(err) {
		t.Fatal("ACL socket retained")
	}
	after, _ := os.ReadFile(f.headFile)
	if !bytes.Equal(head, after) || !reflect.DeepEqual(before, recoveryFiles(t, f.statePath)) {
		t.Fatal("socket ACL refusal changed custody")
	}
	f.deps.listen = good
	f.serves(t)
}

// Claim: an unexpected accept failure is returned to the caller rather than a silent clean stop; ordinary cancellation remains a clean stop and the directory restarts.
func TestJ7ServiceAcceptError(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	socket, err := openJ7Socket(f.socketDir, f.uid, uint32(os.Getgid()), createControlSocket)
	if err != nil {
		t.Fatal(err)
	}
	socket.listener.Close() // not socket.stop: simulate an unexpected accept failure
	if err := socket.serve(t.Context(), nil, newJ7Latch(), nil); err == nil || err.Error() != "keymaker: accept failed" {
		t.Fatal("silent accept failure", err)
	}
	socket.remove()
	f.serves(t)
}
