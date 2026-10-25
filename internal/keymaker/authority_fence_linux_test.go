//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type pc2FenceFixture struct {
	path   string
	dir    *os.File
	policy authorityFencePolicy
}

func pc2FenceSetup(t *testing.T) pc2FenceFixture {
	t.Helper()
	p := t.TempDir()
	if e := os.Chmod(p, 0750); e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"authority.lock", "package.lock"} {
		if e := os.WriteFile(filepath.Join(p, n), nil, 0640); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(filepath.Join(p, n), 0640); e != nil {
			t.Fatal(e)
		}
	}
	d, e := os.Open(p)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Close() })
	stat := func(p string) authorityFenceIdentity {
		var s unix.Stat_t
		if e := unix.Lstat(p, &s); e != nil {
			t.Fatal(e)
		}
		return authorityFenceIdentity{Device: uint64(s.Dev), Inode: s.Ino, UID: s.Uid, GID: s.Gid, Mode: s.Mode}
	}
	return pc2FenceFixture{p, d, authorityFencePolicy{Directory: stat(p), Authority: stat(filepath.Join(p, "authority.lock")), Package: stat(filepath.Join(p, "package.lock"))}}
}
func pc2FenceRefusal(t *testing.T, f pc2FenceFixture, claim, want string) {
	t.Helper()
	c, e := openAuthorityFence(f.dir, f.policy)
	if e == nil {
		defer c.Close()
		var l *authorityFenceLocked
		l, e = c.TryLock()
		if l != nil {
			l.Close()
		}
	}
	if e == nil {
		t.Fatalf("%s: admitted invalid fence", claim)
	}
	if authorityCode(e) != want {
		t.Fatalf("%s: expected %s, got %v", claim, want, e)
	}
}

// Real unprivileged files prove pinned identity, no creation and independent
// nonblocking flock admission. Foreign ownership/access is a separate window test.
func TestPC2FenceIdentity(t *testing.T) {
	if os.Getenv("KEYMAKER_PC2_FENCE_INHERITED") == "1" {
		pc2FenceInheritedChild(t)
		return
	}
	t.Run("real_inherited_ofd", pc2FenceInheritedProcess)
	for _, name := range []string{"missing", "symlink", "hardlink", "owner", "group", "mode", "device", "inode", "package_alias", "directory_mode", "directory_inode", "nonregular"} {
		t.Run(name, func(t *testing.T) {
			f := pc2FenceSetup(t)
			p := filepath.Join(f.path, "authority.lock")
			switch name {
			case "missing":
				if e := os.Remove(p); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(p, p+".real"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("authority.lock.real", p); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(p, p+".alias"); e != nil {
					t.Fatal(e)
				}
			case "owner":
				f.policy.Authority.UID++
			case "group":
				f.policy.Authority.GID++
			case "mode":
				if e := os.Chmod(p, 0660); e != nil {
					t.Fatal(e)
				}
			case "device":
				f.policy.Authority.Device++
			case "inode":
				f.policy.Authority.Inode++
			case "package_alias":
				f.policy.Package = f.policy.Authority
			case "directory_mode":
				if e := os.Chmod(f.path, 0770); e != nil {
					t.Fatal(e)
				}
			case "directory_inode":
				f.policy.Directory.Inode++
			case "nonregular":
				if e := os.Remove(p); e != nil {
					t.Fatal(e)
				}
				if e := unix.Mkfifo(p, 0640); e != nil {
					t.Fatal(e)
				}
			}
			want := "fence_identity"
			switch name {
			case "missing", "symlink":
				want = "fence_open"
			case "directory_mode", "directory_inode":
				want = "fence_directory"
			}
			pc2FenceRefusal(t, f, name, want)
			if name == "missing" {
				if _, e := os.Lstat(p); !os.IsNotExist(e) {
					t.Fatal("missing: fence was created")
				}
			}
		})
	}
	t.Run("replacement_after_open", func(t *testing.T) {
		f := pc2FenceSetup(t)
		c, e := openAuthorityFence(f.dir, f.policy)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		p := filepath.Join(f.path, "authority.lock")
		if e = os.Rename(p, p+".old"); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(p, nil, 0640); e != nil {
			t.Fatal(e)
		}
		if e = os.Chmod(p, 0640); e != nil {
			t.Fatal(e)
		}
		l, e := c.TryLock()
		if l != nil {
			l.Close()
		}
		if e == nil {
			t.Fatal("inode_swap: replacement admitted")
		}
		if authorityCode(e) != "fence_identity" {
			t.Fatalf("replacement identity refusal: %v", e)
		}
	})
	// Rechecking a terminal capability detects an object replaced after admission;
	// release closes the old OFD and does not act on the replacement object.
	t.Run("replacement_while_locked", func(t *testing.T) {
		f := pc2FenceSetup(t)
		c, e := openAuthorityFence(f.dir, f.policy)
		if e != nil {
			t.Fatal(e)
		}
		l, e := c.TryLock()
		if e != nil {
			c.Close()
			t.Fatal(e)
		}
		defer l.Close()
		p := filepath.Join(f.path, "authority.lock")
		if e = os.Rename(p, p+".old"); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(p, nil, 0640); e != nil {
			t.Fatal(e)
		}
		if e = l.Check(); authorityCode(e) != "fence_identity" {
			t.Fatalf("terminal identity replacement: %v", e)
		}
	})
	t.Run("distinct_ofd", func(t *testing.T) {
		f := pc2FenceSetup(t)
		c, e := openAuthorityFence(f.dir, f.policy)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		flags, e := unix.FcntlInt(c.file.Fd(), unix.F_GETFL, 0)
		if e != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_NONBLOCK == 0 {
			t.Fatal("read-only nonblocking open", flags, e)
		}
		flags, e = unix.FcntlInt(c.file.Fd(), unix.F_GETFD, 0)
		if e != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("CLOEXEC", flags, e)
		}
		l, e := c.TryLock()
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		if e = c.Close(); authorityCode(e) != "fence_consumed" {
			t.Fatal("candidate released terminal lock", e)
		}
		pc2FenceRefusal(t, f, "independent_contender", "fence_busy")
		if e = l.Check(); e != nil {
			t.Fatal(e)
		}
		copied := *l
		if e = copied.Close(); e == nil {
			t.Fatal("copied terminal capability unlocked original")
		}
		pc2FenceRefusal(t, f, "copied_holder_still_locked", "fence_busy")
		if e = l.Close(); e != nil {
			t.Fatal(e)
		}
		fresh, e := openAuthorityFence(f.dir, f.policy)
		if e != nil {
			t.Fatal(e)
		}
		defer fresh.Close()
		next, e := fresh.TryLock()
		if e != nil {
			t.Fatal("fresh valid fence after refusal", e)
		}
		next.Close()
	})
	// Ownership seals reject copies, descriptor substitution and a foreign creator
	// process without granting those objects the right to close the original OFD.
	for _, name := range []string{"copied", "duplicated", "foreign_process"} {
		t.Run(name, func(t *testing.T) {
			f := pc2FenceSetup(t)
			c, e := openAuthorityFence(f.dir, f.policy)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			copy := *c
			switch name {
			case "duplicated":
				fd, e := unix.Dup(int(c.file.Fd()))
				if e != nil {
					t.Fatal(e)
				}
				dup := os.NewFile(uintptr(fd), "dup")
				defer dup.Close()
				copy.self = &copy
				copy.file = dup
			case "foreign_process":
				copy.self = &copy
				copy.pid--
			}
			if l, e := copy.TryLock(); authorityCode(e) != "fence_provenance" {
				if l != nil {
					l.Close()
				}
				t.Fatalf("%s OFD: expected fence_provenance, got %v", name, e)
			}
			l, e := c.TryLock()
			if e != nil {
				t.Fatal("invalid copy damaged original", e)
			}
			l.Close()
		})
	}
}

// Explicit test-only ExtraFiles inheritance demonstrates that a child cannot
// adopt an inherited lock OFD or unlock its parent by releasing its own copies.
// Ordinary opens remain CLOEXEC; production has no descriptor adoption API.
func pc2FenceInheritedProcess(t *testing.T) {
	f := pc2FenceSetup(t)
	c, e := openAuthorityFence(f.dir, f.policy)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	l, e := c.TryLock()
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	raw, e := json.Marshal(f.policy)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPC2FenceIdentity$", "-test.timeout=8s")
	cmd.ExtraFiles = []*os.File{c.file, c.dir}
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "KEYMAKER_PC2_FENCE_INHERITED=1", "KEYMAKER_PC2_FENCE_PARENT=" + strconv.Itoa(os.Getpid()), "KEYMAKER_PC2_FENCE_POLICY=" + string(raw)}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	t.Logf("inherited OFD test child pid=%d", cmd.Process.Pid)
	if e = cmd.Wait(); e != nil {
		t.Fatalf("inherited OFD child: %v %s", e, output.Bytes())
	}
	pc2FenceRefusal(t, f, "parent_lock_survives_child", "fence_busy")
}
func pc2FenceInheritedChild(t *testing.T) {
	var policy authorityFencePolicy
	if e := json.Unmarshal([]byte(os.Getenv("KEYMAKER_PC2_FENCE_POLICY")), &policy); e != nil {
		t.Fatal(e)
	}
	pid, e := strconv.Atoi(os.Getenv("KEYMAKER_PC2_FENCE_PARENT"))
	if e != nil || pid == os.Getpid() {
		t.Fatal("invalid parent process")
	}
	file := os.NewFile(3, "inherited-fence")
	defer file.Close()
	dir := os.NewFile(4, "inherited-anchor")
	defer dir.Close()
	c := &authorityFenceCandidate{file: file, issued: file, dir: dir, fd: file.Fd(), pid: pid, policy: policy}
	c.self = c
	if l, e := c.TryLock(); authorityCode(e) != "fence_provenance" {
		if l != nil {
			l.Close()
		}
		t.Fatalf("inherited provenance: %v", e)
	}
	fresh, e := openAuthorityFence(dir, policy)
	if e != nil {
		t.Fatal(e)
	}
	defer fresh.Close()
	if l, e := fresh.TryLock(); authorityCode(e) != "fence_busy" {
		if l != nil {
			l.Close()
		}
		t.Fatalf("inherited independent OFD contention: %v", e)
	}
}
