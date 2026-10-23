//go:build linux

package keymaker

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/relux-works/swarma-keymaker/internal/control"
)

// NewDaemonServer owns both listeners and one set of admission/work limits.
// Missing helper authority refuses independently of surface A.
func NewDaemonServer(socketDir string, e *Engine, cfg NativeConfig, gid uint32, verifier OperatorActVerifier) (*Server, error) {
	s, err := NewServer(socketDir, e, LinuxPeer{})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Server, error) { s.Close(); s.cleanup(); return nil, err }
	native, err := NewNative(e, cfg, verifier, s.requests)
	if err != nil {
		return fail(err)
	}
	wire, err := control.New(native, native, native, native, native)
	if err != nil {
		return fail(err)
	}
	listener, inode, device, err := createControlSocket(s.dir, gid)
	if err != nil {
		return fail(err)
	}
	s.native = native
	s.controlListener = listener
	s.controlWire = wire
	s.ControlPath = filepath.Join(socketDir, "control.sock")
	s.controlInode = inode
	s.controlDevice = device
	return s, nil
}

// Publish only after exact owner/group/mode verification. The initial bind is
// hidden behind a new 0700 directory, so umask cannot expose a temporary public
// control listener. Existing entries are never removed to make startup work.
func createControlSocket(dir *os.File, gid uint32) (*net.UnixListener, uint64, uint64, error) {
	anchor := fmt.Sprintf("/proc/self/fd/%d", dir.Fd())
	if _, err := os.Lstat(anchor + "/control.sock"); !os.IsNotExist(err) {
		return nil, 0, 0, failure("control socket already exists")
	}
	if err := syscall.Mkdirat(int(dir.Fd()), "control.stage", 0700); err != nil {
		return nil, 0, 0, failure("control staging unavailable")
	}
	fd, err := syscall.Openat(int(dir.Fd()), "control.stage", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, 0, failure("control staging unavailable")
	}
	stage := os.NewFile(uintptr(fd), "control staging")
	defer stage.Close()
	staged := fmt.Sprintf("/proc/self/fd/%d/control.sock", stage.Fd())
	var owned bool
	defer func() {
		if owned {
			syscall.Unlinkat(fd, "control.sock")
		}
		os.Remove(anchor + "/control.stage")
	}()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: staged, Net: "unix"})
	if err != nil {
		return nil, 0, 0, failure("control socket creation failed")
	}
	owned = true
	listener.SetUnlinkOnClose(false)
	fail := func() (*net.UnixListener, uint64, uint64, error) {
		listener.Close()
		return nil, 0, 0, failure("control socket permissions failed")
	}
	if syscall.Fchownat(fd, "control.sock", os.Getuid(), int(gid), 0x100 /* Linux AT_SYMLINK_NOFOLLOW */) != nil || syscall.Fchmodat(fd, "control.sock", 0660, 0) != nil {
		return fail()
	}
	st, err := os.Lstat(staged)
	if err != nil {
		return fail()
	}
	stat := st.Sys().(*syscall.Stat_t)
	if st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0660 || stat.Uid != uint32(os.Getuid()) || stat.Gid != gid {
		return fail()
	}
	if syscall.Renameat(fd, "control.sock", int(dir.Fd()), "control.sock") != nil {
		return fail()
	}
	owned = false
	if dir.Sync() != nil {
		listener.Close()
		syscall.Unlinkat(int(dir.Fd()), "control.sock")
		return nil, 0, 0, failure("control socket publication failed")
	}
	return listener, stat.Ino, uint64(stat.Dev), nil
}
