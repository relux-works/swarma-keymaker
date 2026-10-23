package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Resolve every component without following links, then keep the opened inode.
func openNoLinks(name string, flags int, mode os.FileMode) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW), Mode: uint64(mode), Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func rootFromFile(file *os.File) (*os.Root, error) {
	return os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
}
func openRootNoLinks(name string) (*os.Root, error) {
	f, err := openNoLinks(name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return rootFromFile(f)
}
func openRootFile(root *os.Root, name string, flags int, mode os.FileMode) (*os.File, error) {
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat2(int(dir.Fd()), name, &unix.OpenHow{Flags: uint64(flags | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_NONBLOCK), Mode: uint64(mode), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}
func writeRootFile(root *os.Root, name string, body []byte, mode os.FileMode) error {
	f, err := openRootFile(root, name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func readRootFile(root *os.Root, name string) ([]byte, error) {
	f, err := openRootFile(root, name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errInput
	}
	return io.ReadAll(f)
}

// External Go tools cannot use os.Root. Restrict their filesystem writes in
// the kernel as well as passing the pinned target descriptor. ABI 3 is needed
// for TRUNCATE; unsupported/disabled Landlock refuses before starting the child.
// The restriction is thread-local and inherited by fork/exec. The dedicated
// locked goroutine exits without unlocking, so Go destroys its restricted thread.
func startConfined(cmd *exec.Cmd, root *os.File) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		err := restrictWrites(int(root.Fd()))
		if err == nil {
			err = cmd.Start()
		}
		result <- err
	}()
	return <-result
}
func restrictWrites(fd int) error {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 3 {
		return fmt.Errorf("write confinement unavailable")
	}
	rights := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK | unix.LANDLOCK_ACCESS_FS_MAKE_SYM | unix.LANDLOCK_ACCESS_FS_REFER | unix.LANDLOCK_ACCESS_FS_TRUNCATE)
	attr := struct{ Access uint64 }{rights}
	rules, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return errno
	}
	defer unix.Close(int(rules))
	// The kernel path-beneath ABI is packed: uint64 access followed by int32 fd.
	path := struct {
		Access uint64
		Parent int32
		_      uint32
	}{rights, int32(fd), 0}
	_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, rules, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&path)), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	_, _, errno = unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, rules, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
func runConfined(cmd *exec.Cmd, root *os.File) error {
	// Pre-open default child stdio before the confined thread starts it.
	sink, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer sink.Close()
	if cmd.Stdin == nil {
		cmd.Stdin = sink
	}
	if cmd.Stdout == nil {
		cmd.Stdout = sink
	}
	if cmd.Stderr == nil {
		cmd.Stderr = sink
	}
	if err := startConfined(cmd, root); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "release child pid=%d\n", cmd.Process.Pid)
	return cmd.Wait()
}
func createTarget(parent *os.Root, name string) (*os.Root, error) {
	if name != filepath.Base(name) {
		return nil, errTarget
	}
	if err := parent.Mkdir(name, 0700); err != nil {
		return nil, errTarget
	}
	f, err := openRootFile(parent, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, errTarget
	}
	defer f.Close()
	return rootFromFile(f)
}

// Unlike MkdirAll, this refuses symlinks in every existing directory component.
func mkdirRootAll(root *os.Root, name string) error {
	if name == "." {
		return nil
	}
	if filepath.IsAbs(name) || filepath.Clean(name) != name {
		return errTarget
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { dir.Close() }()
	for _, part := range strings.Split(name, string(filepath.Separator)) {
		if part == ".." || part == "" {
			return errTarget
		}
		if err := unix.Mkdirat(int(dir.Fd()), part, 0700); err != nil && err != unix.EEXIST {
			return err
		}
		fd, err := unix.Openat2(int(dir.Fd()), part, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
		if err != nil {
			return err
		}
		dir.Close()
		dir = os.NewFile(uintptr(fd), part)
	}
	return nil
}

func cleanupRoot(root *os.Root) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(-1)
	closeErr := dir.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for _, entry := range entries {
		if err := root.RemoveAll(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}
