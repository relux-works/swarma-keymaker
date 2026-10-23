package main

import (
	"crypto/rand"
	"errors"
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
func startConfined(cmd *exec.Cmd, root *os.File, exceptions ...*os.File) error {
	var extra []int
	for _, file := range exceptions {
		extra = append(extra, int(file.Fd()))
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		err := restrictWrites(int(root.Fd()), extra...)
		if err == nil {
			err = cmd.Start()
		}
		result <- err
	}()
	return <-result
}
func restrictWrites(fd int, exceptions ...int) error {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 || abi < 3 {
		return fmt.Errorf("write confinement unavailable")
	}
	rights := uint64(unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK | unix.LANDLOCK_ACCESS_FS_MAKE_SYM | unix.LANDLOCK_ACCESS_FS_REFER | unix.LANDLOCK_ACCESS_FS_TRUNCATE)
	handled := rights
	if len(exceptions) != 0 {
		handled |= unix.LANDLOCK_ACCESS_FS_READ_FILE
	}
	attr := struct{ Access uint64 }{handled}
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
	// The Git-only device rule handles READ_FILE. Preserve the write-only
	// sandbox's existing unrestricted read access with a filesystem-root read rule.
	if len(exceptions) != 0 {
		readRoot, err := openNoLinks("/", unix.O_PATH|unix.O_DIRECTORY, 0)
		if err != nil {
			return err
		}
		defer readRoot.Close()
		path.Access = unix.LANDLOCK_ACCESS_FS_READ_FILE
		path.Parent = int32(readRoot.Fd())
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, rules, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&path)), 0, 0, 0)
		if errno != 0 {
			return errno
		}
	}
	// Git 2.53 otherwise fails: "could not open '/dev/null' for reading and
	// writing: Permission denied". The owner authorizes this Git-only exception
	// on a pinned, verified device, without truncate/create/remove/rename rights.
	for _, exception := range exceptions {
		path.Access = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE
		path.Parent = int32(exception)
		_, _, errno = unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, rules, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&path)), 0, 0, 0)
		if errno != 0 {
			return errno
		}
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
func runConfined(cmd *exec.Cmd, root *os.File, exceptions ...*os.File) error {
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
	if err := startConfined(cmd, root, exceptions...); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "release child pid=%d\n", cmd.Process.Pid)
	return cmd.Wait()
}

func validNullStat(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFCHR && st.Rdev == unix.Mkdev(1, 3)
}
func openNullDevice(name string) (*os.File, error) {
	file, err := openNoLinks(name, unix.O_PATH, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if unix.Fstat(int(file.Fd()), &st) != nil || !validNullStat(st) {
		file.Close()
		return nil, fmt.Errorf("null device verification failed")
	}
	return file, nil
}

// Refuse parent directories in which another uid can replace our entries.
func verifyParent(parent *os.Root) error {
	f, err := parent.Open(".")
	if err != nil {
		return errTarget
	}
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil {
		return errTarget
	}
	if st.Mode&0022 != 0 && !(st.Mode&unix.S_ISVTX != 0 && (st.Uid == uint32(os.Geteuid()) || st.Uid == 0)) {
		return errTarget
	}
	return nil
}

func verifyAdoptedRoot(f *os.File) error {
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil {
		return errTarget
	}
	if !validRootStat(st) {
		return errTarget
	}
	entries, err := f.ReadDir(1)
	if err != nil && err != io.EOF || len(entries) != 0 {
		return errTarget
	}
	return nil
}
func validRootStat(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == uint32(os.Geteuid()) && st.Mode&07777 == 0700
}
func createTarget(parent *os.Root, name string) (*os.Root, error) {
	if name != filepath.Base(name) || verifyParent(parent) != nil {
		return nil, errTarget
	}
	if err := parent.Mkdir(name, 0700); err != nil {
		return nil, errTarget
	}
	return adoptTarget(parent, name)
}
func adoptTarget(parent *os.Root, name string) (*os.Root, error) {
	f, err := openRootFile(parent, name, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, errTarget
	}
	defer f.Close()
	if err := verifyAdoptedRoot(f); err != nil {
		return nil, err
	}
	return rootFromFile(f)
}

// Only an exclusively created object is entered, using its creation handle and
// the exact parent handle used for that creation. Never discover ownership by
// enumerating a directory after a child has run.
type createdObject struct {
	object    *os.File
	parent    *os.File
	name      string
	dev       uint64
	ino       uint64
	directory bool
}
type createdObjects struct{ entries []createdObject }

func (c *createdObjects) remember(parent, file *os.File, name string) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		return err
	}
	dup, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return err
	}
	c.entries = append(c.entries, createdObject{os.NewFile(uintptr(dup), name), parent, name, uint64(st.Dev), st.Ino, st.Mode&unix.S_IFMT == unix.S_IFDIR})
	return nil
}
func (c *createdObjects) createFile(root *os.Root, name string, mode os.FileMode) (*os.File, error) {
	parent, err := openRootFile(root, filepath.Dir(name), unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat2(int(parent.Fd()), filepath.Base(name), &unix.OpenHow{Flags: unix.O_CREAT | unix.O_EXCL | unix.O_WRONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW, Mode: uint64(mode), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		parent.Close()
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if err := c.remember(parent, file, filepath.Base(name)); err != nil {
		parent.Close()
		file.Close()
		return nil, err
	}
	return file, nil
}
func (c *createdObjects) writeFile(root *os.Root, name string, body []byte, mode os.FileMode) error {
	file, err := c.createFile(root, name, mode)
	if err != nil {
		return err
	}
	_, err = file.Write(body)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
func (c *createdObjects) close() {
	for _, e := range c.entries {
		e.parent.Close()
		e.object.Close()
	}
	c.entries = nil
}
func (c *createdObjects) cleanup(root *os.Root) error {
	var result error
	for i := len(c.entries) - 1; i >= 0; i-- {
		e := c.entries[i]
		var st unix.Stat_t
		err := unix.Fstatat(int(e.parent.Fd()), e.name, &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == unix.ENOENT {
			continue
		}
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if uint64(st.Dev) != e.dev || st.Ino != e.ino {
			continue
		}
		flags := 0
		if e.directory {
			flags = unix.AT_REMOVEDIR
		}
		// unlinkat of a directory is deliberately nonrecursive: unknown entries stay.
		if err := unix.Unlinkat(int(e.parent.Fd()), e.name, flags); err != nil && err != unix.ENOTEMPTY && err != unix.EEXIST {
			result = errors.Join(result, err)
		}
	}
	return result
}

// Private child scratch is outside the release target. Child-created objects
// have no parent-side creation handle and are NEVER claimed by the ledger.
// If a child leaves files, retain the scratch directory and report its path.
func privateScratch(prefix string) (*os.Root, string, func(), error) {
	base, err := filepath.Abs(os.TempDir())
	if err != nil {
		return nil, "", nil, err
	}
	parent, err := openRootNoLinks(base)
	if err != nil {
		return nil, "", nil, err
	}
	if err = verifyParent(parent); err != nil {
		parent.Close()
		return nil, "", nil, err
	}
	var leaf string
	for i := 0; i < 10; i++ {
		var nonce [16]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			parent.Close()
			return nil, "", nil, err
		}
		leaf = prefix + fmt.Sprintf("%x", nonce[:])
		err = parent.Mkdir(leaf, 0700)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			parent.Close()
			return nil, "", nil, err
		}
	}
	if err != nil {
		parent.Close()
		return nil, "", nil, err
	}
	name := filepath.Join(base, leaf)
	root, err := adoptTarget(parent, filepath.Base(name))
	if err != nil {
		parent.Close()
		return nil, "", nil, err
	}
	anchor, err := root.Open(".")
	if err != nil {
		root.Close()
		parent.Close()
		return nil, "", nil, err
	}
	var st unix.Stat_t
	err = unix.Fstat(int(anchor.Fd()), &st)
	if err != nil {
		anchor.Close()
		root.Close()
		parent.Close()
		return nil, "", nil, err
	}
	cleanup := func() {
		defer anchor.Close()
		root.Close()
		var now unix.Stat_t
		dir, e := parent.Open(".")
		if e == nil {
			if unix.Fstatat(int(dir.Fd()), filepath.Base(name), &now, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Dev == now.Dev && st.Ino == now.Ino {
				if e := unix.Unlinkat(int(dir.Fd()), filepath.Base(name), unix.AT_REMOVEDIR); e != nil {
					fmt.Fprintf(os.Stderr, "retained private scratch: %s\n", name)
				}
			}
			dir.Close()
		}
		parent.Close()
	}
	return root, name, cleanup, nil
}

// Unlike MkdirAll, this refuses symlinks in every existing directory component.
func mkdirRootAll(root *os.Root, name string, ledgers ...*createdObjects) error {
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
		created := true
		if err := unix.Mkdirat(int(dir.Fd()), part, 0700); err != nil {
			if err != unix.EEXIST {
				return err
			}
			created = false
		}
		fd, err := unix.Openat2(int(dir.Fd()), part, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
		if err != nil {
			return err
		}

		next := os.NewFile(uintptr(fd), part)
		if created {
			if err := verifyAdoptedRoot(next); err != nil {
				next.Close()
				return err
			}
			if len(ledgers) > 0 {
				dup, err := unix.FcntlInt(dir.Fd(), unix.F_DUPFD_CLOEXEC, 0)
				if err != nil {
					next.Close()
					return err
				}
				parent := os.NewFile(uintptr(dup), part)
				if err := ledgers[0].remember(parent, next, part); err != nil {
					parent.Close()
					next.Close()
					return err
				}
			}
		}
		dir.Close()
		dir = next
	}
	return nil
}
