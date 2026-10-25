//go:build linux

package keymaker

import (
	"os"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// Identities are prepared outside F_auth against the protected deployment
// manifest. Production pins root ownership, directory 0750 and file 0640.
// The primitive accepts an explicit owner so unprivileged fixtures need no root.
// No serving path calls this primitive in S2a.
type authorityFenceIdentity struct {
	Device, Inode  uint64
	UID, GID, Mode uint32
}
type authorityFencePolicy struct{ Directory, Authority, Package authorityFenceIdentity }

type authorityFenceCandidate struct {
	self              *authorityFenceCandidate
	file, issued, dir *os.File
	fd                uintptr
	pid               int
	policy            authorityFencePolicy
	state             uint32 // fresh -> consumed; a candidate is one transaction only
}

// A terminal capability has no FD accessor, callback, Store, provider, or other
// lock acquisition. Only bounded identity checks and release are available.
type authorityFenceLocked struct {
	self   *authorityFenceLocked
	source *authorityFenceCandidate
	closed uint32
}

func authorityFenceMatches(s *unix.Stat_t, p authorityFenceIdentity, directory bool) bool {
	kind := uint32(unix.S_IFREG)
	mode := uint32(0640)
	if directory {
		kind = unix.S_IFDIR
		mode = 0750
	}
	return s.Mode == kind|mode && p.Mode == kind|mode && s.Uid == p.UID && s.Gid == p.GID && uint64(s.Dev) == p.Device && s.Ino == p.Inode && p.Inode != 0 && (directory || s.Nlink == 1)
}
func authorityFenceAlias(a, b authorityFenceIdentity) bool {
	return a.Device == b.Device && a.Inode == b.Inode
}
func openAuthorityFence(dir *os.File, p authorityFencePolicy) (*authorityFenceCandidate, error) {
	if dir == nil || p.Package.Inode == 0 || authorityFenceAlias(p.Authority, p.Package) {
		return nil, authorityFail("fence_identity")
	}
	var s unix.Stat_t
	if e := unix.Fstat(int(dir.Fd()), &s); e != nil || !authorityFenceMatches(&s, p.Directory, true) {
		return nil, authorityFail("fence_directory")
	}
	// Own a separate directory anchor; never rely on a caller's later FD reuse.
	d, e := unix.Openat(int(dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		return nil, authorityFail("fence_directory")
	}
	anchor := os.NewFile(uintptr(d), "authority-directory")
	fd, e := unix.Openat(d, "authority.lock", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if e != nil {
		anchor.Close()
		return nil, authorityFail("fence_open")
	}
	file := os.NewFile(uintptr(fd), "authority.lock")
	c := &authorityFenceCandidate{file: file, issued: file, dir: anchor, fd: uintptr(fd), pid: os.Getpid(), policy: p}
	c.self = c
	if e = c.check(); e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}
func (c *authorityFenceCandidate) owned() bool {
	return c != nil && c.self == c && c.pid == os.Getpid() && c.file != nil && c.file == c.issued && c.file.Fd() == c.fd
}
func (c *authorityFenceCandidate) check() error {
	if !c.owned() {
		return authorityFail("fence_provenance")
	}
	var d, s, path unix.Stat_t
	if unix.Fstat(int(c.dir.Fd()), &d) != nil || !authorityFenceMatches(&d, c.policy.Directory, true) || unix.Fstat(int(c.fd), &s) != nil || !authorityFenceMatches(&s, c.policy.Authority, false) || unix.Fstatat(int(c.dir.Fd()), "authority.lock", &path, unix.AT_SYMLINK_NOFOLLOW) != nil || !authorityFenceMatches(&path, c.policy.Authority, false) || authorityFenceAlias(c.policy.Authority, c.policy.Package) {
		return authorityFail("fence_identity")
	}
	return nil
}
func (c *authorityFenceCandidate) TryLock() (*authorityFenceLocked, error) {
	if !c.owned() {
		return nil, authorityFail("fence_provenance")
	}
	if !atomic.CompareAndSwapUint32(&c.state, 0, 1) {
		return nil, authorityFail("fence_consumed")
	}
	refuse := func(e error) (*authorityFenceLocked, error) { c.closeOwned(); return nil, e }
	if e := c.check(); e != nil {
		return refuse(e)
	}
	if e := unix.Flock(int(c.fd), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return refuse(authorityFail("fence_busy"))
	}
	if e := c.check(); e != nil {
		return refuse(e)
	}
	l := &authorityFenceLocked{source: c}
	l.self = l
	return l, nil
}
func (c *authorityFenceCandidate) closeOwned() error {
	e := c.file.Close()
	d := c.dir.Close()
	if e != nil {
		return e
	}
	return d
}
func (c *authorityFenceCandidate) Close() error {
	if !c.owned() {
		return authorityFail("fence_provenance")
	}
	if !atomic.CompareAndSwapUint32(&c.state, 0, 1) {
		return authorityFail("fence_consumed")
	}
	return c.closeOwned()
}
func (l *authorityFenceLocked) Check() error {
	if l == nil || l.self != l || atomic.LoadUint32(&l.closed) != 0 || !l.source.owned() {
		return authorityFail("fence_provenance")
	}
	return l.source.check()
}
func (l *authorityFenceLocked) Close() error {
	if l == nil || l.self != l || !l.source.owned() {
		return authorityFail("fence_provenance")
	}
	if !atomic.CompareAndSwapUint32(&l.closed, 0, 1) {
		return authorityFail("fence_consumed")
	}
	// Closing our sole owned OFD releases flock; no descriptor is exported.
	return l.source.closeOwned()
}
