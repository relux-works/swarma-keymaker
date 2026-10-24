//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
)

type Peer struct {
	UID uint32
	GID uint32
	PID int32
}
type PeerSource interface {
	Credentials(*net.UnixConn) (Peer, Code)
}
type LinuxPeer struct{}

func (LinuxPeer) Credentials(c *net.UnixConn) (Peer, Code) {
	return kernelPeer(c)
}
func kernelPeer(c net.Conn) (Peer, Code) {
	source, ok := c.(syscall.Conn)
	if !ok {
		return Peer{}, "peer_identity_unavailable"
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return Peer{}, "peer_identity_unavailable"
	}
	var cred *syscall.Ucred
	var inner error
	err = raw.Control(func(fd uintptr) {
		cred, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil || inner != nil || cred == nil {
		return Peer{}, "peer_identity_unavailable"
	}
	return Peer{UID: cred.Uid, GID: cred.Gid, PID: cred.Pid}, ""
}

// OpenDirectory walks descriptors without following symlinks. The final directory
// must have exact owner/mode. Callers retain the fd across all relative file work.
func OpenDirectory(path string, uid uint32, mode uint32) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, failure("unsafe directory")
	}
	fd, err := syscall.Open("/", syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, failure("directory unavailable")
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, e := syscall.Openat(fd, part, syscall.O_DIRECTORY|syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if e != nil {
			return nil, failure("unsafe directory")
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), path)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&07777 != mode {
		f.Close()
		return nil, failure("unsafe directory ownership or mode")
	}
	return f, nil
}
func openRelative(dir *os.File, name string, flags int, uid uint32, mode uint32) (*os.File, error) {
	if name == "" || filepath.Base(name) != name {
		return nil, failure("invalid filename")
	}
	fd, err := syscall.Openat(int(dir.Fd()), name, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, mode)
	if err != nil {
		return nil, failure("protected file unavailable")
	}
	f := os.NewFile(uintptr(fd), name)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uid || st.Mode&07777 != mode || st.Nlink != 1 {
		f.Close()
		return nil, failure("unsafe protected file")
	}
	return f, nil
}

func LoadMaster(path string, uid uint32) (*Master, error) {
	dir, err := OpenDirectory(filepath.Dir(path), uid, 0700)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	f, err := openRelative(dir, filepath.Base(path), syscall.O_RDONLY, uid, 0600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return nil, failure("secure allocation unavailable")
	}
	m := &Master{seed: b[:32], mapped: true}
	m.locked = syscall.Mlock(b) == nil
	// MADV_DONTDUMP excludes this allocation even if an unrelated component enables dumps.
	if syscall.Madvise(b, 16 /* Linux MADV_DONTDUMP */) != nil {
		m.Close()
		return nil, failure("dump exclusion unavailable")
	}
	n, e := io.ReadFull(f, m.seed)
	var extra [1]byte
	more, eof := f.Read(extra[:])
	if n != 32 || e != nil || more != 0 || eof != io.EOF {
		m.Close()
		return nil, failure("invalid master file length")
	}
	return m, nil
}
func (m *Master) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	if m.mapped {
		b := m.seed[:4096]
		erase(b)
		if m.locked {
			syscall.Munlock(b)
		}
		m.seed = nil
		return syscall.Munmap(b)
	}
	erase(m.seed)
	m.seed = nil
	return nil
}

func HardenProcess() error {
	if syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}) != nil {
		return failure("cannot disable core dumps")
	}
	_, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, 4, 0, 0, 0, 0, 0) // PR_SET_DUMPABLE=0.
	if e != 0 {
		return failure("cannot disable diagnostic dumps")
	}
	var limit syscall.Rlimit
	if syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit) != nil {
		return failure("cannot read descriptor limit")
	}
	if limit.Cur > 512 {
		limit.Cur = 512
		if syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit) != nil {
			return failure("cannot bound descriptors")
		}
	}
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(256 << 20)
	debug.SetMaxThreads(64)
	return nil
}

// StrictJSON rejects unknown members/trailing data and bounds configuration reads.
func StrictJSON(r io.Reader, v any) error {
	b, err := io.ReadAll(io.LimitReader(r, (256<<20)+1))
	if err != nil || len(b) > 256<<20 {
		return failure("state capacity exceeded")
	}
	if duplicateJSON(b) {
		return failure("ambiguous JSON evidence")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(v); err != nil {
		return failure("invalid configuration")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return failure("invalid configuration")
	}
	return nil
}

// ProtectedConfig requires root ownership and non-writable ancestors. The master
// loader additionally pins its service-owned 0700 immediate parent by descriptor.
func ProtectedConfig(path string, v any) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return failure("configuration path must be absolute")
	}
	for d := filepath.Dir(path); ; d = filepath.Dir(d) {
		st, err := os.Lstat(d)
		if err != nil || !st.IsDir() || st.Mode().Perm()&022 != 0 || st.Sys().(*syscall.Stat_t).Uid != 0 {
			return failure("unsafe configuration parent")
		}
		if d == "/" {
			break
		}
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return failure("configuration unavailable")
	}
	defer dir.Close()
	// root-readable configuration may be 0600 or group-readable 0640; never writable by peers.
	var f *os.File
	for _, mode := range []uint32{0600, 0640} {
		f, err = openRelative(dir, filepath.Base(path), syscall.O_RDONLY, 0, mode)
		if err == nil {
			break
		}
	}
	if err != nil {
		return err
	}
	defer f.Close()
	return StrictJSON(f, v)
}

// UnavailableGeneration never treats UID existence as account-incarnation authority.
type UnavailableGeneration struct{}

func (UnavailableGeneration) Lookup(context.Context, uint32) (Generation, Code) {
	return Generation{}, "generation_source_unavailable"
}
func (UnavailableGeneration) WithActive(context.Context, uint32, string, func(context.Context) Code) Code {
	return "generation_source_unavailable"
}
func (UnavailableGeneration) WithEvidence(context.Context, []GenerationCondition, func(context.Context) Code) Code {
	return "generation_source_unavailable"
}
func (UnavailableGeneration) Watch(uint32, string) (<-chan struct{}, func()) {
	c := make(chan struct{})
	close(c)
	return c, func() {}
}

// safeAncestors is a production configuration preflight. Test-only injected
// runtimes do not relax deployment ownership or writable-ancestor checks.
func safeAncestors(path string, uid uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return failure("unsafe configured path")
	}
	for d := path; ; d = filepath.Dir(d) {
		st, e := os.Lstat(d)
		if e != nil || !st.IsDir() || st.Mode().Perm()&022 != 0 {
			return failure("unsafe configured ancestor")
		}
		owner := st.Sys().(*syscall.Stat_t).Uid
		if owner != 0 && owner != uid {
			return failure("unsafe configured ancestor owner")
		}
		if d == "/" {
			return nil
		}
	}
}
func duplicateJSON(b []byte) bool {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 16 {
			return false
		}
		token, e := d.Token()
		if e != nil {
			return false
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return false
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, e := d.Token()
			return e == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return true
	}
	_, e := d.Token()
	return e != io.EOF
}
