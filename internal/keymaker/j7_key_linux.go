//go:build linux

package keymaker

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const j7SeedMagic = "keymaker-secp-root/1\n"

// InitializeJ7Seed is an explicit fresh operator boundary, not daemon startup or
// an agent import/export API. The already protected holder-owned directory must
// be 0700. Existing target or staging evidence refuses; nothing is overwritten.
// Independent invocations obtain fresh roots, but cannot prove separate users,
// exclusive custodians, or detect a malicious operator copying root material.
func InitializeJ7Seed(path string, uid uint32, role, instance string) error {
	return initializeJ7Seed(path, uid, role, instance, rand.Reader, func(f *os.File, b []byte) error {
		for len(b) > 0 {
			n, err := f.Write(b)
			if err != nil {
				return err
			}
			if n <= 0 {
				return io.ErrShortWrite
			}
			b = b[n:]
		}
		return nil
	})
}

func j7SeedHeader(role, instance string) ([]byte, error) {
	if !validJ7Role(role) || !validJ7Instance(instance) {
		return nil, errJ7Key
	}
	return []byte(j7SeedMagic + role + "\n" + instance + "\n"), nil
}

// The reader/writer seam is private and used only by isolated fault tests.
func initializeJ7Seed(path string, uid uint32, role, instance string, entropy io.Reader, write func(*os.File, []byte) error) error {
	if uint32(os.Geteuid()) != uid {
		return errJ7Key
	}
	header, err := j7SeedHeader(role, instance)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." {
		return errJ7Key
	}
	dir, err := OpenDirectory(filepath.Dir(path), uid, 0700)
	if err != nil {
		return errJ7Key
	}
	defer dir.Close()
	name := filepath.Base(path)
	stage := "." + name + ".next"
	var st unix.Stat_t
	if unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != unix.ENOENT {
		return errJ7Key
	}
	// Complete entropy is obtained before creating any filesystem intent.
	var seed [32]byte
	defer erase(seed[:])
	if entropy == nil {
		return errJ7Key
	}
	if _, err := io.ReadFull(entropy, seed[:]); err != nil {
		return errJ7Key
	}
	f, err := openRelative(dir, stage, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL, uid, 0600)
	if err != nil {
		return errJ7Key
	}
	var owned syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &owned) != nil {
		f.Close()
		return errJ7Key
	}
	published := false
	defer func() {
		f.Close()
		if !published {
			var current unix.Stat_t
			if unix.Fstatat(int(dir.Fd()), stage, &current, unix.AT_SYMLINK_NOFOLLOW) == nil && uint64(current.Ino) == owned.Ino && uint64(current.Dev) == uint64(owned.Dev) {
				_ = unix.Unlinkat(int(dir.Fd()), stage, 0)
				_ = dir.Sync()
			}
		}
	}()
	record := append(header, seed[:]...)
	defer erase(record)
	if write == nil || write(f, record) != nil || f.Sync() != nil {
		return errJ7Key
	}
	// Verify exact complete bytes and protection using a separate read descriptor
	// before publication, including faults that report success after a short write.
	check, err := openRelative(dir, stage, syscall.O_RDONLY, uid, 0600)
	if err != nil {
		return errJ7Key
	}
	got, e := io.ReadAll(io.LimitReader(check, int64(len(record)+1)))
	closeErr := check.Close()
	valid := e == nil && closeErr == nil && bytes.Equal(got, record)
	erase(got)
	if !valid {
		return errJ7Key
	}
	if unix.Renameat2(int(dir.Fd()), stage, int(dir.Fd()), name, unix.RENAME_NOREPLACE) != nil {
		return errJ7Key
	}
	published = true
	if dir.Sync() != nil {
		return errJ7Key
	}
	return nil
}

// loadJ7Key only opens existing, exact role/instance-bound material. It never
// calls initialization, repairs a record, or interprets a legacy Ed25519 seed.
func loadJ7Key(path string, uid uint32, role, instance, epoch, registry string) (*j7Key, error) {
	header, err := j7SeedHeader(role, instance)
	if err != nil || epoch == "" || registry == "" {
		return nil, errJ7Key
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errJ7Key
	}
	dir, err := OpenDirectory(filepath.Dir(path), uid, 0700)
	if err != nil {
		return nil, errJ7Key
	}
	defer dir.Close()
	f, err := openRelative(dir, filepath.Base(path), syscall.O_RDONLY, uid, 0600)
	if err != nil {
		return nil, errJ7Key
	}
	defer f.Close()
	got := make([]byte, len(header))
	if _, err = io.ReadFull(f, got); err != nil || !bytes.Equal(got, header) {
		erase(got)
		return nil, errJ7Key
	}
	erase(got)
	b, err := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	if err != nil {
		return nil, errJ7Key
	}
	k := &j7Key{seed: b[:32], mapped: true, role: role, instance: instance, epoch: epoch, registry: registry, entropy: rand.Reader}
	k.locked = syscall.Mlock(b) == nil
	if unix.Madvise(b, unix.MADV_DONTDUMP) != nil {
		k.close()
		return nil, errJ7Key
	}
	n, e := io.ReadFull(f, k.seed)
	var extra [1]byte
	more, end := f.Read(extra[:])
	erase(extra[:])
	if n != 32 || e != nil || more != 0 || end != io.EOF {
		k.close()
		return nil, errJ7Key
	}
	return k, nil
}

func (k *j7Key) close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return nil
	}
	k.closed = true
	if k.mapped {
		b := k.seed[:4096]
		erase(b)
		if k.locked {
			_ = syscall.Munlock(b)
		}
		k.seed = nil
		return syscall.Munmap(b)
	}
	erase(k.seed)
	k.seed = nil
	return nil
}
