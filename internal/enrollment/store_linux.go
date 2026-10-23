//go:build linux

package enrollment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/relux-works/swarma-registrar/registry"
	"golang.org/x/sys/unix"
)

const maxStateBytes = 16 << 20
const acceptedMarker = "accepted/1\n"

type stateRecord struct {
	Version int                 `json:"version"`
	High    *registry.HighWater `json:"high_water"`
}

// StateDigest names a reconciled state exactly; a digest computed from a local
// file is not independently trusted freshness evidence by itself.
func StateDigest(high *registry.HighWater) string {
	b, _ := json.Marshal(stateRecord{1, high})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type durableOps interface {
	Write(*os.File, []byte) (int, error)
	Sync(*os.File) error
	Close(*os.File) error
	Rename(string, string) error
	RenameNoReplace(string, string) error
	Remove(string) error
	SyncDir(string) error
}
type diskOps struct{}

func (diskOps) Write(f *os.File, b []byte) (int, error) { return f.Write(b) }
func (diskOps) Close(f *os.File) error                  { return f.Close() }
func (diskOps) Sync(f *os.File) error                   { return f.Sync() }
func (diskOps) Rename(old, next string) error           { return os.Rename(old, next) }

// RenameNoReplace preserves prior consuming evidence without a pre-rename probe.
func (diskOps) RenameNoReplace(old, next string) error {
	return unix.Renameat2(unix.AT_FDCWD, old, unix.AT_FDCWD, next, unix.RENAME_NOREPLACE)
}
func (diskOps) Remove(path string) error { return os.Remove(path) }
func (diskOps) SyncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

type fileStore struct {
	ctx    context.Context
	dir    string
	files  Files
	ops    durableOps
	failed bool
	owner  uint32
}

func newFileStore(ctx context.Context, dir string, files Files) *fileStore {
	return &fileStore{ctx: ctx, dir: dir, files: files, ops: diskOps{}, owner: uint32(os.Geteuid())}
}

// Service reads and commits open only the lock created by operator publication.
func (s *fileStore) lock() (*os.File, error) { return s.openLock(false) }

func (s *fileStore) openLock(create bool) (*os.File, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	if err := safeParents(s.files, s.dir, s.owner); err != nil {
		return nil, err
	}
	m, err := s.files.Lstat(s.dir)
	if err != nil {
		return nil, err
	}
	if m.Mode.Perm()&0077 != 0 {
		return nil, errTrust
	}
	path := filepath.Join(s.dir, "high-water.lock")
	flags := syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if create {
		flags |= syscall.O_CREAT | syscall.O_EXCL
	}
	fd, err := syscall.Open(path, flags, 0600)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errTrust
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if create {
		if err := s.setOwner(f); err != nil {
			f.Close()
			return nil, err
		}
	}
	// Check the opened inode via the same metadata adapter used by fixtures.
	m, err = s.files.Lstat(path)
	if err != nil || !safeMeta(m, false, s.owner) {
		f.Close()
		return nil, errTrust
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, errTrust
	}
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, err
		}
		select {
		case <-s.ctx.Done():
			f.Close()
			return nil, s.ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}
func unlock(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }
func (s *fileStore) read() (*registry.HighWater, error) {
	f, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock(f)
	return s.readLocked()
}
func (s *fileStore) readLocked() (*registry.HighWater, error) {
	marker, err := protectedRead(s.files, filepath.Join(s.dir, "accepted"), 32, s.owner)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errTrust
	}
	if err != nil {
		return nil, err
	}
	if string(marker) != acceptedMarker {
		return nil, errTrust
	}
	b, err := protectedRead(s.files, filepath.Join(s.dir, "high-water.json"), maxStateBytes, s.owner)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errTrust
	}
	if err != nil {
		return nil, err
	}
	var record stateRecord
	if strictJSON(b, &record) != nil || record.Version != 1 || record.High == nil || !revisionPattern.MatchString(record.High.Revision) || record.High.Hosts == nil {
		return nil, errTrust
	}
	return record.High.Clone(), nil
}

// Commit performs a locked CAS and fsync/rename/fsync publication. Any error
// invalidates this instance. After rename, an error can mean INDETERMINATE durable
// state: callers must fence and require trusted startup reconciliation. This is
// the pinned registrar Store contract; no compensating write is claimed to
// make failed I/O transactional.
func (s *fileStore) Commit(previous *registry.HighWater, next registry.HighWater) (err error) {
	if s.failed {
		return errTrust
	}
	defer func() {
		if err != nil {
			s.failed = true
		}
	}()
	f, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock(f)
	current, err := s.readLocked()
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(previous, current) {
		return errTrust
	}
	return s.publish(next)
}

// publish is shared by existing-state CAS and explicit operator initialization.
// Its caller holds the state lock; it never makes a freshness decision.
func (s *fileStore) publish(next registry.HighWater) (err error) {
	if err = s.ctx.Err(); err != nil {
		return err
	}
	b, err := json.Marshal(stateRecord{1, next.Clone()})
	if err != nil || len(b) > maxStateBytes {
		return errTrust
	}
	temp, err := os.CreateTemp(s.dir, ".high-water-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err = s.setOwner(temp); err != nil {
		temp.Close()
		return err
	}
	n, writeErr := s.ops.Write(temp, b)
	if writeErr == nil && n != len(b) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = s.ops.Sync(temp)
	}
	closeErr := s.ops.Close(temp)
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err = s.ctx.Err(); err != nil {
		return err
	}
	if err = s.ops.Rename(tempPath, filepath.Join(s.dir, "high-water.json")); err != nil {
		return err
	}
	return s.ops.SyncDir(s.dir)
}

// Only operator publication can target another UID; service writes keep their
// configured owner. Ownership is fixed before file fsync and publication.
func (s *fileStore) setOwner(f *os.File) error {
	if s.owner == uint32(os.Geteuid()) {
		return nil
	}
	if os.Geteuid() != 0 {
		return errTrust
	}
	return f.Chown(int(s.owner), -1)
}
