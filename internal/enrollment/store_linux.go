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
	Sync(*os.File) error
	Rename(string, string) error
	SyncDir(string) error
}
type diskOps struct{}

func (diskOps) Sync(f *os.File) error         { return f.Sync() }
func (diskOps) Rename(old, next string) error { return os.Rename(old, next) }
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
}

func newFileStore(ctx context.Context, dir string, files Files) *fileStore {
	return &fileStore{ctx: ctx, dir: dir, files: files, ops: diskOps{}}
}
func (s *fileStore) lock() (*os.File, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	if err := safeParents(s.files, s.dir, uint32(os.Geteuid())); err != nil {
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
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	// Check the opened inode via the same metadata adapter used by fixtures.
	m, err = s.files.Lstat(path)
	if err != nil || !safeMeta(m, false, uint32(os.Geteuid())) {
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
	marker, err := protectedRead(s.files, filepath.Join(s.dir, "accepted"), 32, uint32(os.Geteuid()))
	if errors.Is(err, os.ErrNotExist) {
		if _, stateErr := s.files.Lstat(filepath.Join(s.dir, "high-water.json")); errors.Is(stateErr, os.ErrNotExist) {
			return nil, nil
		}
		return nil, errTrust
	}
	if err != nil {
		return nil, err
	}
	if string(marker) != acceptedMarker {
		return nil, errTrust
	}
	b, err := protectedRead(s.files, filepath.Join(s.dir, "high-water.json"), maxStateBytes, uint32(os.Geteuid()))
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
func (s *fileStore) marker() error {
	path := filepath.Join(s.dir, "accepted")
	if b, err := protectedRead(s.files, path, 32, uint32(os.Geteuid())); err == nil {
		if string(b) == acceptedMarker {
			return nil
		}
		return errTrust
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	_, err = f.WriteString(acceptedMarker)
	if err == nil {
		err = s.ops.Sync(f)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return s.ops.SyncDir(s.dir)
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
	n, writeErr := temp.Write(b)
	if writeErr == nil && n != len(b) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = s.ops.Sync(temp)
	}
	closeErr := temp.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err = s.marker(); err != nil {
		return err
	}
	if err = s.ctx.Err(); err != nil {
		return err
	}
	if err = s.ops.Rename(tempPath, filepath.Join(s.dir, "high-water.json")); err != nil {
		return err
	}
	return s.ops.SyncDir(s.dir)
}
