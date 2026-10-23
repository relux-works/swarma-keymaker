//go:build linux

package enrollment

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/relux-works/swarma-registrar/registry"
)

// initialPublisher is an operator-only Store. Authority never constructs it.
// The operator must hold an exclusive directory lease across inspection,
// confirmation and publication. An I/O failure retains all available evidence;
// neither this publisher nor a service restart retries initialization implicitly.
type initialPublisher struct{ store *fileStore }

func emptyState(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errTrust
	}
	return nil
}

func (p initialPublisher) Commit(previous *registry.HighWater, next registry.HighWater) (err error) {
	if previous != nil {
		return errTrust
	}
	return p.publish(next, nil)
}

// publish keeps the initial Store lock through the operator receipt's durable
// publication. The optional finish action must leave a startup fence on error.
func (p initialPublisher) publish(next registry.HighWater, finish func() error) (err error) {
	s := p.store
	if s.failed {
		return errTrust
	}
	defer func() {
		if err != nil {
			s.failed = true
		}
	}()
	if err = emptyState(s.dir); err != nil {
		return err
	}
	lock, err := s.openLock(true)
	if err != nil {
		return err
	}
	defer unlock(lock)
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0].Name() != "high-water.lock" {
		return errTrust
	}
	if err = p.marker(); err != nil {
		return err
	}
	if err = s.publish(next); err != nil {
		return err
	}
	if finish != nil {
		return finish()
	}
	return nil
}

func (p initialPublisher) marker() error {
	s := p.store
	path := filepath.Join(s.dir, "accepted")
	if b, err := protectedRead(s.files, path, 32, s.owner); err == nil {
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
	if err := s.setOwner(f); err != nil {
		f.Close()
		return err
	}
	// First retain the directory entry, even if the marker write is interrupted.
	// An empty/partial marker is evidence requiring operator recovery, never a
	// fresh bootstrap. No high-water file is created until the marker is durable.
	err = s.ops.SyncDir(s.dir)
	if err == nil {
		var n int
		n, err = s.ops.Write(f, []byte(acceptedMarker))
		if err == nil && n != len(acceptedMarker) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = s.ops.Sync(f)
	}
	closeErr := s.ops.Close(f)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return s.ops.SyncDir(s.dir)
}
