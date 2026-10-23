//go:build linux

package enrollment

import (
	"io"
	"os"
	"syscall"
)

// LinuxFiles refuses final-component symlinks and reads/stat-checks the same fd.
// Ancestors are separately required to be protected directories.
type LinuxFiles struct{}

func metadata(info os.FileInfo) (Metadata, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Metadata{}, errTrust
	}
	return Metadata{Mode: info.Mode(), UID: st.Uid}, nil
}
func (LinuxFiles) Lstat(path string) (Metadata, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Metadata{}, err
	}
	return metadata(info)
}
func (LinuxFiles) Read(path string, limit int64) ([]byte, Metadata, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, Metadata{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, Metadata{}, err
	}
	m, err := metadata(info)
	if err != nil || !m.Mode.IsRegular() {
		return nil, m, errTrust
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, m, err
	}
	if int64(len(b)) > limit {
		return nil, m, errTrust
	}
	return b, m, nil
}

// Readable probes regular Git storage without reading whole packs into memory.
func (LinuxFiles) Readable(path string) error {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errTrust
	}
	return nil
}
