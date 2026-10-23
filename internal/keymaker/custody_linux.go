//go:build linux

package keymaker

import (
	"io"
	"os"
	"syscall"
)

// openCustodyState runs under LockState. Neither valid journal evidence nor its
// absence can recreate bindings. Both stores must survive independently; only a
// snapshot initialized from an empty directory permits creating a new journal.
func openCustodyState(state *os.File, uid uint32) (*Store, *Journal, *os.File, error) {
	s, err := OpenStore(state, uid)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.initialized {
		if err = syscall.Mkdirat(int(state.Fd()), "audit", 0700); err != nil {
			return nil, nil, nil, failure("audit initialization failed")
		}
		if err = state.Sync(); err != nil {
			return nil, nil, nil, failure("audit initialization failed")
		}
	}
	fd, err := syscall.Openat(int(state.Fd()), "audit", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, nil, failure("audit evidence unavailable")
	}
	dir := os.NewFile(uintptr(fd), "audit")
	fail := func() (*Store, *Journal, *os.File, error) {
		dir.Close()
		return nil, nil, nil, failure("audit evidence unavailable")
	}
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Uid != uid || st.Mode&07777 != 0700 {
		return fail()
	}
	if !s.initialized {
		// Existing snapshots require retained journal evidence, even if empty
		// state was all that survived a crash during first initialization.
		entries, e := dir.ReadDir(1)
		if len(entries) == 0 || e != nil && e != io.EOF {
			return fail()
		}
	}
	j, err := OpenJournal(dir, uid)
	if err != nil {
		dir.Close()
		return nil, nil, nil, err
	}
	return s, j, dir, nil
}
