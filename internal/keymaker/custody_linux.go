//go:build linux

package keymaker

import (
	"crypto/rand"
	"os"
	"syscall"
)

// openCustodyState runs under LockState. Neither valid journal evidence nor its
// absence can recreate bindings. Both stores must survive independently; only a
// snapshot initialized from an empty directory permits creating a new journal.
func openCustodyState(state *os.File, uid uint32) (*Store, *Journal, *os.File, error) {
	s, err := loadStore(state, uid)
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
	j, err := openJournalChecked(dir, uid, systemAuditClock{}, rand.Reader, func(j *Journal) error {
		if s.initialized {
			if j.seq != 0 {
				return failure("unexpected bootstrap audit evidence")
			}
			return nil
		}
		if !s.matchesCommit(j.binding) {
			return failure("binding journal recovery mismatch")
		}
		for _, request := range s.requests {
			if request.Status == "pending" {
				return failure("unresolved native mutation intent")
			}
		}
		return nil
	})
	if err != nil {
		dir.Close()
		return nil, nil, nil, err
	}
	s.journal, s.auditDir = j, dir
	if s.initialized {
		if c := s.persist(); c != "" {
			j.Close()
			dir.Close()
			return nil, nil, nil, c
		}
	}
	return s, j, dir, nil
}
