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
	return openCustodyStateClock(state, uid, systemAuditClock{})
}

func openCustodyStateClock(state *os.File, uid uint32, clock AuditClock) (*Store, *Journal, *os.File, error) {
	return openCustodyStateMessage(state, uid, clock, 0, false)
}
func openCustodyStateMessage(state *os.File, uid uint32, clock AuditClock, floor int, recovery bool, expected ...j7Expectation) (*Store, *Journal, *os.File, error) {
	return openCustodyStateMessageMode(state, uid, clock, floor, recovery, false, expected...)
}

// deferred is reserved for stopped operators: no initialization or writer open
// occurs until an already-reconciled command actually commits.
func openCustodyStateMessageMode(state *os.File, uid uint32, clock AuditClock, floor int, recovery, deferred bool, expected ...j7Expectation) (*Store, *Journal, *os.File, error) {
	s, err := loadStoreMessage(state, uid, floor, recovery)
	if err != nil {
		return nil, nil, nil, err
	}
	if s.initialized {
		if deferred {
			return nil, nil, nil, failure("binding snapshot unavailable")
		}
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
	j, err := openJournalCheckedMode(dir, uid, clock, rand.Reader, func(j *Journal) error {
		if s.initialized {
			if j.seq != 0 {
				return failure("unexpected bootstrap audit evidence")
			}
			return nil
		}
		if !s.matchesCommit(j.binding) && !recovery {
			return failure("binding journal recovery mismatch")
		}
		if s.j7 != nil && !recovery {
			if err := s.validateJ7(); err != nil {
				return err
			}
		}
		if s.messages != nil && !recovery {
			s.journal = j
			err := s.validateMessages()
			s.journal = nil
			if err != nil {
				return err
			}
		}
		if len(expected) > 0 {
			s.journal = j
			ok := s.j7HeadMatches(expected[0])
			s.journal = nil
			if !ok {
				return failure("J7 expected head mismatch")
			}
		}
		for _, request := range s.requests {
			if request.Status == "pending" {
				return failure("unresolved native mutation intent")
			}
		}
		return nil
	}, deferred)
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
