package keymaker

import (
	"crypto/rand"
	"os"
	"time"
)

// Existing custody/transport fixtures assert journal semantics independently of
// host NTP. They now opt into a fixed trusted clock explicitly; production's
// missing-policy default is covered separately by TestTimeConfidenceAuditDefault.
type fixtureAuditClock struct{}

func (fixtureAuditClock) UTC() (time.Time, bool) {
	return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC), true
}
func fixtureOpenJournal(dir *os.File, uid uint32) (*Journal, error) {
	return openJournal(dir, uid, fixtureAuditClock{}, rand.Reader)
}
func fixtureOpenStore(dir *os.File, uid uint32) (*Store, error) {
	s, e := OpenStore(dir, uid)
	if e == nil {
		s.journal.clock = fixtureAuditClock{}
	}
	return s, e
}
func fixtureOpenCustodyState(dir *os.File, uid uint32) (*Store, *Journal, *os.File, error) {
	return openCustodyStateClock(dir, uid, fixtureAuditClock{})
}
