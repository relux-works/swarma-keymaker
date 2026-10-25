//go:build linux

package enrollment

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/timeconfidence"
	"golang.org/x/sys/unix"
)

const consumedName = "consumed-approvals"
const approvalTTL = 10 * time.Minute
const ledgerPrefix = "consumed-approvals/1 "

type approvalInstant struct {
	bootID         string
	utc, boot      int64
	trusted        bool
	uncertainty    time.Duration
	authorityUntil time.Time
}
type approvalSource interface {
	sample() (approvalInstant, error)
}
type linuxApprovalSource struct {
	ctx      context.Context
	provider *timeconf.Provider
}

// UTC and boot identity come from the shared confidence provider. The separate
// CLOCK_BOOTTIME reading is only the nonextendable elapsed approval TTL; its
// wall time is never used as a substitute for a confidence verdict.
func (s linuxApprovalSource) sample() (approvalInstant, error) {
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	v, err := timeconfidence.Sample(ctx, s.provider)
	if err != nil {
		return approvalInstant{}, fmt.Errorf("clock_untrusted: %w", err)
	}
	var boot unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot) != nil {
		return approvalInstant{}, fmt.Errorf("clock_untrusted")
	}
	return approvalInstant{bootID: v.Boot, utc: v.Now.UnixNano(), boot: boot.Nano(), trusted: true, uncertainty: v.Uncertainty, authorityUntil: v.AuthorityUntil}, nil
}

// Fixture substitution is package-private; policy is always decoded from the
// existing root-owned pin configuration before a production collector is made.
// Keep one provider across the initial observation and approval decision so a
// hold observed at process start cannot be erased by constructing another one.
func approvalSourceFor(ctx context.Context, files Files, policy *timeconf.Policy) (approvalSource, error) {
	if source, ok := files.(interface{ approvalSource() approvalSource }); ok {
		return source.approvalSource(), nil
	}
	p, err := timeconf.Production(policy, nil)
	if err != nil || timeconfidence.Start(ctx, p) != nil {
		return nil, fmt.Errorf("clock_untrusted")
	}
	return linuxApprovalSource{ctx, p}, nil
}

func randomApprovalID() (string, error) {
	var b [32]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func validApprovalID(id string) bool {
	b, err := hex.DecodeString(id)
	return err == nil && len(b) == 32 && hex.EncodeToString(b) == id
}
func newCommandApproval(path string, c PinConfig, digest string, source approvalSource) (commandApproval, error) {
	if source == nil {
		return commandApproval{}, fmt.Errorf("clock_untrusted")
	}
	i, err := source.sample()
	if err != nil {
		return commandApproval{}, err
	}
	if _, ok := approvalUpper(i); !ok {
		return commandApproval{}, fmt.Errorf("clock_untrusted")
	}
	id, err := randomApprovalID()
	return commandApproval{Version: 1, ConfigPathSHA256: digestBytes([]byte(path)), PinSHA256: pinDigest(c), StateSHA256: digest, ID: id, BootID: i.bootID, ConfirmedUTC: i.utc, ConfirmedBoot: i.boot}, err
}
func approvalValid(a commandApproval, source approvalSource) error {
	if source == nil {
		return errTrust
	}
	now, err := source.sample()
	if err != nil {
		return err
	}
	upper, ok := approvalUpper(now)
	if !validApprovalID(a.ID) || !validApprovalID(a.LedgerID) || !ok || a.ConfirmedUTC <= 0 || a.ConfirmedBoot <= 0 {
		return errTrust
	}
	if now.bootID == "" || now.bootID != a.BootID {
		return fmt.Errorf("approval_boot_changed")
	}
	// Compare before subtracting to avoid overflow on hostile persisted integers.
	if now.utc < a.ConfirmedUTC || now.boot < a.ConfirmedBoot {
		return fmt.Errorf("approval_clock_rollback")
	}
	wallAge, bootAge := now.utc-a.ConfirmedUTC, now.boot-a.ConfirmedBoot
	if upper-a.ConfirmedUTC >= int64(approvalTTL) || bootAge >= int64(approvalTTL) {
		return fmt.Errorf("approval_expired")
	}
	// NTP slewing/sampling may change the UTC/boot offset slightly; a clock step
	// exceeding two seconds is refused. The independent boot TTL always holds.
	if wallAge-bootAge > int64(2*time.Second) || bootAge-wallAge > int64(2*time.Second) {
		return fmt.Errorf("approval_clock_discontinuity")
	}
	return nil
}

// Current provider facts remain in memory, unchanged. The persisted issue point
// is still O_issue: retaining L_issue/deadline/receipt requires the later codec
// review. This tightening alone does not qualify the full 600-second contract.
func approvalUpper(i approvalInstant) (int64, bool) {
	if i.utc <= 0 || i.boot <= 0 {
		return 0, false
	}
	_, u, ok := timeconfidence.Bounds(timeconf.Sample{Now: time.Unix(0, i.utc), Boot: i.bootID, Trusted: i.trusted, Fresh: true, Uncertainty: i.uncertainty, AuthorityUntil: i.authorityUntil})
	if !ok {
		return 0, false
	}
	return u.UnixNano(), true
}

// The ledger is created by the operator, never by startup. The service only
// appends under the Store lock. A missing/replaced/malformed ledger refuses;
// the receipt binds its random generation as well as its own random ID.
func openConsumed(c PinConfig, files Files, flags int) (*os.File, string, map[string]bool, error) {
	path := filepath.Join(c.StateDir, consumedName)
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	fail := func(err error) (*os.File, string, map[string]bool, error) { f.Close(); return nil, "", nil, err }
	info, err := f.Stat()
	m, metaErr := openedMetadata(files, f)
	named, nameErr := os.Lstat(path)
	if err != nil || metaErr != nil || nameErr != nil || !info.Mode().IsRegular() || !os.SameFile(info, named) || !safeMeta(m, false, *c.ServiceUID) || m.Links != 1 || m.Mode.Perm() != 0600 {
		return fail(errTrust)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxStateBytes+1))
	if err != nil {
		return fail(err)
	}
	if len(b) > maxStateBytes || len(b) == 0 || b[len(b)-1] != '\n' {
		return fail(errTrust)
	}
	lines := strings.Split(string(b[:len(b)-1]), "\n")
	if !strings.HasPrefix(lines[0], ledgerPrefix) {
		return fail(errTrust)
	}
	id := strings.TrimPrefix(lines[0], ledgerPrefix)
	if !validApprovalID(id) {
		return fail(errTrust)
	}
	consumed := make(map[string]bool, len(lines)-1)
	for _, entry := range lines[1:] {
		if !validApprovalID(entry) || consumed[entry] {
			return fail(errTrust)
		}
		consumed[entry] = true
	}
	// Reserve space for another complete entry before beginning an append.
	if len(b)+65 > maxStateBytes {
		return fail(fmt.Errorf("consumed_approvals_capacity"))
	}
	return f, id, consumed, nil
}

func prepareConsumedLedger(c PinConfig, files Files, ops durableOps) (string, error) {
	f, id, _, err := openConsumed(c, files, syscall.O_RDONLY)
	if err == nil {
		return id, f.Close()
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	id, err = randomApprovalID()
	if err != nil {
		return "", err
	}
	path := filepath.Join(c.StateDir, consumedName)
	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return "", err
	}
	f = os.NewFile(uintptr(fd), path)
	defer f.Close()
	store := newFileStore(context.Background(), c.StateDir, files, c.ObjectFormat)
	store.owner = *c.ServiceUID
	if err = store.setOwner(f); err != nil {
		return "", err
	}
	data := []byte(ledgerPrefix + id + "\n")
	n, err := ops.Write(f, data)
	if err != nil {
		return "", err
	}
	if n != len(data) {
		return "", io.ErrShortWrite
	}
	if err = ops.Sync(f); err != nil {
		return "", err
	}
	if err = ops.Close(f); err != nil {
		return "", err
	}
	if err = ops.SyncDir(c.StateDir); err != nil {
		return "", err
	}
	return id, nil
}

func consumeApproval(ctx context.Context, c PinConfig, files Files, approval commandApproval, ops durableOps) error {
	f, id, consumed, err := openConsumed(c, files, syscall.O_RDWR|syscall.O_APPEND)
	if err != nil {
		return err
	}
	defer f.Close()
	if id != approval.LedgerID || consumed[approval.ID] {
		return fmt.Errorf("approval_already_consumed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	data := []byte(approval.ID + "\n")
	n, err := ops.Write(f, data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	if err = ops.Sync(f); err != nil {
		return err
	}
	return ops.Close(f)
}
