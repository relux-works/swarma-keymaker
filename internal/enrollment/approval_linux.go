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
	"unsafe"
)

const consumedName = "consumed-approvals"
const approvalTTL = 10 * time.Minute
const ledgerPrefix = "consumed-approvals/1 "

type approvalInstant struct {
	bootID    string
	utc, boot int64
	trusted   bool
}
type approvalSource interface {
	sample() (approvalInstant, error)
}
type linuxApprovalSource struct{}

// Query only (Timex.Modes == 0): never change the system clock. CLOCK_BOOTTIME
// includes suspend and cannot be extended by moving the UTC clock backwards.
func (linuxApprovalSource) sample() (approvalInstant, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return approvalInstant{}, fmt.Errorf("boot_id_unavailable: %w", err)
	}
	id := strings.TrimSuffix(string(b), "\n")
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return approvalInstant{}, errTrust
	}
	if raw, err := hex.DecodeString(strings.ReplaceAll(id, "-", "")); err != nil || len(raw) != 16 {
		return approvalInstant{}, errTrust
	}
	var tx syscall.Timex
	state, err := syscall.Adjtimex(&tx)
	if err != nil {
		return approvalInstant{}, fmt.Errorf("clock_untrusted: %w", err)
	}
	var ts syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7 /* CLOCK_BOOTTIME */, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		return approvalInstant{}, errno
	}
	return approvalInstant{id, time.Now().UTC().UnixNano(), ts.Nano(), state != 5 && tx.Status&(0x40|0x1000) == 0}, nil
}

// Only package-local fixture adapters can substitute the clock. Public callers
// cannot supply a request-controlled clock, boot ID or trust flag.
func approvalSourceFor(files Files) approvalSource {
	if source, ok := files.(interface{ approvalSource() approvalSource }); ok {
		return source.approvalSource()
	}
	return linuxApprovalSource{}
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
	i, err := source.sample()
	if err != nil {
		return commandApproval{}, err
	}
	if !i.trusted || i.utc <= 0 || i.boot <= 0 || i.bootID == "" {
		return commandApproval{}, fmt.Errorf("clock_untrusted")
	}
	id, err := randomApprovalID()
	return commandApproval{Version: 1, ConfigPathSHA256: digestBytes([]byte(path)), PinSHA256: pinDigest(c), StateSHA256: digest, ID: id, BootID: i.bootID, ConfirmedUTC: i.utc, ConfirmedBoot: i.boot}, err
}
func approvalValid(a commandApproval, source approvalSource) error {
	now, err := source.sample()
	if err != nil {
		return err
	}
	if !validApprovalID(a.ID) || !validApprovalID(a.LedgerID) || !now.trusted || a.ConfirmedUTC <= 0 || a.ConfirmedBoot <= 0 {
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
	if wallAge >= int64(approvalTTL) || bootAge >= int64(approvalTTL) {
		return fmt.Errorf("approval_expired")
	}
	// NTP slewing/sampling may change the UTC/boot offset slightly; a clock step
	// exceeding two seconds is refused. The independent boot TTL always holds.
	if wallAge-bootAge > int64(2*time.Second) || bootAge-wallAge > int64(2*time.Second) {
		return fmt.Errorf("approval_clock_discontinuity")
	}
	return nil
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
	store := newFileStore(context.Background(), c.StateDir, files)
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
