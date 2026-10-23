//go:build linux

package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A refused clock check burns consent in BOTH publication modes. Recovering
// only the clock cannot authorize another start; explicit recovery followed by
// a new confirmation on the SAME state is the positive control.
func TestApprovalAttemptClockRefusalRetry(t *testing.T) {
	for _, bootstrap := range []bool{false, true} {
		for _, kind := range []string{"untrusted", "boot-unreadable"} {
			t.Run(stringMode(bootstrap)+"/"+kind, func(t *testing.T) {
				f, _, digest := approvalModeFixture(t, bootstrap)
				clock := approvalTestClock(f)
				approveMode(t, f, digest, bootstrap)
				before := reconciliationImage(t, f)
				if kind == "untrusted" {
					clock.instant.trusted = false
				} else {
					clock.err = errors.New("boot_id_unavailable: fixture denial")
				}
				assertBootstrapFenced(t, f)
				clock.instant.trusted = true
				clock.err = nil
				assertBootstrapFenced(t, f)
				assertReceiptInvalidated(t, f, before)
				repairConsumptionAndConfirm(t, f)
			})
		}
	}
}

// Every listed payload-validation refusal happens AFTER receipt invalidation.
// Only that rename may change the image; removing the injected problem cannot
// revive consent. Explicit fixture recovery plus NEW confirmation admits.
func TestApprovalAttemptPostLockRefusals(t *testing.T) {
	cases := []string{"malformed", "wrong-digest", "wrong-pin", "wrong-config", "other-boot", "expired", "untrusted", "boot-unreadable", "clock-backward", "clock-step", "ledger-missing", "ledger-malformed", "ledger-generation", "ledger-used-id", "pin-policy", "pin-member-type", "unknown-config-member", "retained-state", "pending", "unknown-evidence"}
	for _, bootstrap := range []bool{false, true} {
		for _, kind := range cases {
			t.Run(stringMode(bootstrap)+"/"+kind, func(t *testing.T) {
				f, _, digest := approvalModeFixture(t, bootstrap)
				clock := approvalTestClock(f)
				originalClock := clock.instant
				approveMode(t, f, digest, bootstrap)
				rp := filepath.Join(f.config.StateDir, approvalName)
				lp := filepath.Join(f.config.StateDir, consumedName)
				sp := filepath.Join(f.config.StateDir, "high-water.json")
				ledger, e := os.ReadFile(lp)
				if e != nil {
					t.Fatal(e)
				}
				state, e := os.ReadFile(sp)
				if e != nil {
					t.Fatal(e)
				}
				receipt := readCommandApproval(t, f)
				originalConfig := f.config
				switch kind {
				case "malformed":
					if e = os.WriteFile(rp, []byte("{"), 0644); e != nil {
						t.Fatal(e)
					}
				case "wrong-digest":
					receipt.StateSHA256 = strings.Repeat("0", 64)
				case "wrong-pin":
					receipt.PinSHA256 = strings.Repeat("0", 64)
				case "wrong-config":
					receipt.ConfigPathSHA256 = strings.Repeat("0", 64)
				case "other-boot":
					clock.instant.bootID = "other-boot"
				case "expired":
					clock.instant.utc += int64(approvalTTL)
					clock.instant.boot += int64(approvalTTL)
				case "untrusted":
					clock.instant.trusted = false
				case "boot-unreadable":
					clock.err = errors.New("boot_id_unavailable: fixture denial")
				case "clock-backward":
					clock.instant.utc--
				case "clock-step":
					clock.instant.boot += int64(time.Minute)
					clock.instant.utc += int64(time.Minute - 3*time.Second)
				case "ledger-missing":
					if e = os.Remove(lp); e != nil {
						t.Fatal(e)
					}
				case "ledger-malformed":
					if e = os.WriteFile(lp, []byte("not-a-ledger"), 0600); e != nil {
						t.Fatal(e)
					}
				case "ledger-generation":
					receipt.LedgerID = strings.Repeat("0", 64)
				case "ledger-used-id":
					if e = consumeApproval(context.Background(), f.config, f.files, receipt, diskOps{}); e != nil {
						t.Fatal(e)
					}
				case "pin-policy":
					f.config.Publisher = "invalid"
					f.writeConfig()
				case "pin-member-type":
					b, e := os.ReadFile(f.configPath)
					if e != nil {
						t.Fatal(e)
					}
					bad := strings.Replace(string(b), `"publisher":"`+f.config.Publisher+`"`, `"publisher":false`, 1)
					if bad == string(b) {
						t.Fatal("config type plant not applied")
					}
					if e = os.WriteFile(f.configPath, []byte(bad), 0600); e != nil {
						t.Fatal(e)
					}
				case "unknown-config-member":
					b, e := os.ReadFile(f.configPath)
					if e != nil {
						t.Fatal(e)
					}
					if e = os.WriteFile(f.configPath, append([]byte(`{"unexpected":true,`), b[1:]...), 0600); e != nil {
						t.Fatal(e)
					}
				case "retained-state":
					if e = os.WriteFile(sp, []byte("{"), 0600); e != nil {
						t.Fatal(e)
					}
				case "pending":
					if e = os.WriteFile(pendingPath(f.configPath), []byte("pending"), 0600); e != nil {
						t.Fatal(e)
					}
				case "unknown-evidence":
					if e = os.WriteFile(filepath.Join(f.config.StateDir, "unknown"), []byte("evidence"), 0600); e != nil {
						t.Fatal(e)
					}
				}
				if kind == "wrong-digest" || kind == "wrong-pin" || kind == "wrong-config" || kind == "ledger-generation" {
					b, e := json.Marshal(receipt)
					if e != nil {
						t.Fatal(e)
					}
					if e = os.WriteFile(rp, b, 0644); e != nil {
						t.Fatal(e)
					}
				}
				before := reconciliationImage(t, f)
				assertBootstrapFenced(t, f)
				assertReceiptInvalidated(t, f, before)
				clock.instant = originalClock
				clock.err = nil
				f.config = originalConfig
				f.writeConfig()
				if e = os.WriteFile(sp, state, 0600); e != nil {
					t.Fatal(e)
				}
				if kind == "ledger-missing" || kind == "ledger-malformed" {
					if e = os.WriteFile(lp, ledger, 0600); e != nil {
						t.Fatal(e)
					}
				}
				for _, p := range []string{pendingPath(f.configPath), filepath.Join(f.config.StateDir, "unknown")} {
					if e = os.Remove(p); e != nil && !errors.Is(e, os.ErrNotExist) {
						t.Fatal(e)
					}
				}
				assertBootstrapFenced(t, f)
				repairConsumptionAndConfirm(t, f)
			})
		}
	}
}

type prelockFiles struct {
	fixtureFiles
	config       string
	payloadReads int
}

func (f *prelockFiles) Read(path string, limit int64) ([]byte, Metadata, error) {
	if path != f.config {
		f.payloadReads++
	}
	return f.fixtureFiles.Read(path, limit)
}

// Each documented not-begun gate preserves every consent/state byte and reads
// no payload outside the protected config. Repairing only that prerequisite
// allows the original approval exactly once: refusal is not consumption.
func TestApprovalAttemptPreLockRefusals(t *testing.T) {
	cases := []string{"closed", "commit-fault", "target-changed", "config-unreadable", "config-unsafe", "config-malformed", "config-state-relative", "directory-unsafe", "directory-lease", "lock-missing", "lock-unsafe", "lock-unreadable", "canceled", "lock-wait-canceled"}
	for _, bootstrap := range []bool{false, true} {
		for _, kind := range cases {
			t.Run(stringMode(bootstrap)+"/"+kind, func(t *testing.T) {
				f, _, digest := approvalModeFixture(t, bootstrap)
				approveMode(t, f, digest, bootstrap)
				files := &prelockFiles{fixtureFiles: f.files, config: f.configPath}
				a := New(f.configPath, files, nil)
				restore := func() {}
				ctx := context.Background()
				expected := EnrollmentUnverified
				switch kind {
				case "closed":
					a.Close()
				case "commit-fault":
					a.commitFault = true
				case "target-changed":
					a.stateDir = filepath.Join(f.base, "other-state")
				case "config-unreadable":
					if e := os.Chmod(f.configPath, 0000); e != nil {
						t.Fatal(e)
					}
					restore = func() {
						if e := os.Chmod(f.configPath, 0600); e != nil {
							t.Fatal(e)
						}
					}
					expected = EnrollmentUnavailable
				case "config-unsafe":
					files.override[f.configPath] = Metadata{Mode: 0600, UID: 424242}
					restore = func() { delete(files.override, f.configPath) }
				case "config-malformed":
					if e := os.WriteFile(f.configPath, []byte("{"), 0600); e != nil {
						t.Fatal(e)
					}
					restore = f.writeConfig
				case "config-state-relative":
					old := f.config
					f.config.StateDir = "state"
					f.writeConfig()
					f.config = old
					restore = f.writeConfig
				case "directory-unsafe":
					files.override[f.config.StateDir] = Metadata{Mode: os.ModeDir | 0777, UID: 424242}
					restore = func() {
						files.override[f.config.StateDir] = Metadata{Mode: os.ModeDir | 0700, UID: uint32(os.Geteuid())}
					}
				case "directory-lease":
					lease, e := directoryLease(f.config.StateDir, f.files, uint32(os.Geteuid()), true)
					if e != nil {
						t.Fatal(e)
					}
					restore = func() { unlock(lease) }
				case "lock-missing":
					path := filepath.Join(f.config.StateDir, "high-water.lock")
					saved := filepath.Join(f.base, "saved-lock")
					if e := os.Rename(path, saved); e != nil {
						t.Fatal(e)
					}
					restore = func() {
						if e := os.Rename(saved, path); e != nil {
							t.Fatal(e)
						}
					}
				case "lock-unsafe":
					path := filepath.Join(f.config.StateDir, "high-water.lock")
					files.override[path] = Metadata{Mode: 0600, UID: 424242}
					restore = func() { delete(files.override, path) }
				case "lock-unreadable":
					path := filepath.Join(f.config.StateDir, "high-water.lock")
					if e := os.Chmod(path, 0000); e != nil {
						t.Fatal(e)
					}
					restore = func() {
						if e := os.Chmod(path, 0600); e != nil {
							t.Fatal(e)
						}
					}
				case "canceled":
					var cancel context.CancelFunc
					ctx, cancel = context.WithCancel(ctx)
					cancel()
				case "lock-wait-canceled":
					lock, e := newFileStore(ctx, f.config.StateDir, f.files).lock()
					if e != nil {
						t.Fatal(e)
					}
					restore = func() { unlock(lock) }
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
					defer cancel()
				}
				// Keep the snapshot readable for the real config-permission fault; the
				// observation reads occur outside the instrumented startup operation.
				unreadable := ""
				if kind == "config-unreadable" {
					unreadable = f.configPath
				}
				if kind == "lock-unreadable" {
					unreadable = filepath.Join(f.config.StateDir, "high-water.lock")
				}
				if unreadable != "" {
					if e := os.Chmod(unreadable, 0600); e != nil {
						t.Fatal(e)
					}
				}
				before := reconciliationImage(t, f)
				if unreadable != "" {
					if e := os.Chmod(unreadable, 0000); e != nil {
						t.Fatal(e)
					}
				}

				expectCode(t, expected, a.Reload(ctx))
				key, code := authorize(a)
				expectCode(t, expected, code)
				if key != (EnrolledKey{}) {
					t.Fatal("pre-lock refusal granted authority")
				}
				a.Close()
				if files.payloadReads != 0 {
					t.Fatalf("pre-lock payload reads=%d", files.payloadReads)
				}
				if unreadable != "" {
					info, e := os.Stat(unreadable)
					if e != nil || info.Mode().Perm() != 0000 {
						t.Fatal("refusal changed unreadable mode", e)
					}
					if e = os.Chmod(unreadable, 0600); e != nil {
						t.Fatal(e)
					}
				}
				assertUnchanged(t, f, before)
				restore()
				startApproved(t, f).Close()
				assertBootstrapFenced(t, f)
			})
		}
	}
}
