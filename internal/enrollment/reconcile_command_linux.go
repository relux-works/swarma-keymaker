//go:build linux

package enrollment

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	format "github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/registry"
)

const approvalName = "reconciliation.json"
const pendingName = ".reconciliation-pending"

// The service must not be able to remove a failed-publication fence. Its path
// is derived from the protected config location, never from a request argument.
func pendingPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), pendingName+"-"+digestBytes([]byte(configPath)))
}

func openedMetadata(files Files, f *os.File) (Metadata, error) {
	if adapter, ok := files.(interface {
		openedMetadata(*os.File) (Metadata, error)
	}); ok {
		return adapter.openedMetadata(f)
	}
	info, err := f.Stat()
	if err != nil {
		return Metadata{}, err
	}
	return metadata(info)
}

// ReconciliationReport is one JSON object per stdout line. Summary/prompt go to
// stderr. Digest covers all history and permanent ownership, not just Hosts.
type ReconciliationReport struct {
	Version              int                  `json:"version"`
	PinRevision          string               `json:"pin_revision"`
	PinSHA256            string               `json:"pin_sha256"`
	PublisherFingerprint string               `json:"publisher_fingerprint"`
	Audience             string               `json:"audience"`
	LocalRevision        string               `json:"local_revision"`
	Hosts                []ReconciliationHost `json:"hosts"`
	StateSHA256          string               `json:"state_sha256"`
	SnapshotSHA256       string               `json:"snapshot_sha256"`
	Evidence             []string             `json:"evidence"`
	Match                bool                 `json:"match"`
	Reason               string               `json:"reason"`
	Approved             bool                 `json:"approved"`
}
type ReconciliationHost struct {
	Host    string `json:"host"`
	Seq     int64  `json:"seq"`
	ID      string `json:"id"`
	Revoked bool   `json:"revoked"`
}
type commandApproval struct {
	Version          int    `json:"version"`
	ConfigPathSHA256 string `json:"config_path_sha256"`
	PinSHA256        string `json:"pin_sha256"`
	StateSHA256      string `json:"state_sha256"`
}

func pinDigest(c PinConfig) string { b, _ := json.Marshal(c); return digestBytes(b) }
func digestBytes(b []byte) string  { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// directoryLease never creates a file or changes directory contents. Protected
// parents prevent path replacement in the command policy. All enrollment
// authorities retain a shared lock; the operator needs the exclusive lock.
func directoryLease(path string, files Files, owner uint32, exclusive bool) (*os.File, error) {
	if err := safeParents(files, path, owner); err != nil {
		return nil, err
	}
	m, err := files.Lstat(path)
	if err != nil || m.Mode.Perm() != 0700 {
		return nil, errTrust
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	opened, e := f.Stat()
	named, e2 := os.Lstat(path)
	if e != nil || e2 != nil || !os.SameFile(opened, named) {
		f.Close()
		return nil, errTrust
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err = syscall.Flock(fd, mode|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("enrollment_authority_live: %w", err)
	}
	return f, nil
}
func commandConfig(c PinConfig, files Files) error {
	// A service cannot replace the state-directory inode by renaming its parent.
	if c.ServiceUID == nil || *c.ServiceUID == 0 {
		return fmt.Errorf("service_uid_required")
	}
	if err := safeParents(files, filepath.Dir(c.StateDir), 0); err != nil {
		return err
	}
	m, err := files.Lstat(c.StateDir)
	if err != nil || !safeMeta(m, true, *c.ServiceUID) || m.UID != *c.ServiceUID || m.Mode.Perm() != 0700 {
		return errTrust
	}
	return nil
}

type previewStore struct{ before, after *registry.HighWater }

func (s *previewStore) Commit(previous *registry.HighWater, next registry.HighWater) error {
	if !reflect.DeepEqual(previous, s.before) || s.after != nil {
		return errTrust
	}
	s.after = next.Clone()
	return nil
}

// inspectReconciliation only reads real state. Registrar Commit is captured in
// memory so the exact production loader can compute its proposed full state.
func inspectReconciliation(ctx context.Context, configPath string, c PinConfig, files Files) (ReconciliationReport, *registry.HighWater, error) {
	r := ReconciliationReport{Version: 1, PinRevision: c.Revision, PinSHA256: pinDigest(c), Audience: c.Audience, Hosts: []ReconciliationHost{}, Evidence: []string{}}
	publisher, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(c.Publisher, "ed25519:"))
	r.PublisherFingerprint = "SHA256:" + digestBytes(publisher)
	entries, err := os.ReadDir(c.StateDir)
	if err != nil {
		r.Reason = "state_unavailable"
		return r, nil, err
	}
	interrupted := false
	if _, err := os.Lstat(pendingPath(configPath)); !errors.Is(err, os.ErrNotExist) {
		r.Evidence = append(r.Evidence, "operator_publication_pending")
		interrupted = true
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "accepted":
			r.Evidence = append(r.Evidence, "bootstrap_marker_present")
		case "high-water.json", "high-water.lock", approvalName:
		default:
			r.Evidence = append(r.Evidence, entry.Name())
			interrupted = true
		}
	}
	store := newFileStore(ctx, c.StateDir, files)
	store.owner = *c.ServiceUID
	high, err := store.readLocked() // Directory lease already excludes all writers.
	if err != nil || high == nil {
		r.Reason = "interrupted_or_missing_state"
		return r, nil, errTrust
	}
	r.LocalRevision = high.Revision
	r.StateSHA256 = StateDigest(high)
	for host, h := range high.Hosts {
		r.Hosts = append(r.Hosts, ReconciliationHost{host, h.Seq, h.ID, h.Revoked})
	}
	sort.Slice(r.Hosts, func(i, j int) bool { return r.Hosts[i].Host < r.Hosts[j].Host })
	if interrupted {
		r.Reason = "interrupted_commit_evidence"
		return r, high, errTrust
	}
	policy, err := format.NewPolicy(c.Audience, c.Publisher, c.Stations)
	if err != nil {
		r.Reason = "invalid_pin"
		return r, high, err
	}
	if err = safeRepository(ctx, files, c.Registry); err != nil {
		r.Reason = "registry_unavailable"
		return r, high, err
	}
	verifier := newGitVerifier(ctx, c.Registry, c.Revision, c.Maintainers)
	snapshotEntries, err := verifier.entries()
	if err != nil {
		r.Reason = "snapshot_unverified"
		return r, high, err
	}
	// An isolated fresh preview derives state solely from the approved registry.
	// FirstUse here selects the registrar's validation mode, not local bootstrap:
	// actual accepted state is mandatory above and no persistent Store is passed.
	_, candidate, err := (registry.Loader{Policy: policy, Verifier: verifier, Store: &previewStore{}}).Load(registry.Input{Revision: c.Revision, Entries: snapshotEntries, FirstUse: true})
	if err != nil {
		r.Reason = "snapshot_rejected: " + err.Error()
		return r, high, errTrust
	}
	r.SnapshotSHA256 = StateDigest(candidate)
	// Independently retain the production ancestry/history checks against the
	// real local state. Fresh preview cannot waive a monotonicity refusal.
	capture := &previewStore{before: high.Clone()}
	_, proposed, validationErr := (registry.Loader{Policy: policy, Verifier: verifier, Store: capture}).Load(registry.Input{Revision: c.Revision, Entries: snapshotEntries, Retained: high.Clone(), Reconciled: true})
	same := reflect.DeepEqual(high, candidate)
	r.Match = validationErr == nil && same && reflect.DeepEqual(high, proposed)
	if validationErr != nil {
		r.Reason = "snapshot_rejected: " + validationErr.Error()
		if !same {
			r.Reason += "; " + stateDifference(high, candidate)
		}
		return r, high, errTrust
	}
	if !r.Match {
		r.Reason = stateDifference(high, candidate)
		return r, high, errTrust
	}
	r.Reason = "matching_state"
	return r, high, nil
}

func stateDifference(local, next *registry.HighWater) string {
	hosts := make([]string, 0, len(local.Hosts)+len(next.Hosts))
	for host := range local.Hosts {
		hosts = append(hosts, host)
	}
	for host := range next.Hosts {
		if _, ok := local.Hosts[host]; !ok {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		h, localOK := local.Hosts[host]
		n, nextOK := next.Hosts[host]
		if !localOK {
			return "local_missing_host: " + host
		}
		if !nextOK {
			return "snapshot_missing_host: " + host
		}
		if n.Seq < h.Seq {
			return "snapshot_rollback: " + host
		}
		if n.ID != h.ID || n.Revoked != h.Revoked {
			return "snapshot_different_id_or_revocation: " + host
		}
	}
	if local.Revision != next.Revision {
		return "accepted_revision_differs_from_pin"
	}
	return "history_or_ownership_differs"
}

// Reconcile is the root operator command, never a bootstrap or repair operation.
// The only writes are a one-use approval and its fail-closed publication marker.
func Reconcile(ctx context.Context, configPath, confirm string, input io.Reader, out, summary io.Writer) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("operator_root_required")
	}
	return reconcileCommand(ctx, configPath, confirm, input, out, summary, LinuxFiles{}, diskOps{})
}
func reconcileCommand(ctx context.Context, configPath, confirm string, input io.Reader, out, summary io.Writer, files Files, ops durableOps) error {
	c, _, err := loadConfig(configPath, files)
	if err != nil {
		return fmt.Errorf("pin_unavailable: %w", err)
	}
	if err = commandConfig(c, files); err != nil {
		return err
	}
	lease, err := directoryLease(c.StateDir, files, *c.ServiceUID, true)
	if err != nil {
		return err
	}
	defer unlock(lease)
	// Lock an existing Store inode read-only; unlike Store.read this cannot create
	// high-water.lock and cannot turn a missing directory into bootstrap evidence.
	lockPath := filepath.Join(c.StateDir, "high-water.lock")
	fd, err := syscall.Open(lockPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("existing_store_lock_required: %w", err)
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	defer unlock(lock)
	info, err := lock.Stat()
	m, metaErr := openedMetadata(files, lock)
	if err != nil || metaErr != nil || !info.Mode().IsRegular() || !safeMeta(m, false, *c.ServiceUID) {
		return errTrust
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("store_writer_live: %w", err)
	}
	inspect := func(c PinConfig) (ReconciliationReport, *registry.HighWater, error) {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		return inspectReconciliation(bounded, configPath, c, files)
	}
	report, _, inspectionErr := inspect(c)
	if err = json.NewEncoder(out).Encode(report); err != nil {
		return err
	}
	fmt.Fprintf(summary, "Pin %s; publisher %s; audience %s\nLocal %s; state SHA256 %s; %s\n", report.PinRevision, report.PublisherFingerprint, report.Audience, report.LocalRevision, report.StateSHA256, report.Reason)
	if inspectionErr != nil {
		if strings.Contains(report.Reason, "registry_rollback") {
			fmt.Fprintln(summary, "Rollback validation refused: the pin may regress revision, omit an accepted host/sequence, change an accepted ID, or resurrect a tombstone. Retained state was preserved.")
		}
		return fmt.Errorf("reconciliation_refused: %s", report.Reason)
	}
	if confirm == "" {
		fmt.Fprintf(summary, "After independently establishing pin freshness, type the full state SHA256 to approve one startup: ")
		if input == nil {
			return fmt.Errorf("confirmation_required")
		}
		confirm, err = readConfirmation(ctx, input)
		if err != nil {
			return err
		}
	}
	if confirm != report.StateSHA256 {
		return fmt.Errorf("confirmation_digest_mismatch")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// Re-read both protected policy and proposed state after user interaction.
	current, _, err := loadConfig(configPath, files)
	if err != nil {
		return err
	}
	if pinDigest(current) != report.PinSHA256 {
		return fmt.Errorf("pin_changed_during_confirmation")
	}
	fresh, _, err := inspect(current)
	if err != nil || fresh.StateSHA256 != confirm || !fresh.Match {
		return fmt.Errorf("state_changed_during_confirmation")
	}
	if _, existingErr := os.Lstat(filepath.Join(c.StateDir, approvalName)); !errors.Is(existingErr, os.ErrNotExist) {
		return fmt.Errorf("approval_already_present: consume at startup or perform separate operator recovery")
	}
	if err = writeCommandApproval(ctx, configPath, c, report.StateSHA256, ops); err != nil {
		return fmt.Errorf("approval_write_failed_fenced: %w", err)
	}
	report.Approved = true
	// Publication has committed: output errors cannot retract operator consent.
	if err = json.NewEncoder(out).Encode(report); err != nil {
		return fmt.Errorf("approval_committed_output_failed: %w", err)
	}
	fmt.Fprintln(summary, "Approved one startup. Start the enrollment authority; every later restart requires a new confirmation.")
	return nil
}

// The command owns its input; cancellation closes a closable input (including
// stdin) so SIGINT/SIGTERM releases both leases while waiting for confirmation.
func readConfirmation(ctx context.Context, input io.Reader) (string, error) {
	type readResult struct {
		line string
		err  error
	}
	result := make(chan readResult, 1)
	go func() {
		line, err := bufio.NewReader(io.LimitReader(input, 130)).ReadString('\n')
		result <- readResult{line, err}
	}()
	select {
	case <-ctx.Done():
		if closer, ok := input.(io.Closer); ok {
			_ = closer.Close()
		}
		return "", ctx.Err()
	case r := <-result:
		if r.err != nil && !errors.Is(r.err, io.EOF) {
			return "", r.err
		}
		return strings.TrimSuffix(r.line, "\n"), nil
	}
}

func writeCommandApproval(ctx context.Context, configPath string, c PinConfig, digest string, ops durableOps) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	pending := pendingPath(configPath)
	fd, err := syscall.Open(pending, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0644)
	if err != nil {
		return err
	}
	marker := os.NewFile(uintptr(fd), pending)
	// Even an empty marker refuses startup. Its entry is durable before any
	// candidate approval can replace the existing one. Never clean it on error.
	err = ops.Sync(marker)
	closeErr := ops.Close(marker)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = ops.SyncDir(filepath.Dir(pending)); err != nil {
		return err
	}
	data, err := json.Marshal(commandApproval{Version: 1, ConfigPathSHA256: digestBytes([]byte(configPath)), PinSHA256: pinDigest(c), StateSHA256: digest})
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(c.StateDir, ".reconciliation-")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	// Public data; the unprivileged service can read but cannot create root-owned
	// approval inodes. The private parent prevents access by unrelated accounts.
	err = temp.Chmod(0644)
	if err == nil {
		var n int
		n, err = ops.Write(temp, data)
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = ops.Sync(temp)
	}
	closeErr = ops.Close(temp)
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = ops.Rename(temp.Name(), filepath.Join(c.StateDir, approvalName)); err != nil {
		return err
	}
	if err = ops.SyncDir(c.StateDir); err != nil {
		return err
	}
	// Final fallible action: do not fsync after clearing the fence. If a crash
	// resurrects this marker, startup safely refuses and requires operator repair.
	return os.Remove(pending)
}

// commandReconciler is New's production default. Only the command's root-owned,
// single-use record can authorize existing state; nil injection never means
// mere local-file readability is sufficient.
type commandReconciler struct {
	configPath string
	files      Files
	consumeOps durableOps
}

func (r *commandReconciler) Check(ctx context.Context, high *registry.HighWater) error {
	c, _, err := loadConfig(r.configPath, r.files)
	if err != nil {
		return err
	}
	return r.checkPinned(ctx, high, c)
}
func (r *commandReconciler) checkPinned(ctx context.Context, high *registry.HighWater, c PinConfig) error {
	if high == nil || ctx.Err() != nil {
		return errTrust
	}
	if err := commandConfig(c, r.files); err != nil {
		return err
	}
	if uint32(os.Geteuid()) != *c.ServiceUID {
		return errTrust
	}
	// Serialize receipt reads/consumption across startup instances. Lifecycle
	// leases are shared, so without this lock two starts could hold the same
	// root-owned inode before either unlinks it.
	store := newFileStore(ctx, c.StateDir, r.files)
	lock, err := store.lock()
	if err != nil {
		return err
	}
	defer unlock(lock)
	actual, err := store.readLocked()
	if err != nil || !reflect.DeepEqual(actual, high) {
		return errTrust
	}

	if _, err := os.Lstat(pendingPath(r.configPath)); !errors.Is(err, os.ErrNotExist) {
		return errTrust
	}
	entries, err := os.ReadDir(c.StateDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "accepted", "high-water.json", "high-water.lock", approvalName:
		default:
			return errTrust
		}
	}
	path := filepath.Join(c.StateDir, approvalName)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	m, err := openedMetadata(r.files, f)
	if err != nil || !safeMeta(m, false, 0) || m.Links != 1 || m.Mode.Perm() != 0644 {
		return errTrust
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return errTrust
	}
	var approval commandApproval
	if strictJSON(b, &approval) != nil || approval.Version != 1 || approval.ConfigPathSHA256 != digestBytes([]byte(r.configPath)) || approval.PinSHA256 != pinDigest(c) || approval.StateSHA256 != StateDigest(high) {
		return errTrust
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	// The service may unlink but cannot manufacture a root-owned inode. Check
	// named/opened identity before unlink and nlink==0 afterwards: hard-linking a
	// receipt or swapping its path cannot make it reusable across process starts.
	named, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, named) {
		return errTrust
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	info, err = f.Stat()
	if err != nil {
		return err
	}
	st := info.Sys().(*syscall.Stat_t)
	if st.Nlink != 0 {
		return errTrust
	}
	ops := r.consumeOps
	if ops == nil {
		ops = diskOps{}
	}
	if err = ops.SyncDir(c.StateDir); err != nil {
		return err
	}
	return ctx.Err()
}
