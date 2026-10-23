package enrollment

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"time"

	format "github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/registry"
)

type Code string

const (
	OK                    Code = ""
	EnrollmentUnavailable Code = "enrollment_unavailable"
	EnrollmentUnverified  Code = "enrollment_unverified"
	HostRevoked           Code = "host_revoked"
	UIDNotPermitted       Code = "uid_not_permitted"
	NameNotPermitted      Code = "name_not_permitted"
	NameInvalid           Code = "name_invalid"
	AudienceMismatch      Code = "audience_mismatch"
	KeyNotEnrolled        Code = "key_not_enrolled"
	KeyNotValidNow        Code = "key_not_valid_now"
	EnrollmentUnsupported Code = "enrollment_unsupported"
	GenerationMismatch    Code = "generation_mismatch"
)

// Reconciler attests freshness from evidence independent of restored local state.
// Check receives a copy. nil is conservative: existing local state alone cannot
// establish freshness. A service must supply its qualified startup policy.
type Reconciler interface {
	Check(context.Context, *registry.HighWater) error
}

// EnrolledKey is public admission data, not a signature or an active binding.
// Integration must repeat authority checks at its final release barrier.
type EnrolledKey struct {
	Key, Host, RecordID, Revision, Audience string
	NotBefore, NotAfter                     int64
}

// Authority serializes reloads with admission and never exposes old snapshots.
// Files=nil selects LinuxFiles. No registry or network I/O occurs in Authorize.
type Authority struct {
	mu          sync.RWMutex
	configPath  string
	files       Files
	reconcile   Reconciler
	config      PinConfig
	policy      *format.Policy
	snapshot    *registry.Snapshot
	retained    *registry.HighWater
	stateDir    string
	fence       Code
	commitFault bool
	storeOps    durableOps
}

func New(configPath string, files Files, reconcile Reconciler) *Authority {
	if files == nil {
		files = LinuxFiles{}
	}
	return &Authority{configPath: configPath, files: files, reconcile: reconcile, fence: EnrollmentUnavailable}
}

// Reload validates protected pins and the complete snapshot, persists rollback
// evidence, then switches authority. Failure fences; Commit errors require a new
// Authority and trusted startup reconciliation, not another live reload.
func (a *Authority) Reload(ctx context.Context) Code {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snapshot = nil
	a.policy = nil
	a.fence = EnrollmentUnverified
	if a.commitFault {
		return a.fence
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	config, policy, err := loadConfig(a.configPath, a.files)
	if err != nil {
		a.fence = localCode(err)
		return a.fence
	}
	if a.stateDir != "" && config.StateDir != a.stateDir {
		return a.fence
	}
	a.stateDir = config.StateDir
	store := newFileStore(ctx, config.StateDir, a.files)
	if a.storeOps != nil {
		store.ops = a.storeOps
	}
	retained, err := store.read()
	if err != nil {
		a.fence = localCode(err)
		return a.fence
	}
	if retained == nil {
		return a.fence
	}
	if a.retained != nil {
		if !reflect.DeepEqual(retained, a.retained) {
			return a.fence
		}
	} else if a.reconcile == nil || a.reconcile.Check(ctx, retained.Clone()) != nil {
		return a.fence
	}
	if err = safeRepository(ctx, a.files, config.Registry); err != nil {
		a.fence = localCode(err)
		return a.fence
	}
	verifier := newGitVerifier(ctx, config.Registry, config.Revision, config.Maintainers)
	entries, err := verifier.entries()
	if err != nil {
		a.fence = localCode(err)
		return a.fence
	}
	snapshot, high, err := (registry.Loader{Policy: policy, Verifier: verifier, Store: store}).Load(registry.Input{Revision: config.Revision, Entries: entries, Retained: retained, Reconciled: true})
	if err != nil {
		a.commitFault = store.failed
		a.fence = mapDiagnostic(err)
		return a.fence
	}
	a.retained = high.Clone()
	if ctx.Err() != nil {
		return a.fence
	}
	a.config = config
	a.policy = policy
	a.snapshot = snapshot
	a.fence = OK
	return OK
}

// Authorize checks a caller-derived purpose-2 public key. The key and issuedAt
// must come from trusted core state, never untrusted request key selectors.
func (a *Authority) Authorize(ctx context.Context, peerUID uint32, generation, key, name, aud string, issuedAt, now time.Time) (EnrolledKey, Code) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	deny := func(code Code) (EnrolledKey, Code) { return EnrolledKey{}, code }
	if ctx.Err() != nil {
		return deny(EnrollmentUnavailable)
	}
	if a.snapshot == nil {
		code := a.fence
		if code == OK {
			code = EnrollmentUnavailable
		}
		return deny(code)
	}
	record, window, found := a.snapshot.LookupKey(key)
	if !found {
		return deny(KeyNotEnrolled)
	}
	if !window.ValidAt(issuedAt.Unix(), now.Unix()) {
		return deny(KeyNotValidNow)
	}
	if record.Revoked() {
		return deny(HostRevoked)
	}
	// Registrar name semantics always use the protected audience before comparing
	// the request audience. No local copy of name grammar is maintained.
	if err := a.snapshot.Authorize(record.Host(), name); err != nil {
		return deny(mapDiagnostic(err))
	}
	rows := record.UIDMap()
	if len(rows) == 0 {
		return deny(EnrollmentUnverified)
	}
	var matched *format.UIDEntry
	for i := range rows {
		if rows[i].UID == peerUID {
			matched = &rows[i]
			break
		}
	}
	if matched == nil {
		return deny(UIDNotPermitted)
	}
	if matched.Exe != nil {
		return deny(EnrollmentUnsupported)
	}
	permitted := false
	for _, candidate := range matched.Names {
		if candidate == name {
			permitted = true
			break
		}
	}
	if !permitted {
		return deny(NameNotPermitted)
	}
	admitted, exists := a.config.Generations[strconv.FormatUint(uint64(peerUID), 10)]
	if !exists || generation != admitted {
		return deny(GenerationMismatch)
	}
	if aud != a.policy.Audience() {
		return deny(AudienceMismatch)
	}
	return EnrolledKey{Key: key, Host: record.Host(), RecordID: record.ID(), Revision: a.snapshot.Revision(), Audience: a.policy.Audience(), NotBefore: window.NotBefore, NotAfter: window.NotAfter}, OK
}
func mapDiagnostic(err error) Code {
	var refusal *registry.Error
	if errors.As(err, &refusal) {
		switch refusal.Code {
		case registry.NameInvalid:
			return NameInvalid
		case registry.NameNotPermitted:
			return NameNotPermitted
		case registry.HostRevoked:
			return HostRevoked
		}
	}
	return EnrollmentUnverified
}
