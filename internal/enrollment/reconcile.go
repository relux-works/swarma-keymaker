package enrollment

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"github.com/relux-works/swarma-registrar/registry"
)

// OperatorReconciler is the only supplied startup policy. A fresh instance is
// required for every process start; approval files from earlier starts cannot
// automatically un-fence a local restored high-water file.
type OperatorReconciler struct {
	path, challenge string
	files           Files
}

// NewOperatorReconciler creates a public per-start challenge, not a credential.
// path is the root-owned operator approval input, read only when Check is called.
func NewOperatorReconciler(path string, files Files) (*OperatorReconciler, error) {
	if !absolute(path) {
		return nil, errTrust
	}
	if files == nil {
		files = LinuxFiles{}
	}
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, err
	}
	return &OperatorReconciler{path: path, challenge: hex.EncodeToString(challenge[:]), files: files}, nil
}
func (r *OperatorReconciler) Challenge() string {
	if r == nil {
		return ""
	}
	return r.challenge
}

// Check requires an explicit protected operator decision for this startup and
// complete state digest. The operator must reconcile freshness before writing
// it; copying a local digest without that decision does not meet the contract.
func (r *OperatorReconciler) Check(ctx context.Context, high *registry.HighWater) error {
	if r == nil || r.challenge == "" || high == nil || ctx.Err() != nil {
		return errTrust
	}
	b, err := protectedRead(r.files, r.path, 4096, 0)
	if err != nil {
		return err
	}
	var approval struct {
		Startup string `json:"startup_id"`
		Digest  string `json:"state_sha256"`
	}
	if strictJSON(b, &approval) != nil || approval.Startup != r.challenge || approval.Digest != StateDigest(high) {
		return errTrust
	}
	return ctx.Err()
}
