package keymaker

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-envelope/record"
)

const messageAuthorRole = "message-author"

var errMessageAuthorKey = errors.New("message-author custody unavailable")

// Independent purpose-9 root capability. Only public test fixtures construct it;
// no production factory, loader, initializer or transport calls it. Reusing the
// hardened arithmetic protocol does not share a J7 root, role or capability.
// Erasure is best effort in Go, not a hardware non-extraction guarantee.
type messageAuthorKey struct {
	mu                              sync.Mutex
	seed                            []byte
	role, instance, epoch, registry string
	entropy                         io.Reader
	closed                          bool
	mapped, locked                  bool
	beforeVerify                    func([]byte)
}

func (k *messageAuthorKey) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[message-author custody]")
}
func (*messageAuthorKey) MarshalJSON() ([]byte, error) { return nil, errMessageAuthorKey }
func (*messageAuthorKey) MarshalText() ([]byte, error) { return nil, errMessageAuthorKey }
func (k *messageAuthorKey) close() error {
	if k == nil {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	err := eraseMALiveMemory(k.seed, k.mapped, k.locked)
	k.mapped = false
	k.locked = false
	k.seed = nil
	k.entropy = nil
	k.closed = true
	return err
}
func validateMessageAuthorPath(path string) ([]uint32, error) {
	p, c := parsePath(path)
	if c != "" || len(p) != 4 || p[0] != 0x80000009 {
		return nil, errMessageAuthorKey
	}
	for _, n := range p[1:] {
		if n <= 0x80000000 {
			return nil, errMessageAuthorKey
		}
	}
	return p, nil
}

// Lock order is Store -> custody. The live holder supplies GEN, current tuple
// and release barriers; fixture-only callers exercise this arithmetic directly.
func (k *messageAuthorKey) selected(store *Store, b Binding, plan *messageAuthorPlan) ([]byte, Code) {
	if store == nil {
		return nil, "binding_not_found"
	}
	if k == nil {
		return nil, "custody_unavailable"
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.selectedHeld(store, b, plan, nil)
}

// selectedHeld is private to the held live barrier. Store and custody are held
// by its caller; before records invoking only AFTER all pre-crypto preparation.
func (k *messageAuthorKey) selectedHeld(store *Store, b Binding, plan *messageAuthorPlan, before func() Code) ([]byte, Code) {
	current, c := store.lookup(b.UID, b.Generation)
	if c != "" {
		return nil, c
	}
	if current != b || k.epoch == "" || current.Epoch != k.epoch || k.registry == "" || current.RegistryRevision != k.registry {
		return nil, "binding_conflict"
	}
	if ValidatePath(current.Path, "agent-identity") != "" {
		return nil, "binding_conflict"
	}
	path := "m/9'" + strings.TrimPrefix(current.Path, "m/1'")
	if k.closed || len(k.seed) != 32 || k.role != messageAuthorRole || !validJ7Instance(k.instance) {
		return nil, "custody_unavailable"
	}
	p, e := validateMessageAuthorPath(path)
	if e != nil {
		return nil, "custody_unavailable"
	}
	node, e := deriveJ7Node(k.seed, p, j7MAC)
	if e != nil {
		return nil, "custody_unavailable"
	}
	defer erase(node[:])
	var scalar btcec.ModNScalar
	if scalar.SetByteSlice(node[:32]) || scalar.IsZero() {
		scalar.Zero()
		return nil, "custody_unavailable"
	}
	private := btcec.PrivKeyFromScalar(&scalar)
	scalar.Zero()
	defer private.Zero()
	public := schnorr.SerializePubKey(private.PubKey())
	key := "bip340:" + base64.RawURLEncoding.EncodeToString(public)
	if record.ValidateKey(key) != nil {
		return nil, "sign_key_mismatch"
	}
	if plan == nil {
		return public, ""
	}
	if key != plan.key {
		return nil, "sign_key_mismatch"
	}
	// Recheck the immutable copy, so even an internally malformed/forged plan
	// cannot bypass the exact upstream byte/three-path admission gates.
	if _, c := prepareMessageAuthor(plan.original, key, plan.attestation); c != "" {
		return nil, c
	}
	hash := sha256.Sum256(plan.original)
	var aux [32]byte
	defer erase(aux[:])
	if k.entropy == nil {
		return nil, "entropy_unavailable"
	}
	if _, e := io.ReadFull(k.entropy, aux[:]); e != nil {
		return nil, "entropy_unavailable"
	}
	if before != nil {
		if c := before(); c != "" {
			return nil, c
		}
	}
	sig, e := schnorr.Sign(private, hash[:], schnorr.CustomNonce(aux))
	if e != nil {
		return nil, "custody_unavailable"
	}
	out := sig.Serialize()
	if k.beforeVerify != nil {
		k.beforeVerify(out)
	}
	if record.VerifySignature(key, out, plan.original) != nil {
		erase(out)
		return nil, "custody_unavailable"
	}
	return out, ""
}
func (k *messageAuthorKey) publicSelected(s *Store, b Binding) (string, Code) {
	p, c := k.selected(s, b, nil)
	if c != "" {
		return "", c
	}
	return "bip340:" + base64.RawURLEncoding.EncodeToString(p), ""
}
func (k *messageAuthorKey) signSelected(s *Store, b Binding, p *messageAuthorPlan) ([]byte, Code) {
	if p == nil {
		return nil, "signer_payload_invalid"
	}
	return k.selected(s, b, p)
}

func messageAuthorPublicString(public []byte) string {
	return "bip340:" + base64.RawURLEncoding.EncodeToString(public)
}
