package keymaker

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const (
	j7RequestRole    = "j7-request"
	j7DelegationRole = "delegation"
)

var errJ7Key = errors.New("key custody unavailable")

// j7Key is a separate root capability, never an Ed25519 Master or transport
// handler. Its immutable role/instance pins come from protected provisioning.
// Go/library temporaries make erasure best effort, not hardware non-extraction.
type j7Key struct {
	mu                              sync.Mutex
	seed                            []byte
	role, instance, epoch, registry string
	entropy                         io.Reader
	mapped, locked, closed          bool
}

// Formatting and serialization must never expose the root through diagnostics.
func (*j7Key) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "[key custody]") }
func (*j7Key) MarshalJSON() ([]byte, error) { return nil, errJ7Key }
func (*j7Key) MarshalText() ([]byte, error) { return nil, errJ7Key }

func validJ7Role(role string) bool { return role == j7RequestRole || role == j7DelegationRole }
func validJ7Instance(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return id != strings.Repeat("0", 32)
}

// validateJ7Path does not extend ValidatePath, Registry.Resolve or Master APIs.
func validateJ7Path(path, role string) ([]uint32, error) {
	p, c := parsePath(path)
	if c != "" || len(p) != 4 || !validJ7Role(role) {
		return nil, errJ7Key
	}
	want := uint32(7)
	if role == j7DelegationRole {
		want = 8
	}
	if p[0] != want|0x80000000 {
		return nil, errJ7Key
	}
	for _, n := range p[1:] {
		if n == 0x80000000 {
			return nil, errJ7Key
		}
	}
	return p, nil
}

func j7MAC(key, data []byte) (out [64]byte) {
	h := hmac.New(sha512.New, key)
	_, _ = h.Write(data)
	sum := h.Sum(nil)
	copy(out[:], sum)
	erase(sum)
	return
}

// deriveJ7Node implements only SLIP-0010's hardened HMAC/retry protocol.
// Scalar operations are supplied by the pinned curve library. An invalid child
// retries at the SAME index with 0x01 || prior IR || ser32(i), never i+1.
func deriveJ7Node(seed []byte, path []uint32, mac func([]byte, []byte) [64]byte) ([64]byte, error) {
	var zero [64]byte
	if len(seed) < 16 || len(seed) > 64 {
		return zero, errJ7Key
	}
	for _, i := range path {
		if i&0x80000000 == 0 {
			return zero, errJ7Key
		}
	}
	node := mac([]byte("Bitcoin seed"), seed)
	var scalar btcec.ModNScalar
	defer scalar.Zero()
	for scalar.SetByteSlice(node[:32]) || scalar.IsZero() {
		next := mac([]byte("Bitcoin seed"), node[:])
		erase(node[:])
		node = next
		erase(next[:])
	}
	for _, index := range path {
		var data [37]byte
		copy(data[1:33], node[:32])
		binary.BigEndian.PutUint32(data[33:], index)
		for {
			child := mac(node[32:], data[:])
			var tweak btcec.ModNScalar
			overflow := tweak.SetByteSlice(child[:32])
			// IL=0 is valid for a child when IL+parent remains nonzero.
			tweak.Add(&scalar)
			if !overflow && !tweak.IsZero() {
				scalar.Set(&tweak)
				scalar.PutBytesUnchecked(child[:32])
				erase(node[:])
				node = child
				tweak.Zero()
				erase(child[:])
				break
			}
			tweak.Zero()
			data[0] = 1
			copy(data[1:33], child[32:])
			erase(child[:])
		}
		erase(data[:])
	}
	return node, nil
}

func j7Verify(public, message, signature []byte) bool {
	if len(public) != 32 || len(message) != 32 || len(signature) != 64 {
		return false
	}
	p, err := schnorr.ParsePubKey(public)
	if err != nil {
		return false
	}
	s, err := schnorr.ParseSignature(signature)
	return err == nil && s.Verify(message, p)
}

// withPath holds custody through fresh auxiliary entropy, library signing and
// self-verification. It is not admission, typed-body validation or effect release.
func (k *j7Key) withPath(path string, message *[32]byte) ([]byte, error) {
	if k == nil {
		return nil, errJ7Key
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed || len(k.seed) != 32 {
		return nil, errJ7Key
	}
	p, err := validateJ7Path(path, k.role)
	if err != nil {
		return nil, err
	}
	node, err := deriveJ7Node(k.seed, p, j7MAC)
	if err != nil {
		return nil, err
	}
	defer erase(node[:])
	var scalar btcec.ModNScalar
	if scalar.SetByteSlice(node[:32]) || scalar.IsZero() {
		scalar.Zero()
		return nil, errJ7Key
	}
	private := btcec.PrivKeyFromScalar(&scalar)
	scalar.Zero()
	defer private.Zero()
	public := schnorr.SerializePubKey(private.PubKey())
	if message == nil {
		return public, nil
	}
	var aux [32]byte
	defer erase(aux[:])
	if k.entropy == nil {
		return nil, errJ7Key
	}
	if _, err := io.ReadFull(k.entropy, aux[:]); err != nil {
		return nil, errJ7Key
	}
	sig, err := schnorr.Sign(private, message[:], schnorr.CustomNonce(aux))
	if err != nil {
		return nil, errJ7Key
	}
	result := sig.Serialize()
	if !j7Verify(public, message[:], result) {
		erase(result)
		return nil, errJ7Key
	}
	return result, nil
}

// request reselects the exact protected active binding. No caller path/key is
// accepted. Future admission must already hold the generation/run barrier.
func (k *j7Key) request(store *Store, selected Binding, message *[32]byte) ([]byte, error) {
	if k == nil || k.role != j7RequestRole || store == nil {
		return nil, errJ7Key
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, c := store.lookup(selected.UID, selected.Generation)
	if c != "" || current != selected || k.epoch == "" || current.Epoch != k.epoch || k.registry == "" || current.RegistryRevision != k.registry {
		return nil, errJ7Key
	}
	if ValidatePath(current.Path, "agent-identity") != "" {
		return nil, errJ7Key
	}
	return k.withPath("m/7'"+strings.TrimPrefix(current.Path, "m/1'"), message)
}

// A retained parent-slot source owns allocation/provenance and holds its
// exclusion barrier through use. There is intentionally no production source
// yet. A supplied integer or public parent ID is not an allocation credential.
type j7ParentSlots interface {
	withParentSlot(reference string, use func(j7ParentSlot) error) error
}
type j7ParentSlot struct {
	instance, epoch, registry, parent string
	product, project, slot            uint32
}

// parent public-key provisioning precedes the parent's signature. Signing also
// requires the exact bound parent. Full child/node/lifecycle admission is later.
func (k *j7Key) parent(source j7ParentSlots, reference string, message *[32]byte) ([]byte, error) {
	if k == nil || k.role != j7DelegationRole || source == nil || reference == "" {
		return nil, errJ7Key
	}
	var result []byte
	calls := 0
	err := source.withParentSlot(reference, func(row j7ParentSlot) error {
		calls++
		if calls != 1 || row.instance != k.instance || row.epoch != k.epoch || row.registry != k.registry || message != nil && row.parent != reference {
			return errJ7Key
		}
		for _, n := range []uint32{row.product, row.project, row.slot} {
			if n == 0 || n > 0x7fffffff {
				return errJ7Key
			}
		}
		path := fmt.Sprintf("m/8'/%d'/%d'/%d'", row.product, row.project, row.slot)
		var err error
		result, err = k.withPath(path, message)
		return err
	})
	want := 32
	if message != nil {
		want = 64
	}
	if err != nil || calls != 1 || len(result) != want {
		erase(result)
		return nil, errJ7Key
	}
	return result, nil
}
