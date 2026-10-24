package keymaker

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"

	"github.com/relux-works/waggle/record"
)

// messageKeyAdapter is reserved for K3. No production constructor/dispatch uses
// it. A future caller must hold the generation admission/release barrier; this
// adapter additionally rechecks the selected registration under the Store lock.
// It neither certifies authority nor provides a message-admission API.
type messageKeyAdapter struct {
	master                  *Master
	store                   *Store
	epoch, registryRevision string
}

// withKey keeps selection and custody use ordered against binding withdrawal.
// Lock order is generation (held by future caller) -> Store -> Master.
func (a messageKeyAdapter) withKey(selected Binding, use func(ed25519.PrivateKey) []byte) ([]byte, Code) {
	if a.store == nil {
		return nil, "binding_not_found"
	}
	a.store.mu.Lock()
	defer a.store.mu.Unlock()
	current, c := a.store.lookup(selected.UID, selected.Generation)
	if c != "" {
		return nil, c
	}
	if current != selected || a.epoch == "" || current.Epoch != a.epoch || a.registryRevision == "" || current.RegistryRevision != a.registryRevision {
		return nil, "binding_conflict"
	}
	if c := ValidatePath(current.Path, "agent-identity"); c != "" {
		return nil, c
	}
	// Only the purpose ancestor changes; there is no caller-selected sibling path,
	// generation hash, extra component or allocation in this capability.
	path := "m/4'" + strings.TrimPrefix(current.Path, "m/1'")
	return a.master.withPurpose(path, "swarma-msg", use)
}

// sign is an unused purpose-4 custody capability reserved for S3. It supplies no
// admission, certification, durable retry, audit or release authorization itself.
func (a messageKeyAdapter) sign(selected Binding, preimage []byte) ([]byte, Code) {
	return a.withKey(selected, func(key ed25519.PrivateKey) []byte { return ed25519.Sign(key, preimage) })
}

// public assembles a candidate ID with the standard base64 codec. The pinned
// record API has no encoder: KeyBytes owns canonical encoding/length validation
// and ValidateKey owns curve/subgroup validation; neither is copied here.
func (a messageKeyAdapter) public(selected Binding) ([]byte, string, Code) {
	public, code := a.withKey(selected, func(key ed25519.PrivateKey) []byte { return append([]byte(nil), key[32:]...) })
	if code != "" {
		return nil, "", code
	}
	id := "ed25519:" + base64.RawURLEncoding.EncodeToString(public)
	algorithm, decoded, err := record.KeyBytes(id)
	if err != nil || algorithm != "ed25519" || !bytes.Equal(decoded, public) || record.ValidateKey(id) != nil {
		return nil, "", "sign_key_mismatch"
	}
	return public, id, ""
}
