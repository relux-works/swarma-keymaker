//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func j7Hex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func j7Fixture(t *testing.T, role string) *j7Key {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	k := &j7Key{seed: seed, role: role, instance: strings.Repeat("1", 32), epoch: "epoch", registry: "registry", entropy: bytes.NewReader(make([]byte, 256))}
	t.Cleanup(func() { _ = k.close() })
	return k
}
func j7Binding() Binding {
	return Binding{UID: 1001, Generation: "generation", Path: "m/1'/1'/2'/3'", Owner: "owner", Number: 1, Lifetime: "persistent", Status: "active", Epoch: "epoch", RegistryRevision: "registry"}
}
func j7Store(b Binding) *Store { s := NewStore(); s.records = []Binding{b}; s.next = 2; return s }
func j7Config(role string) string {
	return `{"service_role":"` + role + `","j7_key_file":"/fixture/root","instance_id":"11111111111111111111111111111111","service_uid":1001,"service_gid":1001,"master_epoch":"epoch","registry_revision":"registry"}`
}

// Official positive/negative BIP-340 vectors cover all 32-byte messages, including
// strict scalar/field/parity failures. Four variable-length valid vectors are
// outside this backend's explicit 32-byte profile, never called invalid BIP-340.
func TestJ7KeyOfficialBIP340(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/j7/bip340.csv")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != "34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d" {
		t.Fatal("official vector identity changed")
	}
	rows, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	checked, outside := 0, 0
	for _, r := range rows[1:] {
		public, message, sig := j7Hex(t, r[2]), j7Hex(t, r[4]), j7Hex(t, r[5])
		if len(message) != 32 {
			outside++
			if j7Verify(public, message, sig) {
				t.Fatal("accepted outside message profile")
			}
			continue
		}
		checked++
		want := r[6] == "TRUE"
		if j7Verify(public, message, sig) != want {
			t.Fatalf("official verification index %s", r[0])
		}
		if r[1] != "" {
			var scalar btcec.ModNScalar
			if scalar.SetByteSlice(j7Hex(t, r[1])) || scalar.IsZero() {
				t.Fatal("invalid public fixture scalar")
			}
			key := btcec.PrivKeyFromScalar(&scalar)
			scalar.Zero()
			var aux [32]byte
			copy(aux[:], j7Hex(t, r[3]))
			got, e := schnorr.Sign(key, message, schnorr.CustomNonce(aux))
			key.Zero()
			erase(aux[:])
			if e != nil || !bytes.Equal(got.Serialize(), sig) {
				t.Fatalf("official signing index %s", r[0])
			}
		}
	}
	if checked != 15 || outside != 4 {
		t.Fatalf("corpus scope %d/%d", checked, outside)
	}
	base := rows[1]
	p, m, s := j7Hex(t, base[2]), j7Hex(t, base[4]), j7Hex(t, base[5])
	for _, bad := range [][]byte{s[:63], append(append([]byte{}, s...), 0), nil} {
		if j7Verify(p, m, bad) {
			t.Fatal("signature length accepted")
		}
	}
	for _, bad := range [][]byte{p[:31], append([]byte{2}, p...), append([]byte{3}, p...), bytes.Repeat([]byte{255}, 32)} {
		if j7Verify(bad, m, s) {
			t.Fatal("non x-only/invalid key accepted")
		}
	}
}

type j7VectorFile struct {
	Format   string `json:"format"`
	TestOnly bool   `json:"test_only"`
	Seed     string `json:"slip_seed_hex"`
	Nodes    []struct {
		Path    string `json:"path"`
		Chain   string `json:"chain_code_hex"`
		Private string `json:"private_hex"`
		Public  string `json:"public_compressed_hex"`
	} `json:"slip_nodes"`
	Synthetic string `json:"synthetic_seed_hex"`
	Cases     []struct {
		Role   string `json:"role"`
		Path   string `json:"path"`
		Public string `json:"public_x_hex"`
	} `json:"cases"`
}

// Published SLIP-0010 master and first hardened child anchor private, chain and
// public bytes independently; synthetic four-level role fixtures anchor siblings.
func TestJ7KeySLIPVectors(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/j7/keys.json")
	if err != nil {
		t.Fatal(err)
	}
	var v j7VectorFile
	if json.Unmarshal(raw, &v) != nil || !v.TestOnly || v.Format != "keymaker-j7-keys/1" || len(v.Nodes) != 2 || len(v.Cases) != 3 {
		t.Fatal("fixture contract")
	}
	for _, row := range v.Nodes {
		p, c := parsePath(row.Path)
		if c != "" {
			t.Fatal(c)
		}
		node, err := deriveJ7Node(j7Hex(t, v.Seed), p, j7MAC)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := btcec.PrivKeyFromBytes(node[:32])
		if hex.EncodeToString(node[:32]) != row.Private || hex.EncodeToString(node[32:]) != row.Chain || hex.EncodeToString(key.PubKey().SerializeCompressed()) != row.Public {
			t.Fatalf("published node %s", row.Path)
		}
		key.Zero()
		erase(node[:])
	}
	seen := map[string]bool{}
	for _, row := range v.Cases {
		k := j7Fixture(t, row.Role)
		k.seed = j7Hex(t, v.Synthetic)
		public, err := k.withPath(row.Path, nil)
		if err != nil || hex.EncodeToString(public) != row.Public || seen[row.Public] {
			t.Fatalf("synthetic public fixture %s", row.Path)
		}
		seen[row.Public] = true
	}
}

// Controlled HMAC outputs exercise standard zero/overflow master retry, child
// overflow/zero-sum retry and the valid zero-tweak neighbour at the SAME index.
func TestJ7KeyRetrySemantics(t *testing.T) {
	order := j7Hex(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	for _, masterBad := range [][]byte{make([]byte, 32), order} {
		calls := 0
		mac := func(key, data []byte) (out [64]byte) {
			calls++
			switch calls {
			case 1:
				copy(out[:32], masterBad)
				out[63] = 9
			case 2:
				if string(key) != "Bitcoin seed" || len(data) != 64 || data[63] != 9 {
					t.Fatal("master retry changed")
				}
				out[31] = 1
			}
			return
		}
		node, err := deriveJ7Node(make([]byte, 32), nil, mac)
		if err != nil || calls != 2 || node[31] != 1 {
			t.Fatal("master retry")
		}
		erase(node[:])
	}
	for _, bad := range [][]byte{order, j7Hex(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140")} {
		calls := 0
		mac := func(_ []byte, data []byte) (out [64]byte) {
			calls++
			switch calls {
			case 1:
				out[31] = 1
			case 2:
				if data[0] != 0 || !bytes.Equal(data[33:], []byte{128, 0, 0, 7}) {
					t.Fatal("child initial path")
				}
				copy(out[:32], bad)
				out[63] = 9
			case 3:
				if data[0] != 1 || data[32] != 9 || !bytes.Equal(data[33:], []byte{128, 0, 0, 7}) {
					t.Fatal("child retry skipped index or IR")
				}
				out[31] = 2
			}
			return
		}
		node, err := deriveJ7Node(make([]byte, 32), []uint32{0x80000007}, mac)
		if err != nil || calls != 3 || node[31] != 3 {
			t.Fatal("child retry")
		}
		erase(node[:])
	}
	calls := 0
	node, err := deriveJ7Node(make([]byte, 32), []uint32{0x80000007}, func(_, _ []byte) (out [64]byte) {
		calls++
		if calls == 1 {
			out[31] = 1
		}
		return
	})
	if err != nil || calls != 2 || node[31] != 1 {
		t.Fatal("zero child tweak incorrectly refused")
	}
	erase(node[:])
	if _, err := deriveJ7Node(make([]byte, 32), []uint32{7}, j7MAC); err == nil {
		t.Fatal("nonhardened derivation")
	}
}

// Exact active binding/epoch/registry selection is ordered by Store; aux entropy
// is consumed freshly per signature. Wrong role, stale binding or entropy failure
// yields no result, beside real self-verifying request signatures.
func TestJ7PurposeRequestSelection(t *testing.T) {
	k := j7Fixture(t, j7RequestRole)
	b := j7Binding()
	store := j7Store(b)
	public, err := k.request(store, b, nil)
	if err != nil {
		t.Fatal(err)
	}
	var message [32]byte
	k.entropy = bytes.NewReader(append(make([]byte, 32), bytes.Repeat([]byte{1}, 32)...))
	sig1, err := k.request(store, b, &message)
	if err != nil || !j7Verify(public, message[:], sig1) {
		t.Fatal("valid request signing")
	}
	sig2, err := k.request(store, b, &message)
	if err != nil || bytes.Equal(sig1, sig2) || !j7Verify(public, message[:], sig2) {
		t.Fatal("fresh auxiliary entropy")
	}
	if sig, err := k.request(store, b, &message); err == nil || sig != nil {
		t.Fatal("entropy exhaustion produced output")
	}
	for _, change := range []func(*Binding){func(x *Binding) { x.Number++ }, func(x *Binding) { x.Path = "m/1'/1'/2'/4'" }, func(x *Binding) { x.Epoch = "other" }, func(x *Binding) { x.RegistryRevision = "other" }, func(x *Binding) { x.Generation = "other" }, func(x *Binding) { x.UID++ }} {
		bad := b
		change(&bad)
		if got, err := k.request(store, bad, nil); err == nil || got != nil {
			t.Fatal("changed binding admitted")
		}
	}
	for _, status := range []string{"unbound", "revoked"} {
		bad := b
		bad.Status = status
		if got, err := k.request(j7Store(bad), bad, nil); err == nil || got != nil {
			t.Fatal("inactive binding admitted")
		}
	}
	if got, err := j7Fixture(t, j7DelegationRole).request(store, b, nil); err == nil || got != nil {
		t.Fatal("delegation role used request path")
	}
	for _, path := range []string{"m/1'/1'/2'/3'", "m/8'/1'/2'/3'", "m/7'/1'/2'/3", "m/7'/1'/2'", "m/7'/0'/2'/3'"} {
		if got, err := k.withPath(path, nil); err == nil || got != nil {
			t.Fatal("wrong path admitted")
		}
	}
	_ = k.close()
	if got, err := k.request(store, b, nil); err == nil || got != nil {
		t.Fatal("closed custody admitted")
	}
}

type j7FixtureSlots struct {
	row       j7ParentSlot
	reference string
}

func (s j7FixtureSlots) withParentSlot(ref string, use func(j7ParentSlot) error) error {
	if ref != s.reference {
		return errJ7Key
	}
	return use(s.row)
}

// Protected slot-source fixtures show namespace/key separation and source pin
// checks only. They do not implement durable allocation, node or child admission.
func TestJ7PurposeParentSelection(t *testing.T) {
	k := j7Fixture(t, j7DelegationRole)
	row := j7ParentSlot{instance: k.instance, epoch: k.epoch, registry: k.registry, product: 1, project: 2, slot: 1}
	source := j7FixtureSlots{row: row, reference: "allocation"}
	public, err := k.parent(source, "allocation", nil)
	if err != nil {
		t.Fatal(err)
	}
	var message [32]byte
	if got, err := k.parent(source, "allocation", &message); err == nil || got != nil {
		t.Fatal("unbound parent signed")
	}
	source.row.parent = "parent"
	source.reference = "parent"
	sig, err := k.parent(source, "parent", &message)
	if err != nil || !j7Verify(public, message[:], sig) {
		t.Fatal("bound fixture primitive", err)
	}
	source.row.slot = 2
	next, err := k.parent(source, "parent", nil)
	if err != nil || bytes.Equal(public, next) {
		t.Fatal("parent slot key isolation")
	}
	if got, err := k.parent(nil, "parent", nil); err == nil || got != nil {
		t.Fatal("bare reference without source admitted")
	}
	for _, change := range []func(*j7ParentSlot){func(r *j7ParentSlot) { r.instance = "other" }, func(r *j7ParentSlot) { r.epoch = "other" }, func(r *j7ParentSlot) { r.registry = "other" }, func(r *j7ParentSlot) { r.parent = "other" }, func(r *j7ParentSlot) { r.slot = 0 }, func(r *j7ParentSlot) { r.slot = 0x80000000 }, func(r *j7ParentSlot) { r.product = 0 }} {
		bad := source
		change(&bad.row)
		if got, err := k.parent(bad, "parent", &message); err == nil || got != nil {
			t.Fatal("wrong protected slot facts admitted")
		}
	}
	if got, err := j7Fixture(t, j7RequestRole).parent(source, "parent", nil); err == nil || got != nil {
		t.Fatal("request key selected delegation slot")
	}
}

// Explicit initialization publishes complete fixture roots without overwrite;
// entropy/partial-write faults leave no loadable target. Role/instance checks
// and filesystem protection refuse bad neighbours; restart never recreates loss.
func TestJ7KeyInitializationAndLoading(t *testing.T) {
	uid := uint32(os.Getuid())
	instance := strings.Repeat("1", 32)
	fresh := func() string {
		dir := t.TempDir()
		if os.Chmod(dir, 0700) != nil {
			t.Fatal("chmod fixture")
		}
		return filepath.Join(dir, "root")
	}
	load := func(path string, role, id string) (*j7Key, error) {
		return loadJ7Key(path, uid, role, id, "epoch", "registry")
	}
	path := fresh()
	if err := InitializeJ7Seed(path, uid, j7RequestRole, instance); err != nil {
		t.Fatal(err)
	}
	k, err := load(path, j7RequestRole, instance)
	if err != nil {
		t.Fatal(err)
	}
	defer k.close()
	if legacy, err := LoadMaster(path, uid); err == nil {
		legacy.Close()
		t.Fatal("secp record accepted as legacy master")
	}
	before, _ := os.ReadFile(path)
	if err := InitializeJ7Seed(path, uid, j7RequestRole, instance); err == nil {
		t.Fatal("overwrote established root")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing root changed")
	}
	erase(before)
	erase(after)
	for _, pair := range [][2]string{{j7DelegationRole, instance}, {j7RequestRole, strings.Repeat("2", 32)}, {"legacy", instance}} {
		if got, err := load(path, pair[0], pair[1]); err == nil || got != nil {
			t.Fatal("wrong role/instance admitted")
		}
	}
	for _, fault := range []string{"entropy", "short-success", "write-error"} {
		p := fresh()
		reader := io.Reader(bytes.NewReader(make([]byte, 3)))
		writer := func(f *os.File, b []byte) error { _, e := f.Write(b); return e }
		if fault != "entropy" {
			reader = bytes.NewReader(make([]byte, 32))
			writer = func(f *os.File, b []byte) error { _, _ = f.Write(b[:len(b)-1]); return nil }
			if fault == "write-error" {
				writer = func(f *os.File, b []byte) error { _, _ = f.Write(b[:3]); return io.ErrShortWrite }
			}
		}
		if err := initializeJ7Seed(p, uid, j7RequestRole, instance, reader, writer); err == nil {
			t.Fatal("fault accepted")
		}
		if got, err := load(p, j7RequestRole, instance); err == nil || got != nil {
			t.Fatal("partial seed load accepted")
		}
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("fault published target")
		}
	}
	other := fresh()
	if err := InitializeJ7Seed(other, uid, j7DelegationRole, strings.Repeat("2", 32)); err != nil {
		t.Fatal(err)
	}
	d, err := loadJ7Key(other, uid, j7DelegationRole, strings.Repeat("2", 32), "epoch", "registry")
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	p1, e1 := k.withPath("m/7'/1'/2'/3'", nil)
	p2, e2 := d.withPath("m/8'/1'/2'/3'", nil)
	if e1 != nil || e2 != nil || bytes.Equal(p1, p2) || bytes.Equal(k.seed, d.seed) {
		t.Fatal("isolated roots not independent")
	}
	// Correct role/path under a separately generated request instance also differs.
	p := fresh()
	if InitializeJ7Seed(p, uid, j7RequestRole, strings.Repeat("3", 32)) != nil {
		t.Fatal("second request init")
	}
	k2, e := load(p, j7RequestRole, strings.Repeat("3", 32))
	if e != nil {
		t.Fatal(e)
	}
	defer k2.close()
	p3, e := k2.withPath("m/7'/1'/2'/3'", nil)
	if e != nil || bytes.Equal(p1, p3) {
		t.Fatal("same namespace independent instances")
	}
	for _, mode := range []os.FileMode{0644, 0400} {
		if os.Chmod(path, mode) != nil {
			t.Fatal("chmod")
		}
		if got, err := load(path, j7RequestRole, instance); err == nil || got != nil {
			t.Fatal("wrong seed mode admitted")
		}
	}
	_ = os.Chmod(path, 0600)
	if got, err := loadJ7Key(path, uid+1, j7RequestRole, instance, "epoch", "registry"); err == nil || got != nil {
		t.Fatal("wrong owner admitted")
	}
	link := filepath.Join(filepath.Dir(path), "hardlink")
	if os.Link(path, link) != nil {
		t.Fatal("hardlink fixture")
	}
	if got, err := load(path, j7RequestRole, instance); err == nil || got != nil {
		t.Fatal("hardlink admitted")
	}
	_ = os.Remove(link)
	symlink := filepath.Join(filepath.Dir(path), "link")
	if os.Symlink(path, symlink) != nil {
		t.Fatal("symlink fixture")
	}
	if got, err := load(symlink, j7RequestRole, instance); err == nil || got != nil {
		t.Fatal("symlink admitted")
	}
	_ = os.Chmod(filepath.Dir(path), 0755)
	if got, err := load(path, j7RequestRole, instance); err == nil || got != nil {
		t.Fatal("unsafe directory admitted")
	}
	_ = os.Chmod(filepath.Dir(path), 0700)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got, err := load(path, j7RequestRole, instance); err == nil || got != nil {
		t.Fatal("missing established root admitted")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("loader recreated root")
	}
	for _, raw := range [][]byte{make([]byte, 32), []byte(j7SeedMagic), append([]byte(j7SeedMagic+j7RequestRole+"\n"+instance+"\n"), make([]byte, 33)...)} {
		p := fresh()
		if os.WriteFile(p, raw, 0600) != nil {
			t.Fatal("write fixture")
		}
		if got, err := load(p, j7RequestRole, instance); err == nil || got != nil {
			t.Fatal("malformed seed record admitted")
		}
	}
}

// The config union distinguishes roles and fails startup before touching any
// fixture path or opening sockets. Legacy fixtures keep their original decoder.
func TestJ7PurposeConfigStartup(t *testing.T) {
	for _, role := range []string{j7RequestRole, j7DelegationRole} {
		cfg, err := ParseConfig(strings.NewReader(j7Config(role)))
		if err != nil {
			t.Fatal(err)
		}
		var status bytes.Buffer
		want := Code("operation_unsupported")
		if role == j7RequestRole {
			want = "j7_configuration_incomplete"
		}
		if err := serveValidatedConfig(context.Background(), cfg, &status, nil); err != want || status.Len() != 0 {
			t.Fatal("new profile reached legacy startup", err)
		}
		if err := serveWithClock(context.Background(), cfg, &status, nil, nil); err != Code("operation_unsupported") {
			t.Fatal("direct startup bypass", err)
		}
		for _, bad := range []string{strings.Replace(j7Config(role), `"service_uid":1001`, `"master_file":"/fixture/legacy","service_uid":1001`, 1), strings.Replace(j7Config(role), `"j7_key_file":"/fixture/root",`, "", 1), strings.Replace(j7Config(role), role, "unknown", 1), strings.Replace(j7Config(role), `"service_role":"`+role+`"`, `"service_role":null`, 1), strings.Replace(j7Config(role), `"instance_id":"11111111111111111111111111111111"`, `"instance_id":"00000000000000000000000000000000"`, 1)} {
			if _, err := ParseConfig(strings.NewReader(bad)); err == nil {
				t.Fatal("mixed/invalid role configuration admitted")
			}
		}
	}
	for _, purpose := range []string{"j7-request", "delegation", "lip14-delegation"} {
		if ValidatePath("m/7'/1'/2'/3'", purpose) == "" {
			t.Fatal("legacy purpose widened")
		}
	}
	m := &Master{seed: make([]byte, 32)}
	defer m.Close()
	for _, p := range []string{"m/7'/1'/2'/3'", "m/8'/1'/2'/3'"} {
		if public, c := m.Public(p); c == "" || public != nil {
			t.Fatal("legacy public API widened")
		}
		if sig, c := m.Sign(p, make([]byte, 32)); c == "" || sig != nil {
			t.Fatal("legacy signing API widened")
		}
	}
}

// Legacy internal Master selection, name resolution and registration keep their
// purpose allowlists. Refused registrations consume no binding number or state;
// nearby legacy positives demonstrate that these paths are otherwise usable.
func TestJ7PurposeLegacyIsolation(t *testing.T) {
	m := &Master{seed: make([]byte, 32)}
	defer m.Close()
	called := false
	use := func(key ed25519.PrivateKey) []byte { called = true; return append([]byte(nil), key[32:]...) }
	if public, code := m.withPurpose("m/1'/1'/1'/1'", "agent-identity", use); code != "" || len(public) != 32 || !called {
		t.Fatal("legacy internal positive", code)
	}
	registry := nativeRegistry()
	for _, row := range []struct{ purpose, path string }{{"j7-request", "m/7'/1'/1'/1'"}, {"delegation", "m/8'/1'/1'/1'"}, {"child-delegation", "m/8'/1'/1'/1'"}, {"lip14-delegation", "m/8'/1'/1'/1'"}} {
		called = false
		if public, code := m.withPurpose(row.path, row.purpose, use); code != "purpose_unknown" || public != nil || called {
			t.Fatal("legacy internal purpose widened", code)
		}
		if path, code := registry.Resolve(Names{Purpose: row.purpose, Product: "sample", Project: "core", Agent: "station-a"}); code != "purpose_unknown" || path != "" {
			t.Fatal("legacy name purpose widened", code)
		}
		s := NewStore()
		b := fixtureBinding(30001)
		b.Path = row.path
		if _, code := s.Register(fixtureOperator, fixtureOperator, b); code != "binding_conflict" || len(s.Snapshot()) != 0 || s.next != 1 {
			t.Fatal("legacy registration widened or changed state", code)
		}
		b.Path = "m/1'/1'/1'/1'"
		if registered, code := s.Register(fixtureOperator, fixtureOperator, b); code != "" || registered.Number != 1 {
			t.Fatal("legacy registration positive", code)
		}
	}
	if path, code := registry.Resolve(Names{Purpose: "agent-identity", Product: "sample", Project: "core", Agent: "station-a"}); code != "" || path != "m/1'/1'/1'/1'" {
		t.Fatal("legacy registry positive", code)
	}
}

// Reflection/AST guards detect secret-accessor or field exports; redacted format
// and refused serialization are executable controls on synthetic roots only.
func TestJ7NoSecretExport(t *testing.T) {
	k := j7Fixture(t, j7RequestRole)
	for _, format := range []string{"%v", "%+v", "%#v", "%x"} {
		if fmt.Sprintf(format, k) != "[key custody]" {
			t.Fatal("custody diagnostics expose state")
		}
	}
	if b, err := json.Marshal(k); err == nil || b != nil {
		t.Fatal("custody serialized")
	}
	typ := reflect.TypeOf(k)
	for i := 0; i < typ.Elem().NumField(); i++ {
		if typ.Elem().Field(i).PkgPath == "" {
			t.Fatal("exported custody field")
		}
	}
	allowed := map[string]bool{"Format": true, "MarshalJSON": true, "MarshalText": true}
	for i := 0; i < typ.NumMethod(); i++ {
		if !allowed[typ.Method(i).Name] {
			t.Fatalf("unreviewed exported custody method %s", typ.Method(i).Name)
		}
	}
	for _, name := range []string{"j7_key.go", "j7_key_linux.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.IsExported() && fn.Name.Name != "InitializeJ7Seed" {
				t.Fatalf("unreviewed key API %s", fn.Name.Name)
			}
		}
	}
	for _, name := range []string{"native.go", "../control/server.go"} {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		// PR3's opt-in control dispatch is authorized. Legacy Native still
		// exposes neither typed signing nor child signing; all control handlers
		// keep child signing closed. Executable adapter tests cover the marker.
		methods := []string{`"sign_child_grant"`}
		if name == "native.go" {
			methods = append(methods, `"j7_sign"`)
		}
		for _, method := range methods {
			if bytes.Contains(b, []byte(method)) {
				t.Fatal("forbidden transport route registered")
			}
		}
	}
}
