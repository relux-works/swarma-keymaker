package keymaker

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func readFixture(t *testing.T, name string, v any) {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("../../vectors", name))
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, v); e != nil {
		t.Fatal(e)
	}
}
func fromHex(t *testing.T, s string) []byte {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

// All independently published nodes check the private derivation routine against
// public-key/chain-code oracles; these public test seeds never become deployment keys.
func TestPublishedDerivation(t *testing.T) {
	var f struct {
		Vectors []struct {
			ID    string `json:"id"`
			Seed  string `json:"seed_hex"`
			Nodes []struct {
				Path   string `json:"path"`
				Chain  string `json:"chain_code_hex"`
				Public string `json:"public_key_slip_hex"`
			} `json:"nodes"`
		} `json:"vectors"`
	}
	readFixture(t, "slip0010-ed25519.json", &f)
	for _, v := range f.Vectors {
		for _, n := range v.Nodes {
			t.Run(v.ID+"/"+n.Path, func(t *testing.T) {
				p, c := parsePath(n.Path)
				if c != "" {
					t.Fatal(c)
				}
				node := deriveNode(fromHex(t, v.Seed), p)
				defer erase(node)
				key := ed25519.NewKeyFromSeed(node[:32])
				defer erase(key)
				if hex.EncodeToString(node[32:]) != n.Chain || "00"+hex.EncodeToString(key[32:]) != n.Public {
					t.Fatal("published derivation mismatch")
				}
			})
		}
	}
}

// The name registry resolves each shipped tuple to the fixed independently stored
// path and derived public key, including host-purpose and ancestor separation.
func TestRegistryPathVectors(t *testing.T) {
	var f struct {
		Seed     string   `json:"seed_hex"`
		Registry Registry `json:"registry"`
		Vectors  []struct {
			ID     string `json:"id"`
			Names  Names  `json:"names"`
			Path   string `json:"path"`
			Public string `json:"public_key_hex"`
		} `json:"vectors"`
	}
	readFixture(t, "keymaker-paths.json", &f)
	for _, v := range f.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			path, c := f.Registry.Resolve(v.Names)
			if c != "" || path != v.Path {
				t.Fatal("registry resolution mismatch", c)
			}
			indices, c := parsePath(path)
			if c != "" {
				t.Fatal(c)
			}
			node := deriveNode(fromHex(t, f.Seed), indices)
			defer erase(node)
			key := ed25519.NewKeyFromSeed(node[:32])
			defer erase(key)
			if hex.EncodeToString(key[32:]) != v.Public {
				t.Fatal("path public mismatch")
			}
		})
	}
}

// Malformed/colliding registries and altered history refuse; valid append-only
// extension succeeds. No lookup performs an implicit allocation.
func TestRegistryRejectsInvalidHistory(t *testing.T) {
	base := Registry{Products: []Product{{Name: "sample", Index: 1, Projects: []Project{{Name: "core", Index: 1, Agents: []AgentName{{Name: "worker", Index: 1}}}}}}}
	for _, bad := range []Registry{{Products: []Product{{Name: "sample", Index: 2}}}, {Products: []Product{{Name: "Sample", Index: 1}}}, {Products: []Product{{Name: "sample", Index: 1}, {Name: "sample", Index: 2}}}} {
		if bad.Validate() != "name_registry_invalid" {
			t.Fatal("invalid registry accepted")
		}
	}
	next := base
	next.Products = append(append([]Product(nil), base.Products...), Product{Name: "other", Index: 2})
	if next.Extends(base) != "" || base.Extends(next) != "name_registry_invalid" {
		t.Fatal("history extension invariant")
	}
	if _, c := base.Resolve(Names{"agent-identity", "unknown", "core", "worker"}); c != "name_unknown" {
		t.Fatal(c)
	}
	if _, c := base.Resolve(Names{"agent-identity", "Sample", "core", "worker"}); c != "name_invalid" {
		t.Fatal(c)
	}
}

// Unsafe file types/modes/owners/parents/lengths cannot load a master. The nearby
// valid control signs, verifies and refuses use after best-effort zeroising Close.
func TestMasterStorageGuards(t *testing.T) {
	for _, kind := range []string{"mode", "owner", "parent-mode", "symlink", "parent-symlink", "hardlink", "short", "long", "directory", "valid"} {
		t.Run(kind, func(t *testing.T) {
			d := t.TempDir()
			if e := os.Chmod(d, 0700); e != nil {
				t.Fatal(e)
			}
			p := filepath.Join(d, "master.seed")
			data := bytes.Repeat([]byte{7}, 32)
			if kind == "short" {
				data = data[:31]
			}
			if kind == "long" {
				data = append(data, 8)
			}
			if e := os.WriteFile(p, data, 0600); e != nil {
				t.Fatal(e)
			}
			uid := uint32(os.Getuid())
			switch kind {
			case "mode":
				os.Chmod(p, 0640)
			case "owner":
				uid++
			case "parent-mode":
				os.Chmod(d, 0755)
			case "symlink":
				os.Rename(p, p+".real")
				os.Symlink(p+".real", p)
			case "parent-symlink":
				os.Symlink(d, d+"-link")
				t.Cleanup(func() { os.Remove(d + "-link") })
				p = filepath.Join(d+"-link", "master.seed")
			case "hardlink":
				os.Link(p, p+".link")
			case "directory":
				os.Remove(p)
				os.Mkdir(p, 0600)
			}
			m, e := LoadMaster(p, uid)
			if kind != "valid" {
				if e == nil {
					m.Close()
					t.Fatal("unsafe master accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			pub, c := m.Public("m/1'/1'/1'/1'")
			if c != "" {
				t.Fatal(c)
			}
			sig, c := m.Sign("m/1'/1'/1'/1'", []byte("fixture"))
			if c != "" || !ed25519.Verify(pub, []byte("fixture"), sig) {
				t.Fatal("valid master signing failed")
			}
			m.Close()
			if _, c = m.Sign("m/1'/1'/1'/1'", nil); c == "" {
				t.Fatal("closed master used")
			}
		})
	}
}
