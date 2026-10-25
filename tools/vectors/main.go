// Offline fixture tooling only. Never read an installation master or service state.
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Agent struct {
	Name  string `json:"name"`
	Index uint32 `json:"index"`
}
type Project struct {
	Name   string  `json:"name"`
	Index  uint32  `json:"index"`
	Agents []Agent `json:"agents"`
}
type Product struct {
	Name     string    `json:"name"`
	Index    uint32    `json:"index"`
	Projects []Project `json:"projects"`
}
type Registry struct {
	Products []Product `json:"products"`
}
type Names struct {
	Purpose string `json:"purpose"`
	Product string `json:"product"`
	Project string `json:"project"`
	Agent   string `json:"agent"`
}
type PathVector struct {
	ID      string   `json:"id"`
	Names   Names    `json:"names"`
	Path    string   `json:"path"`
	Indices []uint32 `json:"hardened_indices"`
	Public  string   `json:"public_key_hex"`
	Chain   string   `json:"chain_code_hex"`
	SSH     string   `json:"ssh_public_key"`
}
type Paths struct {
	Format   string       `json:"format"`
	Seed     string       `json:"seed_hex"`
	Registry Registry     `json:"registry"`
	Vectors  []PathVector `json:"vectors"`
}
type Published struct {
	Format  string `json:"format"`
	Source  string `json:"source"`
	SHA256  string `json:"source_sha256"`
	Note    string `json:"note"`
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
type Input map[string]any
type Refusals struct {
	Format   string `json:"format"`
	Note     string `json:"note"`
	Negative []struct {
		ID       string `json:"id"`
		Claim    string `json:"claim"`
		Input    Input  `json:"input"`
		Code     string `json:"expected_code"`
		Wire     string `json:"expected_wire_hex,omitempty"`
		Control  string `json:"positive_control"`
		Mutation string `json:"mutation_path"`
	} `json:"negative"`
	Positive []struct {
		ID     string `json:"id"`
		Claim  string `json:"claim"`
		Input  Input  `json:"input"`
		Result string `json:"expected_result"`
	} `json:"positive"`
}

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func require(ok bool, msg string) {
	if !ok {
		fail(fmt.Errorf("%s", msg))
	}
}
func read(path string, v any) []byte {
	b, err := os.ReadFile(path)
	fail(err)
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	fail(d.Decode(v))
	var extra any
	require(d.Decode(&extra) == io.EOF, path+": trailing JSON or decode error")
	return b
}

func decodeHex(s string) []byte { b, e := hex.DecodeString(s); fail(e); return b }
func mac(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	_, e := h.Write(data)
	fail(e)
	return h.Sum(nil)
}
func derive(seed []byte, path string) ([]byte, []byte) {
	require(len(seed) >= 16 && len(seed) <= 64, "SLIP seed length")
	parts := strings.Split(path, "/")
	require(parts[0] == "m", "path root")
	node := mac([]byte("ed25519 seed"), seed)
	for _, p := range parts[1:] {
		require(strings.HasSuffix(p, "'"), "non-hardened path")
		n, e := strconv.ParseUint(strings.TrimSuffix(p, "'"), 10, 31)
		fail(e)
		data := make([]byte, 37)
		copy(data[1:33], node[:32])
		binary.BigEndian.PutUint32(data[33:], uint32(n)|0x80000000)
		node = mac(node[32:], data)
	}
	key := ed25519.NewKeyFromSeed(node[:32])
	pub := key.Public().(ed25519.PublicKey)
	return pub, node[32:]
}
func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

var validName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func scope(entries []Agent) {
	names := map[string]bool{}
	indices := map[uint32]bool{}
	for _, e := range entries {
		require(validName.MatchString(e.Name) && e.Index > 0 && e.Index <= 0x7fffffff, "registry entry invalid")
		require(!names[e.Name] && !indices[e.Index], "registry collision")
		names[e.Name] = true
		indices[e.Index] = true
	}
	// This fixture contains the complete historical allocation of each scope.
	for i := 1; i <= len(entries); i++ {
		require(indices[uint32(i)], "fixture allocation is not contiguous")
	}
}
func resolve(r Registry, n Names) []uint32 {
	purpose := map[string]uint32{"agent-identity": 1, "host-registration": 2}[n.Purpose]
	require(purpose != 0, "unknown purpose")
	var products []Agent
	for _, p := range r.Products {
		products = append(products, Agent{p.Name, p.Index})
		var projects []Agent
		for _, q := range p.Projects {
			projects = append(projects, Agent{q.Name, q.Index})
			scope(q.Agents)
		}
		scope(projects)
	}
	scope(products)
	for _, p := range r.Products {
		if p.Name != n.Product {
			continue
		}
		for _, q := range p.Projects {
			if q.Name != n.Project {
				continue
			}
			for _, a := range q.Agents {
				if a.Name == n.Agent {
					return []uint32{purpose, p.Index, q.Index, a.Index}
				}
			}
		}
	}
	fail(fmt.Errorf("name tuple not in registry: %+v", n))
	return nil
}

// This check proves all 12 published Ed25519 public keys AND chain codes agree
// with an independent published oracle. It does not validate any daemon policy.
func checkPublished() {
	var p Published
	read("vectors/slip0010-ed25519.json", &p)
	require(len(p.Vectors) == 2, "published vector count")
	count := 0
	for _, v := range p.Vectors {
		require(len(v.Nodes) == 6, "published node count")
		for _, n := range v.Nodes {
			pub, chain := derive(decodeHex(v.Seed), n.Path)
			require("00"+hex.EncodeToString(pub) == n.Public, v.ID+" "+n.Path+": published public mismatch")
			require(hex.EncodeToString(chain) == n.Chain, v.ID+" "+n.Path+": published chain mismatch")
			count++
		}
	}
	fmt.Printf("published SLIP-0010 Ed25519 controls: %d nodes match\n", count)
}

func differences(a, b any, path string) []string {
	ma, oka := a.(map[string]any)
	mb, okb := b.(map[string]any)
	if oka && okb {
		keys := map[string]bool{}
		for k := range ma {
			keys[k] = true
		}
		for k := range mb {
			keys[k] = true
		}
		var out []string
		for k := range keys {
			va, aa := ma[k]
			vb, bb := mb[k]
			if !aa || !bb {
				out = append(out, path+"/"+k)
			} else {
				out = append(out, differences(va, vb, path+"/"+k)...)
			}
		}
		sort.Strings(out)
		return out
	}
	if reflect.DeepEqual(a, b) {
		return nil
	}
	return []string{path}
}

// Pairing proves fixture integrity: one changed input field, named positive
// control, stable documented code. It intentionally does not implement refusals.
func checkPairs() {
	var r Refusals
	read("vectors/refusals.json", &r)
	require(len(r.Negative) > 0 && len(r.Positive) > 0, "empty refusal vectors")
	controls := map[string]Input{}
	ids := map[string]bool{}
	for _, p := range r.Positive {
		require(p.ID != "" && !ids[p.ID] && p.Claim != "" && p.Result != "", "invalid control")
		ids[p.ID] = true
		controls[p.ID] = p.Input
	}
	spec, e := os.ReadFile("spec/keymaker.md")
	fail(e)
	for _, n := range r.Negative {
		require(n.ID != "" && !ids[n.ID] && n.Claim != "", "invalid negative id/claim")
		ids[n.ID] = true
		p, ok := controls[n.Control]
		require(ok, "missing control: "+n.ID)
		diff := differences(map[string]any(p), map[string]any(n.Input), "")
		require(len(diff) == 1 && diff[0] == n.Mutation, fmt.Sprintf("%s pairing: %v expected %s", n.ID, diff, n.Mutation))
		require(n.Code != "" && bytes.Contains(spec, []byte("`"+n.Code+"`")), "undocumented refusal: "+n.ID)
		if n.Wire != "" {
			require(n.Wire == "0000000105", "wrong SSH failure encoding: "+n.ID)
		}
	}
	fmt.Printf("fixture structure: %d negative/control pairs; no service policy exercised\n", len(r.Negative))
}
func main() {
	check := flag.Bool("check", false, "verify fixtures without writes")
	write := flag.Bool("write", false, "regenerate path expectations only")
	flag.Parse()
	require(*check != *write && flag.NArg() == 0, "use exactly one of -check or -write from repository root")
	checkPublished()
	checkPairs()
	checkAuthorityVectors()
	var p Paths
	original := read("vectors/keymaker-paths.json", &p)
	require(p.Format == "keymaker-paths/1" && len(p.Vectors) > 0, "path fixture format")
	seen := map[string]bool{}
	seenPath := map[string]bool{}
	seenPub := map[string]bool{}
	for i := range p.Vectors {
		v := &p.Vectors[i]
		require(v.ID != "" && !seen[v.ID], "duplicate vector id")
		seen[v.ID] = true
		indices := resolve(p.Registry, v.Names)
		path := "m"
		hardened := make([]uint32, len(indices))
		for j, n := range indices {
			path += fmt.Sprintf("/%d'", n)
			hardened[j] = n | 0x80000000
		}
		pub, chain := derive(decodeHex(p.Seed), path)
		v.Path = path
		v.Indices = hardened
		v.Public = hex.EncodeToString(pub)
		v.Chain = hex.EncodeToString(chain)
		blob := append(sshString([]byte("ssh-ed25519")), sshString(pub)...)
		v.SSH = "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
		require(!seenPath[path] && !seenPub[v.Public], "fixture path/public collision")
		seenPath[path] = true
		seenPub[v.Public] = true
	}
	b, e := json.MarshalIndent(p, "", "  ")
	fail(e)
	b = append(b, '\n')
	if *write {
		fail(os.WriteFile("vectors/keymaker-paths.json", b, 0644))
		fmt.Printf("wrote %d Keymaker path controls\n", len(p.Vectors))
	} else {
		require(bytes.Equal(original, b), "Keymaker path fixtures differ; inspect before -write")
		fmt.Printf("Keymaker path controls: %d exact matches\n", len(p.Vectors))
	}
}

// These fixture checks prove byte/hash/domain and mutation-pair integrity only.
// They do not implement a PC2 reader or evaluate the expected rejection verdicts.
type authorityGolden struct {
	ID       string `json:"id"`
	Path     string `json:"path"`
	Encoding string `json:"encoding"`
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
	Domain   string `json:"domain"`
}
type authorityMutation struct {
	Kind   string          `json:"kind"`
	Member string          `json:"member,omitempty"`
	Value  json.RawMessage `json:"value,omitempty"`
}
type authorityFixtures struct {
	Format  string            `json:"format"`
	Claim   string            `json:"claim"`
	Goldens []authorityGolden `json:"goldens"`
	Links   []struct {
		Object   string `json:"object"`
		Member   string `json:"member"`
		Preimage string `json:"preimage"`
		Prefix   string `json:"prefix"`
	} `json:"links"`
	Groups []struct {
		ID       string `json:"id"`
		Claim    string `json:"claim"`
		Negative struct {
			Control   string            `json:"control"`
			Mutation  authorityMutation `json:"mutation"`
			Bytes     int               `json:"bytes"`
			SHA256    string            `json:"sha256"`
			Rejection string            `json:"expected_rejection"`
		} `json:"negative"`
		Positive struct {
			Golden   string `json:"golden"`
			Expected string `json:"expected"`
		} `json:"positive"`
	} `json:"groups"`
	Maximal struct {
		ID      string `json:"id"`
		Entries int    `json:"entries"`
		Bytes   int    `json:"bytes"`
		Claim   string `json:"claim"`
	} `json:"maximal"`
}

func authorityHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func authorityObject(b []byte) map[string]any {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v map[string]any
	fail(d.Decode(&v))
	var extra any
	require(d.Decode(&extra) == io.EOF, "authority fixture trailing data")
	return v
}
func authorityBytes(v any) []byte {
	// The fixtures use ASCII strings and integer json.Number values; this is
	// fixture serialization, not the production CCJ-1 Unicode/schema reader.
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	fail(e.Encode(v))
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}
func authorityMutate(control []byte, m authorityMutation) []byte {
	if m.Kind == "truncate" {
		require(len(control) > 0, "empty truncate control")
		return control[:len(control)-1]
	}
	if m.Kind == "duplicate" {
		return append([]byte(`{"version":"keymaker-authority/2",`), control[1:]...)
	}
	obj := authorityObject(control)
	var value any
	if len(m.Value) != 0 {
		d := json.NewDecoder(bytes.NewReader(m.Value))
		d.UseNumber()
		fail(d.Decode(&value))
	}
	switch m.Kind {
	case "set":
		obj[m.Member] = value
	case "delete":
		_, ok := obj[m.Member]
		require(ok, "delete plant missed")
		delete(obj, m.Member)
	case "rename":
		v, ok := obj[m.Member]
		require(ok, "rename plant missed")
		delete(obj, m.Member)
		obj[value.(string)] = v
	case "append_role":
		obj["files"] = append(obj["files"].([]any), value)
	case "remove_group":
		var groups []any
		for _, item := range obj["groups"].([]any) {
			g := item.(map[string]any)
			if g["owner"] != "manager" || g["kind"] != "holds" {
				groups = append(groups, g)
			}
		}
		obj["groups"] = groups
	case "grow_total":
		entries := obj["entries"].([]any)
		applied := false
		for i := len(entries) - 1; i >= 0; i-- {
			e := entries[i].(map[string]any)
			s := e["owner"].(string)
			if len(s) < 255 {
				e["owner"] = s + "x"
				applied = true
				break
			}
		}
		require(applied, "total plant missed")
	default:
		fail(fmt.Errorf("unknown authority fixture mutation: %s", m.Kind))
	}
	return authorityBytes(obj)
}

func checkAuthorityVectors() {
	var f authorityFixtures
	read("vectors/authority-root.json", &f)
	require(f.Format == "keymaker-authority-vectors/1" && f.Claim != "", "authority fixture format")
	goldens := map[string][]byte{}
	for _, g := range f.Goldens {
		require(g.ID != "" && goldens[g.ID] == nil && strings.HasPrefix(g.Path, "vectors/authority-root/") && !strings.Contains(g.Path, ".."), "authority fixture path/id")
		raw, e := os.ReadFile(g.Path)
		fail(e)
		if g.Encoding == "gzip" {
			z, e := gzip.NewReader(bytes.NewReader(raw))
			fail(e)
			raw, e = io.ReadAll(io.LimitReader(z, 2097153))
			fail(e)
			fail(z.Close())
		} else {
			require(g.Encoding == "identity", "authority fixture encoding")
		}
		require(len(raw) <= 2097152 && len(raw) == g.Bytes && authorityHash(raw) == g.SHA256, "authority golden bytes/hash: "+g.ID)
		obj := authorityObject(raw)
		require(bytes.Equal(raw, authorityBytes(obj)), "authority golden canonical bytes: "+g.ID)
		domain, ok := obj["version"]
		if !ok {
			domain = obj["type"]
		}
		if domain == nil {
			domain = "schema-" + fmt.Sprint(obj["schema_version"])
		}
		require(fmt.Sprint(domain) == g.Domain && g.Domain != "", "authority golden domain: "+g.ID)
		goldens[g.ID] = raw
	}
	seen := map[string]bool{}
	// Each negative is materialized before its nearby positive is checked.
	// Only the exact planted bytes, length, digest and pairing are asserted;
	// expected_rejection is an unrun consumer obligation, never a green verdict.
	for _, group := range f.Groups {
		n := group.Negative
		require(group.ID != "" && !seen[group.ID] && group.Claim != "", "authority pair id/claim")
		seen[group.ID] = true
		control, ok := goldens[n.Control]
		require(ok && n.Control == group.Positive.Golden && n.Rejection != "", "authority pair control")
		bad := authorityMutate(control, n.Mutation)
		require(!bytes.Equal(bad, control) && len(bad) == n.Bytes && authorityHash(bad) == n.SHA256, "authority negative bytes/hash: "+group.ID)
		require(group.Positive.Expected == "format-control-only", "authority vector overclaims runtime result")
	}
	for _, link := range f.Links {
		obj, ok := goldens[link.Object]
		preimage, exists := goldens[link.Preimage]
		require(ok && exists && (link.Prefix == "sha256:" || link.Prefix == ""), "authority preimage link")
		var selected any = authorityObject(obj)
		for _, member := range strings.Split(link.Member, ".") {
			selected = selected.(map[string]any)[member]
		}
		require(selected == link.Prefix+authorityHash(preimage), "authority linked digest: "+link.Object+"/"+link.Member)
	}
	max := f.Maximal
	raw, ok := goldens[max.ID]
	require(ok && max.Bytes == 1048576 && len(raw) == max.Bytes && max.Claim != "", "authority maximal root cap")
	entries := authorityObject(raw)["entries"].([]any)
	require(len(entries) == max.Entries && len(entries) <= 4096, "authority maximal root rows")
	for i, item := range entries {
		e := item.(map[string]any)
		require(e["registration_number"] == json.Number(strconv.Itoa(i+1)) && len(e["owner"].(string)) <= 255, "authority maximal root field bounds")
	}
	require(len(f.Goldens) == 38 && len(f.Groups) == 21 && len(f.Links) == 9, "authority vector inventory")
	for _, phase := range []string{"legacy_validated", "s2_staged", "s2_committed", "combined_staged", "combined_committed", "released"} {
		require(goldens["migration-"+phase] != nil, "authority migration vector missing")
	}
	fmt.Printf("authority-root fixture integrity: %d goldens, %d negative/control pairs, %d preimage links; reader verdicts NOT RUN\n", len(f.Goldens), len(f.Groups), len(f.Links))
}
