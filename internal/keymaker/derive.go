package keymaker

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

func erase(b []byte) { clear(b); runtime.KeepAlive(b) }

func parsePath(path string) ([]uint32, Code) {
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] != "m" {
		return nil, "path_invalid"
	}
	var out []uint32
	for _, p := range parts[1:] {
		if !strings.HasSuffix(p, "'") {
			return nil, "path_not_hardened"
		}
		n, err := strconv.ParseUint(strings.TrimSuffix(p, "'"), 10, 31)
		if err != nil || strconv.FormatUint(n, 10)+"'" != p {
			return nil, "path_invalid"
		}
		out = append(out, uint32(n)|0x80000000)
	}
	return out, ""
}

func ValidatePath(path, purpose string) Code {
	p, c := parsePath(path)
	if c != "" {
		return c
	}
	if len(p) != 4 {
		return "path_invalid"
	}
	var index uint32
	switch purpose {
	case "agent-identity":
		index = 1
	case "host-registration":
		index = 2
	case "swarma-msg":
		// Internal message capability only; public Master APIs stay purpose 1.
		index = 4
	default:
		return "purpose_unknown"
	}
	if p[0] != index|0x80000000 {
		return "purpose_unknown"
	}
	return ""
}

// deriveNode is private: only internal tests inspect chain codes. Service methods
// expose public keys or signatures, never derivation nodes.
func deriveNode(seed []byte, indices []uint32) []byte {
	h := hmac.New(sha512.New, []byte("ed25519 seed"))
	h.Write(seed)
	node := h.Sum(nil)
	for _, index := range indices {
		data := make([]byte, 37)
		copy(data[1:33], node[:32])
		binary.BigEndian.PutUint32(data[33:], index)
		h = hmac.New(sha512.New, node[32:])
		h.Write(data)
		next := h.Sum(nil)
		erase(data)
		erase(node)
		node = next
	}
	return node
}

type Signer interface {
	Public(path string) ([]byte, Code)
	Sign(path string, data []byte) ([]byte, Code)
}

// Master owns a locked allocation when supported. Go's HMAC/Ed25519/runtime may
// retain copies; clearing these buffers is best effort, not non-extraction.
type Master struct {
	mu     sync.Mutex
	seed   []byte
	locked bool
	mapped bool
	closed bool
}

func (m *Master) Locked() bool { return m.locked }
func (m *Master) withKey(path string, f func(ed25519.PrivateKey) []byte) ([]byte, Code) {
	return m.withPurpose(path, "agent-identity", f)
}

func (m *Master) withPurpose(path, purpose string, f func(ed25519.PrivateKey) []byte) ([]byte, Code) {
	result, code, _ := m.withPurposeCause(path, purpose, f)
	return result, code
}

func (m *Master) withPurposeCause(path, purpose string, f func(ed25519.PrivateKey) []byte) ([]byte, Code, custodyCause) {
	if c := ValidatePath(path, purpose); c != "" {
		return nil, c, ""
	}
	if m == nil {
		return nil, "custody_unavailable", custodyUnloaded
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, "custody_unavailable", custodyClosed
	}
	if len(m.seed) == 0 {
		return nil, "custody_unavailable", custodyUnloaded
	}
	if len(m.seed) != 32 {
		return nil, "custody_unavailable", custodyProtectionFailed
	}
	indices, _ := parsePath(path)
	node := deriveNode(m.seed, indices)
	defer erase(node)
	key := ed25519.NewKeyFromSeed(node[:32])
	defer erase(key)
	return f(key), "", ""
}
func (m *Master) Public(path string) ([]byte, Code) {
	return m.withKey(path, func(k ed25519.PrivateKey) []byte { return append([]byte(nil), k[32:]...) })
}
func (m *Master) Sign(path string, data []byte) ([]byte, Code) {
	return m.withKey(path, func(k ed25519.PrivateKey) []byte { return ed25519.Sign(k, data) })
}

var validName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

type AgentName struct {
	Name  string `json:"name"`
	Index uint32 `json:"index"`
}
type Project struct {
	Name   string      `json:"name"`
	Index  uint32      `json:"index"`
	Agents []AgentName `json:"agents"`
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

func validScope(entries []AgentName) bool {
	seen := map[string]bool{}
	ids := map[uint32]bool{}
	for i, e := range entries {
		// Array order retains historical allocation order; no gaps, reassignment or sorting.
		if !validName.MatchString(e.Name) || e.Index != uint32(i+1) || e.Index > 0x7fffffff || seen[e.Name] || ids[e.Index] {
			return false
		}
		seen[e.Name] = true
		ids[e.Index] = true
	}
	return true
}
func (r Registry) Validate() Code {
	var ps []AgentName
	for _, p := range r.Products {
		ps = append(ps, AgentName{p.Name, p.Index})
		var js []AgentName
		for _, j := range p.Projects {
			js = append(js, AgentName{j.Name, j.Index})
			if !validScope(j.Agents) {
				return "name_registry_invalid"
			}
		}
		if !validScope(js) {
			return "name_registry_invalid"
		}
	}
	if !validScope(ps) {
		return "name_registry_invalid"
	}
	return ""
}
func (r Registry) Resolve(n Names) (string, Code) {
	purpose := uint32(0)
	switch n.Purpose {
	case "agent-identity":
		purpose = 1
	case "host-registration":
		purpose = 2
	default:
		return "", "purpose_unknown"
	}
	for _, name := range []string{n.Product, n.Project, n.Agent} {
		if !validName.MatchString(name) {
			return "", "name_invalid"
		}
	}
	if c := r.Validate(); c != "" {
		return "", c
	}
	for _, p := range r.Products {
		if p.Name != n.Product {
			continue
		}
		for _, j := range p.Projects {
			if j.Name != n.Project {
				continue
			}
			for _, a := range j.Agents {
				if a.Name == n.Agent {
					return "m/" + strconv.Itoa(int(purpose)) + "'/" + strconv.Itoa(int(p.Index)) + "'/" + strconv.Itoa(int(j.Index)) + "'/" + strconv.Itoa(int(a.Index)) + "'", ""
				}
			}
		}
	}
	return "", "name_unknown"
}

// Extends rejects deletion, reordering or changes of historical allocations.
func (r Registry) Extends(old Registry) Code {
	if c := r.Validate(); c != "" {
		return c
	}
	if len(r.Products) < len(old.Products) {
		return "name_registry_invalid"
	}
	for i, p := range old.Products {
		n := r.Products[i]
		if p.Name != n.Name || p.Index != n.Index || len(n.Projects) < len(p.Projects) {
			return "name_registry_invalid"
		}
		for j, q := range p.Projects {
			v := n.Projects[j]
			if q.Name != v.Name || q.Index != v.Index || len(v.Agents) < len(q.Agents) {
				return "name_registry_invalid"
			}
			for k, a := range q.Agents {
				if a != v.Agents[k] {
					return "name_registry_invalid"
				}
			}
		}
	}
	return ""
}

func (r Registry) ContainsIdentityPath(path string) bool {
	if ValidatePath(path, "agent-identity") != "" || r.Validate() != "" {
		return false
	}
	indices, _ := parsePath(path)
	for _, p := range r.Products {
		if p.Index|0x80000000 != indices[1] {
			continue
		}
		for _, j := range p.Projects {
			if j.Index|0x80000000 != indices[2] {
				continue
			}
			for _, a := range j.Agents {
				if a.Index|0x80000000 == indices[3] {
					return true
				}
			}
		}
	}
	return false
}
