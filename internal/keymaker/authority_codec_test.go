package keymaker

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type pc2Golden struct {
	ID, Path, Encoding, Domain string
	Bytes                      int
	SHA256                     string
}
type pc2Mutation struct {
	Kind, Member string
	Value        json.RawMessage
}
type pc2Pair struct {
	ID       string
	Negative struct {
		Control   string
		Mutation  pc2Mutation
		Bytes     int
		SHA256    string
		Rejection string `json:"expected_rejection"`
	}
	Positive struct{ Golden string }
}
type pc2Manifest struct {
	Goldens []pc2Golden
	Groups  []pc2Pair
	Links   []struct{ Object, Member, Preimage, Prefix string }
}

func pc2Fixtures(t *testing.T) (pc2Manifest, map[string][]byte) {
	t.Helper()
	var m pc2Manifest
	b, e := os.ReadFile("../../vectors/authority-root.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &m); e != nil {
		t.Fatal(e)
	}
	all := map[string][]byte{}
	for _, g := range m.Goldens {
		b, e = os.ReadFile(filepath.Join("../..", g.Path))
		if e != nil {
			t.Fatal(e)
		}
		if g.Encoding == "gzip" {
			z, e := gzip.NewReader(bytes.NewReader(b))
			if e != nil {
				t.Fatal(e)
			}
			b, e = io.ReadAll(io.LimitReader(z, 2097153))
			if e != nil {
				t.Fatal(e)
			}
			if e = z.Close(); e != nil {
				t.Fatal(e)
			}
		}
		if len(b) != g.Bytes || messageHash(b) != g.SHA256 {
			t.Fatal("independent golden integrity", g.ID)
		}
		all[g.ID] = b
	}
	return m, all
}
func pc2Object(t *testing.T, b []byte) map[string]any {
	t.Helper()
	v, e := parseAuthorityCCJ(b, stateBudget)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func pc2Bytes(t *testing.T, v any) []byte {
	t.Helper()
	b, e := canonical(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func pc2Kind(g pc2Golden) authorityKind {
	if g.Domain == "schema-3" {
		return authoritySnapshotKind
	}
	if strings.HasSuffix(g.ID, "root-preimage") {
		return authorityRootPreimageKind
	}
	if g.ID == "attempt-preimage" {
		return authorityAttemptPreimageKind
	}
	return authorityKind(g.Domain)
}

// Fixture wrappers only supply inputs to real pure validators. They are never
// production format kinds, signed-provider evidence, or admission decisions.
func pc2Check(t *testing.T, g pc2Golden, b []byte, all map[string][]byte) error {
	t.Helper()
	o, e := parseAuthorityCCJ(b, authorityLimit(pc2Kind(g)))
	if e != nil {
		return e
	}
	switch g.Domain {
	case "1":
		var disk bindingDisk
		return StrictJSON(bytes.NewReader(b), &disk)
	case "schema-3":
		_, e = decodeAuthority(b, authoritySnapshotKind)
	case "keymaker-manager-read-fixture/1":
		e = checkAuthorityContinuity(o["root"], o["continuity"])
	case "keymaker-anchor-fixture/1":
		e = authorityAnchorRule()(o["anchor"])
	case "keymaker-journal-fixture/1":
		e = authorityJournalRule()(o["journal"])
		if e == nil {
			e = checkAuthorityJournalPrior(o["journal"], true)
		}
	case "keymaker-journal-domain-fixture/1":
		e = checkAuthorityJournal(o["checkpoint"], o["protected_high_water"], o["genesis_authority"], o["operation"] == "activation")
	case "keymaker-ccj-boundary-fixture/1":
		return nil
	default:
		_, e = decodeAuthority(b, pc2Kind(g))
		if e == nil && g.Domain == "pc2-hold/1" {
			e = verifyAuthorityHold(o, func(d string) (authorityKind, []byte, error) {
				for _, p := range all {
					if authorityDigest(p) == d {
						v := pc2Object(t, p)
						kind, _ := v["type"].(string)
						if kind == "" {
							kind, _ = v["version"].(string)
						}
						if kind == "pc2-activation-attempt/1" {
							kind = string(authorityAttemptPreimageKind)
						}
						return authorityKind(kind), p, nil
					}
				}
				return "", nil, authorityFail("origin_unavailable")
			})
		}
		if e == nil && g.ID == "capacity-genesis-inventory" {
			e = checkAuthoritySlot(o, pc2Object(t, all["capacity-genesis-commit"]), pc2Object(t, all["capacity-genesis-reservation"]))
		}
	}
	return e
}
func pc2Plant(t *testing.T, b []byte, m pc2Mutation) []byte {
	t.Helper()
	if m.Kind == "truncate" {
		return b[:len(b)-1]
	}
	if m.Kind == "duplicate" {
		return append([]byte(`{"version":"keymaker-authority/2",`), b[1:]...)
	}
	if m.Kind == "replace_bytes" {
		var p struct {
			Offset        int
			Before, After string
		}
		var fields struct {
			Offset int
			Before string `json:"before_hex"`
			After  string `json:"after_hex"`
		}
		if e := json.Unmarshal(m.Value, &fields); e != nil {
			t.Fatal(e)
		}
		p.Offset, p.Before, p.After = fields.Offset, fields.Before, fields.After
		a, e := hex.DecodeString(p.Before)
		if e != nil {
			t.Fatal(e)
		}
		z, e := hex.DecodeString(p.After)
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(b[p.Offset:p.Offset+len(a)], a) {
			t.Fatal("byte plant missed")
		}
		out := append([]byte{}, b[:p.Offset]...)
		out = append(out, z...)
		return append(out, b[p.Offset+len(a):]...)
	}
	o := pc2Object(t, b)
	var value any
	if len(m.Value) > 0 {
		d := json.NewDecoder(bytes.NewReader(m.Value))
		d.UseNumber()
		if e := d.Decode(&value); e != nil {
			t.Fatal(e)
		}
	}
	switch m.Kind {
	case "set":
		o[m.Member] = value
	case "delete":
		delete(o, m.Member)
	case "rename":
		o[value.(string)] = o[m.Member]
		delete(o, m.Member)
	case "append_role":
		o["files"] = append(o["files"].([]any), value)
	case "remove_group":
		a := []any{}
		for _, r := range o["groups"].([]any) {
			v := r.(map[string]any)
			if v["owner"] != "manager" || v["kind"] != "holds" {
				a = append(a, r)
			}
		}
		o["groups"] = a
	case "grow_total":
		a := o["entries"].([]any)
		found := false
		for i := len(a) - 1; i >= 0; i-- {
			r := a[i].(map[string]any)
			if len(r["owner"].(string)) < 255 {
				r["owner"] = r["owner"].(string) + "x"
				found = true
				break
			}
		}
		if !found {
			t.Fatal("growth plant missed")
		}
	default:
		t.Fatal("unknown plant", m.Kind)
	}
	return pc2Bytes(t, o)
}

// Every independent G4 negative is refused for its named contract, followed by
// its adjacent accepted control. Fixture-context checks prove no real custody.
func TestPC2CombinedCodecClosed(t *testing.T) {
	m, all := pc2Fixtures(t)
	for _, name := range []string{"legacy-snapshot", "schema2-snapshot"} {
		t.Run(name+"-as-combined", func(t *testing.T) {
			if _, e := decodeAuthority(all[name], authoritySnapshotKind); e == nil {
				t.Fatal("P-PC2_SCHEMA2_EXTEND: old schema accepted as combined")
			}
		})
	}
	byID := map[string]pc2Golden{}
	for _, g := range m.Goldens {
		byID[g.ID] = g
	}
	for _, p := range m.Groups {
		t.Run(p.ID, func(t *testing.T) {
			g := byID[p.Negative.Control]
			bad := pc2Plant(t, all[g.ID], p.Negative.Mutation)
			if len(bad) != p.Negative.Bytes || messageHash(bad) != p.Negative.SHA256 {
				t.Fatal("negative oracle mismatch")
			}
			e := pc2Check(t, g, bad, all)
			if e == nil {
				t.Fatal("negative accepted", p.Negative.Rejection)
			}
			if authorityCode(e) != p.Negative.Rejection {
				t.Fatalf("wrong rejection: want %s got %v", p.Negative.Rejection, e)
			}
			if e = pc2Check(t, g, all[p.Positive.Golden], all); e != nil {
				t.Fatal("positive refused", e)
			}
		})
	}
}

// All84 independent byte oracles round-trip through production CCJ and format
// rules. Legacy/S2 use their original reader; fixture-only tags are not roots.
func TestPC2GoldenRoundTrip(t *testing.T) {
	m, all := pc2Fixtures(t)
	if len(m.Goldens) != 84 {
		t.Fatal("oracle inventory")
	}
	for _, g := range m.Goldens {
		t.Run(g.ID, func(t *testing.T) {
			b := all[g.ID]
			o, e := parseAuthorityCCJ(b, authorityLimit(pc2Kind(g)))
			if e != nil {
				t.Fatal(e)
			}
			out, e := marshalAuthorityCCJ(o, authorityLimit(pc2Kind(g)))
			if e != nil || !bytes.Equal(out, b) {
				t.Fatal("CCJ roundtrip", e)
			}
			if e = pc2Check(t, g, b, all); e != nil {
				t.Fatal(e)
			}
			if g.Domain == "1" {
				var disk bindingDisk
				if e := StrictJSON(bytes.NewReader(b), &disk); e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(pc2Bytes(t, disk), b) {
					t.Fatal("legacy typed roundtrip")
				}
			} else if !strings.Contains(g.Domain, "fixture/") {
				typed, e := decodeAuthority(b, pc2Kind(g))
				if e != nil {
					t.Fatal(e)
				}
				encoded, e := encodeAuthority(typed, pc2Kind(g))
				if e != nil || !bytes.Equal(encoded, b) {
					t.Fatal("typed roundtrip", e)
				}
			}
			if strings.Contains(g.Domain, "fixture/") {
				if _, e = decodeAuthority(b, authorityRootKind); e == nil {
					t.Fatal("fixture accepted as root")
				}
			}
		})
	}
}

// Every declared link uses production typed encoding with independent expected
// bytes/hashes; no import or execution of the offline vector implementation.
func TestPC2GoldenLinks(t *testing.T) {
	m, all := pc2Fixtures(t)
	byID := map[string]pc2Golden{}
	for _, g := range m.Goldens {
		byID[g.ID] = g
	}
	if len(m.Links) != 31 {
		t.Fatal("link inventory")
	}
	for _, l := range m.Links {
		t.Run(l.Object+"/"+l.Member, func(t *testing.T) {
			g := byID[l.Preimage]
			o, e := decodeAuthority(all[g.ID], pc2Kind(g))
			if e != nil {
				t.Fatal(e)
			}
			b, e := encodeAuthority(o, pc2Kind(g))
			if e != nil || !bytes.Equal(b, all[g.ID]) {
				t.Fatal("typed preimage bytes", e)
			}
			var selected any = pc2Object(t, all[l.Object])
			for _, k := range strings.Split(l.Member, ".") {
				selected = selected.(map[string]any)[k]
			}
			if selected != l.Prefix+messageHash(b) {
				t.Fatal("production link mismatch")
			}
		})
	}
}

// Closed member sets keep secrets and returned envelopes out of logical root
// bytes; refusal never rewrites the original file, even for truncated evidence.
func TestPC2RootExcludesSecrets(t *testing.T) {
	_, all := pc2Fixtures(t)
	original := all["minimal-root"]
	for _, key := range []string{"master_seed", "private_key", "chain_code", "raw_pin", "operator_document", "returned_envelope", "FreshnessReceipt"} {
		o := pc2Object(t, original)
		o[key] = "fixture-only-sensitive-marker"
		if _, e := decodeAuthority(pc2Bytes(t, o), authorityRootKind); e == nil {
			t.Fatal("forbidden root field", key)
		}
	}
	p := filepath.Join(t.TempDir(), "truncated")
	bad := original[:len(original)-1]
	if e := os.WriteFile(p, bad, 0600); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = decodeAuthority(b, authorityRootKind); e == nil {
		t.Fatal("truncated file accepted")
	}
	after, e := os.ReadFile(p)
	if e != nil || !bytes.Equal(bad, after) {
		t.Fatal("decoder changed evidence")
	}
}

// Typed combined intake cannot reinterpret either existing installed schema.
// The unchanged legacy/S2 content digests still hash their original bodies.
func TestPC2LegacyS2Isolation(t *testing.T) {
	_, all := pc2Fixtures(t)
	for _, name := range []string{"legacy-snapshot", "schema2-snapshot"} {
		t.Run(name, func(t *testing.T) {
			raw := all[name]
			if _, e := decodeAuthority(raw, authoritySnapshotKind); e == nil {
				t.Fatal("P-PC2_SCHEMA2_EXTEND: old schema accepted as combined")
			}
			var disk bindingDisk
			if e := StrictJSON(bytes.NewReader(raw), &disk); e != nil {
				t.Fatal(e)
			}
			s := NewStore()
			s.schema = disk.SchemaVersion
			s.messages = disk.Messages
			s.next = disk.Next
			s.records = disk.Records
			s.requests = disk.Requests
			got, e := s.contentDigest(disk.Version)
			if e != nil {
				t.Fatal(e)
			}
			body := pc2Object(t, raw)
			delete(body, "audit_seq")
			delete(body, "audit_hash")
			if got != messageHash(pc2Bytes(t, body)) {
				t.Fatal("original content digest changed")
			}
		})
	}
	var old bindingDisk
	if e := StrictJSON(bytes.NewReader(all["combined-snapshot"]), &old); e == nil {
		t.Fatal("serving reader accepted combined schema")
	}
}
func pc2Binding() map[string]any {
	return map[string]any{"uid": int64(10), "generation": strings.Repeat("1", 32), "path": "m/1'/1'/1'/1'", "owner": "owner", "registration_number": int64(1), "lifetime": "ephemeral", "registrar_principal": map[string]any{"uid": int64(1), "generation": strings.Repeat("2", 32)}, "status": "active", "master_epoch": "epoch", "registry_revision": "registry"}
}
func pc2Request() map[string]any {
	return map[string]any{"caller": map[string]any{"uid": int64(1), "generation": strings.Repeat("2", 32)}, "id": strings.Repeat("a", 32), "method": "register", "arguments": "{}", "status": "pending", "result": nil}
}

// Nonempty histories retain original binding/native IDs and explicit null
// result semantics; invalid neighbors cannot hide behind empty golden arrays.
func TestPC2PopulatedPrivatePayload(t *testing.T) {
	_, all := pc2Fixtures(t)
	p := pc2Object(t, all["private-payload"])
	p["next_registration_number"] = int64(2)
	p["records"] = []any{pc2Binding()}
	p["requests"] = []any{pc2Request()}
	raw := pc2Bytes(t, p)
	if _, e := decodeAuthority(raw, "keymaker-private/3"); e != nil {
		t.Fatal("nonempty control", e)
	}
	for _, name := range []string{"binding-extra", "bad-path", "bad-lifetime", "allocator", "duplicate-live", "request-extra", "null-committed", "duplicate-id", "argument-limit", "result-limit", "unrelated-dispatch"} {
		t.Run(name, func(t *testing.T) {
			p := pc2Object(t, raw)
			b := p["records"].([]any)[0].(map[string]any)
			r := p["requests"].([]any)[0].(map[string]any)
			switch name {
			case "binding-extra":
				b["secret"] = true
			case "bad-path":
				b["path"] = "m/4'/1'/1'/1'"
			case "bad-lifetime":
				b["lifetime"] = "session"
			case "allocator":
				p["next_registration_number"] = int64(1)
			case "duplicate-live":
				b2 := authorityCopy(b)
				b2["registration_number"] = int64(2)
				p["next_registration_number"] = int64(3)
				p["records"] = []any{b, b2}
			case "request-extra":
				r["receipt"] = true
			case "null-committed":
				r["status"] = "committed"
			case "duplicate-id":
				p["requests"] = []any{r, authorityCopy(r)}
			case "argument-limit":
				r["arguments"] = `{"x":"` + strings.Repeat("x", 65536) + `"}`
			case "result-limit":
				r["status"] = "committed"
				r["result"] = map[string]any{"x": strings.Repeat("x", 65536)}
			case "unrelated-dispatch":
				p["message_dispatch"] = []any{map[string]any{"transaction": strings.Repeat("a", 32), "codec": "keymaker-msg-state/2"}}
			}
			if _, e := decodeAuthority(pc2Bytes(t, p), "keymaker-private/3"); e == nil {
				t.Fatal("nonempty negative accepted", name)
			}
		})
	}
	p = pc2Object(t, raw)
	r := p["requests"].([]any)[0].(map[string]any)
	r["status"] = "committed"
	r["result"] = map[string]any{"registration_number": int64(1), "public_key": "original-result"}
	if b, e := encodeAuthority(p, "keymaker-private/3"); e != nil || !bytes.Equal(b, pc2Bytes(t, p)) {
		t.Fatal("committed native result changed", e)
	}
}

// Lexical noncanonical variants fail before typed defaults or hash checks.
// Exact scalar values, including nonnormalized Unicode, keep their bytes.
func TestPC2CCJNeighbors(t *testing.T) {
	for _, s := range []string{` {"a":1}`, `{"a":1}` + "\n", `{"a":1} {}`, `{"z":1,"a":2}`, `{"a":01}`, `{"a":-0}`, `{"a":1e0}`, `{"a":0.1}`, `{"a":9007199254740992}`, `{"a":-9007199254740992}`, `{"a":"\ud800"}`, `{"a":"\u0061"}`, `{"a":1,"\u0061":2}`, `{"a":+1}`, "\xef\xbb\xbf{}"} {
		if _, e := parseAuthorityCCJ([]byte(s), 65536); e == nil {
			t.Fatal("noncanonical neighbor accepted", s)
		}
	}
	for _, s := range []string{`{"a":9007199254740991}`, `{"a":-9007199254740991}`, `{"a":"é"}`, `{"a":"é"}`, `{"a":"<>&  "}`, `{"a":"\u0000\n\t"}`} {
		o, e := parseAuthorityCCJ([]byte(s), 65536)
		if e != nil {
			t.Fatal("canonical control", s, e)
		}
		b, e := marshalAuthorityCCJ(o, 65536)
		if e != nil || string(b) != s {
			t.Fatal("scalar normalization", e)
		}
	}
	for _, v := range []any{nil, float64(1), json.Number("1"), map[string]any(nil), []any(nil), string([]byte{255})} {
		if _, e := marshalAuthorityCCJ(map[string]any{"a": v}, 65536); e == nil && v != nil {
			t.Fatal("encoder silently coerced value", v)
		}
	}
	if arUID(int64(4294967295)) != nil || arUID(int64(4294967296)) == nil {
		t.Fatal("UID boundary")
	}
	if arText(strings.Repeat("é", 127)+"x") != nil || arText(strings.Repeat("é", 128)) == nil {
		t.Fatal("UTF8 byte field bound")
	}
}

// The entry-count ceiling is independent of the 1MiB encoded-root ceiling;
// a 4096-row array can satisfy its count gate while failing the tighter byte cap.
func TestPC2EntryCountAndNestedClosure(t *testing.T) {
	_, all := pc2Fixtures(t)
	max := pc2Object(t, all["maximal-root"])
	template := max["entries"].([]any)[0].(map[string]any)
	rows := []any{}
	for i := 0; i < 4096; i++ {
		r := authorityCopy(template)
		r["registration_number"] = int64(i + 1)
		rows = append(rows, r)
	}
	if e := arEntries(rows); e != nil {
		t.Fatal("4096 count control", e)
	}
	rows = append(rows, template)
	if e := arEntries(rows); authorityCode(e) != "array_limit" {
		t.Fatal("4097 count", e)
	}
	for _, path := range [][]string{{"binding_commit"}, {"payload"}, {"payload", "device"}, {"participants"}, {"manager_baseline"}, {"journal"}} {
		r := pc2Object(t, all["minimal-root"])
		o := r
		for _, k := range path {
			o = o[k].(map[string]any)
		}
		o["unexpected"] = true
		if _, e := decodeAuthority(pc2Bytes(t, r), authorityRootKind); authorityCode(e) != "unknown_member" {
			t.Fatal("nested closure", path, e)
		}
	}
}
