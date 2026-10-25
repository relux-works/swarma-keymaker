package keymaker

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/waggle/record"
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

const pc2EdKey = "ed25519:11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
const pc2P256Key = "p256:AtvuKbwrlJKTmC1cFKDUv9lAx4xolphryoTXkRZN0Ayl"

// Each of G4's fourteen literal classes passes; neighboring composite names,
// wrong-owner classes and partial/unknown names must not be substring members.
func TestPC2CapacityClassesExact(t *testing.T) {
	for owner, kinds := range map[string][]string{
		"keymaker": {"installed", "artifacts", "recovery", "staging", "pending_proofs", "policy_history", "root_history", "migration_history", "reservation_metadata"},
		"manager":  {"attempts", "holds", "recovery", "inventory", "staging"},
	} {
		for _, kind := range kinds {
			o := map[string]any{"version": "keymaker-capacity-inventory/1", "owner": owner, "kind": kind, "objects": []any{}}
			if _, e := decodeAuthority(pc2Bytes(t, o), "keymaker-capacity-inventory/1"); e != nil {
				t.Fatal("literal class refused", owner, kind, e)
			}
		}
		for _, kind := range []string{"installed artifacts", "artifacts recovery staging", "attempts holds", "installed ", " installed", "install", "unknown"} {
			o := map[string]any{"version": "keymaker-capacity-inventory/1", "owner": owner, "kind": kind, "objects": []any{}}
			if _, e := decodeAuthority(pc2Bytes(t, o), "keymaker-capacity-inventory/1"); authorityCode(e) != "not_aggregate" {
				t.Fatalf("P-PC2_CLASS_SUBSTRING: %s/%s: %v", owner, kind, e)
			}
		}
	}
	for _, pair := range [][2]string{{"keymaker", "holds"}, {"manager", "installed"}} {
		if authorityClass(pair[0], pair[1]) {
			t.Fatal("wrong owner class", pair)
		}
	}
}

func pc2Original(t *testing.T, kind string) string {
	t.Helper()
	body := map[string]any{"type": kind}
	d := "sha256:" + strings.Repeat("a", 64)
	switch kind {
	case "journal-entry/1":
		body = map[string]any{"type": kind, "registry": pc2EdKey, "owner": "owner", "seq": int64(1), "at": "2026-10-25T00:00:00Z", "prev": nil, "op": "add", "record_type": "attestation/1", "record": d}
	case "checkpoint/1":
		body = map[string]any{"type": kind, "registry": pc2EdKey, "owner": "owner", "seq": int64(1), "at": "2026-10-25T00:00:00Z", "head": d, "snapshot": d}
	case "revocation/1":
		body = map[string]any{"type": kind, "issuer": pc2EdKey, "issued_at": "2026-10-25T00:00:00Z", "complete": true, "entries": []any{}}
	}
	id, e := record.ContentID(kind, body)
	if e != nil {
		t.Fatal(e)
	}
	env := map[string]any{"version": "swarm-envelope/2", "id": id, "body": body}
	if kind != "journal-entry/1" {
		// This is a format control, not a valid signature or provider qualification.
		env["signatures"] = []any{map[string]any{"role": "author", "key": pc2EdKey, "sig": base64.RawURLEncoding.EncodeToString(make([]byte, 64))}}
	}
	return base64.RawURLEncoding.EncodeToString(pc2Bytes(t, env))
}
func pc2Publication(t *testing.T) map[string]any {
	t.Helper()
	return map[string]any{"transaction": strings.Repeat("1", 32), "content_id": "sha256:" + strings.Repeat("a", 64), "entry": pc2Original(t, "journal-entry/1"), "suffix": []any{pc2Original(t, "journal-entry/1")}, "checkpoint": pc2Original(t, "checkpoint/1"), "conflict": nil, "snapshot": pc2Original(t, "revocation/1"), "validation": map[string]any{"registry_id": pc2EdKey, "owner": "owner", "registry_seq": int64(1), "registry_head": "sha256:" + strings.Repeat("b", 64), "checkpoint_id": "sha256:" + strings.Repeat("c", 64), "previous_checkpoint_id": nil}, "witness": true}
}

// Known publication fields obey their own exact vocabularies and original-byte
// bounds, not reflected Go shapes. WC1's unbound inner codec stays unsupported:
// even a well-shaped record cannot qualify publication; empty inventory passes.
func TestPC2PublicationFields(t *testing.T) {
	_, all := pc2Fixtures(t)
	empty := all["private-payload"]
	check := func(pub map[string]any) error {
		p := pc2Object(t, empty)
		p["messages"].(map[string]any)["publications"] = []any{pub}
		_, e := decodeAuthority(pc2Bytes(t, p), "keymaker-private/3")
		return e
	}
	cases := []struct {
		name, field, code string
		value             any
	}{
		{"transaction", "transaction", "field_format", "not-an-id"},
		{"content-id", "content_id", "field_format", strings.Repeat("a", 64)},
		{"entry-url", "entry", "publication_original", "https://example.invalid/entry"},
		{"entry-padding", "entry", "publication_original", pc2Original(t, "journal-entry/1") + "="},
		{"entry-size", "entry", "publication_original", base64.RawURLEncoding.EncodeToString(make([]byte, 8193))},
		{"checkpoint-domain", "checkpoint", "publication_original", pc2Original(t, "journal-entry/1")},
		{"snapshot-domain", "snapshot", "publication_original", pc2Original(t, "checkpoint/1")},
		{"suffix-count", "suffix", "array_limit", make([]any, 65)},
		{"suffix-url", "suffix", "publication_original", []any{"https://example.invalid/entry"}},
		{"validation-boolean", "validation", "wrong_type", true},
		{"validation-id", "validation", "field_format", map[string]any{"registry_id": pc2EdKey, "owner": "owner", "registry_seq": int64(1), "registry_head": "not-a-digest", "checkpoint_id": "sha256:" + strings.Repeat("c", 64), "previous_checkpoint_id": nil}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pub := pc2Publication(t)
			pub[c.field] = c.value
			if e := check(pub); authorityCode(e) != c.code {
				t.Fatalf("P-PC2_PUBLICATION_SHAPE: want %s: %v", c.code, e)
			}
		})
	}
	for _, w := range []any{true, false, nil, "url", map[string]any{"retained_originals": "unbound"}} {
		pub := pc2Publication(t)
		pub["witness"] = w
		if e := check(pub); authorityCode(e) != "publication_witness_codec_pending" {
			t.Fatalf("P-PC2_PUBLICATION_SHAPE: unsupported WC1 accepted or misclassified: %v", e)
		}
	}
	if _, e := decodeAuthority(empty, "keymaker-private/3"); e != nil {
		t.Fatal("empty publication control", e)
	}
}

// Both normal and recovery mode obey sequence/checkpoint/snapshot continuity;
// higher-sequence new checkpoints and same-checkpoint retransmission controls pass.
func TestPC2FreshnessEndpointContinuity(t *testing.T) {
	_, all := pc2Fixtures(t)
	for _, mode := range []string{"normal", "reanchor"} {
		for _, name := range []string{"rollback", "equal-seq-fork", "same-checkpoint-snapshot", "advance", "same-checkpoint"} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				o := pc2Object(t, all["freshness-artifact-"+mode])
				old := o["old_anchor"].(map[string]any)
				next := o["new_anchor"].(map[string]any)
				old["registry_seq"] = int64(10)
				next["registry_seq"] = int64(11)
				old["checkpoint_id"] = "sha256:" + strings.Repeat("a", 64)
				next["checkpoint_id"] = "sha256:" + strings.Repeat("b", 64)
				old["snapshot"] = "sha256:" + strings.Repeat("c", 64)
				next["snapshot"] = "sha256:" + strings.Repeat("d", 64)
				switch name {
				case "rollback":
					next["registry_seq"] = int64(9)
				case "equal-seq-fork":
					next["registry_seq"] = int64(10)
				case "same-checkpoint-snapshot":
					next["registry_seq"] = int64(10)
					next["checkpoint_id"] = old["checkpoint_id"]
				case "same-checkpoint":
					next["registry_seq"] = int64(10)
					next["checkpoint_id"] = old["checkpoint_id"]
					next["snapshot"] = old["snapshot"]
				}
				if a, ok := o["receipt_audit"].(map[string]any); ok {
					a["checkpoint_id"] = next["checkpoint_id"]
					a["snapshot_id"] = next["snapshot"]
					if mode == "reanchor" {
						a["old_checkpoint_id"] = old["checkpoint_id"]
					}
				}
				if a, ok := o["reanchor"].(map[string]any); ok {
					a["new_checkpoint_id"] = next["checkpoint_id"]
					a["old_checkpoint_id"] = old["checkpoint_id"]
				}
				_, e := decodeAuthority(pc2Bytes(t, o), "message-freshness/1")
				if name == "advance" || name == "same-checkpoint" {
					if e != nil {
						t.Fatal("valid continuity refused", e)
					}
				} else if authorityCode(e) != "freshness_endpoint_continuity" {
					t.Fatalf("P-PC2_FRESHNESS_ENDPOINT: want continuity refusal: %v", e)
				}
			})
		}
	}
}

func pc2Intent() map[string]any {
	return map[string]any{"version": "keymaker-message-artifact/3", "kind": "intent", "body": map[string]any{"binding": pc2Binding(), "issuer_policy": map[string]any{"path": "m/5'/1'/1'/1'", "key": pc2EdKey, "master_epoch": "epoch", "registry_revision": "registry", "lifetime_seconds": int64(60)}, "key_id": pc2EdKey, "issued_at": "2026-10-25T00:00:00Z", "reserved_bytes": int64(messageProofReserve), "base_version": int64(1), "base_digest": strings.Repeat("a", 64), "previous_current": nil}}
}

// Message subjects and purpose-5 issuer slots are Ed25519 only; both registry
// policy keys keep the broader waggle Key domain, including a valid P-256 point.
func TestPC2MessageKeyDomains(t *testing.T) {
	for _, slot := range []string{"subject", "issuer", "valid"} {
		t.Run(slot, func(t *testing.T) {
			o := pc2Intent()
			b := o["body"].(map[string]any)
			if slot == "subject" {
				b["key_id"] = pc2P256Key
			}
			if slot == "issuer" {
				b["issuer_policy"].(map[string]any)["key"] = pc2P256Key
			}
			_, e := decodeAuthority(pc2Bytes(t, o), "keymaker-message-artifact/3")
			if slot == "valid" {
				if e != nil {
					t.Fatal("Ed25519 control", e)
				}
			} else if authorityCode(e) != "key_domain" {
				t.Fatalf("P-PC2_MESSAGE_KEY_DOMAIN: %s: %v", slot, e)
			}
		})
	}
	_, all := pc2Fixtures(t)
	p := pc2Object(t, all["message-policy"])
	for _, k := range []string{"key", "attestation_root"} {
		p["registry_root"].(map[string]any)[k] = pc2P256Key
	}
	if _, e := decodeAuthority(pc2Bytes(t, p), "keymaker-message-policy/1"); e != nil {
		t.Fatal("P-256 registry control", e)
	}
}

// Waggle Owner and retained S2 association strings are nonempty UTF-8 byte
// strings, including controls. G4 Text remains its distinct control-free type.
func TestPC2OwnerGrammar(t *testing.T) {
	_, all := pc2Fixtures(t)
	for _, owner := range []string{"o", "a\nb", "a\x00b", "a\u0085b", strings.Repeat("é", 127) + "x", "e\u0301"} {
		p := pc2Object(t, all["message-policy"])
		p["owner"] = owner
		raw := pc2Bytes(t, p)
		o, e := decodeAuthority(raw, "keymaker-message-policy/1")
		if e != nil {
			t.Fatalf("P-PC2_OWNER_TEXT: valid owner refused: %v", e)
		}
		out, e := encodeAuthority(o, "keymaker-message-policy/1")
		if e != nil || !bytes.Equal(raw, out) {
			t.Fatal("owner byte preservation", e)
		}
	}
	for _, owner := range []string{"", strings.Repeat("é", 128)} {
		p := pc2Object(t, all["message-policy"])
		p["owner"] = owner
		if _, e := decodeAuthority(pc2Bytes(t, p), "keymaker-message-policy/1"); authorityCode(e) != "field_limit" {
			t.Fatal("owner bounds", e)
		}
	}
	if e := arText("a\nb"); authorityCode(e) != "field_limit" {
		t.Fatal("G4 Text narrowed incorrectly", e)
	}
	for _, field := range []string{"owner", "master_epoch", "registry_revision"} {
		o := pc2Intent()
		b := o["body"].(map[string]any)
		b["binding"].(map[string]any)[field] = "a\x00\nb"
		if field != "owner" {
			b["issuer_policy"].(map[string]any)[field] = "a\x00\nb"
		}
		if _, e := decodeAuthority(pc2Bytes(t, o), "keymaker-message-artifact/3"); e != nil {
			t.Fatal("retained S2 association text", field, e)
		}
	}
}

// Original-envelope format checks accept bounded owner bytes, including valid
// whitespace, without treating unsigned fixture signatures as authentication.
// Invalid enums, IDs, members and decoded-byte bounds refuse at that same gate.
func TestPC2PublicationOriginalGrammar(t *testing.T) {
	for _, kind := range []string{"journal-entry/1", "checkpoint/1", "revocation/1"} {
		rule := authorityOriginalRule(kind, false)
		encoded := pc2Original(t, kind)
		if e := rule(encoded); e != nil {
			t.Fatal("original format control", kind, e)
		}
		raw, e := record.DecodeBase64(encoded, -1)
		if e != nil {
			t.Fatal(e)
		}
		spaced := " \n" + string(raw) + " \n"
		if e := rule(base64.RawURLEncoding.EncodeToString([]byte(spaced))); e != nil {
			t.Fatal("owner whitespace control", e)
		}
		for _, name := range []string{"unknown", "missing", "id", "type", "registry-key", "enum", "signature", "oversize"} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				o := pc2Object(t, raw)
				b := o["body"].(map[string]any)
				switch name {
				case "unknown":
					b["extra"] = true
				case "missing":
					delete(b, "type")
				case "id":
					o["id"] = "sha256:" + strings.Repeat("f", 64)
				case "type":
					b["type"] = "other/1"
				case "registry-key":
					if kind == "revocation/1" {
						b["issuer"] = "not-a-key"
					} else {
						b["registry"] = "not-a-key"
					}
				case "enum":
					if kind == "journal-entry/1" {
						b["op"] = "add revoke"
					} else if kind == "revocation/1" {
						b["entries"] = []any{map[string]any{"kind": "key record", "id": pc2EdKey, "from": "2026-10-25T00:00:00Z"}}
					} else {
						o["signatures"].([]any)[0].(map[string]any)["role"] = "author witness"
					}
				case "signature":
					if kind == "journal-entry/1" {
						o["signatures"] = []any{}
					} else {
						o["signatures"].([]any)[0].(map[string]any)["sig"] = "bad"
					}
				case "oversize":
					b["owner"] = strings.Repeat("x", 8193)
				}
				// Recompute the ID for body changes so rejection cannot rely solely on
				// stale identity; unknown domain cannot be assigned a supported tag.
				if name != "id" {
					if id, e := record.ContentID(kind, b); e == nil {
						o["id"] = id
					}
				}
				if e := rule(base64.RawURLEncoding.EncodeToString(pc2Bytes(t, o))); authorityCode(e) != "publication_original" {
					t.Fatal("invalid original accepted", name, e)
				}
			})
		}
	}
	// 64 raw entries is the count boundary, independent of pending WC1 format.
	pub := pc2Publication(t)
	entries := make([]any, 64)
	for i := range entries {
		entries[i] = pub["entry"]
	}
	pub["suffix"] = entries
	if e := authorityPublicationRule()(pub); authorityCode(e) != "publication_witness_codec_pending" {
		t.Fatal("64-entry control did not reach pending owner codec", e)
	}
}

// The reflection-backed certificate row receives semantic key checks too. A
// genuine Ed25519 certificate is the adjacent control; P-256 registry keys
// remain exercised separately by TestPC2MessageKeyDomains.
func TestPC2RetainedCertificateKeyDomains(t *testing.T) {
	i, b, public, facts, _ := messageIssuerFixture(t)
	b.Generation = strings.Repeat("1", 32)
	mb := messageBindingOf(b)
	facts.CurrentGenerations = messageEvidence(t, map[string]any{messageTestID(public): map[string]any{"uid": int64(mb.UID), "generation": mb.Generation, "registration_number": int64(mb.Number), "master_epoch": mb.Epoch, "owner": mb.Owner, "path": mb.Path, "active": true}})
	cert, code := i.prepare(t.Context(), strings.Repeat("1", 32), b, public, facts)
	if code != "" {
		t.Fatal("certificate control preparation", code)
	}
	raw := pc2Bytes(t, cert)
	for _, slot := range []string{"valid", "subject", "issuer"} {
		o := pc2Object(t, raw)
		if slot == "subject" {
			o["key_id"] = pc2P256Key
		}
		if slot == "issuer" {
			o["issuer_policy"].(map[string]any)["key"] = pc2P256Key
		}
		e := authorityCertificateRule()(o)
		if slot == "valid" {
			if e != nil {
				t.Fatal("certificate control", e)
			}
		} else if authorityCode(e) != "key_domain" {
			t.Fatal("retained certificate key domain", slot, e)
		}
	}
}
