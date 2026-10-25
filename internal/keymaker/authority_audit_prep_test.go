package keymaker

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func pc2AuditInput(t *testing.T) authorityAuditInput {
	t.Helper()
	body, e := os.ReadFile("../../vectors/authority-root/binding-body.json")
	if e != nil {
		t.Fatal(e)
	}
	stamp := "2026-10-25T00:00:00Z"
	tail := authorityAuditTail{Seq: 1, Hash: strings.Repeat("0", 64)}
	return authorityAuditInput{
		Body: body, TransactionID: "sha256:ca605968290d62605131c574f35565c6ee4a2fe468800d489f400c48cf3d2c99",
		Tail: tail, BindingVersion: 1, Instance: strings.Repeat("1", 32), Timestamp: &stamp,
		Rotation: &authorityAuditRotationReservation{Tail: tail, Segment: 1, FirstSeq: 1, SegmentBytes: 1000, SegmentLimit: 64 << 20, SealBytes: 1024, NewSegments: 1},
		Message:  &authorityAuditMessageReservation{Tail: tail, Reserved: messageAuditReserve, Remaining: messageAuditReserve, TotalBytes: 1000, TotalLimit: (1 << 30) + (16 << 20)},
	}
}

// Invalid tails, tickets, cyclic fields, identities and frame bounds return no
// partial plan and leave all supplied bytes/values unchanged. Each has the same
// valid adjacent control; these value checks do not authenticate a live ticket.
func TestPC2AuditPrepareRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, code string
		change     func(*authorityAuditInput)
	}{
		{"tail-mismatch", "audit_tail_mismatch", func(in *authorityAuditInput) { in.Rotation.Tail.Seq++ }},
		{"message-tail-mismatch", "audit_tail_mismatch", func(in *authorityAuditInput) { in.Message.Tail.Hash = strings.Repeat("a", 64) }},
		{"tail-hash", "audit_tail_mismatch", func(in *authorityAuditInput) { in.Tail.Hash = "invalid" }},
		{"tail-overflow", "audit_reservation_overflow", func(in *authorityAuditInput) { in.Tail.Seq = uint64(authoritySafeInteger) }},
		{"binding-overflow", "audit_reservation_overflow", func(in *authorityAuditInput) { in.BindingVersion = math.MaxUint64 }},
		{"binding-mismatch", "audit_binding_mismatch", func(in *authorityAuditInput) { in.BindingVersion = 0 }},
		{"reservation-overflow", "audit_reservation_overflow", func(in *authorityAuditInput) { in.Message.TotalBytes = math.MaxInt64 }},
		{"total-limit-overflow", "audit_reservation_overflow", func(in *authorityAuditInput) { in.Message.TotalLimit = math.MaxInt64 }},
		{"segment-limit-overflow", "audit_reservation_overflow", func(in *authorityAuditInput) { in.Rotation.SegmentLimit = math.MaxInt64 }},
		{"negative-reservation", "audit_reservation_invalid", func(in *authorityAuditInput) { in.Message.Remaining = -1 }},
		{"missing-rotation", "audit_reservation_missing", func(in *authorityAuditInput) { in.Rotation = nil }},
		{"missing-message", "audit_reservation_missing", func(in *authorityAuditInput) { in.Message = nil }},
		{"exhausted-message", "audit_reservation_overflow", func(in *authorityAuditInput) { in.Message.Remaining = 0 }},
		{"transaction-mismatch", "authority_transaction_mismatch", func(in *authorityAuditInput) { in.TransactionID = "sha256:" + strings.Repeat("a", 64) }},
		{"candidate-mismatch", "authority_transaction_mismatch", func(in *authorityAuditInput) {
			o := pc2Object(t, in.Body)
			o["authority"].(map[string]any)["master_epoch"] = "different"
			in.Body = pc2Bytes(t, o)
		}},
		{"self-hash", "unknown_member", func(in *authorityAuditInput) {
			o := pc2Object(t, in.Body)
			o["authority"].(map[string]any)["record_digest"] = strings.Repeat("a", 64)
			in.Body = pc2Bytes(t, o)
		}},
		{"future-root", "unknown_member", func(in *authorityAuditInput) {
			o := pc2Object(t, in.Body)
			o["authority"].(map[string]any)["root_digest"] = "sha256:" + strings.Repeat("a", 64)
			in.Body = pc2Bytes(t, o)
		}},
		{"future-audit", "unknown_member", func(in *authorityAuditInput) {
			o := pc2Object(t, in.Body)
			o["authority"].(map[string]any)["binding_commit"] = map[string]any{}
			in.Body = pc2Bytes(t, o)
		}},
		{"oversize-frame", "audit_frame_limit", func(in *authorityAuditInput) { in.Instance = strings.Repeat("a", 8193) }},
		{"undersized-segment", "audit_frame_limit", func(in *authorityAuditInput) {
			in.Rotation.SegmentLimit, in.Rotation.SegmentBytes = 1, 0
			in.Rotation.FirstSeq = in.Tail.Seq + 1
		}},
		{"bad-time", "field_format", func(in *authorityAuditInput) { *in.Timestamp = "2026-10-25T00:00:00.1Z" }},
		{"body-intake-limit", "total_limit", func(in *authorityAuditInput) { in.Body = bytes.Repeat([]byte{' '}, 2*authorityRootLimit+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := pc2AuditInput(t)
			if _, e := prepareAuthorityAudit(in); e != nil {
				t.Fatal("valid control", e)
			}
			tc.change(&in)
			before, _ := json.Marshal(in)
			out, e := prepareAuthorityAudit(in)
			after, _ := json.Marshal(in)
			if authorityCode(e) != tc.code || !reflect.DeepEqual(out, authorityPreparedAudit{}) || !bytes.Equal(before, after) {
				t.Fatalf("refusal invariant: want=%s error=%v partial=%t changed=%t", tc.code, e, !reflect.DeepEqual(out, authorityPreparedAudit{}), !bytes.Equal(before, after))
			}
		})
	}
}

// Independent Python hashlib/json constants fix exact LF-inclusive frame bytes,
// C and the resulting R hash. G4 supplies B3/candidate/transaction preimages;
// it supplies no audit-frame golden for this timestamp/tail.
func TestPC2AuditPreparedGolden(t *testing.T) {
	in := pc2AuditInput(t)
	before, _ := json.Marshal(in)
	out, e := prepareAuthorityAudit(in)
	if e != nil {
		t.Fatal(e)
	}
	after, _ := json.Marshal(in)
	repeat, repeatErr := prepareAuthorityAudit(in)
	if !bytes.Equal(before, after) || repeatErr != nil || !reflect.DeepEqual(out, repeat) {
		t.Fatal("successful preparation mutated inputs or acquired ambient state", repeatErr)
	}
	const frame = `{"domain":"control","generation":null,"instance":"11111111111111111111111111111111","master_epoch":null,"operation":"binding_commit","path":null,"payload_digest":"4a88e584c4e2cc47b7e072c8458d1c33f1a581a68ba680dcf53cf88a2a29e6bf","peer_uid":null,"previous_digest":"0000000000000000000000000000000000000000000000000000000000000000","record_digest":"2b53085fdb55f0206211fe8c5c9bfb6b49dbac2acf2a96f52f2204941f96d601","refusal_code":null,"request_id":"binding:2","result":"success","seq":2,"surface":"control","time":"2026-10-25T00:00:00Z"}` + "\n"
	want := bindingCommit{Version: 2, Digest: "4a88e584c4e2cc47b7e072c8458d1c33f1a581a68ba680dcf53cf88a2a29e6bf", Seq: 2, Hash: "2b53085fdb55f0206211fe8c5c9bfb6b49dbac2acf2a96f52f2204941f96d601"}
	if len(out.Frames) != 1 || string(out.Frames[0]) != frame || out.Binding != want || out.Tail != (authorityAuditTail{Seq: want.Seq, Hash: want.Hash}) || out.Root["root_digest"] != "sha256:db635bfcdbc92c0f84227c4622e3dc2d8ade0b2bdbc98886b6138e6bed2b8b0c" {
		t.Fatal("independent audit/C/R golden mismatch")
	}
	body, e := authorityBindingPreimage(out.Root)
	if e != nil || !bytes.Equal(pc2Bytes(t, body), in.Body) {
		t.Fatal("audit/root hashes entered B3", e)
	}
	candidate, e := authorityCandidate(body)
	wantCandidate, readErr := os.ReadFile("../../vectors/authority-root/candidate.json")
	if e != nil || readErr != nil || !bytes.Equal(pc2Bytes(t, candidate), wantCandidate) {
		t.Fatal("G4 candidate mismatch", e, readErr)
	}
	if out.MessageRemaining != in.Message.Remaining-int64(len(frame)) || out.MessageReserved != in.Message.Reserved-int64(len(frame)) || out.Rotation != nil {
		t.Fatal("reservation charge mismatch")
	}
	// Supplied unknown time remains null/unknown, rather than acquiring time.
	in.Timestamp = nil
	unknown, e := prepareAuthorityAudit(in)
	if e != nil || !bytes.Contains(unknown.Frames[0], []byte(`"time":null`)) || !bytes.Contains(unknown.Frames[0], []byte(`"result":"unknown"`)) {
		t.Fatal("unknown time not preserved", e)
	}
}

// Exact-fit frame, message and rotation reservations succeed; adjacent smaller
// reservations refuse without a plan. Seal bytes follow the existing recipe.
func TestPC2AuditPrepareBounds(t *testing.T) {
	in := pc2AuditInput(t)
	base, e := prepareAuthorityAudit(in)
	if e != nil {
		t.Fatal(e)
	}
	n := int64(len(base.Frames[0]))
	in.Rotation.SegmentLimit = n
	in.Rotation.SegmentBytes = 1
	in.Message.TotalLimit = in.Message.TotalBytes + n + 7
	in.Message.Remaining, in.Message.Reserved = n, n+7
	out, e := prepareAuthorityAudit(in)
	wantSeal := `{"first_seq":1,"last_digest":"` + in.Tail.Hash + `","last_seq":1}`
	if e != nil || out.Rotation == nil || string(out.Rotation.Seal) != wantSeal || out.Rotation.NextSegment != 2 || out.MessageRemaining != 0 || out.MessageReserved != 7 {
		t.Fatal("exact-fit rotation/charge", e)
	}
	in.Rotation.SealBytes = int64(len(wantSeal))
	if _, e := prepareAuthorityAudit(in); e != nil {
		t.Fatal("exact seal reservation", e)
	}
	for _, change := range []func(*authorityAuditInput){
		func(in *authorityAuditInput) { in.Rotation.SealBytes-- },
		func(in *authorityAuditInput) { in.Rotation.NewSegments = 0 },
		func(in *authorityAuditInput) { in.Message.TotalLimit-- },
		func(in *authorityAuditInput) { in.Message.Remaining-- },
		func(in *authorityAuditInput) { in.Rotation.Segment = uint64(authoritySafeInteger) },
	} {
		bad := in
		r, m := *in.Rotation, *in.Message
		bad.Rotation, bad.Message = &r, &m
		change(&bad)
		out, e := prepareAuthorityAudit(bad)
		if authorityCode(e) != "audit_reservation_overflow" || !reflect.DeepEqual(out, authorityPreparedAudit{}) {
			t.Fatal("smaller reservation accepted", e)
		}
	}
}

// This bounded construction check excludes ambient time, providers, locks and
// I/O from the preparer file: no global variables, only strconv and a reviewed
// pure-helper call set. Input types contain values, not callbacks/capabilities.
func TestPC2AuditPreparationPurity(t *testing.T) {
	f, e := parser.ParseFile(token.NewFileSet(), "authority_audit_prep.go", nil, 0)
	if e != nil {
		t.Fatal(e)
	}
	for _, imp := range f.Imports {
		if imp.Path.Value != `"strconv"` {
			t.Fatal("preparer clock/I/O import", imp.Path.Value)
		}
	}
	allowed := strings.Fields("prepareAuthorityAudit len int64 uint64 append authorityFail validDigest arID arStamp decodeAuthority authorityCandidate authorityTransaction encodeAuthority authorityDigest authorityCopy sealAuthorityRoot canonical auditDigest")
	for _, decl := range f.Decls {
		if d, ok := decl.(*ast.GenDecl); ok && d.Tok == token.VAR {
			t.Fatal("preparer ambient state")
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				for _, name := range allowed {
					if name == id.Name {
						return true
					}
				}
				t.Fatal("preparer non-pure call", id.Name)
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "FormatUint" {
				t.Fatal("preparer indirect call")
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != "strconv" {
				t.Fatal("preparer capability call")
			}
		}
		return true
	})
	var valuesOnly func(reflect.Type)
	valuesOnly = func(typ reflect.Type) {
		switch typ.Kind() {
		case reflect.Struct:
			for i := 0; i < typ.NumField(); i++ {
				valuesOnly(typ.Field(i).Type)
			}
		case reflect.Pointer, reflect.Slice:
			valuesOnly(typ.Elem())
		case reflect.String, reflect.Uint64, reflect.Int64, reflect.Uint8:
		default:
			t.Fatal("preparer input capability", typ)
		}
	}
	valuesOnly(reflect.TypeOf(authorityAuditInput{}))
}

type pc2AuditFixedClock struct{ stamp *string }

func (c pc2AuditFixedClock) UTC() (time.Time, bool) {
	if c.stamp == nil {
		return time.Time{}, false
	}
	v, e := time.Parse("2006-01-02T15:04:05Z", *c.stamp)
	return v, e == nil
}

// Real old-path appends, including rotation and unknown time, retain exactly
// the preparer's bytes/seal/tail. No serving caller is redirected to preparation.
func TestPC2AuditEncoderGoldenParity(t *testing.T) {
	for _, rotate := range []bool{false, true} {
		for _, trusted := range []bool{false, true} {
			t.Run(strconv.FormatBool(rotate)+"/"+strconv.FormatBool(trusted), func(t *testing.T) {
				in := pc2AuditInput(t)
				if !trusted {
					in.Timestamp = nil
				}
				d := t.TempDir()
				if e := os.Chmod(d, 0700); e != nil {
					t.Fatal(e)
				}
				dir, e := OpenDirectory(d, uint32(os.Getuid()), 0700)
				if e != nil {
					t.Fatal(e)
				}
				defer dir.Close()
				j, e := openJournal(dir, uint32(os.Getuid()), pc2AuditFixedClock{in.Timestamp}, bytes.NewReader(bytes.Repeat([]byte{0x11}, 16)))
				if e != nil {
					t.Fatal(e)
				}
				defer j.Close()
				if _, c := j.commitBinding(1, strings.Repeat("0", 64)); c != "" {
					t.Fatal(c)
				}
				in.Tail = authorityAuditTail{Seq: j.seq, Hash: j.previous}
				in.Rotation.Tail, in.Message.Tail = in.Tail, in.Tail
				in.Rotation.SegmentBytes, in.Message.TotalBytes = j.size, j.total
				if rotate {
					preview, e := prepareAuthorityAudit(in)
					if e != nil {
						t.Fatal(e)
					}
					j.segmentLimit = j.size + int64(len(preview.Frames[0])) - 1
					in.Rotation.SegmentLimit = j.segmentLimit
				}
				out, e := prepareAuthorityAudit(in)
				if e != nil {
					t.Fatal(e)
				}
				oldSize := j.size
				if got, c := j.commitBinding(2, out.Binding.Digest); c != "" || got != out.Binding {
					t.Fatal("old encoder tail mismatch", c)
				}
				b, e := os.ReadFile(filepath.Join(d, auditName(j.segment)))
				if !rotate {
					b = b[oldSize:]
				}
				if e != nil || !bytes.Equal(b, out.Frames[0]) {
					t.Fatal("P-PC2_AUDIT_ENCODER_BYTE: existing append bytes differ", e)
				}
				if rotate {
					seal, e := os.ReadFile(filepath.Join(d, auditName(1)+".seal"))
					if e != nil || out.Rotation == nil || !bytes.Equal(seal, out.Rotation.Seal) {
						t.Fatal("existing rotation seal differs", e)
					}
				}
			})
		}
	}
}
