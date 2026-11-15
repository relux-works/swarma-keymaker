package j7lifecycle_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"

	wire "github.com/relux-works/swarma-keymaker/j7lifecycle"
)

const requestID = "00000000000000000000000000000001"
const runID = "11111111111111111111111111111111"

func requestFor(kind string) wire.Request {
	r := wire.Request{ID: requestID, Method: wire.HelloMethod, Versions: []int64{1}}
	switch kind {
	case "hello":
	case "hello-no-v1":
		r.Versions = []int64{2}
	case "bind", "child", "owner":
		r.Method, r.Versions, r.TimeoutMS = wire.BindMethod, nil, 2000
		r.Bind = &wire.BindParams{IdentityRegistrationNumber: 1, InputPrincipal: wire.Principal{UID: 22001, Generation: "input-generation-1"}, Origin: &wire.Origin{Kind: "admission", EventID: strings.Repeat("a", 64), GrantID: strings.Repeat("b", 64), TipHash: strings.Repeat("c", 64), Mode: "enforcing"}}
		if kind == "child" {
			r.Bind.Origin = nil
			r.Bind.ParentRun = runID
		}
		if kind == "owner" {
			r.Bind.Origin = &wire.Origin{Kind: "owner_command", CommandID: strings.Repeat("d", 64)}
		}
	case "end", "rebind":
		r.Method, r.Versions, r.TimeoutMS, r.RunID = wire.EndMethod, nil, 2000, runID
		if kind == "rebind" {
			r.Method = wire.RebindMethod
		}
	default:
		panic("unknown reference context")
	}
	return r
}
func literalFrame(body string) []byte {
	f := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(f, uint32(len(body)))
	copy(f[4:], body)
	return f
}
func encoded(t *testing.T, r wire.Request) []byte {
	t.Helper()
	f, e := wire.EncodeRequestFrame(r)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func rejectRequest(t *testing.T, f []byte, want error) {
	t.Helper()
	r, e := wire.DecodeRequestFrame(f)
	if !errors.Is(e, want) || !reflect.DeepEqual(r, wire.Request{}) {
		t.Fatalf("request refusal/zero value: got %v, %+v want %v", e, r, want)
	}
}
func rejectResponse(t *testing.T, q wire.Request, f []byte, want error) {
	t.Helper()
	r, e := wire.DecodeResponseFrame(q, f)
	if !errors.Is(e, want) || !reflect.DeepEqual(r, wire.Response{}) {
		t.Fatalf("response refusal/zero value: got %v, %+v want %v frame=%q", e, r, want, f)
	}
}

// The nearby valid variants fix the wire vocabulary; semantic neighbors cannot
// introduce selectors, partial variants or new origin/generation authority.
func TestLifecycleWireClosedRequests(t *testing.T) {
	for _, kind := range []string{"hello", "hello-no-v1", "bind", "owner", "child", "end", "rebind"} {
		t.Run(kind, func(t *testing.T) {
			q := requestFor(kind)
			got, e := wire.DecodeRequestFrame(encoded(t, q))
			if e != nil || !reflect.DeepEqual(q, got) {
				t.Fatalf("valid variant %s: %v %+v", kind, e, got)
			}
		})
	}
	cases := []struct {
		name   string
		kind   string
		change func(*wire.Request)
	}{
		{"empty-id", "bind", func(r *wire.Request) { r.ID = "" }},
		{"upper-id", "bind", func(r *wire.Request) { r.ID = strings.Repeat("A", 32) }},
		{"query", "end", func(r *wire.Request) { r.Method = "j7_run_query" }},
		{"sign", "end", func(r *wire.Request) { r.Method = "j7_sign" }},
		{"generic-digest", "end", func(r *wire.Request) { r.Method = "sign" }},
		{"hello-timeout", "hello", func(r *wire.Request) { r.TimeoutMS = 1 }},
		{"hello-no-offer", "hello", func(r *wire.Request) { r.Versions = nil }},
		{"hello-duplicate", "hello", func(r *wire.Request) { r.Versions = []int64{1, 1} }},
		{"hello-zero", "hello", func(r *wire.Request) { r.Versions = []int64{0, 1} }},
		{"hello-unsafe", "hello", func(r *wire.Request) { r.Versions = []int64{wire.MaxInteger + 1} }},
		{"hello-bind", "hello", func(r *wire.Request) { r.Bind = requestFor("bind").Bind }},
		{"bind-nil", "bind", func(r *wire.Request) { r.Bind = nil }},
		{"bind-run-selector", "bind", func(r *wire.Request) { r.RunID = runID }},
		{"bind-versions", "bind", func(r *wire.Request) { r.Versions = []int64{1} }},
		{"identity-zero", "bind", func(r *wire.Request) { r.Bind.IdentityRegistrationNumber = 0 }},
		{"identity-unsafe", "bind", func(r *wire.Request) { r.Bind.IdentityRegistrationNumber = uint64(wire.MaxInteger) + 1 }},
		{"input-zero", "bind", func(r *wire.Request) { r.Bind.InputPrincipal.UID = 0 }},
		{"generation-empty", "bind", func(r *wire.Request) { r.Bind.InputPrincipal.Generation = "" }},
		{"generation-utf8", "bind", func(r *wire.Request) { r.Bind.InputPrincipal.Generation = string([]byte{255}) }},
		{"root-no-origin", "bind", func(r *wire.Request) { r.Bind.Origin = nil }},
		{"child-with-origin", "child", func(r *wire.Request) { r.Bind.Origin = requestFor("bind").Bind.Origin }},
		{"parent-not-id", "child", func(r *wire.Request) { r.Bind.ParentRun = "parent" }},
		{"matrix-event", "bind", func(r *wire.Request) { r.Bind.Origin.EventID = "$event" }},
		{"admission-mode", "bind", func(r *wire.Request) { r.Bind.Origin.Mode = "held" }},
		{"admission-command", "bind", func(r *wire.Request) { r.Bind.Origin.CommandID = strings.Repeat("d", 64) }},
		{"owner-extra", "owner", func(r *wire.Request) { r.Bind.Origin.EventID = strings.Repeat("a", 64) }},
		{"foreign-origin", "bind", func(r *wire.Request) { r.Bind.Origin.Kind = "owner" }},
		{"end-bind", "end", func(r *wire.Request) { r.Bind = requestFor("bind").Bind }},
		{"end-empty-run", "end", func(r *wire.Request) { r.RunID = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q := requestFor(c.kind)
			c.change(&q)
			b, e := wire.EncodeRequestFrame(q)
			if e != wire.ErrRequest || b != nil {
				t.Fatalf("invalid typed request encoded: %v %x", e, b)
			}
		})
	}
	// These values intentionally remain opaque: no UUID/ASCII/normalization rule.
	for _, gen := range []string{"g", "α\n<>&", "é", "e\u0301"} {
		q := requestFor("bind")
		q.Bind.InputPrincipal.Generation = gen
		q.Bind.InputPrincipal.UID = ^uint32(0)
		q.Bind.IdentityRegistrationNumber = uint64(wire.MaxInteger)
		got, e := wire.DecodeRequestFrame(encoded(t, q))
		if e != nil || got.Bind.InputPrincipal.Generation != gen {
			t.Fatal("opaque generation changed", e)
		}
	}
}

// Native timeout bounds are inclusive; hello keeps its separate exact envelope.
func TestLifecycleWireDeadlines(t *testing.T) {
	for _, n := range []int64{1, 2000} {
		r := requestFor("bind")
		r.TimeoutMS = n
		encoded(t, r)
	}
	for _, n := range []int64{-1, 0, 2001, 5000} {
		r := requestFor("bind")
		r.TimeoutMS = n
		if b, e := wire.EncodeRequestFrame(r); e != wire.ErrRequest || b != nil {
			t.Fatalf("timeout accepted: %d", n)
		}
	}
	base := string(encoded(t, requestFor("end"))[4:])
	for _, v := range []string{`"1"`, `1.5`, `true`, `null`, `2001`, `0`} {
		want := wire.ErrRequest
		if v == `1.5` {
			want = wire.ErrCanonical
		}
		rejectRequest(t, literalFrame(strings.Replace(base, `"timeout_ms":2000`, `"timeout_ms":`+v, 1)), want)
	}
}

// Framing and canonical grammar have exact local errors and zero values, while
// the adjacent 65536-byte canonical request succeeds. This cannot prevent the
// caller's prior byte-slice allocation; cap rejection itself allocates nothing.
func TestLifecycleWireGrammarBounds(t *testing.T) {
	q := requestFor("bind")
	base := encoded(t, q)
	q.Bind.InputPrincipal.Generation += strings.Repeat("g", wire.MaxFrame-(len(base)-4))
	max := encoded(t, q)
	if len(max) != wire.MaxFrame+4 {
		t.Fatal("maximum control length")
	}
	if _, e := wire.DecodeRequestFrame(max); e != nil {
		t.Fatal(e)
	}
	q.Bind.InputPrincipal.Generation += "g"
	if b, e := wire.EncodeRequestFrame(q); e != wire.ErrRequest || b != nil {
		t.Fatal("over-cap request encoded")
	}
	expectedEnd := requestFor("end")
	for _, n := range []uint32{wire.MaxFrame + 1, ^uint32(0)} {
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, n)
		allocs := testing.AllocsPerRun(5, func() {
			if _, e := wire.DecodeRequestFrame(header); e != wire.ErrFrameTooLarge {
				t.Fatal("cap header accepted", e)
			}
			if _, e := wire.DecodeResponseFrame(expectedEnd, header); e != wire.ErrFrameTooLarge {
				t.Fatal("response cap header accepted", e)
			}
		})
		if allocs != 0 {
			t.Fatalf("cap rejection allocated %v", allocs)
		}
	}
	rejectRequest(t, make([]byte, 4), wire.ErrFrameMalformed)
	for n := 0; n < len(base); n++ {
		rejectRequest(t, base[:n], wire.ErrFrameTruncated)
	}
	rejectRequest(t, append(append([]byte{}, base...), 0), wire.ErrTrailingData)
	body := string(base[4:])
	for _, bad := range []string{" " + body, body + "\n", strings.Replace(body, `"method":`, `"method":"j7_run_bind","method":`, 1), strings.Replace(body, `"params":`, `"zzz":0,"params":`, 1), strings.Replace(body, `"uid":22001`, `"uid":-0`, 1), strings.Replace(body, `"uid":22001`, `"uid":2.2001e4`, 1), strings.Replace(body, `input-generation-1`, `\u0069nput-generation-1`, 1), string(append([]byte{255}, []byte(body)...))} {
		rejectRequest(t, literalFrame(bad), wire.ErrCanonical)
	}
	for _, bad := range []string{strings.Replace(body, `"uid":22001`, `"uid":4294967296`, 1), strings.Replace(body, `"origin":{`, `"nonce":0,"origin":{`, 1), strings.Replace(body, `"generation":`, `"extra":0,"generation":`, 1), strings.Replace(body, `"parent_run":""`, `"parent_run":null`, 1)} {
		rejectRequest(t, literalFrame(bad), wire.ErrRequest)
	}
	for depth := 16; depth <= 17; depth++ {
		nested := `{"x":` + strings.Repeat("[", depth-1) + `0` + strings.Repeat("]", depth-1) + `}`
		want := wire.ErrRequest
		if depth == 17 {
			want = wire.ErrCanonical
		}
		rejectRequest(t, literalFrame(nested), want)
	}
	for _, kind := range []string{"generation", "versions"} {
		q := requestFor("bind")
		if kind == "generation" {
			q.Bind.InputPrincipal.Generation = strings.Repeat("x", wire.MaxFrame+1)
		} else {
			q = requestFor("hello")
			q.Versions = make([]int64, wire.MaxFrame)
		}
		if n := testing.AllocsPerRun(5, func() {
			if b, e := wire.EncodeRequestFrame(q); e != wire.ErrRequest || b != nil {
				t.Fatal("obvious oversize encoded")
			}
		}); n != 0 {
			t.Fatalf("obvious oversize copied or allocated: %s %v", kind, n)
		}
	}
}

// Success correlation is local outstanding-request context, never a method
// echoed on wire. Bind/rebind share a shape; end and hello require their own.
func TestLifecycleWireResponseCorrelation(t *testing.T) {
	q := requestFor("end")
	good := `{"request_id":"` + requestID + `","result":{"run_id":"` + runID + `","state":"ended"}}`
	r, e := wire.DecodeResponseFrame(q, literalFrame(good))
	if e != nil || r.Run == nil || r.Run.RunID != q.RunID {
		t.Fatal("end control", e)
	}
	for _, bad := range []string{strings.Replace(good, requestID, strings.Repeat("2", 32), 1), strings.Replace(good, `"`+requestID+`"`, `null`, 1), strings.Replace(good, runID, strings.Repeat("2", 32), 1), strings.Replace(good, `"ended"`, `"live"`, 1), strings.Replace(good, `{"request_id":`, `{"method":"j7_run_end","request_id":`, 1), strings.Replace(good, `{"request_id":`, `{"error":{"code":"busy","retryable":true},"request_id":`, 1), strings.Replace(good, `"state":"ended"`, `"state":"ended","version":1`, 1)} {
		rejectResponse(t, q, literalFrame(bad), wire.ErrResponse)
	}
	rejectResponse(t, requestFor("hello"), literalFrame(good), wire.ErrResponse)
	hello := `{"request_id":"` + requestID + `","result":{"version":1}}`
	if _, e := wire.DecodeResponseFrame(requestFor("hello"), literalFrame(hello)); e != nil {
		t.Fatal(e)
	}
	rejectResponse(t, q, literalFrame(hello), wire.ErrResponse)
	rejectResponse(t, requestFor("hello-no-v1"), literalFrame(hello), wire.ErrResponse)
	live := strings.Replace(good, `"ended"`, `"live"`, 1)
	for _, kind := range []string{"bind", "rebind"} {
		if _, e := wire.DecodeResponseFrame(requestFor(kind), literalFrame(live)); e != nil {
			t.Fatal("live context", kind, e)
		}
	}
	rejectResponse(t, requestFor("rebind"), literalFrame(strings.Replace(live, runID, strings.Repeat("3", 32), 1)), wire.ErrResponse)
	// Unsupported expected methods cannot convert a plausible result into success.
	q.Method = "j7_sign"
	rejectResponse(t, q, literalFrame(good), wire.ErrResponse)
}

// All native refusal pairs are checked by the internal bridge; this public
// path rejects wrong bits/extra diagnostics and preserves unattributed failures.
func TestLifecycleWireRefusals(t *testing.T) {
	q := requestFor("end")
	for _, row := range []struct {
		code string
		bit  bool
	}{{"busy", true}, {"request_deadline_exceeded", true}, {"audit_unavailable", true}, {"role_not_permitted", false}, {"generation_inactive", false}, {"j7_state_fenced", false}, {"request_conflict", false}, {"frame_too_large", false}, {"ccj_noncanonical", false}} {
		for _, id := range []string{"", requestID} {
			r := wire.Response{ID: id, Refusal: &wire.Refusal{Code: row.code, Retryable: row.bit}}
			f, e := wire.EncodeResponseFrame(q, r)
			if id != "" && (row.code == "frame_too_large" || row.code == "ccj_noncanonical") {
				if e != wire.ErrResponse || f != nil {
					t.Fatal("framing error attributed")
				}
				continue
			}
			if e != nil {
				t.Fatal(e)
			}
			got, e := wire.DecodeResponseFrame(q, f)
			if e != nil || !reflect.DeepEqual(got, r) || got.Run != nil {
				t.Fatal("refusal lost", e, got)
			}
			r.Refusal.Retryable = !row.bit
			if f, e := wire.EncodeResponseFrame(q, r); e != wire.ErrResponse || f != nil {
				t.Fatal("retry bit accepted")
			}
		}
	}
	for _, body := range []string{`{"error":{"code":"busy","retryable":false},"request_id":null}`, `{"error":{"code":"free form","retryable":false},"request_id":null}`, `{"error":{"code":"run_bind_unknown","retryable":false},"request_id":null}`, `{"error":{"code":"busy","detail":"payload","retryable":true},"request_id":null}`, `{"error":{"code":"busy","retryable":true},"request_id":""}`, `{"error":{"code":"busy","retryable":true},"request_id":false}`} {
		rejectResponse(t, q, literalFrame(body), wire.ErrResponse)
	}
}

// Failed encoders cannot return a partial frame; failed decoders are exercised
// by the shared refusal helpers across grammar and semantic neighbors above.
func TestLifecycleWireFailureZeroValue(t *testing.T) {
	q := requestFor("end")
	version := int64(1)
	for _, r := range []wire.Response{{}, {ID: requestID}, {ID: requestID, Version: &version}, {ID: requestID, Run: &wire.RunResult{runID, "ended"}, Refusal: &wire.Refusal{"busy", true}}, {Run: &wire.RunResult{runID, "ended"}}, {ID: requestID, Run: &wire.RunResult{runID, "unknown"}}} {
		if f, e := wire.EncodeResponseFrame(q, r); e != wire.ErrResponse || f != nil {
			t.Fatal("partial response encoded", e)
		}
	}
	// Input bytes are not mutated, and decoded pointer/list values do not alias a
	// later decode. This is value conversion, not a persisted state transition.
	q = requestFor("hello")
	f := encoded(t, q)
	saved := bytes.Clone(f)
	a, _ := wire.DecodeRequestFrame(f)
	a.Versions[0] = 99
	b, _ := wire.DecodeRequestFrame(f)
	if !bytes.Equal(saved, f) || b.Versions[0] != 1 {
		t.Fatal("decode aliases input or prior value")
	}
}
