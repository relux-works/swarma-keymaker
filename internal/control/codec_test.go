package control

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

// The decoder rejects each noncanonical/invalid class next to canonical controls;
// this tests codec bytes rather than method or enrollment semantic validity.
func TestCCJNegativeControls(t *testing.T) {
	cases := []struct{ name, bad, good string }{
		{"whitespace", `{ "a":1}`, `{"a":1}`},
		{"trailing-space", `{} `, `{}`},
		{"extra-document", `{}{}`, `{"a":{}}`},
		{"duplicate", `{"a":1,"a":2}`, `{"a":1,"b":2}`},
		{"nested-duplicate", `{"a":{"b":1,"b":2}}`, `{"a":{"b":1,"c":2}}`},
		{"escaped-alias", `{"a":1,"\u0061":2}`, `{"a":1,"b":2}`},
		{"negative-zero", `{"a":-0}`, `{"a":0}`},
		{"fraction", `{"a":1.0}`, `{"a":1}`},
		{"exponent", `{"a":1e0}`, `{"a":1}`},
		{"unsafe-positive", `{"a":9007199254740992}`, `{"a":9007199254740991}`},
		{"unsafe-negative", `{"a":-9007199254740992}`, `{"a":-9007199254740991}`},
		{"overflow", `{"a":9223372036854775808}`, `{"a":9007199254740991}`},
		{"leading-zero", `{"a":01}`, `{"a":1}`},
		{"positive-sign", `{"a":+1}`, `{"a":1}`},
		{"missing-number", `{"a":-}`, `{"a":-1}`},
		{"invalid-utf8", "{\"a\":\"\xff\"}", `{"a":"valid"}`},
		{"lone-high-surrogate", `{"a":"\ud800"}`, `{"a":"😀"}`},
		{"lone-low-surrogate", `{"a":"\udc00"}`, `{"a":"😀"}`},
		{"paired-surrogate-wire", `{"a":"\ud83d\ude00"}`, `{"a":"😀"}`},
		{"escaped-slash", `{"a":"\/"}`, `{"a":"/"}`},
		{"escaped-angle", `{"a":"\u003c"}`, `{"a":"<"}`},
		{"escaped-nonascii", `{"a":"\u00e9"}`, `{"a":"é"}`},
		{"long-newline-escape", `{"a":"\u000a"}`, `{"a":"\n"}`},
		{"uppercase-escape", `{"a":"\u001F"}`, `{"a":"\u001f"}`},
		{"noncontrol-escape", `{"a":"\u007f"}`, "{\"a\":\"\x7f\"}"},
		{"raw-control", "{\"a\":\"\x01\"}", `{"a":"\u0001"}`},
		{"bad-escape", `{"a":"\x01"}`, `{"a":"\u0001"}`},
		{"unterminated", `{"a":"`, `{"a":""}`},
		{"missing-comma", `{"a":1"b":2}`, `{"a":1,"b":2}`},
		{"trailing-comma", `{"a":1,}`, `{"a":1}`},
		{"array-trailing-comma", `{"a":[1,]}`, `{"a":[1]}`},
		{"wrong-literal", `{"a":True}`, `{"a":true}`},
		{"bom", "\xef\xbb\xbf{}", `{}`},
		{"root-array", `[]`, `{}`},
		{"root-null", `null`, `{}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Decode([]byte(c.bad)); err == nil {
				t.Fatal("accepted invalid/noncanonical bytes")
			}
			obj, err := Decode([]byte(c.good))
			if err != nil {
				t.Fatalf("valid control: %v", err)
			}
			out, err := Marshal(obj)
			if err != nil || !bytes.Equal(out, []byte(c.good)) {
				t.Fatalf("control round trip: %q %v", out, err)
			}
		})
	}
}

// Unsorted keys must not enter an object; the same sorted members must pass.
func TestCCJRejectsUnsortedKeys(t *testing.T) {
	if _, err := Decode([]byte(`{"b":1,"a":2}`)); err == nil {
		t.Fatal("unsorted keys accepted")
	}
	if _, err := Decode([]byte(`{"a":2,"b":1}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode([]byte(`{"a":{"c":1,"b":2}}`)); err == nil {
		t.Fatal("nested unsorted keys accepted")
	}
}

// Canonical bytes implement registrar Appendix B PC1-PC7/PC9/PC10 scenarios;
// PC8's surrogate wire spelling is rejected natively, but its scalar encodes raw.
func TestRegistrarCodecControls(t *testing.T) {
	cases := []struct {
		name   string
		object Object
		want   string
	}{
		{"PC1-scalar-order", Object{"𐀀": int64(2), "\ue000": int64(1)}, "{\"\ue000\":1,\"𐀀\":2}"},
		{"PC2-whitespace", Object{"a": Object{"b": int64(1)}}, `{"a":{"b":1}}`},
		{"PC3-array", Object{"a": []any{int64(3), int64(1), int64(2)}}, `{"a":[3,1,2]}`},
		{"PC4-escapes", Object{"a": "\"\\\b\f\n\r\t\x00\x1f"}, `{"a":"\"\\\b\f\n\r\t\u0000\u001f"}`},
		{"PC5-literal", Object{"a": "/<>&é\u2028"}, "{\"a\":\"/<>&é\u2028\"}"},
		{"PC6-integers", Object{"a": []any{-MaxInteger, int64(0), MaxInteger}}, `{"a":[-9007199254740991,0,9007199254740991]}`},
		{"PC7-literals", Object{"a": []any{true, false, nil}}, `{"a":[true,false,null]}`},
		{"PC8-scalar", Object{"a": "😀"}, `{"a":"😀"}`},
		{"PC9-no-normalization", Object{"a": "é", "b": "e\u0301"}, "{\"a\":\"é\",\"b\":\"e\u0301\"}"},
		{"PC10-no-sig-stripping", Object{"a": Object{"sig": "nested"}, "sig": "outer"}, `{"a":{"sig":"nested"},"sig":"outer"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := Marshal(c.object)
			if err != nil || string(out) != c.want {
				t.Fatalf("got %q %v; want %q", out, err, c.want)
			}
			decoded, err := Decode(out)
			if err != nil {
				t.Fatal(err)
			}
			again, err := Marshal(decoded)
			if err != nil || !bytes.Equal(out, again) {
				t.Fatalf("unstable encoding: %q %v", again, err)
			}
		})
	}
}

// The sixteenth container is allowed; the seventeenth and over-cap objects are
// refused on both encoding and decoding without relying on stack exhaustion.
func TestCCJBounds(t *testing.T) {
	for _, depth := range []int{16, 17} {
		data := `{"a":` + strings.Repeat("[", depth-1) + "0" + strings.Repeat("]", depth-1) + "}"
		obj, err := Decode([]byte(data))
		if (err == nil) != (depth == 16) {
			t.Fatalf("depth %d: %v", depth, err)
		}
		if depth == 16 {
			if _, err := Marshal(obj); err != nil {
				t.Fatal(err)
			}
		}
	}
	var nested any = int64(0)
	for range 16 {
		nested = []any{nested}
	}
	if _, err := Marshal(Object{"a": nested}); err == nil {
		t.Fatal("encoded depth 17")
	}
	for _, n := range []int{MaxFrame - 8, MaxFrame - 7} {
		data := `{"a":"` + strings.Repeat("x", n) + `"}`
		_, err := Decode([]byte(data))
		out, encErr := Marshal(Object{"a": strings.Repeat("x", n)})
		valid := len(data) <= MaxFrame
		if (err == nil) != valid || (encErr == nil) != valid {
			t.Fatalf("size %d: %v %v", len(data), err, encErr)
		}
		if valid && string(out) != data {
			t.Fatal("size-bound control changed")
		}
	}
}

// Encoder accepts in-range Go integers, but cannot silently coerce floats,
// unsafe values, invalid strings, unsupported types, or cyclic containers.
func TestEncoderRejectsInvalidValues(t *testing.T) {
	invalid := []any{float64(1), math.Inf(1), MaxInteger + 1, -MaxInteger - 1, uint64(1) << 63, string([]byte{0xff}), []byte("bytes"), map[int]string{1: "x"}}
	cycle := Object{}
	cycle["a"] = cycle
	invalid = append(invalid, cycle)
	for _, v := range invalid {
		if _, err := Marshal(Object{"a": v}); err == nil {
			t.Fatalf("encoded invalid %T", v)
		}
	}
	if _, err := Marshal(Object{string([]byte{0xff}): true}); err == nil {
		t.Fatal("invalid key encoded")
	}
	for _, v := range []any{int(1), int8(-1), int16(2), int32(3), int64(4), uint(1), uint8(2), uint16(3), uint32(4), uint64(MaxInteger)} {
		b, err := Marshal(Object{"a": v})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(b); err != nil {
			t.Fatal(err)
		}
	}
}

// Any accepted bounded fuzz input must re-encode byte-for-byte, and every
// successful encoder result must decode again. Rejections make no validity claim.
func FuzzCCJRoundTrip(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":[true,false,null,0,-1,9007199254740991]}`, `{"a":"/<>&é😀","b":"\u0001\n"}`, `{"b":1,"a":2}`, `{"a":1,"a":2}`, `{"a":-0}`, `{"a":1e0}`, `{"a":"\ud800"}`, "{\"a\":\"\xff\"}", `{}{}","`, strings.Repeat("[", 17)} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxFrame {
			return
		}
		obj, err := Decode(data)
		if err != nil {
			return
		}
		out, err := Marshal(obj)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, out) {
			t.Fatalf("accepted noncanonical bytes %q -> %q", data, out)
		}
		if _, err := Decode(out); err != nil {
			t.Fatal(err)
		}
	})
}
