package stationcaller

import (
	"bytes"
	"strings"
	"testing"
)

// The path maximum follows the registry's three 31-bit names; a typed enormous
// path is refused before splitting. Unsafe wire integers are never coerced.
func TestResultOuterBounds(t *testing.T) {
	p := pubResult()
	p.Path = "m/6'/2147483647'/2147483647'/2147483647'"
	b, err := EncodeResponseFrame(PubkeyMethod, Response{ID: testID, PublicKey: &p})
	if err != nil {
		t.Fatal(err)
	}
	if r, err := DecodeResponseFrame(PubkeyMethod, b); err != nil || r.PublicKey.Path != p.Path {
		t.Fatal("maximum path control", err)
	}
	p.Path = strings.Repeat("/", MaxFrame+1)
	if b, err := EncodeResponseFrame(PubkeyMethod, Response{ID: testID, PublicKey: &p}); err != ErrResponse || b != nil {
		t.Fatal("enormous typed path accepted")
	}
	o := responseObject()
	frame := objectFrame(t, o)
	unsafe := strings.Replace(string(frame[4:]), `"registration_number":1`, `"registration_number":9007199254740992`, 1)
	badResponse(t, PubkeyMethod, packet(unsafe), ErrCanonical)
}

// Canonical epoch values preserve allowed controls/Unicode exactly; alternate
// escape spellings, duplicate members and response-only extra documents refuse.
func TestResponseCanonicalNeighbours(t *testing.T) {
	p := pubResult()
	p.Epoch = "/é\n\x1f\x7f"
	b, err := EncodeResponseFrame(PubkeyMethod, Response{ID: testID, PublicKey: &p})
	if err != nil {
		t.Fatal(err)
	}
	r, err := DecodeResponseFrame(PubkeyMethod, b)
	if err != nil || r.PublicKey.Epoch != p.Epoch {
		t.Fatal("epoch control", err)
	}
	body := string(b[4:])
	for _, bad := range []string{
		strings.Replace(body, `/é`, `\/é`, 1),
		strings.Replace(body, `é`, `\u00e9`, 1),
		strings.Replace(body, `\n`, `\u000a`, 1),
		strings.Replace(body, `\u001f`, `\u001F`, 1),
		strings.Replace(body, "\x7f", `\u007f`, 1),
		strings.Replace(body, `"request_id":`, `"request_id":null,"request_id":`, 1),
		body + "{}",
	} {
		if bad == body {
			t.Fatal("control mutation did not apply")
		}
		badResponse(t, PubkeyMethod, packet(bad), ErrCanonical)
	}
	if bytes.Equal([]byte("é"), []byte("e\u0301")) {
		t.Fatal("invalid independent Unicode control")
	}
}
