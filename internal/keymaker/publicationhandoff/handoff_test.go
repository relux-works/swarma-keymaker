package publicationhandoff

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

//go:embed testdata/already-formed.json
var formed []byte

const transaction = "00112233445566778899aabbccddeeff"

func fixture(t *testing.T, raw []byte) (*Handoff, Request) {
	t.Helper()
	var env struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	h, err := Prepare(transaction, base64.RawURLEncoding.EncodeToString(raw), env.ID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := h.Original()
	if err != nil {
		t.Fatal(err)
	}
	return h, r
}

func TestOriginalLostReplyRetry(t *testing.T) {
	h, r := fixture(t, formed)
	for i := 0; i < 3; i++ {
		retry, outcome, err := h.Retry(r)
		if err != nil || retry != r || outcome.Original() != r || outcome.State() != NoReply || len(outcome.Reply()) != 0 {
			t.Fatal("lost reply changed original outcome", err)
		}
		if retry.Transaction() != transaction || !bytes.Equal(retry.Wire(), formed) || retry.Envelope() != base64.RawURLEncoding.EncodeToString(formed) {
			t.Fatal("original bytes replaced")
		}
	}
	reply := []byte("unverified public fixture reply")
	if err := h.RetainReply(r, reply); err != nil {
		t.Fatal(err)
	}
	reply[0] = 'X'
	_, outcome, err := h.Retry(r)
	if err != nil || outcome.State() != UnverifiedReply || string(outcome.Reply()) != "unverified public fixture reply" {
		t.Fatal("retained outcome lost", err)
	}
	if err := h.RetainReply(r, outcome.Reply()); err != nil {
		t.Fatal("exact replay refused", err)
	}
	if err := h.RetainReply(r, []byte("different reply")); !errors.Is(err, ErrConflict) {
		t.Fatal("conflicting reply replaced evidence", err)
	}
	_, after, _ := h.Retry(r)
	if after != outcome {
		t.Fatal("conflict modified outcome")
	}
}

func TestForeignOriginalAndSameIDChangedBytes(t *testing.T) {
	h, r := fixture(t, formed)
	_, other := fixture(t, append([]byte(" \n"), formed...))
	if other.ContentID() != r.ContentID() || other == r {
		t.Fatal("invalid same-ID control")
	}
	for _, wrong := range []Request{other, {}, {transaction: "ffeeddccbbaa99887766554433221100", contentID: r.contentID, envelope: r.envelope, wire: r.wire}} {
		if _, _, err := h.Retry(wrong); !errors.Is(err, ErrConflict) {
			t.Fatal("foreign retry accepted", err)
		}
		if err := h.RetainReply(wrong, []byte("reply")); !errors.Is(err, ErrConflict) {
			t.Fatal("foreign reply retained", err)
		}
	}
	if err := h.RetainReply(r, []byte("same original repair")); err != nil {
		t.Fatal("valid original control refused", err)
	}
}

func TestWireBoundsAndExactPreservation(t *testing.T) {
	raw := append(bytes.Repeat([]byte(" "), MaxWireBytes-len(formed)), formed...)
	h, r := fixture(t, raw)
	if len(r.Wire()) != MaxWireBytes || !bytes.Equal(r.Wire(), raw) {
		t.Fatal("8192-byte original changed")
	}
	_, _, _ = h.Retry(r)
	if _, err := Prepare(transaction, base64.RawURLEncoding.EncodeToString(append([]byte(" "), raw...)), r.ContentID()); !errors.Is(err, ErrInvalid) {
		t.Fatal("8193-byte envelope accepted", err)
	}
	for _, size := range []int{0, MaxReplyBytes + 1} {
		if err := h.RetainReply(r, bytes.Repeat([]byte("r"), size)); !errors.Is(err, ErrInvalid) {
			t.Fatal("reply bound ignored", size, err)
		}
	}
	if err := h.RetainReply(r, bytes.Repeat([]byte("r"), MaxReplyBytes)); err != nil {
		t.Fatal("bounded reply control refused", err)
	}
}

func TestMalformedAndWrongSignatureRefuse(t *testing.T) {
	_, r := fixture(t, formed)
	for _, tx := range []string{"", strings.ToUpper(transaction), transaction + "0", strings.Repeat("z", 32)} {
		if _, err := Prepare(tx, r.Envelope(), r.ContentID()); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid original transaction accepted", err)
		}
	}
	for _, encoded := range []string{"", r.Envelope() + "=", strings.Repeat("A", base64.RawURLEncoding.EncodedLen(MaxWireBytes)+1), base64.RawURLEncoding.EncodeToString([]byte(`{"body":{},"body":{}}`))} {
		if _, err := Prepare(transaction, encoded, r.ContentID()); !errors.Is(err, ErrInvalid) {
			t.Fatal("malformed envelope accepted", err)
		}
	}
	if _, err := Prepare(transaction, r.Envelope(), "sha256:"+strings.Repeat("0", 64)); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong content ID accepted", err)
	}
	var env map[string]any
	if err := json.Unmarshal(formed, &env); err != nil {
		t.Fatal(err)
	}
	sig := env["signatures"].([]any)[0].(map[string]any)
	sig["sig"] = strings.Repeat("A", 86)
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(transaction, base64.RawURLEncoding.EncodeToString(raw), r.ContentID()); !errors.Is(err, ErrInvalid) {
		t.Fatal("changed author signature accepted", err)
	}
	fixture(t, formed) // Same unmodified original remains a valid byte control.
}

func TestNoPublicationFromReply(t *testing.T) {
	h, r := fixture(t, formed)
	for _, reply := range [][]byte{nil, []byte(`{"published":true,"authenticated":true}`)} {
		if reply != nil {
			if err := h.RetainReply(r, reply); err != nil {
				t.Fatal(err)
			}
		}
		wire, err := h.PublishedWire()
		if wire != nil || !errors.Is(err, ErrUnavailable) {
			t.Fatal("unverified reply promoted to publication", err)
		}
	}
}

func TestZeroNilAndImmutableCopies(t *testing.T) {
	for _, h := range []*Handoff{nil, {}} {
		if _, err := h.Original(); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
		if _, _, err := h.Retry(Request{}); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
		if err := h.RetainReply(Request{}, []byte("reply")); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	h, r := fixture(t, formed)
	wire := r.Wire()
	wire[0] = 'X'
	if !bytes.Equal(r.Wire(), formed) {
		t.Fatal("request bytes aliased")
	}
	if err := h.RetainReply(r, []byte("reply")); err != nil {
		t.Fatal(err)
	}
	_, o, _ := h.Retry(r)
	reply := o.Reply()
	reply[0] = 'X'
	_, after, _ := h.Retry(r)
	if string(after.Reply()) != "reply" {
		t.Fatal("reply aliased")
	}
}

func TestConcurrentExactRetry(t *testing.T) {
	h, r := fixture(t, formed)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 16; n++ {
				if err := h.RetainReply(r, []byte("same reply")); err != nil {
					t.Error(err)
				}
				if original, outcome, err := h.Retry(r); err != nil || original != r || outcome.Original() != r || string(outcome.Reply()) != "same reply" {
					t.Error("concurrent outcome changed", err)
				}
			}
		}()
	}
	wg.Wait()
}
