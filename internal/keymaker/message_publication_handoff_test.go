package keymaker

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keymaker/internal/keymaker/publicationhandoff"
)

// Incomplete metadata and oversized carriers refuse before a handoff exists.
func TestPreparedMessagePublicationRefusesIncomplete(t *testing.T) {
	for _, c := range []messageCertificate{
		{},
		{Transaction: "00112233445566778899aabbccddeeff", Envelope: strings.Repeat("A", 12000)},
		{Transaction: "00112233445566778899aabbccddeeff", Envelope: "e30"},
	} {
		h, err := preparedMessagePublication(c)
		if h != nil || !errors.Is(err, publicationhandoff.ErrInvalid) {
			t.Fatal("incomplete certificate accepted", err)
		}
	}
}

// This is synthetic TEST material only. The existing issuer fixture uses its
// inert test-local deterministic master so the public certificate can be pinned.
// No host key, account, real issuance or production issuer is involved. Signing
// happens inside the test through the existing certificate builder, before the
// already-prepared-certificate helper is called.
func preparedMessageControl(t *testing.T) messageCertificate {
	t.Helper()
	i, b, public, facts, _ := messageIssuerFixture(t)
	c, code := i.prepare(t.Context(), "00112233445566778899aabbccddeeff", b, public, facts)
	if code != "" {
		t.Fatal("synthetic certificate builder failed", code)
	}
	if got := messageVerifyFixture(t, c, facts); got != "accept" {
		t.Fatal("independent full certificate verifier refused control", got)
	}
	raw, err := os.ReadFile("testdata/prepared-message-control.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, mustPreparedMessageWire(t, c)) {
		t.Fatal("builder changed pinned public certificate bytes")
	}
	metadata, err := os.ReadFile("testdata/prepared-message-control-metadata.json")
	if err != nil {
		t.Fatal(err)
	}
	var pinned messageCertificate
	if err := json.Unmarshal(metadata, &pinned); err != nil || pinned != c {
		t.Fatal("builder changed pinned matching metadata", err)
	}
	return c
}

func mustPreparedMessageWire(t *testing.T, c messageCertificate) []byte {
	t.Helper()
	raw, err := record.DecodeBase64(c.Envelope, -1)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func requirePreparedMessageControl(t *testing.T, c messageCertificate) {
	t.Helper()
	h, err := preparedMessagePublication(c)
	if err != nil || h == nil {
		t.Fatal("valid prepared certificate refused", err)
	}
	original, err := h.Original()
	if err != nil || original.Transaction() != c.Transaction || original.Envelope() != c.Envelope || original.ContentID() != c.ContentID || !bytes.Equal(original.Wire(), mustPreparedMessageWire(t, c)) {
		t.Fatal("original transaction, envelope, content ID or wire changed", err)
	}
	wire := original.Wire()
	wire[0] ^= 1
	if !bytes.Equal(original.Wire(), mustPreparedMessageWire(t, c)) {
		t.Fatal("returned wire aliases retained certificate")
	}
	retry, outcome, err := h.Retry(original)
	if err != nil || retry != original || outcome.Original() != original || outcome.State() != publicationhandoff.NoReply {
		t.Fatal("retry changed original operation", err)
	}
	if wire, err := h.PublishedWire(); wire != nil || !errors.Is(err, publicationhandoff.ErrUnavailable) {
		t.Fatal("valid test certificate manufactured publication", err)
	}
}

func TestPreparedMessagePublicationValidControl(t *testing.T) {
	c := preparedMessageControl(t)
	if c.Binding.Path != "m/4'/1'/1'/1'" {
		t.Fatal("control lost retained hardened message path")
	}
	requirePreparedMessageControl(t, c)
}

// Each case changes exactly one independently retained metadata field while
// preserving the signed wire. Restoring only that field must restore success.
func TestPreparedMessagePublicationMetadataNeighbors(t *testing.T) {
	c := preparedMessageControl(t)
	for _, test := range []struct {
		name  string
		field func(*messageCertificate) *string
		bad   string
	}{
		{"binding-path", func(c *messageCertificate) *string { return &c.Binding.Path }, "m/4'/1'/1'/2'"},
		{"binding-generation", func(c *messageCertificate) *string { return &c.Binding.Generation }, c.Binding.Generation + "-other"},
		{"issuer-key", func(c *messageCertificate) *string { return &c.IssuerPolicy.Key }, c.KeyID},
		{"issuer-epoch", func(c *messageCertificate) *string { return &c.IssuerPolicy.Epoch }, c.IssuerPolicy.Epoch + "-other"},
		{"subject-key", func(c *messageCertificate) *string { return &c.KeyID }, c.IssuerPolicy.Key},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := c
			field := test.field(&changed)
			before := *field
			if before == test.bad {
				t.Fatal("neighbor is not distinct")
			}
			*field = test.bad
			if changed.Envelope != c.Envelope || changed.ContentID != c.ContentID || changed.Transaction != c.Transaction {
				t.Fatal("neighbor changed original wire or transaction")
			}
			if h, err := preparedMessagePublication(changed); h != nil || !errors.Is(err, publicationhandoff.ErrInvalid) {
				t.Fatal("single-field metadata mismatch accepted", err)
			}
			*field = before
			if changed != c {
				t.Fatal("repair changed another field")
			}
			requirePreparedMessageControl(t, changed)
		})
	}
}
