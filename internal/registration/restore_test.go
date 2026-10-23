package registration

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// Retention verification consumes neither signing nor entropy and preserves exact
// bytes. Current key/name/audience, current windows, expiry, corrupt bytes and a
// clock earlier than the retained issue time all refuse without a proof.
func TestRestoreRetained(t *testing.T) {
	for _, scenario := range []string{"key", "name", "audience", "window", "expiry", "corrupt", "clock-before-issued", "valid"} {
		t.Run(scenario, func(t *testing.T) {
			f := setup(t)
			original := built(t, f)
			raw := original.Envelope()
			in := f.in
			want := OK
			switch scenario {
			case "key":
				in.Enrolled.Key = "ed25519:other"
				want = "key_not_enrolled"
			case "name":
				in.Name = "host-a_other_role"
				want = "name_not_permitted"
			case "audience":
				in.Audience = "other.invalid"
				want = AudienceMismatch
			case "window":
				in.Enrolled.NotAfter = f.clock.at.Unix()
				want = KeyNotValidNow
			case "expiry":
				f.clock.set(f.clock.at.Truncate(time.Second).Add(120*time.Second), true)
				want = RequestExpired
			case "corrupt":
				raw = []byte("{}")
				want = "registration_malformed"
			case "clock-before-issued":
				f.clock.set(f.clock.at.Truncate(time.Second).Add(-time.Second), true)
				want = ClockUntrusted
			}
			// A fresh builder models daemon restart, so rollback cannot rely on a prior
			// in-memory clock sample. No signer or entropy call is allowed on Restore.
			b, err := New(f.clock, noRestoreEntropy{t}, signFunc(func(context.Context, []byte) ([]byte, Code) { t.Fatal("restore signed again"); return nil, "" }))
			if err != nil {
				t.Fatal(err)
			}
			p, code := b.Restore(context.Background(), raw, in)
			if code != want || (p == nil) != (want != "") {
				t.Fatalf("restore code=%s want=%s", code, want)
			}
			if scenario == "clock-before-issued" {
				f.clock.set(original.issued.Add(time.Second), true)
				if _, code := b.Time(context.Background()); code != ClockUntrusted {
					t.Fatal("restored-proof rollback did not fence clock owner")
				}
			}
			if p != nil && !bytes.Equal(p.Envelope(), raw) {
				t.Fatal("restore changed retained bytes")
			}
		})
	}
}

type noRestoreEntropy struct{ t *testing.T }

func (n noRestoreEntropy) Read([]byte) (int, error) {
	n.t.Fatal("restore consumed entropy")
	return 0, nil
}
