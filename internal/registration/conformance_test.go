package registration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	windows "github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/envelope"
	format "github.com/relux-works/swarma-registrar/registration"
)

type registrationVector struct {
	Row, Domain string
	Control     string `json:"positive_control"`
	Input       struct {
		Bytes string `json:"bytes_base64"`
	}
	Fixture struct {
		Audience string
		Now      int64
		FinalNow int64 `json:"final_now"`
		Registry struct {
			Publisher string   `json:"publisher_key"`
			Stations  []string `json:"station_hosts"`
			Files     []struct {
				Bytes string `json:"bytes_base64"`
			}
		}
	}
	Expected struct{ Code string }
}
type coverageRow struct{ Row, Stage, Reason string }

func decodeFixture(t *testing.T, s string) []byte {
	t.Helper()
	b, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		t.Fatal("invalid published fixture encoding")
	}
	return b
}

// Registrar263ca7fcfd97 and5f44ebf3f788 have identical public trees:
// ccj53452b3e84a131d811221834a1d84c1328dcd5d3, registration
// ed1a0c55fa1da41be6688f5c7c079576b4351df3, enrollment
// 088a2337ff6abb18399b16710353f34cbf6b3bec, registry
// c17d73b2d6ffd5dfc042d3e0d8fc63972c95e00a (git rev-parse commit:path).
// The five added rows R138/R139/PR31-33 concern HTTP Content-Type only;
// vector-coverage.json explicitly excludes that receiver boundary.
func localModule(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json", "github.com/relux-works/swarma-registrar")
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "GOPROXY=") && !strings.HasPrefix(v, "GOSUMDB=") && !strings.HasPrefix(v, "GONOPROXY=") && !strings.HasPrefix(v, "GOVCS=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, "GOPROXY=off", "GOSUMDB=off", "GONOPROXY=none", "GOVCS=*:off")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal("local pinned registrar unavailable; conformance unrun", err)
	}
	var m struct{ Dir, Version string }
	if json.Unmarshal(out, &m) != nil || !filepath.IsAbs(m.Dir) || m.Version != "v0.0.0-20261023164451-5f44ebf3f788" {
		t.Fatal("conformance requires exact local registrar pin")
	}
	return m.Dir
}
func published(t *testing.T) map[string]registrationVector {
	t.Helper()
	rows := map[string]registrationVector{}
	for _, phase := range []string{"0-negative", "1-positive"} {
		paths, err := filepath.Glob(filepath.Join(localModule(t), "vectors", "registration-1", phase, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			raw, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			var row registrationVector
			if json.Unmarshal(raw, &row) != nil || row.Row == "" || row.Domain != "registration/1" || rows[row.Row].Row != "" {
				t.Fatal("bad or duplicate registrar row")
			}
			rows[row.Row] = row
		}
	}
	if len(rows) != 171 {
		t.Fatalf("registrar rows changed: %d; coverage review required", len(rows))
	}
	return rows
}
func upstreamCode(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return "accept"
	}
	var refusal *format.Error
	if !errors.As(err, &refusal) {
		t.Fatalf("untyped registrar verdict: %v", err)
	}
	return string(refusal.Code)
}
func verified(t *testing.T, row registrationVector) *format.Body {
	t.Helper()
	body, err := format.Verify(decodeFixture(t, row.Input.Bytes))
	if err != nil {
		t.Fatal("expected valid proof data", err)
	}
	return body
}
func roundtrip(t *testing.T, row registrationVector) {
	t.Helper()
	raw := decodeFixture(t, row.Input.Bytes)
	body := verified(t, row)
	canonical, pre, err := format.Build(*body, row.Fixture.Audience)
	if err != nil {
		t.Fatal(err)
	}
	if err = format.Check(canonical, row.Fixture.Audience); err != nil {
		t.Fatal(err)
	}
	parsed, err := envelope.Parse(raw, envelope.Registration)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pre, parsed.Preimage) {
		t.Fatal("registrar Build preimage differs from published proof")
	}
	assembled, err := format.Assemble(canonical, parsed.Signature)
	if err != nil {
		t.Fatal(err)
	}
	again, err := format.Verify(assembled)
	if err != nil || !reflect.DeepEqual(body, again) {
		t.Fatal("published proof failed round-trip", err)
	}
}
func configureNames(f *fixture, row registrationVector, body *format.Body) {
	f.in.Name, f.in.Audience, f.in.Enrolled.Audience = body.Name, body.Audience, row.Fixture.Audience
}
func signedWindow(t *testing.T, row registrationVector, key string) windows.Window {
	t.Helper()
	stations := map[string]bool{}
	for _, s := range row.Fixture.Registry.Stations {
		stations[s] = true
	}
	policy, err := windows.NewPolicy(row.Fixture.Audience, row.Fixture.Registry.Publisher, stations)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range row.Fixture.Registry.Files {
		record, err := policy.Parse(decodeFixture(t, file.Bytes))
		if err != nil {
			t.Fatal("invalid signed window fixture", err)
		}
		for _, window := range record.Keys() {
			if window.Key == key {
				return window
			}
		}
	}
	t.Fatal("published window missing selected key")
	return windows.Window{}
}
func releaseFixture(t *testing.T, row registrationVector, at int64) Code {
	t.Helper()
	body := verified(t, row)
	issued, err := time.Parse(time.RFC3339, body.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339, body.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	f := setup(t)
	f.clock.set(time.Unix(at, 0), true)
	// Original verified bytes/window are guard fixtures, not a production import
	// API. The point-clock fixture supplies an explicit five-minute observation
	// grant, as production Build/Restore now require. No registry authority,
	// replay or receiver admission is manufactured.
	p := &Proof{raw: decodeFixture(t, row.Input.Bytes), issued: issued, expires: expires, window: signedWindow(t, row, body.Key), builder: f.builder, authorityUntil: time.Unix(at, 0).Add(5 * time.Minute)}
	return p.Recheck(context.Background())
}

// Every pinned row has an explicit stage or exclusion. Applicable negative rows
// run first with their published exact verdict and a nearby successful control.
// Round-trip projections use original bytes; they do not claim receiver state,
// HTTP/JWT/replay/rate/registry admission or P-256 builder authority.
func TestRegistrarRegistrationConformance(t *testing.T) {
	rows := published(t)
	data, err := os.ReadFile("vector-coverage.json")
	if err != nil {
		t.Fatal(err)
	}
	var coverage []coverageRow
	if json.Unmarshal(data, &coverage) != nil {
		t.Fatal("invalid vector coverage")
	}
	seen := map[string]bool{}
	counts := map[string]int{}
	for _, entry := range coverage {
		row, ok := rows[entry.Row]
		if !ok || seen[entry.Row] || entry.Reason == "" {
			t.Fatal("unknown/duplicate/unexplained coverage row")
		}
		seen[entry.Row] = true
		counts[entry.Stage]++
		if _, ok := rows[row.Control]; !ok {
			t.Fatal("missing published control")
		}
		if entry.Stage == "excluded" {
			t.Logf("%s OUT OF CONSTRUCTION CONTRACT: %s", entry.Row, entry.Reason)
			continue
		}
		t.Run(entry.Row, func(t *testing.T) {
			switch entry.Stage {
			case "verify":
				_, err := format.Verify(decodeFixture(t, row.Input.Bytes))
				if got := upstreamCode(t, err); got != row.Expected.Code {
					t.Fatalf("registrar=%s want=%s", got, row.Expected.Code)
				}
				roundtrip(t, rows[row.Control])
			case "name":
				raw := decodeFixture(t, row.Input.Bytes)
				parsed, err := envelope.Parse(raw, envelope.Registration)
				if err != nil {
					t.Fatal(err)
				}
				canonical, err := ccj.Marshal(parsed.Body, ccj.RegistrationMalformed)
				if err != nil {
					t.Fatal(err)
				}
				if got := upstreamCode(t, format.Check(canonical, row.Fixture.Audience)); got != row.Expected.Code {
					t.Fatalf("name=%s want=%s", got, row.Expected.Code)
				}
				body := verified(t, row)
				f := setup(t)
				configureNames(f, row, body)
				denied(t, f, Code(row.Expected.Code))
				if f.calls != 0 {
					t.Fatal("invalid published name signed")
				}
				roundtrip(t, rows[row.Control])
				control := setup(t)
				configureNames(control, rows[row.Control], verified(t, rows[row.Control]))
				built(t, control)
			case "audience":
				f := setup(t)
				configureNames(f, row, verified(t, row))
				denied(t, f, Code(row.Expected.Code))
				if f.calls != 0 {
					t.Fatal("foreign audience signed")
				}
				roundtrip(t, rows[row.Control])
				control := setup(t)
				configureNames(control, rows[row.Control], verified(t, rows[row.Control]))
				built(t, control)
			case "window":
				if code := releaseFixture(t, row, row.Fixture.Now); string(code) != row.Expected.Code {
					t.Fatalf("window=%s want=%s", code, row.Expected.Code)
				}
				control := rows[row.Control]
				if code := releaseFixture(t, control, control.Fixture.Now); code != "" {
					t.Fatal("published window control refused", code)
				}
			case "expiry":
				at := row.Fixture.Now
				if row.Fixture.FinalNow != 0 {
					at = row.Fixture.FinalNow
				}
				if code := releaseFixture(t, row, at); string(code) != row.Expected.Code {
					t.Fatalf("expiry=%s want=%s", code, row.Expected.Code)
				}
				// Registrar's PR11 allows receiver expiry skew. The helper intentionally
				// does not; use the same proof one nanosecond before exp as its control.
				f := setup(t)
				p := built(t, f)
				f.clock.set(p.expires.Add(-time.Nanosecond), true)
				if code := p.Recheck(context.Background()); code != "" {
					t.Fatal(code)
				}
			case "roundtrip":
				roundtrip(t, row)
			default:
				t.Fatal("unsupported coverage stage", entry.Stage)
			}
		})
	}
	if len(seen) != len(rows) {
		t.Fatal("unmapped published rows")
	}
	t.Logf("registration vectors by stage: %v; excluded rows are not executed conformance", counts)
}

// Three assigned Keymaker helper rows exercise the builder's name/audience
// boundary with generated fixture keys. UID, binding and registry authority in
// their other fields is deliberately outside this pure layer's qualification.
func TestHelperVectors(t *testing.T) {
	raw, err := os.ReadFile("../../vectors/refusals.json")
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		ID      string
		Control string `json:"positive_control"`
		Code    Code   `json:"expected_code"`
		Input   struct {
			Request struct {
				Params struct {
					Name     string
					Audience string `json:"aud"`
				}
			}
		}
	}
	var data struct{ Negative, Positive []row }
	if json.Unmarshal(raw, &data) != nil {
		t.Fatal("invalid helper vectors")
	}
	controls := map[string]row{}
	for _, r := range data.Positive {
		controls[r.ID] = r
	}
	count := 0
	for _, r := range data.Negative {
		if r.ID != "helper-name-slash" && r.ID != "helper-mxid-length" && r.ID != "helper-wrong-audience" {
			continue
		}
		count++
		t.Run(r.ID, func(t *testing.T) {
			control, ok := controls[r.Control]
			if !ok {
				t.Fatal("missing helper control")
			}
			for _, phase := range []string{"negative", "control"} {
				t.Run(phase, func(t *testing.T) {
					v := r
					if phase == "control" {
						v = control
					}
					f := setup(t)
					f.in.Name = v.Input.Request.Params.Name
					f.in.Audience = v.Input.Request.Params.Audience
					f.in.Enrolled.Audience = control.Input.Request.Params.Audience
					if phase == "negative" {
						denied(t, f, r.Code)
						if f.calls != 0 {
							t.Fatal("helper refusal reached signer")
						}
					} else {
						built(t, f)
					}
				})
			}
		})
	}
	if count != 3 {
		t.Fatal("missing assigned helper vectors")
	}
}

// Registrar supports P-256 verification; this builder's v0 algorithm policy
// rejects even its valid published proof key before signing, beside Ed25519.
func TestEd25519Only(t *testing.T) {
	row := published(t)["PR2"]
	body := verified(t, row)
	f := setup(t)
	f.in.Enrolled.Key = body.Key
	denied(t, f, EnrollmentUnsupported)
	if f.calls != 0 {
		t.Fatal("P-256 key reached signer")
	}
	built(t, setup(t))
}
