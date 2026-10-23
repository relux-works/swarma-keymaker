package enrollment

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-registrar/registry"
)

// These two rows require the core binding/release barrier and remain integration
// obligations. This layer never treats uid_map as a replacement for a binding.
var deferredHelperRows = map[string]bool{"helper-missing-binding": true, "helper-revoked-binding-fresh-connection": true}

// Every in-scope authored helper refusal and its paired positive control run
// through a real signed Git snapshot and the unmodified registrar loader. The
// vectors supply facts; no fixture verdict bypasses production authorization.
func TestHelperVectors(t *testing.T) {
	b, err := os.ReadFile("../../vectors/refusals.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Negative []struct {
			ID      string          `json:"id"`
			Input   json.RawMessage `json:"input"`
			Code    Code            `json:"expected_code"`
			Control string          `json:"positive_control"`
		} `json:"negative"`
		Positive []struct {
			ID    string          `json:"id"`
			Input json.RawMessage `json:"input"`
		} `json:"positive"`
	}
	if err = json.Unmarshal(b, &vectors); err != nil {
		t.Fatal(err)
	}
	positives := map[string]json.RawMessage{}
	for _, row := range vectors.Positive {
		positives[row.ID] = row.Input
	}
	count := 0
	for _, negative := range vectors.Negative {
		if !strings.HasPrefix(negative.ID, "helper-") || deferredHelperRows[negative.ID] {
			continue
		}
		count++
		t.Run(negative.ID, func(t *testing.T) { runHelperVector(t, negative.Input, negative.Code) })
		control, ok := positives[negative.Control]
		if !ok {
			t.Fatal("missing positive control")
		}
		t.Run(negative.Control, func(t *testing.T) { runHelperVector(t, control, OK) })
	}
	if count != 14 {
		t.Fatalf("covered %d helper rows, expected 14; review new rows explicitly", count)
	}
}
func runHelperVector(t *testing.T, raw []byte, want Code) {
	t.Helper()
	parsed, err := ccj.Parse(raw, ccj.EnrollmentMalformed)
	if err != nil {
		t.Fatal(err)
	}
	in := parsed.(map[string]any)
	enrollment := in["enrollment"].(map[string]any)
	params := in["request"].(map[string]any)["params"].(map[string]any)
	f := newFixture(t)
	body := baseBody()
	body["host"] = enrollment["host"]
	body["state"] = enrollment["state"]
	body["names"] = enrollment["names"]
	if enrollment["uid_map"] == nil {
		delete(body, "uid_map")
	} else {
		body["uid_map"] = enrollment["uid_map"]
	}
	seed := byte(1)
	if !enrollment["verified"].(bool) {
		seed = 3
	}
	entries := []registry.Entry{{Path: "enrollments/1.json", Bytes: signedRecord(t, body, seed)}}
	f.config.Revision = f.commit(entries, "", true)
	f.config.Generations["30001"] = in["admitted_generation"].(string)
	if !enrollment["available"].(bool) {
		f.config.Registry = filepath.Join(f.base, "missing.git")
	}
	a := f.authority()
	reload := a.Reload(context.Background())
	if want == EnrollmentUnverified || want == EnrollmentUnavailable {
		expectCode(t, want, reload)
	} else {
		expectCode(t, OK, reload)
	}
	before, _ := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
	key := public(2)
	if !enrollment["key_enrolled"].(bool) {
		key = public(3)
	}
	result, code := a.Authorize(context.Background(), uint32(in["peer_uid"].(int64)), in["generation"].(string), key, params["name"].(string), params["aud"].(string), testNow, testNow)
	expectCode(t, want, code)
	if code != OK && !reflect.DeepEqual(result, EnrolledKey{}) {
		t.Fatal("refusal returned admission data")
	}
	if code == OK && (result.Key != key || result.Revision != f.config.Revision || result.Audience != testAudience || result.RecordID == "") {
		t.Fatal("incomplete admission result")
	}
	after, _ := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
	if string(before) != string(after) {
		t.Fatal("authorization mutated rollback state")
	}
}

// Current key selection, exact half-open windows and revocation precede names;
// configured-audience name syntax precedes UID and requested-audience checks.
func TestAuthorityCheckOrder(t *testing.T) {
	for _, name := range []string{"unknown-before-revoked", "window-before-revoked", "revoked-before-name", "name-before-uid", "name-before-audience", "audience-is-configured", "not-before", "not-after", "issued-at-outside", "generation-not-admitted"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			body := baseBody()
			key, nm, aud := public(2), testName, testAudience
			uid := uint32(30001)
			issued, now := testNow, testNow
			want := OK
			switch name {
			case "unknown-before-revoked":
				body["state"] = "revoked"
				key = public(3)
				want = KeyNotEnrolled
			case "window-before-revoked":
				body["state"] = "revoked"
				now = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
				want = KeyNotValidNow
			case "revoked-before-name":
				body["state"] = "revoked"
				nm = "bad/name"
				want = HostRevoked
			case "name-before-uid":
				nm = "bad/name"
				uid = 30002
				want = NameInvalid
			case "name-before-audience":
				nm = "bad/name"
				aud = "other.invalid"
				want = NameInvalid
			case "audience-is-configured":
				aud = strings.Repeat("x", 255)
				want = AudienceMismatch
			case "not-before":
				now = time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)
				want = KeyNotValidNow
			case "not-after":
				now = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
				want = KeyNotValidNow
			case "issued-at-outside":
				issued = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
				want = KeyNotValidNow
			case "generation-not-admitted":
				delete(f.config.Generations, "30001")
				want = GenerationMismatch
			}
			f.config.Revision = f.commit([]registry.Entry{{Path: "enrollments/1.json", Bytes: signedRecord(t, body, 1)}}, "", true)
			a := f.authority()
			expectCode(t, OK, a.Reload(context.Background()))
			_, code := a.Authorize(context.Background(), uid, testGeneration, key, nm, aud, issued, now)
			expectCode(t, want, code)
			// Restore the independent valid record/key/window/name/admission control.
			control := newFixture(t)
			control.config.Revision = control.commit(control.valid(), "", true)
			a = control.authority()
			expectCode(t, OK, a.Reload(context.Background()))
			_, code = authorize(a)
			expectCode(t, OK, code)
		})
	}
}

// An invalid replacement cannot keep serving the previous snapshot; recovery
// requires a fully valid descendant and leaves prior state unchanged on refusal.
func TestFailedReloadFences(t *testing.T) {
	f := newFixture(t)
	entries := f.valid()
	first := f.commit(entries, "", true)
	f.config.Revision = first
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, OK, code)
	original, err := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
	if err != nil {
		t.Fatal(err)
	}
	bad := baseBody()
	bad["seq"] = int64(2)
	candidate := append([]registry.Entry{}, entries...)
	candidate = append(candidate, registry.Entry{Path: "enrollments/2.json", Bytes: signedRecord(t, bad, 3)})
	f.config.Revision = f.commit(candidate, first, true)
	f.writeConfig()
	expectCode(t, EnrollmentUnverified, a.Reload(context.Background()))
	result, code := authorize(a)
	expectCode(t, EnrollmentUnverified, code)
	if result.Key != "" {
		t.Fatal("stale authority escaped")
	}
	current, err := os.ReadFile(filepath.Join(f.config.StateDir, "high-water.json"))
	if err != nil || string(current) != string(original) {
		t.Fatal("failed validation changed durable state")
	}
	candidate[1].Bytes = signedRecord(t, bad, 1)
	f.config.Revision = f.commit(candidate, first, true)
	f.writeConfig()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code = authorize(a)
	expectCode(t, OK, code)
	// Missing pins fence even after a valid reload; restoring them revalidates.
	if err = os.Rename(f.configPath, f.configPath+".old"); err != nil {
		t.Fatal(err)
	}
	expectCode(t, EnrollmentUnavailable, a.Reload(context.Background()))
	_, code = authorize(a)
	expectCode(t, EnrollmentUnavailable, code)
	f.writeConfig()
	expectCode(t, OK, a.Reload(context.Background()))
}

// Historical keys cannot authorize once a newer, valid current record removes
// them; the newly enrolled key is the positive control.
func TestCurrentKeyOnly(t *testing.T) {
	f := newFixture(t)
	entries := f.valid()
	body := baseBody()
	body["seq"] = int64(2)
	body["keys"].([]any)[0].(map[string]any)["key"] = public(3)
	entries = append(entries, registry.Entry{Path: "enrollments/2.json", Bytes: signedRecord(t, body, 1)})
	f.config.Revision = f.commit(entries, "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code := authorize(a)
	expectCode(t, KeyNotEnrolled, code)
	_, code = a.Authorize(context.Background(), 30001, testGeneration, public(3), testName, testAudience, testNow, testNow)
	expectCode(t, OK, code)
}

// Concurrent reads and valid reloads see either complete immutable snapshot;
// this bounded stress case is the targeted race-detector workload.
func TestConcurrentReloadAuthorize(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for j := 0; j < 40; j++ {
				_, code := authorize(a)
				if code != OK {
					t.Errorf("concurrent admission: %s", code)
					return
				}
			}
		}()
	}
	for i := 0; i < 3; i++ {
		expectCode(t, OK, a.Reload(context.Background()))
	}
	group.Wait()
}

// Canceled admission never returns an enrollment; cancellation does not damage
// the otherwise valid immutable snapshot.
func TestCanceledAuthorization(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, code := a.Authorize(ctx, 30001, testGeneration, public(2), testName, testAudience, testNow, testNow)
	expectCode(t, EnrollmentUnavailable, code)
	if result.Key != "" {
		t.Fatal("canceled admission returned data")
	}
	_, code = authorize(a)
	expectCode(t, OK, code)
}

// A fresh generation stays refused until the protected policy explicitly admits
// it; re-admission withdraws the old generation rather than adding a UID fallback.
func TestGenerationReadmission(t *testing.T) {
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	fresh := "00000000000000000000000000000002"
	_, code := a.Authorize(context.Background(), 30001, fresh, public(2), testName, testAudience, testNow, testNow)
	expectCode(t, GenerationMismatch, code)
	f.config.Generations["30001"] = fresh
	f.writeConfig()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code = a.Authorize(context.Background(), 30001, fresh, public(2), testName, testAudience, testNow, testNow)
	expectCode(t, OK, code)
	_, code = authorize(a)
	expectCode(t, GenerationMismatch, code)
}

// An uninitialized Authority has no snapshot and must not return the zero-value
// success code. A constructed, validated instance is the positive control.
func TestZeroAuthorityRefuses(t *testing.T) {
	var empty Authority
	result, code := authorize(&empty)
	expectCode(t, EnrollmentUnavailable, code)
	if result.Key != "" {
		t.Fatal("zero authority returned an enrollment")
	}
	f := newFixture(t)
	f.config.Revision = f.commit(f.valid(), "", true)
	a := f.authority()
	expectCode(t, OK, a.Reload(context.Background()))
	_, code = authorize(a)
	expectCode(t, OK, code)
}
