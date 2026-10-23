package enrollment

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	format "github.com/relux-works/swarma-registrar/enrollment"
	"github.com/relux-works/swarma-registrar/registry"
)

type vectorFile struct {
	Bytes      string `json:"bytes_base64"`
	Kind, Path string
	Repeat     int
	Template   string `json:"path_template"`
}
type registryVector struct {
	Row, Domain, Mode, Claim string
	Control                  string `json:"positive_control"`
	Input                    struct {
		Bytes string `json:"bytes_base64"`
	}
	Fixture struct {
		Audience string
		Registry struct {
			Approved, Available, Descendant bool
			FirstUse                        *bool  `json:"first_use"`
			Signature                       bool   `json:"commit_signature_valid"`
			Persist                         bool   `json:"persist_available"`
			Exact                           bool   `json:"pin_is_exact"`
			RollbackAvailable               bool   `json:"rollback_state_available"`
			Publisher                       string `json:"publisher_key"`
			PreviousPublisher               string `json:"previous_publisher_key"`
			Revision                        string
			PreviousRevision                string `json:"previous_revision"`
			Files                           []vectorFile
			PreviousFiles                   []vectorFile `json:"previous_files"`
			Stations                        []string     `json:"station_hosts"`
			Nonstations                     []string     `json:"nonstation_hosts"`
		}
	}
	Before, After []json.RawMessage
	Expected      struct {
		Code      string
		Canonical string `json:"canonical_bytes_base64"`
		State     struct {
			Ready          bool `json:"admission_ready"`
			Installed      bool `json:"authority_installed"`
			PriorPreserved bool `json:"prior_authority_preserved"`
			Authority      struct {
				IDs      []string `json:"record_ids"`
				Revision *string
			}
			Audit   []json.RawMessage `json:"audit_outcomes"`
			Limiter []json.RawMessage `json:"limiter_events"`
			Nonces  []json.RawMessage `json:"nonce_cache"`
		}
	}
}

func vectorBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(b) != s {
		t.Fatal("invalid fixture base64url")
	}
	return b
}
func vectorEntries(t *testing.T, files []vectorFile) []registry.Entry {
	t.Helper()
	out := []registry.Entry{}
	for _, f := range files {
		if f.Repeat < 1 {
			t.Fatal("fixture repeat must be positive")
		}
		b := vectorBytes(t, f.Bytes)
		kind := registry.Regular
		switch f.Kind {
		case "regular":
		case "symlink":
			kind = registry.Symlink
		case "other":
			kind = registry.Other
		default:
			t.Fatalf("unhandled fixture entry kind %q", f.Kind)
		}
		for i := 0; i < f.Repeat; i++ {
			path := f.Path
			if f.Template != "" {
				path = fmt.Sprintf(f.Template, i)
			}
			out = append(out, registry.Entry{Path: path, Kind: kind, Bytes: b})
		}
	}
	return out
}
func pinnedModuleDirectory(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-json", "github.com/relux-works/swarma-registrar")
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "GOPROXY=") && !strings.HasPrefix(variable, "GOSUMDB=") && !strings.HasPrefix(variable, "GONOPROXY=") && !strings.HasPrefix(variable, "GOVCS=") {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	cmd.Env = append(cmd.Env, "GOPROXY=off", "GOSUMDB=off", "GONOPROXY=none", "GOVCS=*:off")
	b, err := cmd.Output()
	if err != nil {
		t.Fatal("pinned module unavailable locally; conformance unrun:", err)
	}
	var module struct{ Dir, Version string }
	if err = json.Unmarshal(b, &module); err != nil || !filepath.IsAbs(module.Dir) || module.Version == "" {
		t.Fatal("missing pinned module directory")
	}
	return module.Dir
}

// Discover the published rows from the exact local module, without a test-time
// fetch. Symbolic revision labels in the external fixture are instantiated as
// real signed Git OIDs while preserving equality/ancestry/approval relationships.
// Envelope bytes and expected body IDs remain unchanged. Codec controls exercise
// the public codec only; registry rows use the production Verifier and CAS Store.
func TestRegistrarEnrollmentConformance(t *testing.T) {
	root := filepath.Join(pinnedModuleDirectory(t), "vectors", "enrollment-1")
	var paths []string
	counts := map[string]int{}
	for _, phase := range []string{"0-negative", "1-positive"} {
		found, err := filepath.Glob(filepath.Join(root, phase, "*.json"))
		if err != nil {
			t.Fatal(err)
		}
		counts[phase] = len(found)
		paths = append(paths, found...)
	}
	if counts["0-negative"] < 114 || counts["1-positive"] < 25 {
		t.Fatalf("published enrollment vectors missing: %v", counts)
	}
	known := map[string]bool{}
	rows := make([]registryVector, 0, len(paths))
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var v registryVector
		if err = json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		if v.Row == "" || v.Domain != "enrollment/1" || known[v.Row] {
			t.Fatal("invalid fixture row identity")
		}
		known[v.Row] = true
		// New registry fixture facts must be deliberately implemented, never silently
		// ignored when a later dependency pin adds an external-state contract.
		var raw struct {
			Fixture struct{ Registry map[string]json.RawMessage }
		}
		if err = json.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		allowed := map[string]bool{}
		for _, field := range []string{"approved", "available", "commit_signature_valid", "descendant", "files", "persist_available", "pin_is_exact", "previous_files", "previous_revision", "publisher_key", "previous_publisher_key", "revision", "rollback_state_available", "station_hosts", "nonstation_hosts", "first_use"} {
			allowed[field] = true
		}
		for field := range raw.Fixture.Registry {
			if !allowed[field] {
				t.Fatalf("row %s needs support for registry input %s", v.Row, field)
			}
		}
		rows = append(rows, v)
	}
	for _, v := range rows {
		if !known[v.Control] {
			t.Fatalf("row %s has missing control %s", v.Row, v.Control)
		}
		t.Run(v.Row, func(t *testing.T) {
			if len(v.Before) != 0 || len(v.After) != 0 {
				t.Fatal("new scheduled-event fixture requires an explicit runner implementation")
			}
			switch v.Mode {
			case "codec", "codec-extract":
				runCodecVector(t, v)
			case "registry":
				runRegistryVector(t, v)
			default:
				t.Fatalf("unhandled vector mode %s; no silent pass", v.Mode)
			}
		})
	}
	t.Logf("published enrollment vectors: %d negative, %d positive; no deferred rows", counts["0-negative"], counts["1-positive"])
}
func runCodecVector(t *testing.T, v registryVector) {
	t.Helper()
	parsed, err := ccj.Parse(vectorBytes(t, v.Input.Bytes), ccj.EnrollmentMalformed)
	if err != nil {
		t.Fatalf("codec outcome=%v want=%s", err, v.Expected.Code)
	}
	if v.Mode == "codec-extract" {
		object, ok := parsed.(map[string]any)
		if !ok {
			t.Fatal("extraction input is not an object")
		}
		parsed, ok = object["body"]
		if !ok {
			t.Fatal("extraction input lacks body")
		}
	}
	canonical, err := ccj.Marshal(parsed, ccj.EnrollmentMalformed)
	if err != nil {
		t.Fatal(err)
	}
	if v.Expected.Code != "accept" || !bytes.Equal(canonical, vectorBytes(t, v.Expected.Canonical)) {
		t.Fatal("canonical bytes differ from published control")
	}
	// Codec success maps to no loader refusal; this does not admit a peer or key.
	if code := loaderHelperCode(nil); code != OK {
		t.Fatal("codec helper mapping")
	}
}
func loaderHelperCode(err error) Code {
	if err == nil {
		return OK
	}
	return mapDiagnostic(err)
}
func registrarCode(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		return "accept"
	}
	var refusal *registry.Error
	if !errors.As(err, &refusal) {
		t.Fatalf("untyped registrar error: %v", err)
	}
	return string(refusal.Code)
}
func highIDs(high *registry.HighWater) []string {
	unique := map[string]bool{}
	if high != nil {
		for _, host := range high.Hosts {
			for _, id := range host.History {
				unique[id] = true
			}
		}
	}
	out := []string{}
	for id := range unique {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
func runRegistryVector(t *testing.T, v registryVector) {
	t.Helper()
	f := newFixture(t)
	r := v.Fixture.Registry
	stations := map[string]bool{}
	for _, host := range r.Stations {
		stations[host] = true
	}
	for _, host := range r.Nonstations {
		stations[host] = false
	}
	policy, policyErr := format.NewPolicy(v.Fixture.Audience, r.Publisher, stations)
	if policyErr != nil {
		policy = nil
	}
	entries := vectorEntries(t, r.Files)
	previousEntries := vectorEntries(t, r.PreviousFiles)
	candidateRevision, previousRevision := "", ""
	if len(previousEntries) > 0 && !r.Descendant {
		candidateRevision = f.commit(entries, "", r.Signature)
		previousRevision = f.commit(previousEntries, candidateRevision, true)
	} else {
		if len(previousEntries) > 0 {
			previousRevision = f.commit(previousEntries, "", true)
		}
		candidateRevision = f.commit(entries, previousRevision, r.Signature)
	}
	f.config.Revision = candidateRevision
	f.writeConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store := newFileStore(ctx, f.config.StateDir, f.files)
	var previous *registry.HighWater
	if len(previousEntries) > 0 {
		publisher := r.PreviousPublisher
		if publisher == "" {
			publisher = r.Publisher
		}
		previousPolicy, err := format.NewPolicy(v.Fixture.Audience, publisher, stations)
		if err != nil {
			t.Fatal("invalid previous policy:", err)
		}
		verifier := newGitVerifier(ctx, f.repo, previousRevision, []string{f.public})
		_, previous, err = (registry.Loader{Policy: previousPolicy, Verifier: verifier, Store: store}).Load(registry.Input{Revision: previousRevision, Entries: previousEntries, FirstUse: true})
		if err != nil {
			t.Fatal("previous authority fixture rejected:", err)
		}
	}
	statePath := filepath.Join(f.config.StateDir, "high-water.json")
	before, _ := os.ReadFile(statePath)
	approved := candidateRevision
	if !r.Approved {
		approved = previousRevision
		if approved == "" {
			approved = strings.Repeat("0", 40)
		}
	}
	verifier := newGitVerifier(ctx, f.repo, approved, []string{f.public})
	if !r.Available {
		verifier.dir = filepath.Join(f.base, "missing.git")
	}
	inputRevision := candidateRevision
	if !r.Exact {
		inputRevision = r.Revision
	}
	if !r.Persist {
		store.ops = failingOps{stage: "rename"}
	}
	// Older fixtures use the Appendix A initial-bootstrap default. Explicit
	// first_use input in newer fixtures always takes precedence.
	firstUse := previous == nil
	if r.FirstUse != nil {
		firstUse = *r.FirstUse
	}
	snapshot, high, err := (registry.Loader{Policy: policy, Verifier: verifier, Store: store}).Load(registry.Input{Revision: inputRevision, Entries: entries, Retained: previous, FirstUse: firstUse, Reconciled: r.RollbackAvailable})
	if code := registrarCode(t, err); code != v.Expected.Code {
		t.Fatalf("registrar code=%s want=%s", code, v.Expected.Code)
	}
	wantHelper := OK
	if v.Expected.Code != "accept" {
		wantHelper = EnrollmentUnverified
		if !r.Available {
			wantHelper = EnrollmentUnavailable
		}
	}
	actualHelper := loaderHelperCode(err)
	if !r.Available && err != nil {
		actualHelper = EnrollmentUnavailable
	}
	expectCode(t, wantHelper, actualHelper)
	installed := snapshot != nil && high != nil
	if installed != v.Expected.State.Installed || installed != v.Expected.State.Ready {
		t.Fatal("snapshot installation/readiness differs")
	}
	after, _ := os.ReadFile(statePath)
	var final *registry.HighWater
	var revisionLabel *string
	if installed {
		final = high
		label := r.Revision
		revisionLabel = &label
		actual, readErr := store.read()
		if readErr != nil || !reflect.DeepEqual(actual, high) {
			t.Fatal("installed state was not durably committed")
		}
	} else {
		if snapshot != nil || high != nil {
			t.Fatal("failed load returned replacement authority")
		}
		final = previous
		if previous != nil {
			label := r.PreviousRevision
			revisionLabel = &label
		}
		if !bytes.Equal(before, after) {
			t.Fatal("rejected candidate changed previous high-water bytes")
		}
	}
	if v.Expected.State.PriorPreserved != !installed {
		t.Fatal("prior-authority preservation differs")
	}
	if !reflect.DeepEqual(highIDs(final), v.Expected.State.Authority.IDs) || !reflect.DeepEqual(revisionLabel, v.Expected.State.Authority.Revision) {
		t.Fatalf("authority IDs/revision differ: got IDs %v", highIDs(final))
	}
	if len(v.Expected.State.Audit) != 0 || len(v.Expected.State.Limiter) != 0 || len(v.Expected.State.Nonces) != 0 {
		t.Fatal("new non-registry side effects need an integration runner")
	}
}
