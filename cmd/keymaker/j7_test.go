package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/keymaker"
)

const j7TestInstance = "11111111111111111111111111111111"

// j7CommandFixture is an owned scratch tree with a reconciled legacy store
// holding one active binding, built only through the exported custody API. It
// has no generation anchor, so migration can reach only its anchor refusal
// here; the complete migration positives live in the internal package tests.
type j7CommandFixture struct {
	uid, root, state, keyFile, policyFile, input string
	version                                      uint64
	digest                                       string
}

func j7CommandSetup(t *testing.T) *j7CommandFixture {
	t.Helper()
	if os.Getuid() == 0 {
		t.Fatal("test requires an unprivileged runner")
	}
	root := t.TempDir()
	f := &j7CommandFixture{uid: strconv.Itoa(os.Getuid()), root: root, state: filepath.Join(root, "state"), keyFile: filepath.Join(root, "key", "root"), policyFile: filepath.Join(root, "policy", "table.json"), input: filepath.Join(root, "input", "table.json")}
	if os.Chmod(root, 0700) != nil {
		t.Fatal("fixture root")
	}
	for _, d := range []string{f.state, filepath.Dir(f.keyFile), filepath.Dir(f.policyFile), filepath.Dir(f.input)} {
		if os.Mkdir(d, 0700) != nil {
			t.Fatal("fixture directory")
		}
	}
	uid := uint32(os.Getuid())
	dir, e := keymaker.OpenDirectory(f.state, uid, 0700)
	if e != nil {
		t.Fatal(e)
	}
	lock, e := keymaker.LockState(dir, uid)
	if e != nil {
		t.Fatal(e)
	}
	s, e := keymaker.OpenStore(dir, uid)
	if e != nil {
		t.Fatal(e)
	}
	operator := keymaker.Principal{UID: 1, Generation: "operator-incarnation"}
	_, c := s.Register(operator, operator, keymaker.Binding{UID: uid + 100, Generation: "fixture-generation", Path: "m/1'/1'/1'/1'", Owner: "fixture-owner", Lifetime: "ephemeral", Epoch: "fixture-epoch", RegistryRevision: "fixture-revision"})
	// Stop the fixture writer completely before any command runs.
	s.Close()
	lock.Close()
	dir.Close()
	if c != "" {
		t.Fatal(c)
	}
	policy := `{"format":"keymaker-j7-policy/1","identity_registration_number":1,"instance":"` + j7TestInstance + `","rows":[],"version":1}`
	if os.WriteFile(f.input, []byte(policy), 0600) != nil {
		t.Fatal("fixture policy input")
	}
	// The head is read back with the command under test and then used as the
	// independent expectation of the other rows.
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"j7", "head", "--service-uid", f.uid, "--state-dir", f.state, "--schema", "0"}, &out, &errOut); code != 0 {
		t.Fatalf("fixture head: %d %s %s", code, &out, &errOut)
	}
	result := j7Result(t, out.Bytes())
	f.version, f.digest = result.Version, result.Digest
	return f
}

// args returns the complete valid invocation of one subcommand.
func (f *j7CommandFixture) args(command string) []string {
	head := []string{"--expected-version", strconv.FormatUint(f.version, 10), "--expected-digest", f.digest}
	base := []string{"j7", command, "--service-uid", f.uid, "--state-dir", f.state}
	switch command {
	case "seed-init":
		return append(base, "--key-file", f.keyFile, "--instance-id", j7TestInstance)
	case "migrate":
		return append(append(base, "--source-schema", "0", "--instance-id", j7TestInstance, "--identity", "1", "--generation-journal", "/protected/generations"), head...)
	case "policy-publish":
		return append(append(base, "--schema", "5", "--instance-id", j7TestInstance, "--identity", "1", "--policy-file", f.policyFile, "--input", f.input), head...)
	}
	return append(append(base, "--schema", "0"), head...)
}

func j7Replace(args []string, flag, value string) []string {
	out := append([]string{}, args...)
	for i := range out {
		if out[i] == flag {
			out[i+1] = value
		}
	}
	return out
}

func j7Result(t *testing.T, stdout []byte) keymaker.J7OperatorResult {
	t.Helper()
	if !bytes.HasSuffix(stdout, []byte("\n")) || bytes.Count(stdout, []byte("\n")) != 1 {
		t.Fatalf("stdout is not one result line: %q", stdout)
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(stdout, &members) == nil && len(members) == 2 {
		var head struct {
			Version uint64 `json:"expected_version"`
			Digest  string `json:"expected_digest"`
		}
		if json.Unmarshal(stdout, &head) != nil || head.Version == 0 || head.Version > 9007199254740991 || len(head.Digest) != 64 || strings.Trim(head.Digest, "0123456789abcdef") != "" {
			t.Fatalf("invalid head export: %q", stdout)
		}
		want := fmt.Sprintf("{\"expected_version\":%d,\"expected_digest\":\"%s\"}\n", head.Version, head.Digest)
		if string(stdout) != want {
			t.Fatalf("noncanonical head export: %q", stdout)
		}
		return keymaker.J7OperatorResult{Command: keymaker.J7OperatorHead, Outcome: "ok", Version: head.Version, Digest: head.Digest}
	}
	d := json.NewDecoder(bytes.NewReader(stdout))
	d.DisallowUnknownFields()
	var result keymaker.J7OperatorResult
	if d.Decode(&result) != nil || json.Unmarshal(stdout, &members) != nil || len(members) != 7 {
		t.Fatalf("stdout is not the closed result: %q", stdout)
	}
	return result
}

func j7Tree(t *testing.T, root string) string {
	t.Helper()
	var rows []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		row := fmt.Sprintf("%s %v", path, info.Mode())
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			row += fmt.Sprintf(" %x", sha256.Sum256(b))
		}
		rows = append(rows, row)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(rows)
	return strings.Join(rows, "\n")
}

// Claim: a malformed `j7` invocation is a usage error (exit 2) that prints no
// result and touches nothing, while the complete invocation beside it exits 0
// with one closed result line (the positive control).
func TestJ7CommandUsage(t *testing.T) {
	f := j7CommandSetup(t)
	good := f.args("head")
	for name, args := range map[string][]string{
		"no-subcommand":       {"j7"},
		"unknown-subcommand":  {"j7", "export-seed", "--service-uid", f.uid, "--state-dir", f.state},
		"missing-state":       good[:4],
		"missing-schema":      append(append([]string{}, good[:6]...), good[8:]...),
		"repeated-flag":       append(append([]string{}, good...), "--schema", "0"),
		"unknown-flag":        append(append([]string{}, good...), "--config", "/x"),
		"foreign-flag":        append(append([]string{}, good...), "--key-file", f.keyFile),
		"positional-argument": append(append([]string{}, good...), "extra"),
		"half-head":           good[:10],
		"signed-number":       j7Replace(good, "--expected-version", "+"+strconv.FormatUint(f.version, 10)),
		"padded-number":       j7Replace(good, "--schema", "00"),
		"hex-uid":             j7Replace(good, "--service-uid", "0x3e9"),
		"wide-uid":            j7Replace(good, "--service-uid", "4294967296"),
		"seed-missing-key":    f.args("seed-init")[:6],
		"migrate-no-head":     f.args("migrate")[:14],
		"publish-no-input":    append(append([]string{}, f.args("policy-publish")[:14]...), f.args("policy-publish")[16:]...),
	} {
		before := j7Tree(t, f.root)
		var out, errOut bytes.Buffer
		if code := run(context.Background(), args, &out, &errOut); code != 2 || out.Len() != 0 || !strings.HasPrefix(errOut.String(), "usage: keymaker j7 ") {
			t.Fatalf("%s: want usage, got %d %q %q", name, code, &out, &errOut)
		}
		if j7Tree(t, f.root) != before {
			t.Fatal(name, "usage error had an effect")
		}
	}
	var out, errOut bytes.Buffer
	if code := run(context.Background(), good, &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Fatalf("positive control: %d %q %q", code, &out, &errOut)
	}
	if r := j7Result(t, out.Bytes()); r.Command != "j7 head" || r.Outcome != "ok" || r.Version != f.version || r.Digest != f.digest {
		t.Fatalf("positive control result: %+v", r)
	}
}

// Claim: through the real dispatch every subcommand refuses the wrong user, a
// state lock held as a service holds it, a relative path and (head, migrate)
// a wrong head and a wrong schema, with exit 1, the refusal code alone on stderr, one closed
// result line on stdout and no effect on disk; the planted fault removed, the
// same invocation passes that gate (the control: it succeeds, or for the two
// commands this fixture cannot complete it reaches the next, different gate).
func TestJ7CommandRefusals(t *testing.T) {
	// The outcome of the unmodified invocation on this anchorless schema-0
	// fixture: head and seed-init succeed, the other two reach a later gate.
	control := map[string]string{"seed-init": "", "head": "", "migrate": "generation_source_fenced", "policy-publish": "j7_state_fenced"}
	paths := map[string][]string{"seed-init": {"--state-dir", "--key-file"}, "migrate": {"--state-dir", "--generation-journal"}, "policy-publish": {"--state-dir", "--policy-file", "--input"}, "head": {"--state-dir"}}
	for _, command := range []string{"seed-init", "migrate", "policy-publish", "head"} {
		type row struct {
			name   string
			args   func(*j7CommandFixture) []string
			lock   bool
			code   string
			detail string
		}
		rows := []row{
			{"wrong-user", func(f *j7CommandFixture) []string {
				return j7Replace(f.args(command), "--service-uid", strconv.Itoa(os.Getuid()+1))
			}, false, "role_not_permitted", "command runs only as the service user"},
			{"service-lock", func(f *j7CommandFixture) []string { return f.args(command) }, true, "state_locked", "state already locked"},
		}
		for _, flag := range paths[command] {
			rows = append(rows, row{"relative" + flag, func(f *j7CommandFixture) []string {
				return j7Replace(f.args(command), flag, "relative/path")
			}, false, "request_malformed", "path must be absolute and clean"})
		}
		if command == "head" || command == "migrate" {
			rows = append(rows, row{"wrong-head", func(f *j7CommandFixture) []string {
				return j7Replace(f.args(command), "--expected-version", strconv.FormatUint(f.version+1, 10))
			}, false, "j7_state_fenced", "J7 expected head mismatch"})
		}
		if command == "head" || command == "migrate" {
			flag := "--schema"
			if command == "migrate" {
				flag = "--source-schema"
			}
			rows = append(rows, row{"wrong-schema", func(f *j7CommandFixture) []string {
				return j7Replace(f.args(command), flag, "4")
			}, false, "j7_state_fenced", "message schema floor mismatch"})
		}
		for _, row := range rows {
			t.Run(command+"/"+row.name, func(t *testing.T) {
				f := j7CommandSetup(t)
				var release func()
				if row.lock {
					uid := uint32(os.Getuid())
					dir, e := keymaker.OpenDirectory(f.state, uid, 0700)
					if e != nil {
						t.Fatal(e)
					}
					lock, e := keymaker.LockState(dir, uid)
					if e != nil {
						t.Fatal(e)
					}
					release = func() { lock.Close(); dir.Close() }
				}
				before := j7Tree(t, f.root)
				var out, errOut bytes.Buffer
				code := run(context.Background(), row.args(f), &out, &errOut)
				if release != nil {
					release()
				}
				result := j7Result(t, out.Bytes())
				if code != 1 || errOut.String() != row.code+"\n" || result.Outcome != "refused" || result.Refusal != row.code || result.Detail != row.detail || result.Command != "j7 "+command {
					t.Fatalf("negative: %d %q %q", code, &out, &errOut)
				}
				if j7Tree(t, f.root) != before {
					t.Fatal("refusal had an effect")
				}
				out.Reset()
				errOut.Reset()
				code = run(context.Background(), f.args(command), &out, &errOut)
				result = j7Result(t, out.Bytes())
				if result.Refusal != control[command] || result.Refusal == row.code || (code == 0) != (control[command] == "") {
					t.Fatalf("control: %d %q %q", code, &out, &errOut)
				}
			})
		}
	}
}

// Claim: the built binary (with its process hardening) initializes a seed and
// exports the head with exit 0, refuses to initialize over the existing seed
// with exit 1 and unchanged bytes, and never writes the seed to stdout or
// stderr in raw, hex or base64 form.
func TestJ7CommandBinaryNoSecret(t *testing.T) {
	f := j7CommandSetup(t)
	binary := filepath.Join(t.TempDir(), "keymaker")
	if b, e := exec.Command("go", "build", "-buildvcs=false", "-o", binary, ".").CombinedOutput(); e != nil {
		t.Fatalf("build failed: %v %s", e, b)
	}
	var transcript bytes.Buffer
	invoke := func(args []string) (int, keymaker.J7OperatorResult) {
		t.Helper()
		cmd := exec.Command(binary, args...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + f.root}
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		e := cmd.Run()
		code := 0
		if exit, ok := e.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else if e != nil {
			t.Fatal(e)
		}
		transcript.Write(out.Bytes())
		transcript.Write(errOut.Bytes())
		return code, j7Result(t, out.Bytes())
	}
	// Negative first: a planted record is not replaced.
	if os.WriteFile(f.keyFile, []byte("planted existing record"), 0600) != nil {
		t.Fatal("plant seed")
	}
	if code, r := invoke(f.args("seed-init")); code != 1 || r.Refusal != "j7_seed_exists" {
		t.Fatalf("existing seed: %d %+v", code, r)
	}
	if b, _ := os.ReadFile(f.keyFile); string(b) != "planted existing record" {
		t.Fatal("existing record changed")
	}
	if os.Remove(f.keyFile) != nil {
		t.Fatal("remove plant")
	}
	if code, r := invoke(f.args("seed-init")); code != 0 || r.Outcome != "ok" || r.Version != 0 || r.Digest != "" {
		t.Fatalf("seed-init: %d %+v", code, r)
	}
	record, e := os.ReadFile(f.keyFile)
	header := "keymaker-secp-root/1\nj7-request\n" + j7TestInstance + "\n"
	if e != nil || len(record) != len(header)+32 || string(record[:len(header)]) != header {
		t.Fatal("seed record is not the closed request-role record", e)
	}
	if st, e := os.Lstat(f.keyFile); e != nil || st.Mode() != 0600 {
		t.Fatal("seed record protection")
	}
	if code, r := invoke(f.args("seed-init")); code != 1 || r.Refusal != "j7_seed_exists" {
		t.Fatalf("second seed-init: %d %+v", code, r)
	}
	if now, _ := os.ReadFile(f.keyFile); !bytes.Equal(now, record) {
		t.Fatal("second seed-init changed the record")
	}
	if code, r := invoke(f.args("head")); code != 0 || r.Version != f.version || r.Digest != f.digest {
		t.Fatalf("head: %d %+v", code, r)
	}
	seed := record[len(header):]
	for name, needle := range map[string][]byte{
		"raw":       seed,
		"hex":       []byte(hex.EncodeToString(seed)),
		"base64":    []byte(base64.StdEncoding.EncodeToString(seed)),
		"base64url": []byte(base64.RawURLEncoding.EncodeToString(seed)),
		"half":      []byte(hex.EncodeToString(seed[:16])),
	} {
		if bytes.Contains(transcript.Bytes(), needle) {
			t.Fatal("binary output contains the seed as", name)
		}
	}
	// Control for the search itself: the needle is found where the seed is, and
	// the transcript really holds the command output.
	if !bytes.Contains(record, seed) || !bytes.Contains(transcript.Bytes(), []byte(f.digest)) {
		t.Fatal("secret search control failed")
	}
}

// Claim: successful head output is the exact two-field restart-pin grammar
// accepted by the service reader, with no result envelope or file write. A
// wrong head emits a refusal envelope, never installable pin bytes. The fixed
// version-7 vector binds this producer to the agreed reader contract.
func TestJ7CommandHeadExportBytes(t *testing.T) {
	f := j7CommandSetup(t)
	before := j7Tree(t, f.root)
	var out, errOut bytes.Buffer
	bad := j7Replace(f.args("head"), "--expected-version", strconv.FormatUint(f.version+1, 10))
	if code := run(t.Context(), bad, &out, &errOut); code != 1 || j7Result(t, out.Bytes()).Refusal != "j7_state_fenced" || bytes.Contains(out.Bytes(), []byte(`"expected_version"`)) {
		t.Fatal("wrong head became pin bytes")
	}
	out.Reset()
	errOut.Reset()
	if code := run(t.Context(), f.args("head"), &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Fatalf("head: %d %s", code, &errOut)
	}
	want := fmt.Sprintf("{\"expected_version\":%d,\"expected_digest\":\"%s\"}\n", f.version, f.digest)
	if out.String() != want {
		t.Fatalf("wrong export bytes: %q", out.String())
	}
	if j7Tree(t, f.root) != before {
		t.Fatal("head export changed evidence")
	}
	// Decode the shared vector independently of the producer's output helper.
	vector := "{\"expected_version\":7,\"expected_digest\":\"" + strings.Repeat("a", 64) + "\"}\n"
	got := j7Result(t, []byte(vector))
	if got.Version != 7 || got.Digest != strings.Repeat("a", 64) {
		t.Fatal("shared vector mismatch")
	}
	// No Keymaker command can install a root-owned restart pin.
	out.Reset()
	errOut.Reset()
	if code := run(t.Context(), append(f.args("head"), "--head-file", filepath.Join(f.root, "pin")), &out, &errOut); code != 2 || out.Len() != 0 || j7Tree(t, f.root) != before {
		t.Fatal("head-file writing mode admitted")
	}
}

type j7BrokenOutput struct{}

func (j7BrokenOutput) Write([]byte) (int, error) {
	return 0, errors.New("fixture-private-output-error")
}

// Claim: a failed head export write is reported as exit 1 with a fixed
// diagnostic and unchanged state; a working output writer still exports it.
func TestJ7CommandHeadOutputFailure(t *testing.T) {
	f := j7CommandSetup(t)
	before := j7Tree(t, f.root)
	var errOut, out bytes.Buffer
	if code := run(t.Context(), f.args("head"), j7BrokenOutput{}, &errOut); code != 1 || errOut.String() != "keymaker: result unavailable\n" || j7Tree(t, f.root) != before {
		t.Fatal("output failure was hidden or reflected")
	}
	errOut.Reset()
	if code := run(t.Context(), f.args("head"), &out, &errOut); code != 0 || errOut.Len() != 0 || j7Result(t, out.Bytes()).Digest != f.digest {
		t.Fatal("output control failed")
	}
}
