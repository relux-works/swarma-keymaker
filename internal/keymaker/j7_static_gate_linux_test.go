//go:build linux

package keymaker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-keymaker/staticgate"
	"github.com/relux-works/swarma-registrar/ccj"
	"golang.org/x/sys/unix"
)

const j7GateTestPublic = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"

// These local test-only helpers adapt staticgate's genuine/enc/sign helpers:
// start with its genuine vector and sign only with published BIP-340 CSV index 1.
// No test prints a scalar, a generated seed, or statement bytes on failure.
func j7GateEncode(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := ccj.Marshal(value, ccj.RegistrationMalformed)
	if err != nil {
		t.Fatal("test statement encoding failed")
	}
	return raw
}

func j7GateInstall(t *testing.T, f *j7ServiceFixture, edit func(map[string]any)) j7ProductionGate {
	t.Helper()
	raw, err := os.ReadFile("../../vectors/staticgate/genuine.ccj")
	if err != nil {
		t.Fatal(err)
	}
	value, err := ccj.Parse(raw, ccj.RegistrationMalformed)
	if err != nil {
		t.Fatal("genuine vector parsing failed")
	}
	g := value.(map[string]any)
	machine := []byte("0123456789abcdef0123456789abcdef\n")
	host := sha256.Sum256(machine)
	g["host"].(map[string]any)["machine_id_sha256"] = hex.EncodeToString(host[:])
	g["not_before"], g["not_after"] = helperNow.Add(-time.Hour).Format(time.RFC3339), helperNow.Add(time.Hour).Format(time.RFC3339)
	g["keymaker"] = map[string]any{"binary_sha256": strings.Repeat("3", 64), "config_sha256": j7Hash(f.static), "j7_request_key": f.public, "service_uid": int64(f.uid)}
	if edit != nil {
		edit(g)
	}
	raw = j7GateEncode(t, g)
	digest := staticgate.Digest(raw)
	// Published scalar, never an operational key; same vector as staticgate tests.
	scalar, _ := hex.DecodeString("b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef")
	private, _ := btcec.PrivKeyFromBytes(scalar)
	sig, err := schnorr.Sign(private, digest[:])
	private.Zero()
	if err != nil {
		t.Fatal("test signature failed")
	}
	files := *f.cfg.StaticGate
	if err := os.MkdirAll(filepath.Dir(files.StatementFile), 0700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{files.StatementFile: raw, files.SignatureFile: []byte(hex.EncodeToString(sig.Serialize()) + "\n"), files.DigestFile: []byte(hex.EncodeToString(digest[:]) + "\n"), files.ApproverKeyFile: []byte(j7GateTestPublic + "\n")} {
		if err := os.WriteFile(path, body, 0640); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0640); err != nil {
			t.Fatal(err)
		}
	}
	return j7ProductionGate{read: func(path string, limit int64) ([]byte, error) {
		return protectedRead(path, limit, f.uid, uint32(os.Getegid()), 0640)
	}, machine: func() ([]byte, error) { return append([]byte(nil), machine...), nil }}
}

func j7GateInput(f *j7ServiceFixture) j7StaticGateInput {
	return j7StaticGateInput{Files: *f.cfg.StaticGate, ConfigSHA256: j7Hash(f.static), ServiceUID: f.uid, Now: helperNow}
}

// Claim: each malformed configured file refuses with its exact gate code before key/state/socket effects, beside the repaired service.
func TestJ7StaticGateFileFormats(t *testing.T) {
	for _, file := range []string{"key", "digest", "statement", "signature"} {
		t.Run(file, func(t *testing.T) {
			f := j7ServiceSetup(t, j7ServiceOptions{})
			gate := j7GateInstall(t, f, nil)
			f.deps.gate = gate
			files := f.cfg.StaticGate
			path := map[string]string{"key": files.ApproverKeyFile, "digest": files.DigestFile, "statement": files.StatementFile, "signature": files.SignatureFile}[file]
			want := map[string]string{"key": "STATIC_GATE_KEY", "digest": "STATIC_GATE_PIN", "statement": "STATIC_GATE_PIN", "signature": "STATIC_GATE_SIGNATURE"}[file]
			good, _ := os.ReadFile(path)
			bad := map[string][]byte{"empty": {}, "short": good[:len(good)-1], "extra-lf": append(append([]byte(nil), good...), '\n'), "space": append([]byte(" "), good...), "uppercase": bytes.ToUpper(good), "nonhex": append([]byte("z"), good[1:]...)}
			bad["oversized"] = bytes.Repeat([]byte("a"), staticgate.MaxPreimage)
			if file == "statement" {
				delete(bad, "oversized")
			} // its read bound is tested separately
			for name, raw := range bad {
				t.Run(name, func(t *testing.T) {
					if err := os.WriteFile(path, raw, 0640); err != nil {
						t.Fatal(err)
					}
					f.refuses(t, want, j7ServiceRefusal{})
					if err := os.WriteFile(path, good, 0640); err != nil {
						t.Fatal(err)
					}
					f.serves(t)
				})
			}
		})
	}
}

// Claim: every unsafe static input refuses its file-specific code without effects; exact owner/group/mode/link/ancestor/ACL repairs serve.
func TestJ7StaticGateUnsafeFiles(t *testing.T) {
	for _, file := range []string{"key", "digest", "statement", "signature"} {
		t.Run(file, func(t *testing.T) {
			f := j7ServiceSetup(t, j7ServiceOptions{})
			gate := j7GateInstall(t, f, nil)
			f.deps.gate = gate
			files := f.cfg.StaticGate
			path := map[string]string{"key": files.ApproverKeyFile, "digest": files.DigestFile, "statement": files.StatementFile, "signature": files.SignatureFile}[file]
			want := map[string]string{"key": "STATIC_GATE_KEY", "digest": "STATIC_GATE_PIN", "statement": "STATIC_GATE_FORM", "signature": "STATIC_GATE_SIGNATURE"}[file]
			for _, kind := range []string{"missing", "symlink", "hardlink", "directory", "fifo", "mode", "parent-mode", "owner", "group", "acl"} {
				t.Run(kind, func(t *testing.T) {
					moved := path + ".saved"
					local := gate
					var repair func()
					switch kind {
					case "missing", "symlink", "directory", "fifo":
						if os.Rename(path, moved) != nil {
							t.Fatal("move input")
						}
						switch kind {
						case "symlink":
							if os.Symlink(moved, path) != nil {
								t.Fatal("symlink input")
							}
						case "directory":
							if os.Mkdir(path, 0640) != nil {
								t.Fatal("directory input")
							}
						case "fifo":
							if unix.Mkfifo(path, 0640) != nil {
								t.Fatal("fifo input")
							}
						}
						repair = func() {
							if kind != "missing" {
								os.Remove(path)
							}
							if os.Rename(moved, path) != nil {
								t.Fatal("restore input")
							}
						}
					case "hardlink":
						if os.Link(path, moved) != nil {
							t.Fatal("link input")
						}
						repair = func() { os.Remove(moved) }
					case "mode":
						os.Chmod(path, 0600)
						repair = func() { os.Chmod(path, 0640) }
					case "parent-mode":
						os.Chmod(filepath.Dir(path), 0770)
						repair = func() { os.Chmod(filepath.Dir(path), 0700) }
					case "owner", "group":
						local.read = func(p string, limit int64) ([]byte, error) {
							if p != path {
								return gate.read(p, limit)
							}
							owner, group := f.uid, uint32(os.Getegid())
							if kind == "owner" {
								owner++
							} else {
								group++
							}
							return protectedRead(p, limit, owner, group, 0640)
						}
						repair = func() {}
					case "acl":
						// owner rw, named user r, owning group r, mask r, other none.
						acl := []byte{2, 0, 0, 0, 1, 0, 6, 0, 255, 255, 255, 255, 2, 0, 4, 0, 1, 0, 0, 0, 4, 0, 4, 0, 255, 255, 255, 255, 16, 0, 4, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255}
						if err := unix.Setxattr(path, "system.posix_acl_access", acl, 0); err != nil {
							t.Fatal(err)
						}
						repair = func() {
							if unix.Removexattr(path, "system.posix_acl_access") != nil {
								t.Fatal("remove ACL")
							}
						}
					}
					defer func() {
						if repair != nil {
							repair()
						}
					}()
					f.deps.gate = local
					expected := want
					if kind == "parent-mode" {
						expected = "STATIC_GATE_PIN"
					} // all four inputs share this parent; PIN is read first
					f.refuses(t, expected, j7ServiceRefusal{})
					repair()
					repair = nil
					f.deps.gate = gate
					f.serves(t)
				})
			}
		})
	}
}

// Claim: all seven Verify refusals survive startup mapping with no effects and a valid, signed positive beside each.
func TestJ7StaticGateStartup(t *testing.T) {
	for _, row := range []struct {
		name, want string
		edit       func(map[string]any)
		input      func(*j7ProductionGate, *j7ServiceFixture)
	}{
		{"wrong-key", "STATIC_GATE_KEY", nil, func(g *j7ProductionGate, f *j7ServiceFixture) {
			os.WriteFile(f.cfg.StaticGate.ApproverKeyFile, []byte(strings.Repeat("1", 64)+"\n"), 0640)
		}},
		{"wrong-pin", "STATIC_GATE_PIN", nil, func(g *j7ProductionGate, f *j7ServiceFixture) {
			os.WriteFile(f.cfg.StaticGate.DigestFile, []byte(strings.Repeat("1", 64)+"\n"), 0640)
		}},
		{"wrong-machine", "STATIC_GATE_HOST", nil, func(g *j7ProductionGate, f *j7ServiceFixture) {
			g.machine = func() ([]byte, error) { return []byte("other\n"), nil }
		}},
		{"bad-signature", "STATIC_GATE_SIGNATURE", nil, func(g *j7ProductionGate, f *j7ServiceFixture) {
			os.WriteFile(f.cfg.StaticGate.SignatureFile, []byte(strings.Repeat("1", 128)+"\n"), 0640)
		}},
		{"expired", "STATIC_GATE_WINDOW", func(g map[string]any) { g["not_after"] = helperNow.Format(time.RFC3339) }, nil},
		{"wrong-uid", "STATIC_GATE_SCOPE_MISMATCH", func(g map[string]any) { g["keymaker"].(map[string]any)["service_uid"] = int64(38655) }, nil},
		{"wrong-config", "STATIC_GATE_SCOPE_MISMATCH", func(g map[string]any) { g["keymaker"].(map[string]any)["config_sha256"] = strings.Repeat("a", 64) }, nil},
		{"extra-member", "STATIC_GATE_SCOPE_MISMATCH", func(g map[string]any) { g["keymaker"].(map[string]any)["extra"] = int64(1) }, nil},
		{"bad-form", "STATIC_GATE_FORM", func(g map[string]any) { g["v"] = int64(2) }, nil},
		{"bad-binary", "STATIC_GATE_SCOPE_MISMATCH", func(g map[string]any) { g["keymaker"].(map[string]any)["binary_sha256"] = "invalid" }, nil},
		{"bad-request-key", "STATIC_GATE_SCOPE_MISMATCH", func(g map[string]any) { g["keymaker"].(map[string]any)["j7_request_key"] = "invalid" }, nil},
		{"missing-member", "STATIC_GATE_SCOPE_MISMATCH", func(g map[string]any) { delete(g["keymaker"].(map[string]any), "binary_sha256") }, nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := j7ServiceSetup(t, j7ServiceOptions{})
			gate := j7GateInstall(t, f, row.edit)
			if row.input != nil {
				row.input(&gate, f)
			}
			f.deps.gate = gate
			f.refuses(t, row.want, j7ServiceRefusal{})
			f.deps.gate = j7GateInstall(t, f, nil)
			f.serves(t)
		})
	}
}

// Claim: zero seam Now refuses WINDOW, a root-reader cannot read holder files, and a post-load key mismatch refuses before publication, beside valid controls.
func TestJ7StaticGateSeamAndKey(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	gate := j7GateInstall(t, f, nil)
	input := j7GateInput(f)
	input.Now = time.Time{}
	if result, code := gate.verify(t.Context(), input); code != "STATIC_GATE_WINDOW" || result.RequestKey != "" || result.check != nil {
		t.Fatal("zero clock admitted", code)
	}
	if result, code := gate.verify(t.Context(), j7GateInput(f)); code != "" || result.RequestKey != f.public || result.check == nil {
		t.Fatal("valid gate refused", code)
	}
	f.deps.gate = j7StaticGateFunc(func(context.Context, j7StaticGateInput) (j7StaticGateResult, Code) {
		return j7StaticGateResult{RequestKey: f.public}, ""
	})
	f.refuses(t, "static_gate_unavailable", j7ServiceRefusal{})
	f.deps.gate = productionJ7ServiceDeps().gate
	f.refuses(t, "STATIC_GATE_PIN", j7ServiceRefusal{})
	f.deps.gate = j7GateInstall(t, f, func(g map[string]any) { g["keymaker"].(map[string]any)["j7_request_key"] = strings.Repeat("a", 64) })
	f.refuses(t, "j7_request_key_mismatch", j7ServiceRefusal{keyGate: true})
	// Restore the statement whose key matches custody.
	f.deps.gate = j7GateInstall(t, f, nil)
	f.serves(t)
}

type j7GateProbe struct {
	*j7ServiceStub
	handled, released int
}

func (p *j7GateProbe) Handle(context.Context, control.Peer, control.Request) (control.Object, control.Code) {
	p.handled++
	return control.Object{"ok": true}, ""
}
func (p *j7GateProbe) WithActive(ctx context.Context, _ control.Peer, _ control.Request, _ control.Object, release func(context.Context) control.Code) control.Code {
	p.released++
	return release(ctx)
}

// Claim: expiry after startup blocks every start effect without reaching the adapter, but end and release pass; zero time blocks both classes.
func TestJ7StaticGatePerEffect(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	gate := j7GateInstall(t, f, nil)
	verdict, code := gate.verify(t.Context(), j7GateInput(f))
	if code != "" {
		t.Fatal(code)
	}
	probe := &j7GateProbe{j7ServiceStub: &j7ServiceStub{}}
	now := helperNow.Add(time.Hour)
	h := &j7GatedHandler{j7ServiceAdapter: probe, check: verdict.check, now: func(context.Context) (time.Time, Code) { return now, "" }}
	for _, method := range []string{"j7_run_bind", "j7_run_rebind", "j7_sign", "consent_v3", "j7_pubkey"} {
		before := probe.handled
		if obj, c := h.Handle(t.Context(), control.Peer{}, control.Request{Method: method}); c != "STATIC_GATE_WINDOW" || obj != nil || probe.handled != before {
			t.Fatal("expired start reached effect", method, c)
		}
		now = helperNow
		if _, c := h.Handle(t.Context(), control.Peer{}, control.Request{Method: method}); c != "" || probe.handled != before+1 {
			t.Fatal("valid start refused", method, c)
		}
		now = helperNow.Add(time.Hour)
	}
	now = time.Time{}
	if _, c := h.Handle(t.Context(), control.Peer{}, control.Request{Method: "j7_run_end"}); c != "STATIC_GATE_WINDOW" {
		t.Fatal("zero end", c)
	}
	now = helperNow.Add(time.Hour)
	if _, c := h.Handle(t.Context(), control.Peer{}, control.Request{Method: "j7_run_end"}); c != "" {
		t.Fatal("expired end", c)
	}
	released := false
	now = time.Time{}
	if c := h.WithActive(t.Context(), control.Peer{}, control.Request{}, nil, func(context.Context) control.Code { released = true; return "" }); c != "STATIC_GATE_WINDOW" || released || probe.released != 0 {
		t.Fatal("zero release", c)
	}
	now = helperNow.Add(time.Hour)
	if c := h.WithActive(t.Context(), control.Peer{}, control.Request{}, nil, func(context.Context) control.Code { released = true; return "" }); c != "" || !released || probe.released != 1 {
		t.Fatal("expired release", c)
	}
	// Modifying the install files cannot change the captured statement.
	os.WriteFile(f.cfg.StaticGate.StatementFile, []byte("{}"), 0640)
	if c := verdict.check(helperNow, staticgate.ClassStart); c != "" {
		t.Fatal("re-read static bytes", c)
	}
}

// Claim: an expired later bind is audited once without state/head changes; an in-window bind succeeds and its end/release still succeed after expiry.
func TestJ7StaticGateWireExpiry(t *testing.T) {
	uid := uint32(os.Getuid())
	f := j7ServiceSetup(t, j7ServiceOptions{launcher: &Principal{UID: uid, Generation: nativeToken}})
	gate := j7GateInstall(t, f, nil)
	verdict, code := gate.verify(t.Context(), j7GateInput(f))
	if code != "" {
		t.Fatal(code)
	}
	// Compose the production wrapper around the actual custody adapter via its
	// immutable check closure; each wire call supplies a deterministic sample.
	var expired atomic.Bool
	var seen atomic.Int64
	provider, clock, _ := fixtureTimeProvider(t, helperNow)
	f.deps.clock = func(*timeconf.Policy) (*timeconf.Provider, error) { f.trace.add("clock"); return provider, nil }
	f.deps.gate = j7StaticGateFunc(func(ctx context.Context, in j7StaticGateInput) (j7StaticGateResult, Code) {
		return j7StaticGateResult{RequestKey: f.public, check: func(now time.Time, class staticgate.Class) Code {
			seen.Store(now.UnixNano())
			if expired.Load() {
				now = helperNow.Add(time.Hour)
			}
			return verdict.check(now, class)
		}}, ""
	})
	r := f.start(t, j7ServiceInner)
	c := j7ServiceDial(t, f)
	lifecycleHello(t, c, 1)
	before := recoveryFiles(t, f.statePath)
	// Advancing both trusted UTC and elapsed time keeps the provider trusted.
	// The check must receive a fresh provider sample, not the startup sample.
	clock.advance(time.Second)
	// The window switch is atomic because the handler runs in another goroutine.
	expired.Store(true)
	origin := f.sf.origin
	params := j7Params(t, j7BindArguments{Identity: f.sf.binding.Number, Origin: &origin, Input: Principal{uid + 200, "input-a"}})
	j7Call(t, c, 2, "j7_run_bind", params, "STATIC_GATE_WINDOW")
	if seen.Load() != helperNow.Add(time.Second).UnixNano() {
		t.Fatal("per-effect check reused startup time")
	}
	after := recoveryFiles(t, f.statePath)
	changed := 0
	for path, old := range before {
		if after[path] == old {
			continue
		}
		if !strings.Contains(path, "/audit/") || !strings.HasPrefix(after[path], old) || strings.Count(strings.TrimPrefix(after[path], old), "\n") != 1 || !strings.Contains(strings.TrimPrefix(after[path], old), `"refusal_code":"STATIC_GATE_WINDOW"`) {
			t.Fatal("expiry changed non-refusal evidence")
		}
		changed++
	}
	if changed != 1 || len(before) != len(after) {
		t.Fatal("expiry audit count", changed)
	}
	expired.Store(false)
	bound := j7Call(t, c, 3, "j7_run_bind", params, "")
	run, _ := bound["run_id"].(string)
	if !messageID(run) {
		t.Fatal("valid bind has no run")
	}
	expired.Store(true)
	j7Call(t, c, 4, "j7_run_end", control.Object{"run_id": run}, "")
	if e := r.stop(t); e != nil {
		t.Fatal(e)
	}
}

// Claim: unavailable trusted time refuses before handle/release effects, while the same wrapper with a valid trusted sample performs both.
func TestJ7StaticGateTrustedRecheck(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	gate := j7GateInstall(t, f, nil)
	verdict, code := gate.verify(t.Context(), j7GateInput(f))
	if code != "" {
		t.Fatal(code)
	}
	probe := &j7GateProbe{j7ServiceStub: &j7ServiceStub{}}
	trusted := false
	h := &j7GatedHandler{j7ServiceAdapter: probe, check: verdict.check, now: func(context.Context) (time.Time, Code) {
		if !trusted {
			return helperNow, "clock_untrusted"
		}
		return helperNow, ""
	}}
	if _, c := h.Handle(t.Context(), control.Peer{}, control.Request{Method: "j7_run_bind"}); c != "clock_untrusted" || probe.handled != 0 {
		t.Fatal("untrusted handle", c)
	}
	if c := h.WithActive(t.Context(), control.Peer{}, control.Request{}, nil, func(context.Context) control.Code { t.Fatal("untrusted callback"); return "" }); c != "clock_untrusted" || probe.released != 0 {
		t.Fatal("untrusted release", c)
	}
	trusted = true
	if _, c := h.Handle(t.Context(), control.Peer{}, control.Request{Method: "j7_run_bind"}); c != "" || probe.handled != 1 {
		t.Fatal("trusted handle", c)
	}
	if c := h.WithActive(t.Context(), control.Peer{}, control.Request{}, nil, func(context.Context) control.Code { return "" }); c != "" || probe.released != 1 {
		t.Fatal("trusted release", c)
	}
}

type j7StaticGateFunc func(context.Context, j7StaticGateInput) (j7StaticGateResult, Code)

func (fn j7StaticGateFunc) verify(ctx context.Context, in j7StaticGateInput) (j7StaticGateResult, Code) {
	return fn(ctx, in)
}

// Claim: protected machine-id reads refuse a nonregular or foreign file and preserve its exact LF in the digest, beside a valid regular file.
func TestJ7StaticGateMachineFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "machine-id")
	if os.Mkdir(path, 0700) != nil {
		t.Fatal("machine directory")
	}
	if _, e := protectedRead(path, 4096, uint32(os.Getuid()), 0, 0); e == nil {
		t.Fatal("nonregular machine-id accepted")
	}
	os.Remove(path)
	if unix.Mkfifo(path, 0600) != nil {
		t.Fatal("machine FIFO")
	}
	if _, e := protectedRead(path, 4096, uint32(os.Getuid()), 0, 0); e == nil {
		t.Fatal("nonregular machine FIFO accepted")
	}
	os.Remove(path)
	good := []byte("0123456789abcdef0123456789abcdef\n")
	os.WriteFile(path, good, 0644)
	if _, e := protectedRead(path, 4096, uint32(os.Getuid()+1), 0, 0); e == nil {
		t.Fatal("foreign machine-id accepted")
	}
	raw, e := protectedRead(path, 4096, uint32(os.Getuid()), 0, 0)
	if e != nil || !reflect.DeepEqual(raw, good) || sha256.Sum256(raw) == sha256.Sum256(bytes.TrimSpace(good)) {
		t.Fatal("machine-id exact bytes lost")
	}
}

// Claim: production ancestor metadata requires root ownership and no group/other write, with a valid root-owned control beside each refusal.
func TestJ7StaticGateAncestorMetadata(t *testing.T) {
	for _, st := range []syscall.Stat_t{{Uid: 1, Mode: 0755}, {Uid: 0, Mode: 0775}, {Uid: 0, Mode: 0757}} {
		if protectedAncestor(st, 0) {
			t.Fatal("unsafe root ancestry admitted")
		}
		if !protectedAncestor(syscall.Stat_t{Uid: 0, Mode: 0755}, 0) {
			t.Fatal("protected root ancestry refused")
		}
	}
}

// Claim: protected descriptor walks refuse a symlink or default ACL on an ancestor without reading input; the unchanged direct path passes after repair.
func TestJ7StaticGateProtectedAncestors(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "inputs")
	path := filepath.Join(parent, "input")
	if os.Mkdir(parent, 0700) != nil || os.WriteFile(path, []byte("public"), 0640) != nil {
		t.Fatal("input fixture")
	}
	alias := filepath.Join(root, "alias")
	if os.Symlink(parent, alias) != nil {
		t.Fatal("ancestor symlink fixture")
	}
	if _, err := protectedRead(filepath.Join(alias, "input"), 64, uint32(os.Getuid()), uint32(os.Getegid()), 0640); err == nil || err.Error() != "keymaker: unsafe configuration parent" {
		t.Fatal("symlink ancestor admitted", err)
	}
	if _, err := protectedRead(path, 64, uint32(os.Getuid()), uint32(os.Getegid()), 0640); err != nil {
		t.Fatal("direct path refused", err)
	}
	acl := []byte{2, 0, 0, 0, 1, 0, 7, 0, 255, 255, 255, 255, 2, 0, 4, 0, 1, 0, 0, 0, 4, 0, 0, 0, 255, 255, 255, 255, 16, 0, 4, 0, 255, 255, 255, 255, 32, 0, 0, 0, 255, 255, 255, 255}
	if err := unix.Setxattr(parent, "system.posix_acl_default", acl, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedRead(path, 64, uint32(os.Getuid()), uint32(os.Getegid()), 0640); err == nil || err.Error() != "keymaker: unsafe configuration parent" {
		t.Fatal("default ACL ancestor admitted", err)
	}
	if err := unix.Removexattr(parent, "system.posix_acl_default"); err != nil {
		t.Fatal(err)
	}
	if _, err := protectedRead(path, 64, uint32(os.Getuid()), uint32(os.Getegid()), 0640); err != nil {
		t.Fatal("repaired path refused", err)
	}
}

// Claim: exact-length lowercase hex with one LF is accepted; every other file spelling refuses before decoding.
func TestJ7StaticGateHexLines(t *testing.T) {
	for _, digits := range []int{64, 128} {
		good := []byte(strings.Repeat("a", digits) + "\n")
		for _, bad := range [][]byte{nil, good[:digits], append(append([]byte(nil), good...), '\n'), bytes.ToUpper(good), append([]byte("z"), good[1:]...), append([]byte(" "), good[1:]...), append(append([]byte(nil), good[:digits]...), '\r')} {
			if _, ok := j7HexLine(bad, digits); ok {
				t.Fatal("noncanonical hex line accepted")
			}
			if decoded, ok := j7HexLine(good, digits); !ok || string(decoded) != strings.Repeat("a", digits) {
				t.Fatal("canonical hex line refused")
			}
		}
	}
}

// Claim: the installed root-owned machine-id is read at the fixed path without trimming; an unavailable machine-id refuses HOST before effects.
func TestJ7StaticGateProductionMachine(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	gate := j7GateInstall(t, f, nil)
	gate.machine = func() ([]byte, error) { return nil, os.ErrNotExist }
	f.deps.gate = gate
	f.refuses(t, "STATIC_GATE_HOST", j7ServiceRefusal{})
	production := productionJ7StaticGate().(j7ProductionGate)
	if _, err := protectedRead("/etc/machine-id", 4096, 1, 0, 0); err == nil {
		t.Fatal("foreign root file accepted")
	}
	if _, err := protectedRead("/etc/../etc/machine-id", 4096, 0, 0, 0); err == nil {
		t.Fatal("unclean path accepted")
	}
	if _, err := protectedRead("/etc/machine-id", 1, 0, 0, 0); err == nil {
		t.Fatal("oversized root file accepted")
	}
	raw, err := production.machine()
	expected, e := os.ReadFile("/etc/machine-id")
	if err != nil || e != nil || !bytes.Equal(raw, expected) {
		t.Fatal("fixed root-owned machine-id unavailable or changed")
	}
	f.deps.gate = j7GateInstall(t, f, nil)
	f.serves(t)
}

// Claim: oversized inputs and canonical-form violations with correct digest pins refuse FORM without key, state or socket effects, beside exact CCJ-1.
func TestJ7StaticGateStatementBounds(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	for _, kind := range []string{"oversized", "lf", "space", "nonobject", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			gate := j7GateInstall(t, f, nil)
			files := f.cfg.StaticGate
			raw, _ := os.ReadFile(files.StatementFile)
			switch kind {
			case "oversized":
				raw = bytes.Repeat([]byte("a"), staticgate.MaxPreimage)
			case "lf":
				raw = append(raw, '\n')
			case "space":
				raw = append([]byte(" "), raw...)
			case "nonobject":
				raw = []byte("[]")
			case "duplicate":
				raw = bytes.Replace(raw, []byte(`"v":1}`), []byte(`"v":1,"v":1}`), 1)
			}
			os.WriteFile(files.StatementFile, raw, 0640)
			digest := staticgate.Digest(raw)
			os.WriteFile(files.DigestFile, []byte(hex.EncodeToString(digest[:])+"\n"), 0640)
			f.deps.gate = gate
			f.refuses(t, "STATIC_GATE_FORM", j7ServiceRefusal{})
			f.deps.gate = j7GateInstall(t, f, nil)
			f.serves(t)
		})
	}
}

// Claim: unsafe PIN and KEY files together refuse PIN before later reads or
// service effects; repairing both serves with PIN/FORM/KEY/SIGNATURE/HOST order.
func TestJ7StaticGatePinBeforeKey(t *testing.T) {
	f := j7ServiceSetup(t, j7ServiceOptions{})
	gate := j7GateInstall(t, f, nil)
	var reads []string
	read, machine := gate.read, gate.machine
	gate.read = func(path string, limit int64) ([]byte, error) {
		reads = append(reads, path)
		return read(path, limit)
	}
	gate.machine = func() ([]byte, error) {
		reads = append(reads, "machine-id")
		return machine()
	}
	f.deps.gate = gate
	for _, path := range []string{f.cfg.StaticGate.DigestFile, f.cfg.StaticGate.ApproverKeyFile} {
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f.refuses(t, "STATIC_GATE_PIN", j7ServiceRefusal{absent: []string{"ancestors", "head", "generation", "policy"}})
	if !reflect.DeepEqual(reads, []string{f.cfg.StaticGate.DigestFile}) {
		t.Fatal("PIN refusal reached a later input")
	}
	for _, path := range []string{f.cfg.StaticGate.DigestFile, f.cfg.StaticGate.ApproverKeyFile} {
		if err := os.Chmod(path, 0640); err != nil {
			t.Fatal(err)
		}
	}
	reads = nil
	f.serves(t)
	want := []string{f.cfg.StaticGate.DigestFile, f.cfg.StaticGate.StatementFile, f.cfg.StaticGate.ApproverKeyFile, f.cfg.StaticGate.SignatureFile, "machine-id"}
	if !reflect.DeepEqual(reads, want) {
		t.Fatal("static input read order differs from verifier precedence")
	}
}
