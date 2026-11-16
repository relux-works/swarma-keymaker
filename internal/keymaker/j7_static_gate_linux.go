//go:build linux

package keymaker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-keymaker/staticgate"
	"github.com/relux-works/swarma-registrar/ccj"
)

func protectedAncestor(st syscall.Stat_t, owner uint32) bool {
	return (st.Uid == 0 || st.Uid == owner) && st.Mode&022 == 0
}

// protectedRead walks retained descriptors without symlinks. Production pins
// owner to root; the owner argument lets unprivileged tests exercise the same
// file checks. Ancestors are root or owner, never writable by group or other.
// mode zero is reserved for machine-id, whose contract pins no permission mode.
func protectedRead(path string, limit int64, owner, group, mode uint32) ([]byte, error) {
	if !cleanAbsolute(path) {
		return nil, failure("configuration path must be absolute")
	}
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, failure("configuration unavailable")
	}
	dir := os.NewFile(uintptr(fd), "/")
	defer func() { dir.Close() }()
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i := 0; ; i++ {
		var st syscall.Stat_t
		if syscall.Fstat(int(dir.Fd()), &st) != nil || !protectedAncestor(st, owner) || !j7NoACL(int(dir.Fd()), true) {
			return nil, failure("unsafe configuration parent")
		}
		if i == len(parts)-1 {
			break
		}
		next, e := syscall.Openat(int(dir.Fd()), parts[i], syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if e != nil {
			return nil, failure("unsafe configuration parent")
		}
		dir.Close()
		dir = os.NewFile(uintptr(next), parts[i])
	}
	fd, err = syscall.Openat(int(dir.Fd()), parts[len(parts)-1], syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, failure("protected file unavailable")
	}
	f := os.NewFile(uintptr(fd), "protected input")
	defer f.Close()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != owner || st.Nlink != 1 ||
		(mode != 0 && (st.Mode&07777 != mode || st.Gid != group)) || !j7NoACL(fd, false) {
		return nil, failure("unsafe protected file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, failure("protected input capacity exceeded")
	}
	return b, nil
}

// j7ProductionGate has private I/O seams only; no flag or configuration can
// replace the production readers or the fixed machine-id path.
type j7ProductionGate struct {
	read    func(string, int64) ([]byte, error)
	machine func() ([]byte, error)
}

func productionJ7StaticGate() j7StaticGate {
	return j7ProductionGate{
		read: func(path string, limit int64) ([]byte, error) {
			return protectedRead(path, limit, 0, uint32(os.Getgid()), 0640)
		},
		machine: func() ([]byte, error) { return protectedRead("/etc/machine-id", 4096, 0, 0, 0) },
	}
}

func j7HexLine(raw []byte, digits int) ([]byte, bool) {
	if len(raw) != digits+1 || raw[digits] != '\n' {
		return nil, false
	}
	for _, c := range raw[:digits] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return nil, false
		}
	}
	return raw[:digits], true
}

func j7GateCode(err error) Code {
	if err == nil {
		return ""
	}
	var refusal *staticgate.Error
	if errors.As(err, &refusal) {
		return Code(refusal.Code)
	}
	return "static_gate_unavailable"
}

func (g j7ProductionGate) verify(_ context.Context, in j7StaticGateInput) (j7StaticGateResult, Code) {
	var empty j7StaticGateResult
	keyFile, err := g.read(in.Files.ApproverKeyFile, 65)
	key, ok := j7HexLine(keyFile, 64)
	if err != nil || !ok {
		return empty, Code(staticgate.CodeKey)
	}
	digestFile, err := g.read(in.Files.DigestFile, 65)
	digest, ok := j7HexLine(digestFile, 64)
	if err != nil || !ok {
		return empty, Code(staticgate.CodePin)
	}
	raw, err := g.read(in.Files.StatementFile, staticgate.MaxPreimage-int64(len(staticgate.Tag))-1)
	if err != nil {
		return empty, Code(staticgate.CodeForm)
	}
	sigFile, err := g.read(in.Files.SignatureFile, 129)
	sig, ok := j7HexLine(sigFile, 128)
	if err != nil || !ok {
		return empty, Code(staticgate.CodeSignature)
	}
	machine, err := g.machine()
	if err != nil {
		return empty, Code(staticgate.CodeHost)
	}
	inputs := staticgate.Inputs{Consumer: staticgate.Keymaker, MachineIDSHA256: sha256.Sum256(machine)}
	hex.Decode(inputs.ApproverKey[:], key)
	hex.Decode(inputs.StatementDigest[:], digest)
	// Preserve Verify's PIN/FORM/KEY ordering before interpreting the opaque
	// owner section. This first pass uses a nonempty placeholder; only a scope
	// mismatch may proceed to building the expected section below.
	inputs.Now, inputs.Class, inputs.Section = in.Now, staticgate.ClassStart, []byte("{}")
	if _, err := staticgate.Verify(raw, sig, inputs); err != nil && !errors.Is(err, staticgate.ErrScopeMismatch) {
		return empty, j7GateCode(err)
	}
	value, err := ccj.Parse(raw, ccj.RegistrationMalformed)
	if err != nil {
		return empty, Code(staticgate.CodeForm)
	}
	statement, _ := value.(map[string]any)
	section, _ := statement["keymaker"].(map[string]any)
	binary, bOK := section["binary_sha256"].(string)
	requestKey, kOK := section["j7_request_key"].(string)
	if !bOK || !kOK || !validDigest(binary) || !validDigest(requestKey) {
		return empty, Code(staticgate.CodeScopeMismatch)
	}
	inputs.Section, err = ccj.Marshal(map[string]any{
		"binary_sha256": binary, "config_sha256": in.ConfigSHA256,
		"j7_request_key": requestKey, "service_uid": int64(in.ServiceUID),
	}, ccj.RegistrationMalformed)
	if err != nil {
		return empty, Code(staticgate.CodeScopeMismatch)
	}
	// Own the immutable bytes, including across requests; no install file is
	// re-read after startup and no association is supplied by this consumer.
	raw, sig = append([]byte(nil), raw...), append([]byte(nil), sig...)
	check := func(now time.Time, class staticgate.Class) Code {
		current := inputs
		current.Now, current.Class = now, class
		_, err := staticgate.Verify(raw, sig, current)
		return j7GateCode(err)
	}
	if c := check(in.Now, staticgate.ClassStart); c != "" {
		return empty, c
	}
	return j7StaticGateResult{RequestKey: requestKey, check: check}, ""
}

// j7GatedHandler embeds the complete adapter so connection scope, bound-channel
// detection and both control markers survive wrapping. Refusals are returned to
// control, which invokes Refuse once before emitting the error.
type j7GatedHandler struct {
	j7ServiceAdapter
	check func(time.Time, staticgate.Class) Code
	now   func(context.Context) (time.Time, Code)
}

func (h *j7GatedHandler) recheck(ctx context.Context, class staticgate.Class) control.Code {
	now, code := h.now(ctx)
	if code != "" {
		return control.Code(code)
	}
	return control.Code(h.check(now, class))
}

func (h *j7GatedHandler) Handle(ctx context.Context, peer control.Peer, r control.Request) (control.Object, control.Code) {
	class := staticgate.ClassStart
	if r.Method == "j7_run_end" {
		class = staticgate.ClassEnd
	}
	if code := h.recheck(ctx, class); code != "" {
		return nil, code
	}
	return h.j7ServiceAdapter.Handle(ctx, peer, r)
}

func (h *j7GatedHandler) WithActive(ctx context.Context, peer control.Peer, r control.Request, result control.Object, release func(context.Context) control.Code) control.Code {
	// Release is end-class even for a result prepared before window expiry.
	// Check before the inner fence, which itself may touch custody.
	if code := h.recheck(ctx, staticgate.ClassEnd); code != "" {
		return code
	}
	return h.j7ServiceAdapter.WithActive(ctx, peer, r, result, release)
}

var _ j7ServiceAdapter = (*j7GatedHandler)(nil)
