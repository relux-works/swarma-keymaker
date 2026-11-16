// Package staticgate verifies one signed `swarma-s7 static-gate/1` statement
// against caller-supplied pins and expected bytes. It holds no signer and no
// private key, opens no file or socket, reads no clock and hashes no binary.
// The format and its limits are in spec/keymaker-static-gate.md.
package staticgate

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/relux-works/swarma-registrar/ccj"
)

const (
	// Tag is the kind member and the domain-separation line of the preimage.
	Tag = "swarma-s7 static-gate/1"
	// Milestone is the only accepted milestone member.
	Milestone = "G1.0"
	// MaxPreimage bounds len(Tag) + 1 + len(statement) in bytes.
	MaxPreimage = 8192
	// MaxDepth bounds container nesting; the statement object itself is depth 1.
	MaxDepth = 8
	// MaxWindow bounds not_after - not_before.
	MaxWindow = 72 * time.Hour
)

// Code is a stable refusal code.
type Code string

const (
	CodeKey           Code = "STATIC_GATE_KEY"
	CodePin           Code = "STATIC_GATE_PIN"
	CodeForm          Code = "STATIC_GATE_FORM"
	CodeSignature     Code = "STATIC_GATE_SIGNATURE"
	CodeHost          Code = "STATIC_GATE_HOST"
	CodeWindow        Code = "STATIC_GATE_WINDOW"
	CodeScopeMismatch Code = "STATIC_GATE_SCOPE_MISMATCH"
)

// Error is the only error type Verify returns. Code is stable; the text after
// it names the failed check for an operator and is not part of the contract.
type Error struct {
	Code  Code
	check string
}

func (e *Error) Error() string {
	if e.check == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.check
}

// Is matches by Code, so errors.Is(err, staticgate.ErrWindow) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// One sentinel per refusal code, for errors.Is.
var (
	ErrKey           = &Error{Code: CodeKey}
	ErrPin           = &Error{Code: CodePin}
	ErrForm          = &Error{Code: CodeForm}
	ErrSignature     = &Error{Code: CodeSignature}
	ErrHost          = &Error{Code: CodeHost}
	ErrWindow        = &Error{Code: CodeWindow}
	ErrScopeMismatch = &Error{Code: CodeScopeMismatch}
)

// Class is the operation class of the dependent effect.
type Class string

const (
	// ClassStart covers effects that begin or extend work. The window applies.
	ClassStart Class = "start"
	// ClassEnd covers effects that only end work. The comparison with Now is
	// skipped; every other check still applies.
	ClassEnd Class = "end"
)

// Consumer names the caller's own section of the statement.
type Consumer string

const (
	Keymaker   Consumer = "keymaker"
	Dispatcher Consumer = "dispatcher"
	Source     Consumer = "source"
	BrokerTime Consumer = "broker_time"
	BrokerD5   Consumer = "broker_d5"
)

// Inputs are supplied in full by the caller. The two pins and the expected
// bytes come from the caller's protected install, never from the statement.
// An all-zero pin, an all-zero machine-id digest and a zero Now refuse.
type Inputs struct {
	// ApproverKey is the pinned x-only BIP-340 approver key.
	ApproverKey [32]byte
	// StatementDigest is the pinned SHA-256 of the preimage of the one
	// statement in use.
	StatementDigest [32]byte
	// MachineIDSHA256 is SHA-256 of this host's machine-id file content.
	MachineIDSHA256 [32]byte
	// Now is the host clock reading. It is compared for ClassStart only.
	Now time.Time
	// Class is ClassStart or ClassEnd; any other value refuses.
	Class Class
	// Consumer selects the one section that is compared.
	Consumer Consumer
	// Section is the expected CCJ-1 bytes of the consumer's own section.
	Section []byte
	// Association is the expected CCJ-1 bytes of the association member. It
	// is required for Keymaker and Dispatcher and compared whenever present.
	Association []byte
}

// Statement is returned only when every check passed. It carries audit values
// only; it grants nothing by itself and exposes no section content.
type Statement struct {
	// GateID is for audit journaling only.
	GateID        string
	HostLabel     string
	ApproverLabel string
	NotBefore     time.Time
	NotAfter      time.Time
	// Digest is SHA-256 of the preimage, equal to the pinned digest.
	Digest   [32]byte
	Consumer Consumer
	Class    Class
}

// Verify applies the consumer rule to the exact statement bytes raw and the
// wire signature sig (128 lowercase hex characters, nothing else). It returns
// the zero Statement with an *Error on any refusal.
func Verify(raw []byte, sig []byte, in Inputs) (Statement, error) {
	return engine{parse: strictParse}.verify(raw, sig, in)
}

// member is one row of the closed member table. Adding or dropping one closed
// section is one row here plus its vectors.
type member struct {
	name string
	// shape checks a present non-section member; nil for sections.
	shape func(any) bool
	// section marks an opaque owner section that is also a consumer name.
	section bool
	// association marks a consumer that must supply the expected association.
	association bool
}

var members = []member{
	{name: "v", shape: func(v any) bool { n, ok := v.(int64); return ok && n == 1 }},
	{name: "kind", shape: func(v any) bool { return v == any(Tag) }},
	{name: "milestone", shape: func(v any) bool { return v == any(Milestone) }},
	{name: "gate_id", shape: func(v any) bool { return isHex(v, 32) }},
	{name: "host", shape: hostShape},
	{name: "not_before", shape: timeShape},
	{name: "not_after", shape: timeShape},
	{name: "approver", shape: approverShape},
	{name: "association", shape: associationShape},
	{name: "keymaker", section: true, association: true},
	{name: "dispatcher", section: true, association: true},
	{name: "source", section: true},
	{name: "broker_time", section: true},
	{name: "broker_d5", section: true},
}

// check names one removable check. The names are also the Error detail text.
type check string

const (
	ckSize        check = "size"
	ckCodec       check = "codec"
	ckKey         check = "key"
	ckPin         check = "pin"
	ckCanonical   check = "canonical"
	ckDepth       check = "depth"
	ckMembers     check = "members"
	ckFixed       check = "fixed"
	ckShape       check = "shape"
	ckSignature   check = "signature"
	ckHost        check = "host"
	ckClass       check = "class"
	ckWindowWidth check = "window_width"
	ckWindowNow   check = "window_now"
	ckSection     check = "section"
	ckAssociation check = "association"
)

// engine exists so the package tests can prove that each check is the one
// that refuses its negative. Verify always runs with nothing switched off and
// with the strict registrar codec; nothing exported reaches these fields.
type engine struct {
	off   map[check]bool
	parse func([]byte) (any, error)
}

func strictParse(raw []byte) (any, error) { return ccj.Parse(raw, ccj.RegistrationMalformed) }

func refuse(code Code, c check) (Statement, error) {
	return Statement{}, &Error{Code: code, check: string(c)}
}

func (e engine) verify(raw, sig []byte, in Inputs) (Statement, error) {
	on := func(c check) bool { return !e.off[c] }

	// Reading approver.key needs a bounded parse. Bytes that are too long or
	// that the codec refuses (duplicate names, non-integer numbers, invalid
	// UTF-8, codec depth) are a form refusal before any other step.
	if on(ckSize) && len(Tag)+1+len(raw) > MaxPreimage {
		return refuse(CodeForm, ckSize)
	}
	value, err := e.parse(raw)
	if err != nil {
		return refuse(CodeForm, ckCodec)
	}
	g, ok := value.(map[string]any)
	if !ok {
		return refuse(CodeForm, ckCodec)
	}

	// Step 1: the two pins. The key is compared before the digest.
	approver := object(g, "approver")
	if on(ckKey) {
		key, _ := approver["key"].(string)
		if in.ApproverKey == ([32]byte{}) || key != hex.EncodeToString(in.ApproverKey[:]) {
			return refuse(CodeKey, ckKey)
		}
	}
	digest := Digest(raw)
	if on(ckPin) && (in.StatementDigest == ([32]byte{}) || digest != in.StatementDigest) {
		return refuse(CodePin, ckPin)
	}

	// Step 2: canonical form, closed members, exact fixed values and shapes.
	if on(ckCanonical) {
		again, err := ccj.Marshal(value, ccj.RegistrationMalformed)
		if err != nil || !bytes.Equal(again, raw) {
			return refuse(CodeForm, ckCanonical)
		}
	}
	if on(ckDepth) && depth(value) > MaxDepth {
		return refuse(CodeForm, ckDepth)
	}
	if on(ckMembers) {
		if len(g) != len(members) {
			return refuse(CodeForm, ckMembers)
		}
		for _, m := range members {
			if _, ok := g[m.name]; !ok {
				return refuse(CodeForm, ckMembers)
			}
		}
	}
	for _, m := range members {
		v, present := g[m.name]
		if !present {
			continue // absence belongs to the members check
		}
		switch m.name {
		case "v", "kind", "milestone":
			if on(ckFixed) && !m.shape(v) {
				return refuse(CodeForm, ckFixed)
			}
		default:
			if !on(ckShape) {
				continue
			}
			if m.section {
				// Sections are opaque: a non-empty object, nothing more.
				if o, ok := v.(map[string]any); !ok || len(o) == 0 {
					return refuse(CodeForm, ckShape)
				}
			} else if !m.shape(v) {
				return refuse(CodeForm, ckShape)
			}
		}
	}

	// Step 3: BIP-340 over SHA-256(preimage) under the pinned key.
	if on(ckSignature) && !signatureValid(sig, digest, in.ApproverKey) {
		return refuse(CodeSignature, ckSignature)
	}

	// Step 4: this host.
	host := object(g, "host")
	if on(ckHost) {
		id, _ := host["machine_id_sha256"].(string)
		if in.MachineIDSHA256 == ([32]byte{}) || id != hex.EncodeToString(in.MachineIDSHA256[:]) {
			return refuse(CodeHost, ckHost)
		}
	}

	// Step 5: the window. Its width is a property of the statement and is
	// checked for both classes; the comparison with Now is ClassStart only.
	if on(ckClass) && in.Class != ClassStart && in.Class != ClassEnd {
		return refuse(CodeWindow, ckClass)
	}
	notBefore, okBefore := parseTime(g["not_before"])
	notAfter, okAfter := parseTime(g["not_after"])
	if on(ckWindowWidth) && (!okBefore || !okAfter || !notBefore.Before(notAfter) || notAfter.Sub(notBefore) > MaxWindow) {
		return refuse(CodeWindow, ckWindowWidth)
	}
	if on(ckWindowNow) && in.Class != ClassEnd {
		if !okBefore || !okAfter || in.Now.IsZero() || in.Now.Before(notBefore) || !in.Now.Before(notAfter) {
			return refuse(CodeWindow, ckWindowNow)
		}
	}

	// Step 6: exact bytes of the consumer's own section and the association.
	var row *member
	for i := range members {
		if members[i].section && members[i].name == string(in.Consumer) {
			row = &members[i]
		}
	}
	if on(ckSection) {
		if row == nil || len(in.Section) == 0 || !sameBytes(g[string(in.Consumer)], in.Section) {
			return refuse(CodeScopeMismatch, ckSection)
		}
	}
	consumes := len(in.Association) > 0
	if on(ckAssociation) {
		if row != nil && row.association && !consumes {
			return refuse(CodeScopeMismatch, ckAssociation)
		}
		if consumes && !sameBytes(g["association"], in.Association) {
			return refuse(CodeScopeMismatch, ckAssociation)
		}
	}

	out := Statement{
		NotBefore: notBefore, NotAfter: notAfter, Digest: digest,
		Consumer: in.Consumer, Class: in.Class,
	}
	out.GateID, _ = g["gate_id"].(string)
	out.HostLabel, _ = host["label"].(string)
	out.ApproverLabel, _ = approver["label"].(string)
	return out, nil
}

// Digest returns SHA-256(ASCII(Tag) || 0x0a || raw): the value that is signed
// and the value an installer pins. It does not validate raw.
func Digest(raw []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(Tag))
	h.Write([]byte{0x0a})
	h.Write(raw)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func signatureValid(wire []byte, digest, key [32]byte) bool {
	if len(wire) != 2*schnorr.SignatureSize || !lowerHex(string(wire)) {
		return false
	}
	raw := make([]byte, schnorr.SignatureSize)
	if _, err := hex.Decode(raw, wire); err != nil {
		return false
	}
	public, err := schnorr.ParsePubKey(key[:])
	if err != nil {
		return false
	}
	signature, err := schnorr.ParseSignature(raw)
	if err != nil {
		return false
	}
	return signature.Verify(digest[:], public)
}

func sameBytes(v any, expected []byte) bool {
	if v == nil {
		return false
	}
	got, err := ccj.Marshal(v, ccj.RegistrationMalformed)
	return err == nil && bytes.Equal(got, expected)
}

func object(parent map[string]any, name string) map[string]any {
	o, _ := parent[name].(map[string]any)
	return o
}

func depth(v any) int {
	deepest := 0
	switch x := v.(type) {
	case map[string]any:
		for _, child := range x {
			deepest = max(deepest, depth(child))
		}
	case []any:
		for _, child := range x {
			deepest = max(deepest, depth(child))
		}
	default:
		return 0
	}
	return deepest + 1
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isHex(v any, digits int) bool {
	s, ok := v.(string)
	return ok && len(s) == digits && lowerHex(s)
}

func nonEmpty(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

func closed(v any, names ...string) (map[string]any, bool) {
	o, ok := v.(map[string]any)
	if !ok || len(o) != len(names) {
		return nil, false
	}
	for _, name := range names {
		if _, ok := o[name]; !ok {
			return nil, false
		}
	}
	return o, true
}

func hostShape(v any) bool {
	o, ok := closed(v, "label", "machine_id_sha256")
	return ok && nonEmpty(o["label"]) && isHex(o["machine_id_sha256"], 64)
}

func approverShape(v any) bool {
	o, ok := closed(v, "alg", "key", "label")
	return ok && o["alg"] == any("bip340") && isHex(o["key"], 64) && nonEmpty(o["label"])
}

func associationShape(v any) bool {
	o, ok := closed(v, "caller_generation", "caller_key", "caller_uid")
	if !ok || !nonEmpty(o["caller_generation"]) || !ed25519Key(o["caller_key"]) {
		return false
	}
	uid, ok := o["caller_uid"].(int64)
	return ok && uid >= 0 && uid <= 1<<32-1
}

// ed25519Key accepts exactly "ed25519:" plus the canonical unpadded base64url
// spelling of 32 bytes. The bytes are not checked as a curve point.
func ed25519Key(v any) bool {
	const prefix = "ed25519:"
	s, ok := v.(string)
	if !ok || len(s) != len(prefix)+43 || s[:len(prefix)] != prefix {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s[len(prefix):])
	return err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == s[len(prefix):]
}

const timeLayout = "2006-01-02T15:04:05Z"

func timeShape(v any) bool {
	_, ok := parseTime(v)
	return ok
}

// parseTime accepts exactly YYYY-MM-DDTHH:MM:SSZ with a real calendar date.
func parseTime(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok || len(s) != len(timeLayout) {
		return time.Time{}, false
	}
	t, err := time.Parse(timeLayout, s)
	if err != nil || t.Format(timeLayout) != s {
		return time.Time{}, false
	}
	return t, true
}
