package messageauthorcompat_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keymaker/internal/control"
	"github.com/relux-works/swarma-keymaker/messageauthor"
)

type bodyCase struct {
	Name  string
	Body  []byte
	Valid bool
}
type construction struct {
	Kind  string
	Value int64
	Data  []byte
}
type objectCase struct {
	Name   string
	Object construction
	Valid  bool
}
type probeInput struct {
	Bodies  [][]byte
	Objects []construction
}
type verdict struct {
	Accepted     bool
	Error        string
	Bytes        []byte
	MarshalError string
}
type probeOutput struct {
	Bodies  []verdict
	Objects []verdict
}

func diagnostic(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
func repository(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func wireVectors(t *testing.T) []struct{ Name, Kind, Body, Error string } {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repository(t), "messageauthor/testdata/wire-v1/vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Name, Kind, Body, Error string }
	if json.Unmarshal(raw, &rows) != nil || len(rows) == 0 {
		t.Fatal("wire corpus unavailable")
	}
	return rows
}

// Claim: the literal wire-v1 requests/replies keep their exact bytes and typed
// refusals through the root's replaced module on the root Go toolchain. The
// schema-invalid vectors are valid CCJ objects, not canonical-decoder negatives.
func TestMessageAuthorRootWireVectors(t *testing.T) {
	for _, v := range wireVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			frame := make([]byte, 4+len(v.Body))
			binary.BigEndian.PutUint32(frame, uint32(len(v.Body)))
			copy(frame[4:], v.Body)
			var got []byte
			var err error
			if v.Kind == "request" {
				q, e := messageauthor.DecodeRequestFrame(frame)
				err = e
				if e == nil {
					got, err = messageauthor.EncodeRequestFrame(q)
				} else if !reflect.DeepEqual(q, messageauthor.Request{}) {
					t.Fatal("partial rejected request")
				}
			} else {
				q := messageauthor.Request{ID: "0123456789abcdef0123456789abcdef", TimeoutMS: 2000, Method: messageauthor.SignMethod, Preimage: []byte("fixture")}
				if v.Kind == "identity" {
					q.Method = messageauthor.IdentityMethod
					q.Preimage = nil
				}
				r, e := messageauthor.DecodeResponseFrame(q, frame)
				err = e
				if e == nil {
					got, err = messageauthor.EncodeResponseFrame(q, r)
				} else if !reflect.DeepEqual(r, messageauthor.Response{}) {
					t.Fatal("partial rejected response")
				}
			}
			if v.Error != "" {
				want := messageauthor.ErrResponse
				if v.Error == "ErrRequest" {
					want = messageauthor.ErrRequest
				} else if v.Error != "ErrResponse" {
					t.Fatal("unknown vector verdict")
				}
				if err != want || got != nil {
					t.Fatalf("wrong refusal: %v, want %v", err, want)
				}
			} else if err != nil || !bytes.Equal(got, frame) {
				t.Fatalf("wire bytes changed: %v", err)
			}
		})
	}
}

// Read the existing canonical-codec negative table verbatim, so adding a native
// negative or changing its paired valid control also exercises the nested copy.
func codecNegatives(t *testing.T) []bodyCase {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repository(t), "internal/control/codec_test.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []bodyCase
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "TestCCJNegativeControls" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			c, ok := n.(*ast.CompositeLit)
			if !ok || len(c.Elts) != 3 {
				return true
			}
			values := []string{}
			for _, e := range c.Elts {
				v, ok := e.(*ast.BasicLit)
				if !ok || v.Kind != token.STRING {
					return true
				}
				s, err := strconv.Unquote(v.Value)
				if err != nil {
					t.Fatal(err)
				}
				values = append(values, s)
			}
			out = append(out, bodyCase{"native/" + values[0] + "/bad", []byte(values[1]), false}, bodyCase{"native/" + values[0] + "/good", []byte(values[2]), true})
			return false
		})
	}
	if len(out) < 70 {
		t.Fatal("native negative/control table was not read")
	}
	return out
}
func corpus(t *testing.T) ([]bodyCase, []objectCase) {
	bodies := codecNegatives(t)
	for _, v := range wireVectors(t) {
		bodies = append(bodies, bodyCase{"wire/" + v.Name, []byte(v.Body), true})
	}
	// These are the public wire codec's canonical-negative spellings, including
	// malformed UTF-8 as bytes; schema-only refusals remain canonical positives.
	for i, s := range []string{" {}", `{"a":0,"a":1}`, `{"b":0,"a":1}`, `{"a":-0}`, `{"a":1.0}`, `{"a":"\u0061"}`, `{"a":"\/"}`, `{"a":9007199254740992}`, strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17), "{\"a\":\"\xff\"}"} {
		bodies = append(bodies, bodyCase{fmt.Sprintf("wire-negative/%d", i), []byte(s), false})
	}
	objects := []objectCase{}
	for _, n := range []int{65536, 65537} {
		body := `{"a":"` + strings.Repeat("x", n-8) + `"}`
		bodies = append(bodies, bodyCase{fmt.Sprintf("size/%d", n), []byte(body), n == 65536})
		objects = append(objects, objectCase{fmt.Sprintf("size/%d", n), construction{Kind: "string", Data: []byte(strings.Repeat("x", n-8))}, n == 65536})
	}
	for _, n := range []int{16, 17} {
		body := `{"a":` + strings.Repeat("[", n-1) + "0" + strings.Repeat("]", n-1) + "}"
		bodies = append(bodies, bodyCase{fmt.Sprintf("depth/%d", n), []byte(body), n == 16})
		objects = append(objects, objectCase{fmt.Sprintf("depth/%d", n), construction{Kind: "depth", Value: int64(n)}, n == 16})
	}
	for i, s := range []string{"", "{", "{} ", "{}{}", "{}\n", `{"a":1e0}`, `{"a":01}`, `{"a":+1}`, `{"a":true,"a":false}`} {
		bodies = append(bodies, bodyCase{fmt.Sprintf("extra-negative/%d", i), []byte(s), false})
	}
	// Deterministic generated pairs: one canonical object and one forbidden
	// duplicate/trailing/number spelling. Expected verdicts do not come from either codec.
	for i := 0; i < 128; i++ {
		good := fmt.Sprintf(`{"a":%d,"b":[true,null,"é😀"]}`, i)
		bodies = append(bodies, bodyCase{fmt.Sprintf("generated/%d/good", i), []byte(good), true}, bodyCase{fmt.Sprintf("generated/%d/bad", i), []byte(good + " "), false})
	}
	for _, n := range []int64{-9007199254740992, -9007199254740991, -1, 0, 1, 9007199254740991, 9007199254740992} {
		objects = append(objects, objectCase{fmt.Sprintf("integer/%d", n), construction{Kind: "integer", Value: n}, n >= -9007199254740991 && n <= 9007199254740991})
	}
	for _, c := range []construction{{Kind: "unsigned", Value: -1}, {Kind: "float", Value: 1}, {Kind: "unsupported"}, {Kind: "invalid-key"}, {Kind: "cycle"}, {Kind: "string", Data: []byte{0xff}}} {
		objects = append(objects, objectCase{c.Kind, c, false})
	}
	for i, s := range []string{"", "é", "e\u0301", "😀", "\"\\\b\f\n\r\t\x00\x1f", "/<>&\u2028"} {
		objects = append(objects, objectCase{fmt.Sprintf("string/%d", i), construction{Kind: "string", Data: []byte(s)}, true})
	}
	return bodies, objects
}
func nativeObject(c construction) control.Object {
	switch c.Kind {
	case "string":
		return control.Object{"a": string(c.Data)}
	case "depth":
		var v any = int64(0)
		for i := int64(1); i < c.Value; i++ {
			v = []any{v}
		}
		return control.Object{"a": v}
	case "integer":
		return control.Object{"a": c.Value}
	case "unsigned":
		return control.Object{"a": uint64(c.Value)}
	case "float":
		return control.Object{"a": float64(c.Value)}
	case "unsupported":
		return control.Object{"a": []byte("bytes")}
	case "invalid-key":
		return control.Object{string([]byte{0xff}): true}
	case "cycle":
		o := control.Object{}
		o["a"] = o
		return o
	}
	panic("unknown test construction")
}
func runProbe(t *testing.T, in probeInput) probeOutput {
	t.Helper()
	fixture := t.TempDir()
	nested := filepath.Join(repository(t), "messageauthor")
	mod := "module github.com/relux-works/swarma-keymaker/messageauthor/compatprobe\n\ngo 1.26.10\n\nrequire github.com/relux-works/swarma-keymaker/messageauthor v0.0.0\n\nreplace github.com/relux-works/swarma-keymaker/messageauthor => " + strconv.Quote(nested) + "\n"
	raw, err := os.ReadFile("testdata/probe/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(filepath.Join(fixture, "go.mod"), []byte(mod), 0600) != nil || os.WriteFile(filepath.Join(fixture, "main.go"), raw, 0600) != nil {
		t.Fatal("probe fixture write")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	binary := filepath.Join(fixture, "probe")
	cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-mod=readonly", "-o", binary, ".")
	cmd.Dir = fixture
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("probe build: %v\n%s", err, output)
	}
	request, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	cmd = exec.CommandContext(ctx, binary)
	cmd.Dir = fixture
	cmd.Stdin = bytes.NewReader(request)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("probe execution: %v\n%s", err, &stderr)
	}
	var result probeOutput
	if json.Unmarshal(out.Bytes(), &result) != nil {
		t.Fatal("probe result grammar")
	}
	return result
}

// Claim: the actual nested copy and daemon CCJ codec give the same exact bytes,
// refusals and nil outputs for the vector/negative/generated corpus. Explicit
// boundary and valid controls also reject two equally wrong implementations.
func TestMessageAuthorFrameEquality(t *testing.T) {
	bodies, objects := corpus(t)
	input := probeInput{}
	for _, c := range bodies {
		input.Bodies = append(input.Bodies, c.Body)
	}
	for _, c := range objects {
		input.Objects = append(input.Objects, c.Object)
	}
	got := runProbe(t, input)
	if len(got.Bodies) != len(bodies) || len(got.Objects) != len(objects) {
		t.Fatal("probe case count")
	}
	for i, c := range bodies {
		t.Run("decode/"+c.Name, func(t *testing.T) {
			obj, err := control.Decode(c.Body)
			want := verdict{Accepted: err == nil, Error: diagnostic(err)}
			if err == nil {
				b, e := control.Marshal(obj)
				want.Bytes, want.MarshalError = b, diagnostic(e)
			} else if obj != nil {
				t.Fatal("native partial rejection")
			}
			if want.Accepted != c.Valid {
				t.Fatal("native verdict disagrees with independent corpus")
			}
			if !reflect.DeepEqual(got.Bodies[i], want) {
				t.Fatalf("frame drift: nested accepted=%v error=%q, native accepted=%v error=%q", got.Bodies[i].Accepted, got.Bodies[i].Error, want.Accepted, want.Error)
			}
			if c.Valid && !bytes.Equal(want.Bytes, c.Body) {
				t.Fatal("canonical bytes changed")
			}
		})
	}
	for i, c := range objects {
		t.Run("marshal/"+c.Name, func(t *testing.T) {
			b, err := control.Marshal(nativeObject(c.Object))
			want := verdict{Accepted: err == nil, Error: diagnostic(err), Bytes: b}
			if want.Accepted != c.Valid || err != nil && b != nil {
				t.Fatal("native encoder disagrees with independent corpus")
			}
			if !reflect.DeepEqual(got.Objects[i], want) {
				t.Fatalf("frame drift on encoder: nested accepted=%v error=%q, native accepted=%v error=%q", got.Objects[i].Accepted, got.Objects[i].Error, want.Accepted, want.Error)
			}
		})
	}
}
