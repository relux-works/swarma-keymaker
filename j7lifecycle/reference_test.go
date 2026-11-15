package j7lifecycle_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	wire "github.com/relux-works/swarma-keymaker/j7lifecycle"
)

// This test-only reference uses the standard JSON reader and its own canonical
// emitter. It calls neither production codec. Literal vectors define semantic
// expectations independently of encoder/decoder round trips.
func referenceBody(body []byte) (any, error) {
	if len(body) == 0 || len(body) > 65536 || !utf8.Valid(body) {
		return nil, fmt.Errorf("body bounds")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var value any
	if e := d.Decode(&value); e != nil {
		return nil, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, fmt.Errorf("not object")
	}
	out, e := referenceCanonical(value, 0)
	if e != nil || !bytes.Equal(body, out) {
		return nil, fmt.Errorf("noncanonical reference")
	}
	return value, nil
}
func referenceCanonical(value any, depth int) ([]byte, error) {
	switch v := value.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		return []byte(strconv.FormatBool(v)), nil
	case json.Number:
		n, e := strconv.ParseInt(string(v), 10, 64)
		if e != nil || n < -9007199254740991 || n > 9007199254740991 || strconv.FormatInt(n, 10) != string(v) {
			return nil, fmt.Errorf("integer")
		}
		return []byte(v), nil
	case string:
		if !utf8.ValidString(v) {
			return nil, fmt.Errorf("utf8")
		}
		out := []byte{'"'}
		for _, c := range v {
			switch c {
			case '"', '\\':
				out = append(out, '\\', byte(c))
			case '\b':
				out = append(out, `\b`...)
			case '\t':
				out = append(out, `\t`...)
			case '\n':
				out = append(out, `\n`...)
			case '\f':
				out = append(out, `\f`...)
			case '\r':
				out = append(out, `\r`...)
			default:
				if c < 32 {
					out = append(out, fmt.Sprintf(`\u%04x`, c)...)
				} else {
					out = utf8.AppendRune(out, c)
				}
			}
		}
		return append(out, '"'), nil
	case []any:
		if depth >= 16 {
			return nil, fmt.Errorf("depth")
		}
		out := []byte{'['}
		for i, x := range v {
			if i > 0 {
				out = append(out, ',')
			}
			b, e := referenceCanonical(x, depth+1)
			if e != nil {
				return nil, e
			}
			out = append(out, b...)
		}
		return append(out, ']'), nil
	case map[string]any:
		if depth >= 16 {
			return nil, fmt.Errorf("depth")
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				out = append(out, ',')
			}
			key, _ := referenceCanonical(k, depth+1)
			out = append(out, key...)
			out = append(out, ':')
			b, e := referenceCanonical(v[k], depth+1)
			if e != nil {
				return nil, e
			}
			out = append(out, b...)
		}
		return append(out, '}'), nil
	}
	return nil, fmt.Errorf("reference type")
}

type vectorCase struct {
	Name      string `json:"name"`
	Direction string `json:"direction"`
	Context   string `json:"context"`
	Body      string `json:"body"`
	FrameHex  string `json:"frame_hex"`
	Verdict   string `json:"verdict"`
	Error     string `json:"error"`
}
type vectorSet struct {
	Format string       `json:"format"`
	Cases  []vectorCase `json:"cases"`
}
type corpusManifest struct {
	Format            string `json:"format"`
	CompatibilityBase string `json:"compatibility_base"`
	InspectedBase     string `json:"inspected_base"`
	Payload           string `json:"payload"`
	Bytes             int    `json:"bytes"`
	SHA256            string `json:"sha256"`
	Limits            string `json:"limits"`
}

func strictFixture(t *testing.T, b []byte, v any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		t.Fatal(e)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		t.Fatal("fixture trailing data")
	}
}

// Manifest hashes bind a literal public corpus to existing compatibility pins,
// never to the candidate's own eventual commit or to a circular self-hash.
func TestLifecycleWireReference(t *testing.T) {
	meta, e := os.ReadFile("testdata/wire-v1/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	var m corpusManifest
	strictFixture(t, meta, &m)
	if m.Format != "keymaker-j7-lifecycle-wire/1" || m.CompatibilityBase != "2e207dc53526a236cb198d94a9a09b50564cad61" || m.InspectedBase != "dee83bdee21617ac11e2178f85d529b17395ef0b" || m.Payload != "vectors.json" || m.Limits == "" {
		t.Fatal("manifest contract")
	}
	data, e := os.ReadFile("testdata/wire-v1/" + m.Payload)
	if e != nil {
		t.Fatal(e)
	}
	if len(data) != m.Bytes || fmt.Sprintf("%x", sha256.Sum256(data)) != m.SHA256 {
		t.Fatal("fixture hash mismatch")
	}
	var set vectorSet
	strictFixture(t, data, &set)
	if set.Format != m.Format || len(set.Cases) < 12 {
		t.Fatal("corpus identity")
	}
	seen := map[string]bool{}
	for _, c := range set.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if c.Name == "" || seen[c.Name] {
				t.Fatal("duplicate/empty vector name")
			}
			seen[c.Name] = true
			frame, e := hex.DecodeString(c.FrameHex)
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(frame, literalFrame(c.Body)) {
				t.Fatal("literal header/body differs")
			}
			q := requestFor(c.Context)
			if c.Verdict == "accept" {
				if _, e := referenceBody([]byte(c.Body)); e != nil {
					t.Fatal("valid independent reference", e)
				}
				if c.Error != "" {
					t.Fatal("positive error annotation")
				}
				switch c.Direction {
				case "request":
					got, e := wire.DecodeRequestFrame(frame)
					if e != nil {
						t.Fatal(e)
					}
					encoded, e := wire.EncodeRequestFrame(got)
					if e != nil || !bytes.Equal(encoded, frame) {
						t.Fatal("literal request mismatch", e)
					}
					// Check independently constructed complete fields, not just roundtrip.
					if !requestsEqual(got, q) {
						t.Fatal("reference request fields differ")
					}
				case "response":
					got, e := wire.DecodeResponseFrame(q, frame)
					if e != nil {
						t.Fatal(e)
					}
					encoded, e := wire.EncodeResponseFrame(q, got)
					if e != nil || !bytes.Equal(encoded, frame) {
						t.Fatal("literal response mismatch", e)
					}
					// Check decoded values against an independent literal JSON read,
					// not only against the candidate's re-encoder.
					var oracle struct {
						ID     *string `json:"request_id"`
						Result *struct {
							Version *int64 `json:"version"`
							RunID   string `json:"run_id"`
							State   string `json:"state"`
						} `json:"result"`
						Error *struct {
							Code      string `json:"code"`
							Retryable bool   `json:"retryable"`
						} `json:"error"`
					}
					if e := json.Unmarshal([]byte(c.Body), &oracle); e != nil {
						t.Fatal(e)
					}
					id := ""
					if oracle.ID != nil {
						id = *oracle.ID
					}
					if got.ID != id {
						t.Fatal("literal response ID differs")
					}
					if oracle.Error != nil {
						if got.Refusal == nil || got.Refusal.Code != oracle.Error.Code || got.Refusal.Retryable != oracle.Error.Retryable || got.Run != nil || got.Version != nil {
							t.Fatal("literal refusal differs")
						}
					} else if oracle.Result.Version != nil {
						if got.Version == nil || *got.Version != *oracle.Result.Version || got.Run != nil || got.Refusal != nil {
							t.Fatal("literal hello differs")
						}
					} else if got.Run == nil || got.Run.RunID != oracle.Result.RunID || got.Run.State != oracle.Result.State || got.Version != nil || got.Refusal != nil {
						t.Fatal("literal run result differs")
					}
				default:
					t.Fatal("vector direction")
				}
			} else if c.Verdict == "reject" {
				errs := map[string]error{"request": wire.ErrRequest, "response": wire.ErrResponse, "canonical": wire.ErrCanonical}
				want := errs[c.Error]
				if want == nil {
					t.Fatal("unknown error annotation")
				}
				if c.Error == "canonical" {
					if _, e := referenceBody([]byte(c.Body)); e == nil {
						t.Fatal("reference accepted malformed canonical vector")
					}
				} else if _, e := referenceBody([]byte(c.Body)); e != nil {
					t.Fatal("semantic vector has unrelated grammar failure", e)
				}
				switch c.Direction {
				case "request":
					rejectRequest(t, frame, want)
				case "response":
					rejectResponse(t, q, frame, want)
				default:
					t.Fatal("vector direction")
				}
			} else {
				t.Fatal("unknown verdict")
			}
		})
	}
}
func requestsEqual(a, b wire.Request) bool {
	// JSON here compares exported inert fields only; it is not wire encoding.
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// The independent instrument detects an intentionally noncanonical plant, with
// a valid literal control. Semantic rejection is a separate vector obligation.
func TestLifecycleReferenceControl(t *testing.T) {
	good := `{"a":"<é/","b":[1,true,null]}`
	if _, e := referenceBody([]byte(good)); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{" " + good, `{"a":1,"a":1}`, `{"a":1.0}`, `{"a":"\u00e9"}`, `{"a":"\ud800"}`, `{"a":-0}`, `{"a":9007199254740992}`, `{"a":` + strings.Repeat("[", 16) + `0` + strings.Repeat("]", 16) + `}`} {
		if _, e := referenceBody([]byte(bad)); e == nil {
			t.Fatal("reference plant survived", bad)
		}
	}
	// Four-byte framing oracle is independent of the production frame functions.
	f := literalFrame(good)
	if int(binary.BigEndian.Uint32(f[:4])) != len(good) {
		t.Fatal("reference length")
	}
}
