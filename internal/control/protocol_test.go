package control

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

type capReader struct {
	header            [4]byte
	offset, bodyBytes int
}

func (r *capReader) Read(p []byte) (int, error) {
	if r.offset < 4 {
		n := copy(p, r.header[r.offset:])
		r.offset += n
		return n, nil
	}
	// A virtual body avoids constructing attacker-selected body storage in tests.
	for i := range p {
		p[i] = 'x'
	}
	r.bodyBytes += len(p)
	return len(p), nil
}

// The first over-cap header consumes only four bytes and no body allocation;
// the adjacent maximum-size frame remains accepted. Allocation count is bounded
// to the escaping four-byte header, not an attacker-sized backing array.
func TestFrameCapBeforeBodyRead(t *testing.T) {
	r := &capReader{}
	binary.BigEndian.PutUint32(r.header[:], MaxFrame+1)
	allocations := testing.AllocsPerRun(10, func() {
		r.offset = 0
		r.bodyBytes = 0
		body, code := readFrame(r)
		if code != FrameTooLarge || body != nil || r.offset != 4 || r.bodyBytes != 0 {
			t.Fatalf("code=%s body=%d header=%d body-read=%d", code, len(body), r.offset, r.bodyBytes)
		}
	})
	if allocations > 1 {
		t.Fatalf("over-cap allocated %.0f times; at most header allocation allowed", allocations)
	}
	r.offset = 0
	r.bodyBytes = 0
	binary.BigEndian.PutUint32(r.header[:], MaxFrame)
	b, code := readFrame(r)
	if code != "" || len(b) != MaxFrame || r.bodyBytes != MaxFrame {
		t.Fatalf("cap control: %s len=%d read=%d", code, len(b), r.bodyBytes)
	}
}

// Even a uint32-maximum advertised body is refused without a single body read.
func TestFrameHugeHeaderNoBody(t *testing.T) {
	r := &capReader{}
	binary.BigEndian.PutUint32(r.header[:], ^uint32(0))
	if _, code := readFrame(r); code != FrameTooLarge || r.bodyBytes != 0 {
		t.Fatalf("%s body=%d", code, r.bodyBytes)
	}
}

type timeoutReader struct{}

func (timeoutReader) Read([]byte) (int, error) { return 0, timeoutError{} }

type timeoutError struct{}

func (timeoutError) Error() string   { return "test timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// Partial-header and partial-body EOF are truncation; a read timeout is a
// deadline, while clean EOF, zero length and a complete frame remain distinct.
func TestFrameReadFailures(t *testing.T) {
	good := packet([]byte(`{}`))
	for n := 1; n < len(good); n++ {
		_, code := readFrame(bytes.NewReader(good[:n]))
		if code != FrameTruncated {
			t.Fatalf("prefix %d: %s", n, code)
		}
	}
	if b, c := readFrame(bytes.NewReader(nil)); b != nil || c != "" {
		t.Fatalf("clean EOF: %q %s", b, c)
	}
	if _, c := readFrame(bytes.NewReader(make([]byte, 4))); c != FrameMalformed {
		t.Fatal(c)
	}
	if _, c := readFrame(timeoutReader{}); c != DeadlineExceeded {
		t.Fatal(c)
	}
	if _, c := readFrame(io.MultiReader(bytes.NewReader(good[:5]), timeoutReader{})); c != DeadlineExceeded {
		t.Fatal(c)
	}
	if b, c := readFrame(bytes.NewReader(good)); string(b) != "{}" || c != "" {
		t.Fatalf("control: %q %s", b, c)
	}
}

func packet(body []byte) []byte {
	b := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(b, uint32(len(body)))
	copy(b[4:], body)
	return b
}

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return w.Buffer.Write(p)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

// Response framing handles short writes and refuses unsupported/oversize
// output before any bytes are emitted; a zero-progress writer fails promptly.
func TestFrameWriter(t *testing.T) {
	w := &shortWriter{}
	obj := Object{"a": int64(1)}
	if err := writeFrame(w, obj); err != nil {
		t.Fatal(err)
	}
	if b, c := readFrame(bytes.NewReader(w.Bytes())); string(b) != `{"a":1}` || c != "" {
		t.Fatalf("%q %s", b, c)
	}
	w.Reset()
	if err := writeFrame(w, Object{"bad": 1.5}); err == nil || w.Len() != 0 {
		t.Fatal("invalid output written")
	}
	if err := writeFrame(w, Object{"large": strings.Repeat("x", MaxFrame)}); err == nil || w.Len() != 0 {
		t.Fatal("oversize output written")
	}
	if err := writeAll(zeroWriter{}, []byte{1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
}
