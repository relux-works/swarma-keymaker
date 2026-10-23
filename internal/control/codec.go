// Package control implements the native control transport. It supplies no key
// custody, peer-credential implementation, generation authority or durable state.
package control

import (
	"bytes"
	"errors"
	"sort"
	"strconv"
	"unicode/utf8"
)

const MaxFrame = 65536
const MaxDepth = 16
const MaxInteger int64 = 9007199254740991

// Object values use nil, bool, string, int64, []any and Object recursively.
// Marshal also accepts ordinary signed and unsigned Go integer types in range.
type Object = map[string]any

var errCanonical = errors.New("noncanonical CCJ-1 object")

// Decode accepts canonical CCJ-1 objects only, with at most sixteen nested
// containers. It never repairs UTF-8, escapes, number spellings or key order.
func Decode(data []byte) (Object, error) {
	if len(data) == 0 || len(data) > MaxFrame || !utf8.Valid(data) {
		return nil, errCanonical
	}
	p := parser{data: data}
	v, err := p.value(0)
	if err != nil || p.i != len(data) {
		return nil, errCanonical
	}
	obj, ok := v.(Object)
	if !ok {
		return nil, errCanonical
	}
	return obj, nil
}

type parser struct {
	data []byte
	i    int
}

func (p *parser) value(depth int) (any, error) {
	if p.i == len(p.data) {
		return nil, errCanonical
	}
	switch p.data[p.i] {
	case '{':
		if depth >= MaxDepth {
			return nil, errCanonical
		}
		p.i++
		obj := Object{}
		if p.take('}') {
			return obj, nil
		}
		var previous string
		first := true
		for {
			key, err := p.str()
			if err != nil {
				return nil, err
			}
			if !first && key <= previous {
				return nil, errCanonical
			}
			first = false
			previous = key
			if !p.take(':') {
				return nil, errCanonical
			}
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			obj[key] = v
			if p.take('}') {
				return obj, nil
			}
			if !p.take(',') {
				return nil, errCanonical
			}
		}
	case '[':
		if depth >= MaxDepth {
			return nil, errCanonical
		}
		p.i++
		list := []any{}
		if p.take(']') {
			return list, nil
		}
		for {
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
			if p.take(']') {
				return list, nil
			}
			if !p.take(',') {
				return nil, errCanonical
			}
		}
	case '"':
		return p.str()
	case 't':
		if p.literal("true") {
			return true, nil
		}
	case 'f':
		if p.literal("false") {
			return false, nil
		}
	case 'n':
		if p.literal("null") {
			return nil, nil
		}
	default:
		start := p.i
		p.take('-')
		digits := p.i
		for p.i < len(p.data) && p.data[p.i] >= '0' && p.data[p.i] <= '9' {
			p.i++
		}
		if digits == p.i || p.i-digits > 1 && p.data[digits] == '0' {
			return nil, errCanonical
		}
		token := string(p.data[start:p.i])
		n, err := strconv.ParseInt(token, 10, 64)
		if err != nil || n > MaxInteger || n < -MaxInteger || token == "-0" {
			return nil, errCanonical
		}
		return n, nil
	}
	return nil, errCanonical
}
func (p *parser) take(c byte) bool {
	if p.i < len(p.data) && p.data[p.i] == c {
		p.i++
		return true
	}
	return false
}
func (p *parser) literal(s string) bool {
	if bytes.HasPrefix(p.data[p.i:], []byte(s)) {
		p.i += len(s)
		return true
	}
	return false
}
func (p *parser) str() (string, error) {
	if !p.take('"') {
		return "", errCanonical
	}
	var out []byte
	for p.i < len(p.data) {
		c := p.data[p.i]
		p.i++
		switch {
		case c == '"':
			return string(out), nil
		case c < 0x20:
			return "", errCanonical
		case c == '\\':
			if p.i == len(p.data) {
				return "", errCanonical
			}
			esc := p.data[p.i]
			p.i++
			switch esc {
			case '"', '\\':
				out = append(out, esc)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				if len(p.data)-p.i < 4 || p.data[p.i] != '0' || p.data[p.i+1] != '0' {
					return "", errCanonical
				}
				a, b := unhex(p.data[p.i+2]), unhex(p.data[p.i+3])
				p.i += 4
				if a < 0 || b < 0 {
					return "", errCanonical
				}
				v := byte(a*16 + b)
				if v >= 0x20 || v == '\b' || v == '\f' || v == '\n' || v == '\r' || v == '\t' {
					return "", errCanonical
				}
				out = append(out, v)
			default:
				return "", errCanonical
			}
		default:
			out = append(out, c)
		}
	}
	return "", errCanonical
}
func unhex(c byte) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	if c >= 'a' && c <= 'f' {
		return int(c - 'a' + 10)
	}
	return -1
}

// Marshal emits bounded canonical CCJ-1 bytes without HTML escaping or Unicode
// normalization. Unsupported Go values, unsafe integers and invalid strings fail.
func Marshal(obj Object) ([]byte, error) {
	e := encoder{}
	if err := e.value(obj, 0); err != nil {
		return nil, err
	}
	return e.data, nil
}

type encoder struct{ data []byte }

func (e *encoder) add(s string) error {
	if len(s) > MaxFrame-len(e.data) {
		return errCanonical
	}
	e.data = append(e.data, s...)
	return nil
}
func (e *encoder) value(v any, depth int) error {
	switch x := v.(type) {
	case nil:
		return e.add("null")
	case bool:
		return e.add(strconv.FormatBool(x))
	case string:
		return e.str(x)
	case Object:
		if depth >= MaxDepth || len(x) > MaxFrame/2 {
			return errCanonical
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if err := e.add("{"); err != nil {
			return err
		}
		for i, k := range keys {
			if i > 0 {
				if err := e.add(","); err != nil {
					return err
				}
			}
			if err := e.str(k); err != nil {
				return err
			}
			if err := e.add(":"); err != nil {
				return err
			}
			if err := e.value(x[k], depth+1); err != nil {
				return err
			}
		}
		return e.add("}")
	case []any:
		if depth >= MaxDepth || len(x) > MaxFrame/2 {
			return errCanonical
		}
		if err := e.add("["); err != nil {
			return err
		}
		for i, v := range x {
			if i > 0 {
				if err := e.add(","); err != nil {
					return err
				}
			}
			if err := e.value(v, depth+1); err != nil {
				return err
			}
		}
		return e.add("]")
	case int:
		return e.integer(int64(x))
	case int8:
		return e.integer(int64(x))
	case int16:
		return e.integer(int64(x))
	case int32:
		return e.integer(int64(x))
	case int64:
		return e.integer(x)
	case uint:
		return e.unsigned(uint64(x))
	case uint8:
		return e.unsigned(uint64(x))
	case uint16:
		return e.unsigned(uint64(x))
	case uint32:
		return e.unsigned(uint64(x))
	case uint64:
		return e.unsigned(x)
	default:
		return errCanonical
	}
}
func (e *encoder) integer(n int64) error {
	if n < -MaxInteger || n > MaxInteger {
		return errCanonical
	}
	return e.add(strconv.FormatInt(n, 10))
}
func (e *encoder) unsigned(n uint64) error {
	if n > uint64(MaxInteger) {
		return errCanonical
	}
	return e.integer(int64(n))
}
func (e *encoder) str(s string) error {
	if !utf8.ValidString(s) || len(s) > MaxFrame {
		return errCanonical
	}
	if err := e.add("\""); err != nil {
		return err
	}
	const hex = "0123456789abcdef"
	for _, r := range s {
		var part string
		switch r {
		case '"':
			part = `\"`
		case '\\':
			part = `\\`
		case '\b':
			part = `\b`
		case '\f':
			part = `\f`
		case '\n':
			part = `\n`
		case '\r':
			part = `\r`
		case '\t':
			part = `\t`
		default:
			if r < 0x20 {
				part = string([]byte{'\\', 'u', '0', '0', hex[byte(r)>>4], hex[byte(r)&15]})
			} else {
				part = string(r)
			}
		}
		if err := e.add(part); err != nil {
			return err
		}
	}
	return e.add("\"")
}
