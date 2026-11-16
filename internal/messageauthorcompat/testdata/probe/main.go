// This test-only executable observes the real nested internal codec. The root
// test builds it in an isolated module beneath the nested import prefix.
package main

import (
	"encoding/json"
	"os"

	"github.com/relux-works/swarma-keymaker/messageauthor/internal/frame"
)

type construction struct {
	Kind  string
	Value int64
	Data  []byte
}
type input struct {
	Bodies  [][]byte
	Objects []construction
}
type verdict struct {
	Accepted     bool
	Error        string
	Bytes        []byte
	MarshalError string
}
type output struct {
	Bodies  []verdict
	Objects []verdict
}

func diagnostic(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
func object(c construction) frame.Object {
	switch c.Kind {
	case "string":
		return frame.Object{"a": string(c.Data)}
	case "depth":
		var value any = int64(0)
		for i := int64(1); i < c.Value; i++ {
			value = []any{value}
		}
		return frame.Object{"a": value}
	case "integer":
		return frame.Object{"a": c.Value}
	case "unsigned":
		return frame.Object{"a": uint64(c.Value)}
	case "float":
		return frame.Object{"a": float64(c.Value)}
	case "unsupported":
		return frame.Object{"a": []byte("bytes")}
	case "invalid-key":
		return frame.Object{string([]byte{0xff}): true}
	case "cycle":
		o := frame.Object{}
		o["a"] = o
		return o
	}
	panic("unknown test construction")
}
func main() {
	var in input
	if json.NewDecoder(os.Stdin).Decode(&in) != nil {
		os.Exit(2)
	}
	out := output{}
	for _, body := range in.Bodies {
		obj, err := frame.Decode(body)
		v := verdict{Accepted: err == nil, Error: diagnostic(err)}
		if err == nil {
			b, e := frame.Marshal(obj)
			v.Bytes, v.MarshalError = b, diagnostic(e)
		}
		out.Bodies = append(out.Bodies, v)
	}
	for _, c := range in.Objects {
		b, err := frame.Marshal(object(c))
		out.Objects = append(out.Objects, verdict{Accepted: err == nil, Error: diagnostic(err), Bytes: b})
	}
	if json.NewEncoder(os.Stdout).Encode(out) != nil {
		os.Exit(2)
	}
}
