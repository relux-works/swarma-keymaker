package j7lifecycle_test

import (
	"fmt"

	"github.com/relux-works/swarma-keymaker/j7lifecycle"
)

// This example converts bytes only: no socket, account or run is created.
func ExampleEncodeRequestFrame() {
	q := j7lifecycle.Request{ID: "00000000000000000000000000000001", Method: j7lifecycle.HelloMethod, Versions: []int64{1}}
	frame, err := j7lifecycle.EncodeRequestFrame(q)
	if err != nil {
		panic(err)
	}
	parsed, err := j7lifecycle.DecodeRequestFrame(frame)
	if err != nil {
		panic(err)
	}
	fmt.Println(parsed.Method, parsed.Versions)
	// Output: hello [1]
}
