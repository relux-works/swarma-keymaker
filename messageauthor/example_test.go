package messageauthor_test

import (
	"fmt"
	"github.com/relux-works/swarma-keymaker/messageauthor"
)

// This example only converts bytes; the methods are not registered at runtime.
func ExampleEncodeRequestFrame() {
	q := messageauthor.Request{ID: "0123456789abcdef0123456789abcdef", TimeoutMS: 2000, Method: messageauthor.IdentityMethod}
	b, e := messageauthor.EncodeRequestFrame(q)
	if e != nil {
		panic(e)
	}
	v, e := messageauthor.DecodeRequestFrame(b)
	if e != nil {
		panic(e)
	}
	fmt.Println(v.Method)
	// Output: message_author_identity
}
