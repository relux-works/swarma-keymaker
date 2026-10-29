package stationcaller_test

import (
	"fmt"
	"strings"

	"github.com/relux-works/swarma-keymaker/stationcaller"
)

// The public example proves request bytes round-trip through the exported API,
// without connecting to a service or supplying signing/plan authority.
func ExampleEncodeRequestFrame() {
	request := stationcaller.Request{
		ID: "0123456789abcdef0123456789abcdef", TimeoutMS: 2000,
		Method: stationcaller.SignMethod, Profile: stationcaller.DispatcherRequest,
		PlanID: "sha256:" + strings.Repeat("a", 64),
	}
	frame, err := stationcaller.EncodeRequestFrame(request)
	if err != nil {
		panic(err)
	}
	decoded, err := stationcaller.DecodeRequestFrame(frame)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s (%d ms)\n", decoded.Method, decoded.TimeoutMS)
	// Output: sign_station_caller (2000 ms)
}
