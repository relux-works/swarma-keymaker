//go:build linux && multiuid

package keymaker

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-keymaker/internal/testwindow"
)

// Every tagged client/reexec route retains its exact historical argv except
// the selected env path. These pure builders never run sudo or a native body;
// source bindings tie them to all six existing execution sites.
func TestWindowConfiguredClientArguments(t *testing.T) {
	for _, env := range []string{"/usr/bin/env", "/fixture dedicated/env"} {
		w := testwindow.Window{Config: testwindow.Config{Runner: "runner", A: "client-a", B: "client-b", Group: "test-reg", EnvPath: env}, UID: 1000, AID: 1001, BID: 1002}
		cases := []struct {
			name      string
			got, want []string
		}{
			{"ssh", windowClientArguments(w, "client-b", 1002, "/fixture/socket", []byte{1, 2, 3}, true, "/fixture/suite", "token"), []string{"-n", "-u", "client-b", "--", env, "KEYMAKER_TEST_CLIENT=1", "KEYMAKER_CLIENT_UID=1002", "KEYMAKER_CLIENT_SOCKET=/fixture/socket", "KEYMAKER_CLIENT_PUBLIC=AQID", "KEYMAKER_CLIENT_REFUSED=1", "/fixture/suite", "-keymaker-window-token=token"}},
			{"control", nativeWindowClientArguments(w, "client-a", 1001, "/fixture/control", []byte{1, 2, 3}, "binding_not_found", false, false, "/fixture/suite", "token"), []string{"-n", "-u", "client-a", "--", env, "KEYMAKER_TEST_CLIENT=1", "KEYMAKER_CLIENT_SURFACE=control", "KEYMAKER_CLIENT_UID=1001", "KEYMAKER_CLIENT_SOCKET=/fixture/control", "KEYMAKER_CLIENT_PUBLIC=AQID", "KEYMAKER_CLIENT_CODE=binding_not_found", "KEYMAKER_CLIENT_CONNECT_DENIED=0", "/fixture/suite", "-keymaker-window-token=token"}},
			{"denied", nativeWindowClientArguments(w, "client-b", 1002, "/fixture/control", []byte{1, 2, 3}, "", true, false, "/fixture/suite", "token"), []string{"-n", "-u", "client-b", "--", env, "KEYMAKER_TEST_CLIENT=1", "KEYMAKER_CLIENT_SURFACE=control", "KEYMAKER_CLIENT_UID=1002", "KEYMAKER_CLIENT_SOCKET=/fixture/control", "KEYMAKER_CLIENT_PUBLIC=AQID", "KEYMAKER_CLIENT_CODE=", "KEYMAKER_CLIENT_CONNECT_DENIED=1", "/fixture/suite", "-keymaker-window-token=token"}},
			{"helper", nativeWindowClientArguments(w, "client-a", 1001, "/fixture/control", []byte{1, 2, 3}, "", false, true, "/fixture/suite", "token"), []string{"-n", "-u", "client-a", "--", env, "KEYMAKER_TEST_CLIENT=1", "KEYMAKER_CLIENT_SURFACE=control", "KEYMAKER_CLIENT_UID=1001", "KEYMAKER_CLIENT_SOCKET=/fixture/control", "KEYMAKER_CLIENT_PUBLIC=AQID", "KEYMAKER_CLIENT_CODE=", "KEYMAKER_CLIENT_CONNECT_DENIED=0", "KEYMAKER_CLIENT_METHOD=sign_registration", "/fixture/suite", "-keymaker-window-token=token"}},
			{"control-group", windowGroupArguments(w, "TestMultiUIDControl", "30s", "/fixture/config", "/fixture/scratch", "/fixture/tmp", "/fixture/suite", "token"), []string{"-n", "-u", "runner", "-g", "test-reg", "--", env, "KEYMAKER_WINDOW_CONFIG=/fixture/config", "KEYMAKER_WINDOW_SCRATCH=/fixture/scratch", "TMPDIR=/fixture/tmp", "/fixture/suite", "-test.run=^TestMultiUIDControl$", "-test.timeout=30s", "-test.v", "-keymaker-window-token=token"}},
			{"helper-group", windowGroupArguments(w, "TestMultiUIDHelper", "40s", "/fixture/config", "/fixture/scratch", "/fixture/tmp", "/fixture/suite", "token"), []string{"-n", "-u", "runner", "-g", "test-reg", "--", env, "KEYMAKER_WINDOW_CONFIG=/fixture/config", "KEYMAKER_WINDOW_SCRATCH=/fixture/scratch", "TMPDIR=/fixture/tmp", "/fixture/suite", "-test.run=^TestMultiUIDHelper$", "-test.timeout=40s", "-test.v", "-keymaker-window-token=token"}},
			{"pc2", windowFenceArguments(w, "/fixture/tmp", "/fixture/suite", "token"), []string{"-n", "-u", "client-a", "--", env, "KEYMAKER_PC2_FOREIGN_FENCE=1", "KEYMAKER_PC2_EXPECT_OWNER=1000", "TMPDIR=/fixture/tmp", "/fixture/suite", "-test.run=^TestMultiUIDPC2FenceIdentity$", "-test.timeout=8s", "-keymaker-window-token=token"}},
			{"j7-a", windowPolicyArguments(w, "client-a", 1001, "/fixture/table", "/fixture/suite", "token"), []string{"-n", "-u", "client-a", "--", env, "KEYMAKER_J7_POLICY_CLIENT=1", "KEYMAKER_J7_EXPECTED_UID=1001", "KEYMAKER_J7_POLICY_PATH=/fixture/table", "/fixture/suite", "-test.run=^TestMultiUIDJ7PolicyProtection$", "-test.timeout=10s", "-keymaker-window-token=token"}},
			{"j7-b", windowPolicyArguments(w, "client-b", 1002, "/fixture/table", "/fixture/suite", "token"), []string{"-n", "-u", "client-b", "--", env, "KEYMAKER_J7_POLICY_CLIENT=1", "KEYMAKER_J7_EXPECTED_UID=1002", "KEYMAKER_J7_POLICY_PATH=/fixture/table", "/fixture/suite", "-test.run=^TestMultiUIDJ7PolicyProtection$", "-test.timeout=10s", "-keymaker-window-token=token"}},
		}
		for _, tc := range cases {
			if !reflect.DeepEqual(tc.got, tc.want) {
				t.Fatalf("%s selected env argv mismatch: got %q want %q", tc.name, tc.got, tc.want)
			}
		}
	}
	bindings := map[string]string{"runWindowClient": "windowClientArguments", "runNativeWindowClient": "nativeWindowClientArguments", "TestMultiUIDControl": "windowGroupArguments", "TestMultiUIDHelper": "windowGroupArguments", "TestMultiUIDPC2FenceIdentity": "windowFenceArguments", "TestMultiUIDJ7PolicyProtection": "windowPolicyArguments"}
	found := map[string]int{}
	for _, path := range []string{"multiuid_test.go", "authority_fence_multiuid_test.go", "j7_multiuid_test.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			want, ok := bindings[fn.Name.Name]
			if !ok {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if ok {
					if name, ok := call.Fun.(*ast.Ident); ok && name.Name == want {
						found[fn.Name.Name]++
					}
				}
				return true
			})
		}
	}
	for caller := range bindings {
		if found[caller] != 1 {
			t.Fatal("client builder source binding changed", caller, found[caller])
		}
	}
}
