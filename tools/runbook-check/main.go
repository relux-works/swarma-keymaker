// Offline shell-contract regression check. No NSS or account mutation is invoked.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func excerpt(spec, name string) (string, error) {
	begin := "# runbook-check:begin " + name + "\n"
	end := "# runbook-check:end " + name + "\n"
	if strings.Count(spec, begin) != 1 || strings.Count(spec, end) != 1 {
		return "", fmt.Errorf("ambiguous or missing runbook excerpt: %s", name)
	}
	tail := strings.SplitN(spec, begin, 2)[1]
	if !strings.Contains(tail, end) {
		return "", fmt.Errorf("unclosed excerpt: %s", name)
	}
	return strings.SplitN(tail, end, 2)[0], nil
}

type scenario struct {
	name, preflight, allocation, database, key, diagnostic string
	sudoersPath                                            string
	lookupExit, expectedExit, mutations                    int
}

// TestRunbookCollisionBeforeMutation and TestRunbookLookupErrorBeforeMutation
// prove the actual marked shell blocks refuse each named collision/lookup error
// before any mutation stub. NSS, privileges and concurrent account creation are
// outside this bounded check. TestRunbookNoCollisionControl rejects a deny-all fix.
func evaluate(bash, guards string, test scenario) error {
	// PATH is deliberately empty of tools. Only these shell functions can run;
	// unexpected external commands fail rather than touching the host.
	prefix := fmt.Sprintf(`set -euo pipefail
TEST_A=platform-test-a
TEST_B=platform-test-b
TEST_GROUP=platform-test-reg
WINDOW_SUDOERS=%q
getent() {
 if [ "$1" = %q ] && [ "$2" = %q ]; then
  return %d
 fi
 return 2
}
groupadd() { printf 'MUTATION groupadd\n'; }
useradd() { printf 'MUTATION useradd\n'; }
`, test.sudoersPath, test.database, test.key, test.lookupExit)
	script := prefix + guards + test.preflight + test.allocation
	cmd := exec.Command(bash, "--noprofile", "--norc", "-s")
	cmd.Env = []string{"PATH=/nonexistent", "LC_ALL=C"}
	cmd.Stdin = strings.NewReader(script)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return err
		}
		code = exitErr.ExitCode()
	}
	mutations := strings.Count(stdout.String(), "MUTATION ")
	if code != test.expectedExit || mutations != test.mutations ||
		(test.diagnostic != "" && !strings.Contains(stderr.String(), test.diagnostic)) {
		return fmt.Errorf("%s: exit=%d mutations=%d; wanted exit=%d mutations=%d, diagnostic=%q; stderr=%q",
			test.name, code, mutations, test.expectedExit, test.mutations, test.diagnostic, stderr.String())
	}
	fmt.Printf("PASS %s (shell exit %d, mutation stubs %d)\n", test.name, code, mutations)
	return nil
}

func main() {
	check := flag.Bool("check", false, "check marked specification shell blocks without host changes")
	plant := flag.Bool("plant", false, "weaken lookup/path guards in memory; checker must fail")
	flag.Parse()
	if *check == *plant || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "use exactly one of -check or -plant")
		os.Exit(2)
	}
	raw, err := os.ReadFile("spec/keymaker.md")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	blocks := map[string]string{}
	for _, name := range []string{"guards", "service-preflight", "service-allocation", "window-preflight", "window-allocation"} {
		blocks[name], err = excerpt(string(raw), name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if *plant {
		for _, target := range []struct{ block, original, replacement string }{
			{"service-preflight", "require_absent passwd swarma-keymaker\n", "! getent passwd swarma-keymaker > /dev/null\n"},
			{"window-preflight", "require_absent passwd \"$TEST_A\"\n", "! getent passwd \"$TEST_A\" > /dev/null\n"},
			{"window-preflight", "if [ -e \"$WINDOW_SUDOERS\" ] || [ -L \"$WINDOW_SUDOERS\" ]; then\n", "if false; then\n"},
		} {
			if strings.Count(blocks[target.block], target.original) != 1 {
				fmt.Fprintln(os.Stderr, "plant not applied")
				os.Exit(2)
			}
			blocks[target.block] = strings.Replace(blocks[target.block], target.original, target.replacement, 1)
		}
		fmt.Println("PLANT applied in memory: inverted getent for service/window usernames and disabled window path guard")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	// These are checker-owned files, never /etc paths. The marked path guard must
	// reject an existing file or dangling symlink before any allocation stub runs.
	scratch, err := os.MkdirTemp("", "runbook-check-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "checker scratch unavailable")
		os.Exit(2)
	}
	existing := filepath.Join(scratch, "existing-sudoers")
	link := filepath.Join(scratch, "dangling-sudoers")
	if os.WriteFile(existing, []byte("preserve fixture\n"), 0600) != nil || os.Symlink(filepath.Join(scratch, "absent"), link) != nil {
		fmt.Fprintln(os.Stderr, "checker fixtures unavailable")
		os.RemoveAll(scratch)
		os.Exit(2)
	}
	var tests []scenario
	scopes := []struct {
		name string
		keys [][2]string
	}{
		{"service", [][2]string{{"passwd", "swarma-keymaker"}, {"group", "swarma-keymaker"}, {"group", "swarma-registration"}}},
		{"window", [][2]string{{"passwd", "platform-test-a"}, {"group", "platform-test-a"}, {"passwd", "platform-test-b"}, {"group", "platform-test-b"}, {"group", "platform-test-reg"}}},
	}
	for _, scope := range scopes {
		preflight, allocation := blocks[scope.name+"-preflight"], blocks[scope.name+"-allocation"]
		tests = append(tests, scenario{name: "TestRunbookNoCollisionControl/" + scope.name, preflight: preflight, allocation: allocation, database: "none", key: "none", lookupExit: 2, expectedExit: 0, mutations: 3})
		for _, key := range scope.keys {
			for _, status := range []int{0, 1, 3} {
				testName, diagnostic := "TestRunbookCollisionBeforeMutation", "collision: "
				if status != 0 {
					testName, diagnostic = "TestRunbookLookupErrorBeforeMutation", "lookup failed: "
				}
				tests = append(tests, scenario{name: fmt.Sprintf("%s/%s/%s/%s/status-%d", testName, scope.name, key[0], key[1], status), preflight: preflight, allocation: allocation, database: key[0], key: key[1], lookupExit: status, expectedExit: 1, mutations: 0, diagnostic: diagnostic + key[0] + " " + key[1]})
			}
		}
	}
	for _, sample := range []struct{ name, path string }{{"file", existing}, {"dangling-symlink", link}} {
		tests = append(tests, scenario{name: "TestRunbookWindowPathBeforeMutation/" + sample.name,
			preflight: blocks["window-preflight"], allocation: blocks["window-allocation"],
			database: "none", key: "none", lookupExit: 2, sudoersPath: sample.path,
			expectedExit: 1, mutations: 0, diagnostic: "existing window path: " + sample.path})
	}
	// These are synthetic lookup keys, never requested OS allocations. This
	// checks numeric UID/GID guard semantics while the installer uses --system.
	for _, database := range []string{"passwd", "group"} {
		for _, status := range []int{0, 1, 2, 3} {
			test := scenario{name: fmt.Sprintf("TestRunbookNumericKey/%s/status-%d", database, status), preflight: "require_absent " + database + " 123456\n", allocation: "groupadd --system fixture\n", database: database, key: "123456", lookupExit: status, expectedExit: 1, mutations: 0, diagnostic: "lookup failed: "}
			if status == 0 {
				test.diagnostic = "collision: "
			}
			if status == 2 {
				test.expectedExit = 0
				test.mutations = 1
				test.diagnostic = ""
			}
			tests = append(tests, test)
		}
	}
	failures := 0
	for _, test := range tests {
		if test.sudoersPath == "" {
			test.sudoersPath = filepath.Join(scratch, "absent")
		}
		if err := evaluate(bash, blocks["guards"], test); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL", err)
			failures++
		}
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != "preserve fixture\n" {
		fmt.Fprintln(os.Stderr, "FAIL checker-owned sudoers fixture changed")
		failures++
	}
	if err := os.RemoveAll(scratch); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL checker fixture cleanup")
		failures++
	}
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%d/%d runbook checks failed\n", failures, len(tests))
		os.Exit(1)
	}
	fmt.Printf("%d runbook checks passed; no host account writes\n", len(tests))
}
