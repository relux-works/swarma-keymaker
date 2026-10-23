// Shell-contract regression check with stubbed account/install commands.
// Generated sudoers syntax uses the real parser when available.
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
	sudoersPath, stagedPath                                string
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
WINDOW_SUDOERS_NEW=%q
getent() {
 if [ "$1" = %q ] && [ "$2" = %q ]; then
  return %d
 fi
 return 2
}
groupadd() { printf 'MUTATION groupadd\n'; }
useradd() { printf 'MUTATION useradd\n'; }
`, test.sudoersPath, test.stagedPath, test.database, test.key, test.lookupExit)
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

// TestRunbookWindowSudoersCompatibility renders the actual marked printf with
// neutral names and parses it using the installed sudoers parser, unprivileged.
// Parsing proves syntax compatibility; the exact-text control also excludes
// broader Runas rules. Absence is a distinct skip, not a passing parser check.
func checkWindowSudoers(bash, content, scratch string) (bool, error) {
	const visudo = "/usr/sbin/visudo"
	if _, err := os.Stat(visudo); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return true, err
	}
	if os.Geteuid() == 0 {
		return true, errors.New("real parser check must run unprivileged")
	}
	dir, err := os.MkdirTemp(scratch, "sudoers-")
	if err != nil {
		return true, err
	}
	prefix := fmt.Sprintf(`set -euo pipefail
RUNNER_USER=fixture-runner
TEST_A=platform-test-a
TEST_B=platform-test-b
TEST_GROUP=platform-test-reg
WINDOW_TMP=%q
`, dir)
	cmd := exec.Command(bash, "--noprofile", "--norc", "-s")
	cmd.Env = []string{"PATH=/nonexistent", "LC_ALL=C"}
	cmd.Stdin = strings.NewReader(prefix + content)
	if output, err := cmd.CombinedOutput(); err != nil {
		return true, fmt.Errorf("rendering sudoers: %v; %s", err, output)
	}
	path := filepath.Join(dir, "agent-platform-test")
	cmd = exec.Command(visudo, "-cf", path)
	cmd.Env = []string{"PATH=/nonexistent", "LC_ALL=C"}
	if output, err := cmd.CombinedOutput(); err != nil {
		return true, fmt.Errorf("real visudo -cf: %v; %s", err, output)
	}
	expected := "fixture-runner ALL=(platform-test-a,platform-test-b) NOPASSWD: ALL\n" +
		"fixture-runner ALL=(fixture-runner:platform-test-reg) NOPASSWD: ALL\n"
	data, err := os.ReadFile(path)
	if err != nil || string(data) != expected {
		return true, fmt.Errorf("constrained Runas text changed: %v; %q", err, data)
	}
	return true, nil
}

// TestRunbookWindowValidationBeforeMutation checks the complete marked order,
// including account/group steps, staged install, rename and full-policy check.
// A failing candidate validation must leave all mutation stubs uncalled; the
// nearby successful control requires every step. No privileged tool runs here.
func checkWindowValidationOrder(bash, guards, provision, scratch string, reject bool) error {
	dir, err := os.MkdirTemp(scratch, "order-")
	if err != nil {
		return err
	}
	validationExit := 0
	if reject {
		validationExit = 1
	}
	prefix := fmt.Sprintf(`set -euo pipefail
RUNNER_USER=fixture-runner
TEST_A=platform-test-a
TEST_B=platform-test-b
TEST_GROUP=platform-test-reg
WINDOW_SUDOERS=%q
WINDOW_SUDOERS_NEW=%q
PREPARE_DIR=%q
getent() { return 2; }
mktemp() { test "$*" = '-d'; printf '%%s\n' "$PREPARE_DIR"; }
rm() { test "$*" = "-rf -- $WINDOW_TMP"; printf 'CLEANUP\n'; }
groupadd() { printf 'MUTATION groupadd\n'; }
useradd() { printf 'MUTATION useradd\n'; }
usermod() { printf 'MUTATION usermod\n'; }
install() {
 test "$*" = "-o root -g root -m 0440 $WINDOW_TMP/agent-platform-test $WINDOW_SUDOERS_NEW"
 printf 'MUTATION install\n'
}
mv() {
 test "$*" = "-T -- $WINDOW_SUDOERS_NEW $WINDOW_SUDOERS"
 printf 'MUTATION mv\n'
}
id() { printf 'READBACK id\n'; }
visudo() {
 if [ "$*" = "-cf $WINDOW_TMP/agent-platform-test" ]; then
  test -f "$WINDOW_TMP/agent-platform-test"
  printf 'VALIDATE candidate\n'
  return %d
 fi
 test "$*" = '-c'
 printf 'VALIDATE full\n'
}
`, filepath.Join(scratch, "absent-final"), filepath.Join(scratch, "absent-stage"), dir, validationExit)
	cmd := exec.Command(bash, "--noprofile", "--norc", "-s")
	cmd.Env = []string{"PATH=/nonexistent", "LC_ALL=C"}
	cmd.Stdin = strings.NewReader(prefix + guards + provision)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return err
		}
		code = exitErr.ExitCode()
	}
	expected := "VALIDATE candidate\n"
	if !reject {
		expected += "MUTATION groupadd\nMUTATION useradd\nMUTATION useradd\nMUTATION usermod\n" +
			"MUTATION install\nMUTATION mv\nVALIDATE full\nREADBACK id\nREADBACK id\n"
	}
	expected += "CLEANUP\n"
	if code != validationExit || stdout.String() != expected || stderr.Len() != 0 {
		return fmt.Errorf("shell exit=%d, trace=%q; wanted exit=%d, trace=%q; stderr=%q",
			code, stdout.String(), validationExit, expected, stderr.String())
	}
	fmt.Printf("PASS TestRunbookWindowValidationBeforeMutation/reject-%t (shell exit %d; validation first; mutation stubs %d)\n",
		reject, code, strings.Count(stdout.String(), "MUTATION "))
	return nil
}

func main() {
	check := flag.Bool("check", false, "check marked specification shell blocks without host changes")
	plant := flag.Bool("plant", false, "plant guard, parser and validation-order regressions in memory; checker must fail")
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
	for _, name := range []string{"guards", "service-preflight", "service-allocation", "window-preflight", "window-allocation", "window-provision", "window-sudoers-content"} {
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
			{"window-preflight", "if [ -e \"$window_path\" ] || [ -L \"$window_path\" ]; then\n", "if false; then\n"},
		} {
			if strings.Count(blocks[target.block], target.original) != 1 {
				fmt.Fprintln(os.Stderr, "plant not applied")
				os.Exit(2)
			}
			blocks[target.block] = strings.Replace(blocks[target.block], target.original, target.replacement, 1)
		}
		validation := "visudo -cf \"$WINDOW_TMP/agent-platform-test\"\n"
		if strings.Count(blocks["window-provision"], validation) != 1 {
			fmt.Fprintln(os.Stderr, "validation-order plant not applied")
			os.Exit(2)
		}
		blocks["window-provision"] = strings.Replace(blocks["window-provision"], validation, "", 1)
		anchor := "# runbook-check:end window-allocation\n"
		output := "> \"$WINDOW_TMP/agent-platform-test\""
		if strings.Count(blocks["window-provision"], anchor) != 1 || strings.Count(blocks["window-sudoers-content"], output) != 1 {
			fmt.Fprintln(os.Stderr, "validation/parser plant not applied")
			os.Exit(2)
		}
		blocks["window-provision"] = strings.Replace(blocks["window-provision"], anchor, anchor+validation, 1)
		blocks["window-sudoers-content"] = "printf 'Defaults:%s !requiretty\\n' \"$RUNNER_USER\" > \"$WINDOW_TMP/agent-platform-test\"\n" +
			strings.Replace(blocks["window-sudoers-content"], "> \"$WINDOW_TMP/agent-platform-test\"", ">> \"$WINDOW_TMP/agent-platform-test\"", 1)
		fmt.Println("PLANT applied in memory: inverted getent, disabled window path guard, requiretty, and validation after allocation")
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
		// Preserve the original final-name cases and apply both variants to the
		// ignored staging name, which must not bypass the pre-allocation guard.
		for _, staged := range []bool{false, true} {
			test := scenario{name: "TestRunbookWindowPathBeforeMutation/" + sample.name,
				preflight: blocks["window-preflight"], allocation: blocks["window-allocation"],
				database: "none", key: "none", lookupExit: 2,
				expectedExit: 1, mutations: 0, diagnostic: "existing window path: " + sample.path}
			if staged {
				test.name += "/staged"
				test.stagedPath = sample.path
			} else {
				test.sudoersPath = sample.path
			}
			tests = append(tests, test)
		}
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
		if test.stagedPath == "" {
			test.stagedPath = filepath.Join(scratch, "absent-stage")
		}
		if err := evaluate(bash, blocks["guards"], test); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL", err)
			failures++
		}
	}
	for _, reject := range []bool{false, true} {
		if err := checkWindowValidationOrder(bash, blocks["guards"], blocks["window-provision"], scratch, reject); err != nil {
			fmt.Fprintf(os.Stderr, "FAIL TestRunbookWindowValidationBeforeMutation/reject-%t: %v\n", reject, err)
			failures++
		}
	}
	skipped := 0
	if ran, err := checkWindowSudoers(bash, blocks["window-sudoers-content"], scratch); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL TestRunbookWindowSudoersCompatibility:", err)
		failures++
	} else if !ran {
		fmt.Println("SKIPPED TestRunbookWindowSudoersCompatibility: /usr/sbin/visudo is absent; real parser compatibility unverified")
		skipped++
	} else {
		fmt.Println("PASS TestRunbookWindowSudoersCompatibility (real visudo -cf exit 0; exact constrained Runas rules)")
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != "preserve fixture\n" {
		fmt.Fprintln(os.Stderr, "FAIL checker-owned sudoers fixture changed")
		failures++
	}
	if target, err := os.Readlink(link); err != nil || target != filepath.Join(scratch, "absent") {
		fmt.Fprintln(os.Stderr, "FAIL checker-owned sudoers symlink changed")
		failures++
	}
	if _, err := os.Lstat(filepath.Join(scratch, "absent")); !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "FAIL checker-owned dangling target was created")
		failures++
	}
	if err := os.RemoveAll(scratch); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL checker fixture cleanup")
		failures++
	}
	if failures > 0 {
		fmt.Fprintf(os.Stderr, "%d/%d runbook checks failed; %d skipped\n", failures, len(tests)+3, skipped)
		os.Exit(1)
	}
	fmt.Printf("%d runbook checks passed; %d skipped; no host account writes\n", len(tests)+3-skipped, skipped)
}
