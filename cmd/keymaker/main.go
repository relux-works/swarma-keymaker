package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-keymaker/internal/enrollment"
	"github.com/relux-works/swarma-keymaker/internal/keymaker"
)

const version = "0.1.0"

func run(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(out, version)
		return 0
	}
	if len(args) >= 2 && args[0] == "enrollment" && args[1] == "reconcile" {
		return runReconcile(ctx, args[2:], os.Stdin, out, errOut)
	}
	if len(args) >= 1 && args[0] == "message-author" {
		return runMessageAuthor(ctx, args[1:], out, errOut)
	}
	if len(args) >= 1 && args[0] == "j7" {
		return runJ7(ctx, args[1:], out, errOut)
	}
	if len(args) == 0 || args[0] != "serve" {
		fmt.Fprintln(errOut, "usage: keymaker version | serve --config <file> | enrollment reconcile --config <file> [--bootstrap] [--confirm <sha256>] | j7 seed-init|migrate|policy-publish|head <flags> | message-author init|enroll|retire --config <file>")
		return 2
	}
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(errOut)
	config := flags.String("config", "", "root-owned configuration")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	if e := keymaker.ServeProduction(ctx, *config, out); e != nil {
		fmt.Fprintln(errOut, e)
		return 1
	}
	return 0
}
func main() {
	timeconf.CollectorEntry()
	// The stopped-operator commands handle custody, so they get the same
	// process hardening as the service before any argument is interpreted.
	if len(os.Args) > 1 && (os.Args[1] == "j7" || os.Args[1] == "message-author") {
		if e := keymaker.HardenProcess(); e != nil {
			fmt.Fprintln(os.Stderr, e)
			os.Exit(1)
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func runReconcile(ctx context.Context, args []string, input io.Reader, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("enrollment reconcile", flag.ContinueOnError)
	flags.SetOutput(errOut)
	config := flags.String("config", "", "protected enrollment pin configuration")
	confirm := flags.String("confirm", "", "exact full state SHA256; omit to prompt")
	bootstrap := flags.Bool("bootstrap", false, "explicitly initialize a state directory without prior evidence")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *config == "" {
		return 2
	}
	action := enrollment.Reconcile
	if *bootstrap {
		action = enrollment.Bootstrap
	}
	if err := action(ctx, *config, *confirm, input, out, errOut); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	return 0
}

// runJ7 parses one stopped-operator command for the request role. Every flag
// of a command is required exactly once, except the optional expected head of
// `j7 head`. Successful head export prints only the restart-pin JSON line.
// Other successes and all operational refusals print the closed result. Exit 1 prints that
// result with its refusal on stdout and the refusal code on stderr; exit 2 is
// a usage error with no result and no effect.
func runJ7(ctx context.Context, args []string, out, errOut io.Writer) int {
	usage := func() int {
		fmt.Fprintln(errOut, "usage: keymaker j7 seed-init --service-uid <uid> --state-dir <dir> --key-file <file> --instance-id <hex>\n"+
			"       keymaker j7 migrate --service-uid <uid> --state-dir <dir> --source-schema 0|2|4 --expected-version <n> --expected-digest <sha256> --instance-id <hex> --identity <n> --generation-journal <path>\n"+
			"       keymaker j7 policy-publish --service-uid <uid> --state-dir <dir> --schema 4|5 --expected-version <n> --expected-digest <sha256> --instance-id <hex> --identity <n> --policy-file <file> --input <file>\n"+
			"       keymaker j7 head --service-uid <uid> --state-dir <dir> --schema 0|2|4|5 [--expected-version <n> --expected-digest <sha256>]")
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	// Per command: the closed flag set, then how many trailing names are an
	// all-or-none optional group.
	commands := map[string]struct {
		command  string
		names    []string
		optional int
	}{
		"seed-init":      {keymaker.J7OperatorSeedInit, []string{"service-uid", "state-dir", "key-file", "instance-id"}, 0},
		"migrate":        {keymaker.J7OperatorMigrate, []string{"service-uid", "state-dir", "source-schema", "instance-id", "identity", "generation-journal", "expected-version", "expected-digest"}, 0},
		"policy-publish": {keymaker.J7OperatorPolicyPublish, []string{"service-uid", "state-dir", "schema", "instance-id", "identity", "policy-file", "input", "expected-version", "expected-digest"}, 0},
		"head":           {keymaker.J7OperatorHead, []string{"service-uid", "state-dir", "schema", "expected-version", "expected-digest"}, 2},
	}
	spec, ok := commands[args[0]]
	if !ok {
		return usage()
	}
	flags := flag.NewFlagSet("j7 "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	values := map[string]*j7Flag{}
	for _, name := range spec.names {
		values[name] = &j7Flag{}
		flags.Var(values[name], name, "")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return usage()
	}
	given := 0
	for i, name := range spec.names {
		v := values[name]
		if i >= len(spec.names)-spec.optional {
			given += v.count
			if v.count > 1 {
				return usage()
			}
		} else if v.count != 1 {
			return usage()
		}
	}
	if given != 0 && given != spec.optional {
		return usage()
	}
	text := func(name string) string {
		if v := values[name]; v != nil {
			return v.value
		}
		return ""
	}
	valid := true
	number := func(name string, bits int) uint64 {
		v := values[name]
		if v == nil || v.count == 0 {
			return 0
		}
		// Canonical decimal only: no sign, base prefix, separator or padding.
		n, e := strconv.ParseUint(v.value, 10, bits)
		if e != nil || strconv.FormatUint(n, 10) != v.value {
			valid = false
		}
		return n
	}
	schema := "schema"
	if args[0] == "migrate" {
		schema = "source-schema"
	}
	req := keymaker.J7OperatorRequest{
		Command:           spec.command,
		ServiceUID:        uint32(number("service-uid", 32)),
		StateDir:          text("state-dir"),
		Schema:            int(number(schema, 8)),
		ExpectedVersion:   number("expected-version", 64),
		ExpectedDigest:    text("expected-digest"),
		KeyFile:           text("key-file"),
		Instance:          text("instance-id"),
		Identity:          number("identity", 64),
		GenerationJournal: text("generation-journal"),
		PolicyFile:        text("policy-file"),
		PolicyInput:       text("input"),
	}
	if v := values["expected-version"]; v != nil && v.count == 1 {
		req.Expected = true
	}
	if !valid {
		return usage()
	}
	result := keymaker.RunJ7Operator(ctx, req)
	var value any = result
	if result.Outcome == "ok" && req.Command == keymaker.J7OperatorHead {
		// Field order and the single LF below are the operator/service contract.
		value = struct {
			Version uint64 `json:"expected_version"`
			Digest  string `json:"expected_digest"`
		}{result.Version, result.Digest}
	}
	line, e := json.Marshal(value)
	if e != nil {
		fmt.Fprintln(errOut, "keymaker: result unavailable")
		return 1
	}
	if _, err := fmt.Fprintln(out, string(line)); err != nil {
		fmt.Fprintln(errOut, "keymaker: result unavailable")
		return 1
	}
	if result.Outcome != "ok" {
		fmt.Fprintln(errOut, result.Refusal)
		return 1
	}
	return 0
}

// j7Flag records one string flag and how often it was given, so a repeated
// flag is a usage error instead of a silent last-value choice.
type j7Flag struct {
	value string
	count int
}

func (f *j7Flag) String() string { return "" }
func (f *j7Flag) Set(v string) error {
	f.value = v
	f.count++
	return nil
}
