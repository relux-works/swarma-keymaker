//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/relux-works/swarma-keymaker/internal/keymaker"
)

func runMessageAuthor(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] != "init" && args[0] != "enroll" && args[0] != "retire" {
		return 2
	}
	flags := flag.NewFlagSet("message-author "+args[0], flag.ContinueOnError)
	flags.SetOutput(errOut)
	config := flags.String("config", "", "root-owned 0640 participant configuration")
	var number uint64
	if args[0] == "retire" {
		flags.Uint64Var(&number, "registration-number", 0, "exact enrolled registration number")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *config == "" {
		return 2
	}
	if c := keymaker.RunMessageAuthorOperator(ctx, args[0], *config, number, os.Stdin, out); c != "" {
		fmt.Fprintln(errOut, c)
		return 1
	}
	return 0
}
