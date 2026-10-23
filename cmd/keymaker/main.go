package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-keymaker/internal/keymaker"
)

const version = "0.1.0-dev"

func run(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(out, version)
		return 0
	}
	if len(args) == 0 || args[0] != "serve" {
		fmt.Fprintln(errOut, "usage: keymaker version | serve --config <file>")
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
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
