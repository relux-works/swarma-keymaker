package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/swarma-keymaker/internal/enrollment"
	"github.com/relux-works/swarma-keymaker/internal/keymaker"
)

const version = "0.1.0-dev"

func run(ctx context.Context, args []string, out, errOut io.Writer) int {
	if len(args) == 1 && args[0] == "version" {
		fmt.Fprintln(out, version)
		return 0
	}
	if len(args) >= 2 && args[0] == "enrollment" && args[1] == "reconcile" {
		return runReconcile(ctx, args[2:], os.Stdin, out, errOut)
	}
	if len(args) == 0 || args[0] != "serve" {
		fmt.Fprintln(errOut, "usage: keymaker version | serve --config <file> | enrollment reconcile --config <file> [--bootstrap] [--confirm <sha256>]")
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
