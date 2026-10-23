// release-bundle prepares reviewed files offline; it never installs a service.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

type options struct {
	repo, commit, version, target, config, registry, enrollment string
}

func run(ctx context.Context, args []string, out, errOut io.Writer) int {
	var o options
	fs := flag.NewFlagSet("release-bundle", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.StringVar(&o.repo, "repo", "", "clean source repository")
	fs.StringVar(&o.commit, "commit", "", "full source commit SHA")
	fs.StringVar(&o.version, "version", "", "expected keymaker version")
	fs.StringVar(&o.target, "target", "", "new directory outside source and system paths")
	fs.StringVar(&o.config, "config", "", "operator configuration")
	fs.StringVar(&o.registry, "name-indices", "", "operator name-index registry")
	fs.StringVar(&o.enrollment, "enrollment", "", "optional enrollment (validator required)")
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return 2
	}
	if err := assemble(ctx, o); err != nil {
		fmt.Fprintln(errOut, err)
		return 1
	}
	fmt.Fprintln(out, "release bundle prepared; verify SHA256SUMS before the owner runbook")
	return 0
}
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
