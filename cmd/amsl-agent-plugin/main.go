// Command amsl-agent-plugin generates Codex, Claude Code and Cursor plugins
// for an existing CLI from a reviewed cliagent spec, checks generated output
// for drift, and serves the spec's declared tools as a stdio MCP server.
//
//	amsl-agent-plugin generate --spec FILE --out DIR
//	amsl-agent-plugin check    --spec FILE --out DIR
//	amsl-agent-plugin files    --spec FILE --out DIR
//	amsl-agent-plugin serve    (--spec FILE | --spec-json JSON) [--workspace DIR]
//
// During serve, stdout carries only MCP protocol messages; diagnostics go to
// stderr. There is no HTTP listener.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ajent-social/go/cliagent"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const usage = `usage:
  amsl-agent-plugin generate --spec FILE --out DIR
  amsl-agent-plugin check    --spec FILE --out DIR
  amsl-agent-plugin files    --spec FILE --out DIR
  amsl-agent-plugin serve    (--spec FILE | --spec-json JSON) [--workspace DIR]

generate writes Codex, Claude Code and Cursor plugin folders into DIR, which
must be absent or empty. check compares DIR with the spec read-only and exits 1
on drift. files prints the relative paths generate writes. serve runs the
declared tools as a stdio MCP server (stdout is protocol only).
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, serveStdio)
	stop()
	os.Exit(code)
}

// serveFunc runs server until ctx ends or the client disconnects.
type serveFunc func(ctx context.Context, server *mcp.Server) error

func serveStdio(ctx context.Context, server *mcp.Server) error {
	return server.Run(ctx, &mcp.StdioTransport{})
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, serve serveFunc) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, usage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	var err error
	switch args[0] {
	case "generate", "check", "files":
		err = runOutput(args[0], args[1:], stdout, stderr)
	case "serve":
		err = runServe(ctx, args[1:], stderr, serve)
	default:
		err = fmt.Errorf("unknown command %q", args[0])
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "amsl-agent-plugin: %v\n", err)
		return 1
	}
	return 0
}

func runOutput(cmd string, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "cliagent spec JSON file")
	out := fs.String("out", "", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *specPath == "" || *out == "" || fs.NArg() != 0 {
		return fmt.Errorf("%s requires --spec FILE --out DIR and no positional arguments", cmd)
	}
	spec, err := cliagent.LoadSpec(*specPath)
	if err != nil {
		return err
	}
	switch cmd {
	case "generate":
		if err := cliagent.Generate(spec, *out); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "generated %s plugins for %s\n", spec.Plugin.Name, joinHosts())
	case "check":
		if err := cliagent.Check(spec, *out); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "ok")
	case "files":
		paths, err := cliagent.Paths(spec)
		if err != nil {
			return err
		}
		for _, p := range paths {
			fmt.Fprintln(stdout, filepath.ToSlash(filepath.Join(*out, p)))
		}
	}
	return nil
}

func joinHosts() string {
	s := ""
	for i, h := range cliagent.Hosts {
		if i > 0 {
			s += ", "
		}
		s += h
	}
	return s
}

func runServe(ctx context.Context, args []string, stderr io.Writer, serve serveFunc) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "cliagent spec JSON file")
	specJSON := fs.String("spec-json", "", "inline cliagent spec JSON")
	workspace := fs.String("workspace", "", "child working directory (default: current directory)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("serve takes no positional arguments")
	}
	if (*specPath == "") == (*specJSON == "") {
		return errors.New("serve requires exactly one of --spec FILE or --spec-json JSON")
	}
	var spec *cliagent.Spec
	var err error
	if *specPath != "" {
		spec, err = cliagent.LoadSpec(*specPath)
	} else {
		spec, err = cliagent.ParseSpec([]byte(*specJSON))
	}
	if err != nil {
		return err
	}
	runner, err := cliagent.NewRunner(ctx, spec, cliagent.RunnerOptions{Workspace: *workspace})
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "amsl-agent-plugin: serving %d tools for %s (%s) in %s\n",
		len(spec.Tools), spec.Plugin.Name, runner.Executable(), runner.Workspace())
	err = serve(ctx, cliagent.NewServer(runner))
	if ctx.Err() != nil {
		return nil
	}
	return err
}
