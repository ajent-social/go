//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// When set, the test binary behaves as amsl-agent-plugin so stdio tests run a
// real child process through the same run function main uses.
const beMainEnv = "AMSL_AGENT_PLUGIN_TEST_BE_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(beMainEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

const fakeCLI = `#!/bin/sh
case "$1" in
  --version) echo "fakecli 1.2.3" ;;
  echo) shift; for a in "$@"; do printf '%s\n' "$a"; done ;;
  fail) echo "boom" >&2; exit 3 ;;
  *) exit 64 ;;
esac
`

const specText = `{
  "schema_version": 1,
  "plugin": {"name": "fake-cli", "version": "0.1.0", "description": "Fake CLI plugin.", "author": {"name": "Tests"}},
  "cli": {"executable": "fakecli", "install": "Installed by the test.", "version_probe": {"argv": ["--version"], "require_output": "fakecli 1.2.3"}},
  "skill": {"name": "fake-cli", "description": "Use the fake CLI.", "instructions": "# Fake\n\nUse it.\n"},
  "limits": {"timeout_seconds": 10, "max_output_bytes": 65536, "max_concurrent": 2},
  "tools": [
    {"name": "echo", "description": "Echo.", "argv": ["echo"],
     "inputs": [{"name": "text", "type": "string", "positional": true, "required": true, "description": "Text."}],
     "effects": {"read_only": true, "destructive": false, "idempotent": true, "network": false, "cost": "none", "notes": "Prints."}},
    {"name": "fail", "description": "Fail.", "argv": ["fail"],
     "effects": {"read_only": true, "destructive": false, "idempotent": true, "network": false, "cost": "none", "notes": "Fails."}}
  ]
}
`

func setup(t *testing.T) (specPath, binDir string) {
	t.Helper()
	dir := t.TempDir()
	specPath = filepath.Join(dir, "fake.spec.json")
	if err := os.WriteFile(specPath, []byte(specText), 0o644); err != nil {
		t.Fatal(err)
	}
	binDir = filepath.Join(dir, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "fakecli"), []byte(fakeCLI), 0o755); err != nil {
		t.Fatal(err)
	}
	return specPath, binDir
}

func runCLI(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), args, &stdout, &stderr, serveStdio)
	return code, stdout.String(), stderr.String()
}

func TestGenerateCheckFilesCommands(t *testing.T) {
	t.Parallel()
	specPath, _ := setup(t)
	out := filepath.Join(t.TempDir(), "generated")

	if code, _, stderr := runCLI("generate", "--spec", specPath, "--out", out); code != 0 {
		t.Fatalf("generate exit %d: %s", code, stderr)
	}
	if code, stdout, stderr := runCLI("check", "--spec", specPath, "--out", out); code != 0 || stdout != "ok\n" {
		t.Fatalf("check exit %d: %s %s", code, stdout, stderr)
	}
	code, stdout, _ := runCLI("files", "--spec", specPath, "--out", "plugins/generated")
	if code != 0 || !strings.Contains(stdout, "plugins/generated/codex/.codex-plugin/plugin.json\n") || strings.Count(stdout, "\n") != 19 {
		t.Fatalf("files exit %d:\n%s", code, stdout)
	}
	if code, _, stderr := runCLI("generate", "--spec", specPath, "--out", out); code != 1 || !strings.Contains(stderr, "absent or empty") {
		t.Fatalf("second generate exit %d: %s", code, stderr)
	}
	readme := filepath.Join(out, "claude-code", "README.md")
	if err := os.WriteFile(readme, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI("check", "--spec", specPath, "--out", out); code != 1 || !strings.Contains(stderr, "changed: claude-code/README.md") {
		t.Fatalf("check after tamper exit %d: %s", code, stderr)
	}
}

func TestCommandUsageErrors(t *testing.T) {
	t.Parallel()
	specPath, _ := setup(t)
	cases := [][]string{
		{},
		{"bogus"},
		{"generate", "--spec", specPath},
		{"check", "--out", "x"},
		{"generate", "--spec", specPath, "--out", "x", "extra"},
		{"serve"},
		{"serve", "--spec", specPath, "--spec-json", specText},
		{"serve", "--spec-json", `{"schema_version":1}`},
		{"serve", "--spec", specPath, "positional"},
	}
	for _, args := range cases {
		if code, stdout, _ := runCLI(args...); code == 0 || stdout != "" {
			t.Errorf("%q: exit %d stdout %q", args, code, stdout)
		}
	}
}

// generatedServerArgv returns the command and args from a generated .mcp.json.
func generatedServerArgv(t *testing.T, specPath string) (string, []string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "generated")
	if code, _, stderr := runCLI("generate", "--spec", specPath, "--out", out); code != 0 {
		t.Fatalf("generate: %s", stderr)
	}
	raw, err := os.ReadFile(filepath.Join(out, "cursor", ".mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	srv := cfg.MCPServers["fake-cli"]
	if srv.Command != "amsl-agent-plugin" {
		t.Fatalf("command = %q", srv.Command)
	}
	return srv.Command, srv.Args
}

func TestStdioServeProcessSmoke(t *testing.T) {
	t.Parallel()
	specPath, binDir := setup(t)
	_, args := generatedServerArgv(t, specPath)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Dir = t.TempDir()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = append(os.Environ(), beMainEnv+"=1", "PATH="+binDir+":/usr/bin:/bin")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "smoke", Version: "0"}, nil).
		Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect: %v; stderr: %s", err, stderr.String())
	}
	defer cs.Close()
	tools, err := cs.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 2 {
		t.Fatalf("list tools: %v %+v", err, tools)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "over stdio"}})
	if err != nil || res.IsError {
		t.Fatalf("echo: %v %+v", err, res)
	}
	if got := res.StructuredContent.(map[string]any)["stdout"]; got != "over stdio\n" {
		t.Fatalf("stdout = %q", got)
	}
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "fail"})
	if err != nil || !res.IsError {
		t.Fatalf("fail: %v %+v", err, res)
	}
	if !strings.Contains(stderr.String(), "serving 2 tools for fake-cli") {
		t.Fatalf("diagnostics missing from stderr: %s", stderr.String())
	}
}

func TestStdioServeFailsVisiblyWhenCLIMissing(t *testing.T) {
	t.Parallel()
	specPath, _ := setup(t)
	_, args := generatedServerArgv(t, specPath)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), beMainEnv+"=1", "PATH="+t.TempDir())
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("want exit 1, got %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout must stay clean, got %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "CLI missing or incompatible") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}
