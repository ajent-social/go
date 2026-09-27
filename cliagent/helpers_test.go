package cliagent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fakeCLIScript is an offline stand-in for a real CLI. It is test-only.
const fakeCLIScript = `#!/bin/sh
case "$1" in
  --version) echo "fakecli 1.2.3"; exit 0 ;;
  echo) shift; for a in "$@"; do printf '%s\n' "$a"; done; exit 0 ;;
  fail) echo "boom" >&2; exit 3 ;;
  sleep) sleep 30; exit 0 ;;
  background) sleep 30 & exit 0 ;;
  spawn) sleep 30 & echo $! > "$2"; wait; exit 0 ;;
  hold) touch "$2/$$"; sleep 30; exit 0 ;;
  big) head -c 300000 /dev/zero | tr '\000' a; head -c 300000 /dev/zero | tr '\000' b >&2; exit 0 ;;
  env) printf '%s\n' "${FAKECLI_SECRET-unset}" ;;
  pwd) pwd -P ;;
  trapterm) trap 'echo got-term; exit 7' TERM; echo ready; while :; do sleep 0.05; done ;;
  ignoreterm) trap '' TERM; while :; do sleep 0.05; done ;;
  *) echo "unknown $1" >&2; exit 64 ;;
esac
`

// installFakeCLI writes the fake CLI as dir/fakecli and returns dir.
func installFakeCLI(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fakecli")
	if err := os.WriteFile(path, []byte(fakeCLIScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func lookIn(dir string) func(string) (string, error) {
	return func(name string) (string, error) {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); err != nil {
			return "", err
		}
		return p, nil
	}
}

func i64(v int64) *int64 { return &v }

func testSpec() *Spec {
	readOnly := Effects{ReadOnly: true, Idempotent: true, Cost: CostNone, Notes: "Prints only."}
	return &Spec{
		SchemaVersion: SchemaVersion,
		Plugin: Plugin{
			Name:        "fake-cli",
			DisplayName: "Fake CLI",
			Version:     "0.1.0",
			Description: "Test plugin for a fake CLI.",
			Author:      Author{Name: "AMSL contributors", URL: "https://github.com/ajent-social/go"},
			Repository:  "https://github.com/ajent-social/go",
			License:     "Apache-2.0",
			Keywords:    []string{"test", "cli"},
		},
		CLI: CLI{
			Executable:   "fakecli",
			Install:      "Test fixture; installed by the test.",
			VersionProbe: VersionProbe{Argv: []string{"--version"}, RequireOutput: "fakecli 1.2.3"},
		},
		Skill: Skill{
			Name:         "fake-cli",
			Description:  "Use the fake CLI in tests.",
			Instructions: "# Fake CLI\n\nRun the fake CLI when asked.\n",
		},
		Limits: Limits{TimeoutSeconds: 20, MaxOutputBytes: 4096, MaxConcurrent: 2},
		Tools: []*Tool{
			{
				Name: "echo", Title: "Echo", Description: "Print each argument on its own line.",
				Argv: []string{"echo"},
				Inputs: []*Input{
					{Name: "mode", Type: TypeString, Flag: "--mode", Enum: []string{"a", "b"}, Description: "Mode."},
					{Name: "count", Type: TypeInteger, Flag: "--count", Minimum: i64(0), Maximum: i64(5), Description: "Count."},
					{Name: "verbose", Type: TypeBoolean, Flag: "--verbose", Description: "Verbose."},
					{Name: "label", Type: TypeString, Flag: "--label", MaxLength: 16, Description: "Label."},
					{Name: "text", Type: TypeString, Positional: true, Required: true, Description: "Text."},
				},
				Effects: readOnly,
			},
			{Name: "fail", Description: "Exit 3.", Argv: []string{"fail"}, Effects: readOnly},
			{Name: "sleep", Description: "Sleep.", Argv: []string{"sleep"}, Effects: readOnly, TimeoutSeconds: 1},
			{
				Name: "spawn", Description: "Spawn a grandchild.", Argv: []string{"spawn"}, Effects: readOnly,
				Inputs: []*Input{{Name: "pidfile", Type: TypeString, Positional: true, Required: true, Description: "PID file."}},
			},
			{
				Name: "hold", Description: "Hold a slot.", Argv: []string{"hold"}, Effects: readOnly,
				Inputs: []*Input{{Name: "dir", Type: TypeString, Positional: true, Required: true, Description: "Marker dir."}},
			},
			{Name: "big", Description: "Print a lot.", Argv: []string{"big"}, Effects: readOnly},
			{Name: "env", Description: "Print an env var.", Argv: []string{"env"}, Effects: readOnly},
			{Name: "pwd", Description: "Print cwd.", Argv: []string{"pwd"}, Effects: readOnly},
			{
				Name: "trapterm", Description: "Handle SIGTERM.", Argv: []string{"trapterm"},
				Effects: Effects{Destructive: true, Network: true, Cost: CostPossible, Notes: "Pretends to spend money."},
			},
			{Name: "ignoreterm", Description: "Ignore SIGTERM.", Argv: []string{"ignoreterm"}, Effects: readOnly, TimeoutSeconds: 1},
		},
	}
}

// specJSON returns the canonical JSON of testSpec after mutate.
func specJSON(t *testing.T, mutate func(*Spec)) []byte {
	t.Helper()
	s := testSpec()
	if mutate != nil {
		mutate(s)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
