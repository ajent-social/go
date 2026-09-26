//go:build unix

package cliagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func newTestRunner(t *testing.T, s *Spec, opts RunnerOptions) *Runner {
	t.Helper()
	if opts.LookPath == nil {
		opts.LookPath = lookIn(installFakeCLI(t))
	}
	if opts.Workspace == "" {
		opts.Workspace = t.TempDir()
	}
	r, err := NewRunner(context.Background(), s, opts)
	if err != nil {
		t.Fatalf("NewRunner: %v", err)
	}
	return r
}

func TestRunnerRunsDeclaredCommandWithoutShell(t *testing.T) {
	t.Parallel()
	r := newTestRunner(t, testSpec(), RunnerOptions{})
	res, err := r.Call(context.Background(), "echo", []byte(`{"text":"$(touch pwned); a b","mode":"a"}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.Failed() || res.Stdout != "--mode\na\n$(touch pwned); a b\n" || res.Stderr != "" || res.Truncated {
		t.Fatalf("result = %+v", res)
	}
	if strings.Join(res.Argv, " ") != "fakecli echo --mode a $(touch pwned); a b" {
		t.Fatalf("argv = %q", res.Argv)
	}
	if _, err := os.Stat(filepath.Join(r.Workspace(), "pwned")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("argument was interpreted by a shell")
	}
}

func TestRunnerReportsFailureVisibly(t *testing.T) {
	t.Parallel()
	r := newTestRunner(t, testSpec(), RunnerOptions{})
	res, err := r.Call(context.Background(), "fail", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Failed() || res.ExitCode != 3 || res.Stderr != "boom\n" || res.TimedOut || res.Canceled {
		t.Fatalf("result = %+v", res)
	}
}

func TestRunnerRejectsBeforeStarting(t *testing.T) {
	t.Parallel()
	r := newTestRunner(t, testSpec(), RunnerOptions{})
	if _, err := r.Call(context.Background(), "shell", []byte(`{}`)); !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("want ErrUnknownTool, got %v", err)
	}
	marker := t.TempDir()
	if _, err := r.Call(context.Background(), "hold", []byte(`{"dir":"`+marker+`","extra":"x"}`)); !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("want ErrInvalidArguments, got %v", err)
	}
	if entries, _ := os.ReadDir(marker); len(entries) != 0 {
		t.Fatal("invalid call started a process")
	}
}

func TestNewRunnerFailsClosed(t *testing.T) {
	t.Parallel()
	dir := installFakeCLI(t)
	cases := []struct {
		name   string
		mutate func(*Spec)
		look   func(string) (string, error)
	}{
		{"missing executable", nil, lookIn(t.TempDir())},
		{"relative resolution", nil, func(string) (string, error) { return "fakecli", nil }},
		{"version text mismatch", func(s *Spec) { s.CLI.VersionProbe.RequireOutput = "fakecli 9.0.0" }, lookIn(dir)},
		{"probe exits non-zero", func(s *Spec) { s.CLI.VersionProbe.Argv = []string{"fail"} }, lookIn(dir)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := testSpec()
			if tc.mutate != nil {
				tc.mutate(s)
			}
			_, err := NewRunner(context.Background(), s, RunnerOptions{LookPath: tc.look, Workspace: t.TempDir()})
			if !errors.Is(err, ErrIncompatibleCLI) {
				t.Fatalf("want ErrIncompatibleCLI, got %v", err)
			}
		})
	}
}

func TestNewRunnerResolvesThroughPATH(t *testing.T) {
	dir := installFakeCLI(t)
	t.Setenv("PATH", dir)
	r, err := NewRunner(context.Background(), testSpec(), RunnerOptions{Workspace: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if r.Executable() != filepath.Join(dir, "fakecli") {
		t.Fatalf("executable = %s", r.Executable())
	}
	t.Setenv("PATH", t.TempDir())
	if _, err := NewRunner(context.Background(), testSpec(), RunnerOptions{Workspace: t.TempDir()}); !errors.Is(err, ErrIncompatibleCLI) {
		t.Fatalf("missing CLI on PATH: want ErrIncompatibleCLI, got %v", err)
	}
}

func TestRunnerInheritsEnvironmentAndWorkspace(t *testing.T) {
	t.Setenv("FAKECLI_SECRET", "inherited-value")
	ws, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := newTestRunner(t, testSpec(), RunnerOptions{Workspace: ws})
	res, err := r.Call(context.Background(), "env", nil)
	if err != nil || res.Stdout != "inherited-value\n" {
		t.Fatalf("env result = %+v, %v", res, err)
	}
	res, err = r.Call(context.Background(), "pwd", nil)
	if err != nil || res.Stdout != ws+"\n" {
		t.Fatalf("pwd result = %+v, %v (want %s)", res, err, ws)
	}
}

func TestRunnerTimeoutKillsProcessGroup(t *testing.T) {
	t.Parallel()
	r := newTestRunner(t, testSpec(), RunnerOptions{KillGrace: 200 * time.Millisecond})
	pidfile := filepath.Join(t.TempDir(), "pid")
	s := r.spec
	s.Tool("spawn").TimeoutSeconds = 1
	start := time.Now()
	res, err := r.Call(context.Background(), "spawn", []byte(`{"pidfile":"`+pidfile+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Canceled || !res.Failed() {
		t.Fatalf("result = %+v", res)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %v", elapsed)
	}
	waitDead(t, readPID(t, pidfile))
}

func TestRunnerTimeoutEscalatesToSIGKILL(t *testing.T) {
	t.Parallel()
	r := newTestRunner(t, testSpec(), RunnerOptions{KillGrace: 200 * time.Millisecond})
	start := time.Now()
	res, err := r.Call(context.Background(), "ignoreterm", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut {
		t.Fatalf("result = %+v", res)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("SIGTERM-ignoring child survived %v", elapsed)
	}
}

func TestRunnerCancelSendsSIGTERMToGroup(t *testing.T) {
	t.Parallel()
	r := newTestRunner(t, testSpec(), RunnerOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(300*time.Millisecond, cancel)
	res, err := r.Call(ctx, "trapterm", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Canceled || res.TimedOut || res.ExitCode != 7 || !strings.Contains(res.Stdout, "got-term") {
		t.Fatalf("result = %+v", res)
	}
}

func TestRunnerCapsSharedOutput(t *testing.T) {
	t.Parallel()
	r := newTestRunner(t, testSpec(), RunnerOptions{})
	res, err := r.Call(context.Background(), "big", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || !res.Truncated {
		t.Fatalf("result exit=%d truncated=%t", res.ExitCode, res.Truncated)
	}
	if got := len(res.Stdout) + len(res.Stderr); got != r.spec.Limits.MaxOutputBytes {
		t.Fatalf("captured %d bytes, want exactly %d", got, r.spec.Limits.MaxOutputBytes)
	}
}

func TestRunnerRejectsCallsOverConcurrencyLimit(t *testing.T) {
	t.Parallel()
	r := newTestRunner(t, testSpec(), RunnerOptions{KillGrace: 200 * time.Millisecond})
	marker := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan Result, 2)
	for range 2 {
		go func() {
			res, err := r.Call(ctx, "hold", []byte(`{"dir":"`+marker+`"}`))
			if err != nil {
				t.Error(err)
			}
			done <- res
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		entries, _ := os.ReadDir(marker)
		if len(entries) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("holders did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := r.Call(context.Background(), "echo", []byte(`{"text":"x"}`)); !errors.Is(err, ErrBusy) {
		t.Fatalf("third call: want ErrBusy, got %v", err)
	}
	cancel()
	for range 2 {
		if res := <-done; !res.Canceled {
			t.Fatalf("holder result = %+v", res)
		}
	}
	if res, err := r.Call(context.Background(), "echo", []byte(`{"text":"x"}`)); err != nil || res.Failed() {
		t.Fatalf("slot not released: %+v %v", res, err)
	}
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	return pid
}

// waitDead polls until pid no longer exists.
func waitDead(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("grandchild %d still alive after call returned", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
