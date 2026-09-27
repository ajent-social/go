package cliagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrBusy reports that MaxConcurrent invocations are already running.
var ErrBusy = errors.New("cliagent: concurrency limit reached; call rejected")

// ErrUnknownTool reports a tool name the spec does not declare.
var ErrUnknownTool = errors.New("cliagent: unknown tool")

// ErrIncompatibleCLI reports a missing executable or failed version probe.
var ErrIncompatibleCLI = errors.New("cliagent: CLI missing or incompatible")

// DefaultKillGrace is how long a canceled or timed-out process group has after
// SIGTERM before SIGKILL.
const DefaultKillGrace = 5 * time.Second

const probeTimeout = 30 * time.Second

// RunnerOptions configure NewRunner.
type RunnerOptions struct {
	// Workspace is the child working directory. Empty means the current
	// working directory at startup.
	Workspace string
	// KillGrace overrides DefaultKillGrace when positive.
	KillGrace time.Duration
	// LookPath overrides exec.LookPath (tests only need this to avoid
	// mutating PATH).
	LookPath func(string) (string, error)
}

// Runner invokes declared tools of one resolved executable.
type Runner struct {
	spec       *Spec
	executable string
	workspace  string
	killGrace  time.Duration
	slots      chan struct{}
}

// Result is the structured outcome of one invocation. It never contains usage
// or cost figures: the runner does not know them.
type Result struct {
	Argv      []string `json:"argv"`
	ExitCode  int      `json:"exit_code"`
	Stdout    string   `json:"stdout"`
	Stderr    string   `json:"stderr"`
	Truncated bool     `json:"truncated"`
	TimedOut  bool     `json:"timed_out"`
	Canceled  bool     `json:"canceled"`
	// WaitError reports incomplete output collection or another wait failure.
	WaitError string `json:"wait_error,omitempty"`
}

// Failed reports whether the invocation did not complete successfully.
func (r Result) Failed() bool {
	return r.ExitCode != 0 || r.TimedOut || r.Canceled || r.WaitError != ""
}

// NewRunner validates s, resolves its executable once through PATH to an
// absolute path, and runs the version probe. It returns ErrIncompatibleCLI
// (with the probe output) when the CLI is absent or the probe fails; there is
// no fallback executable.
func NewRunner(ctx context.Context, s *Spec, opts RunnerOptions) (*Runner, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if err := platformSupported(); err != nil {
		return nil, err
	}
	lookPath := opts.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	exe, err := lookPath(s.CLI.Executable)
	if err != nil {
		return nil, fmt.Errorf("%w: resolving %q on PATH: %v", ErrIncompatibleCLI, s.CLI.Executable, err)
	}
	if !filepath.IsAbs(exe) {
		return nil, fmt.Errorf("%w: %q resolved to relative path %q; put an absolute directory on PATH", ErrIncompatibleCLI, s.CLI.Executable, exe)
	}
	ws := opts.Workspace
	if ws == "" {
		if ws, err = os.Getwd(); err != nil {
			return nil, fmt.Errorf("cliagent: workspace: %w", err)
		}
	}
	if ws, err = filepath.Abs(ws); err != nil {
		return nil, fmt.Errorf("cliagent: workspace: %w", err)
	}
	fi, err := os.Stat(ws)
	if err != nil {
		return nil, fmt.Errorf("cliagent: workspace: %w", err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("cliagent: workspace %s is not a directory", ws)
	}
	grace := opts.KillGrace
	if grace <= 0 {
		grace = DefaultKillGrace
	}
	r := &Runner{
		spec:       s,
		executable: exe,
		workspace:  ws,
		killGrace:  grace,
		slots:      make(chan struct{}, s.Limits.MaxConcurrent),
	}
	probe := s.CLI.VersionProbe
	res := r.exec(ctx, append([]string(nil), probe.Argv...), probeTimeout)
	combined := res.Stdout + res.Stderr
	if res.Failed() || !strings.Contains(combined, probe.RequireOutput) {
		return nil, fmt.Errorf("%w: %s %s: exit=%d timed_out=%t; required output %q not found; output: %s",
			ErrIncompatibleCLI, s.CLI.Executable, strings.Join(probe.Argv, " "), res.ExitCode, res.TimedOut,
			probe.RequireOutput, truncateForError(combined))
	}
	return r, nil
}

// Executable returns the absolute path resolved at startup.
func (r *Runner) Executable() string { return r.executable }

// Workspace returns the child working directory.
func (r *Runner) Workspace() string { return r.workspace }

// Call validates arguments and runs the named tool. Validation, busy and
// unknown-tool failures return an error before any process starts; process
// outcomes (including non-zero exit, timeout and cancellation) are reported in
// Result.
func (r *Runner) Call(ctx context.Context, tool string, args json.RawMessage) (Result, error) {
	t := r.spec.Tool(tool)
	if t == nil {
		return Result{}, fmt.Errorf("%w %q", ErrUnknownTool, tool)
	}
	argv, err := t.BuildArgv(args)
	if err != nil {
		return Result{}, err
	}
	select {
	case r.slots <- struct{}{}:
	default:
		return Result{}, fmt.Errorf("%w (max_concurrent=%d)", ErrBusy, r.spec.Limits.MaxConcurrent)
	}
	defer func() { <-r.slots }()
	res := r.exec(ctx, argv, time.Duration(r.spec.timeoutFor(t))*time.Second)
	if res.startErr != nil {
		return Result{}, res.startErr
	}
	return res.Result, nil
}

type execResult struct {
	Result
	startErr error
}

func (r *Runner) exec(ctx context.Context, argv []string, timeout time.Duration) execResult {
	display := append([]string{r.spec.CLI.Executable}, argv...)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	budget := &outputBudget{remaining: r.spec.Limits.MaxOutputBytes}
	stdout := &cappedBuffer{budget: budget}
	stderr := &cappedBuffer{budget: budget}
	cmd := exec.CommandContext(runCtx, r.executable, argv...)
	cmd.Dir = r.workspace
	cmd.Stdin = nil
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	configureProcessGroup(cmd, r.killGrace)
	if err := cmd.Start(); err != nil {
		return execResult{Result: Result{Argv: display, ExitCode: -1}, startErr: fmt.Errorf("cliagent: starting %s: %w", r.spec.CLI.Executable, err)}
	}
	waitErr := cmd.Wait()
	killProcessGroup(cmd)
	res := Result{
		Argv:      display,
		ExitCode:  exitCode(cmd, waitErr),
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Truncated: budget.truncated(),
	}
	if waitErr != nil {
		res.WaitError = waitErr.Error()
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		res.TimedOut = true
	} else if ctx.Err() != nil {
		res.Canceled = true
	}
	return execResult{Result: res}
}

func exitCode(cmd *exec.Cmd, waitErr error) int {
	if cmd.ProcessState != nil {
		if code := cmd.ProcessState.ExitCode(); code >= 0 {
			return code
		}
		return -1
	}
	if waitErr != nil {
		return -1
	}
	return 0
}

// outputBudget is shared by stdout and stderr of one invocation.
type outputBudget struct {
	mu        sync.Mutex
	remaining int
	dropped   bool
}

func (b *outputBudget) take(n int) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n > b.remaining {
		b.dropped = true
		n = b.remaining
	}
	b.remaining -= n
	return n
}

func (b *outputBudget) truncated() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.dropped
}

// cappedBuffer keeps bytes while the shared budget lasts and discards the
// rest, always reporting a full write so the child is drained, not blocked.
type cappedBuffer struct {
	mu     sync.Mutex
	budget *outputBudget
	buf    []byte
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	keep := c.budget.take(len(p))
	c.mu.Lock()
	c.buf = append(c.buf, p[:keep]...)
	c.mu.Unlock()
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.ToValidUTF8(string(c.buf), "\uFFFD")
}

func truncateForError(s string) string {
	const max = 2048
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
