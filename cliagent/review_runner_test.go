//go:build unix

package cliagent

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestRunnerReportsIncompleteOutput(t *testing.T) {
	s := testSpec()
	s.Tools = append(s.Tools, &Tool{Name: "background", Description: "Leave output pipe open.", Argv: []string{"background"}, Effects: s.Tools[0].Effects})
	r := newTestRunner(t, s, RunnerOptions{KillGrace: 50 * time.Millisecond})
	res, err := r.Call(context.Background(), "background", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Failed() || !strings.Contains(res.WaitError, exec.ErrWaitDelay.Error()) {
		t.Fatalf("incomplete output reported as success: %+v", res)
	}
}

func TestMCPReportsIncompleteOutputAsToolError(t *testing.T) {
	s := testSpec()
	s.Tools = append(s.Tools, &Tool{Name: "background", Description: "Leave output pipe open.", Argv: []string{"background"}, Effects: s.Tools[0].Effects})
	cs := connect(t, newTestRunner(t, s, RunnerOptions{KillGrace: 50 * time.Millisecond}))
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "background"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(textOf(t, res), exec.ErrWaitDelay.Error()) {
		t.Fatalf("incomplete output not surfaced as tool error: %+v", res)
	}
}
