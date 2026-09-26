//go:build unix

package cliagent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func connect(t *testing.T, r *Runner) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	serverT, clientT := mcp.NewInMemoryTransports()
	ss, err := NewServer(r).Connect(ctx, serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func textOf(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	var b strings.Builder
	for _, c := range res.Content {
		tc, ok := c.(*mcp.TextContent)
		if !ok {
			t.Fatalf("unexpected content %T", c)
		}
		b.WriteString(tc.Text)
	}
	return b.String()
}

func TestMCPInitializeAndListOnlyDeclaredTools(t *testing.T) {
	t.Parallel()
	s := testSpec()
	cs := connect(t, newTestRunner(t, s, RunnerOptions{}))
	init := cs.InitializeResult()
	if init.ServerInfo.Name != "fake-cli" || init.ServerInfo.Version != "0.1.0" || init.Capabilities.Tools == nil {
		t.Fatalf("initialize result = %+v", init)
	}
	list, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range list.Tools {
		names = append(names, tool.Name)
	}
	var want []string
	for _, tool := range s.Tools {
		want = append(want, tool.Name)
	}
	if !reflect.DeepEqual(sortedCopy(names), sortedCopy(want)) {
		t.Fatalf("tools = %v, want %v", names, want)
	}
	for _, tool := range list.Tools {
		decl := s.Tool(tool.Name)
		a := tool.Annotations
		if a == nil || a.ReadOnlyHint != decl.Effects.ReadOnly || a.DestructiveHint == nil || *a.DestructiveHint != decl.Effects.Destructive ||
			a.OpenWorldHint == nil || *a.OpenWorldHint != decl.Effects.Network || a.IdempotentHint != decl.Effects.Idempotent {
			t.Fatalf("%s annotations %+v do not match effects %+v", tool.Name, a, decl.Effects)
		}
		schema := tool.InputSchema.(map[string]any)
		if schema["additionalProperties"] != false {
			t.Fatalf("%s input schema is open", tool.Name)
		}
	}
}

func TestMCPCallToolResults(t *testing.T) {
	t.Parallel()
	cs := connect(t, newTestRunner(t, testSpec(), RunnerOptions{}))
	ctx := context.Background()

	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: map[string]any{"text": "hi; rm -rf /", "count": 2}})
	if err != nil {
		t.Fatal(err)
	}
	var got Result
	raw, _ := json.Marshal(res.StructuredContent)
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if res.IsError || got.ExitCode != 0 || got.Stdout != "--count\n2\nhi; rm -rf /\n" {
		t.Fatalf("echo result = %+v / %+v", res, got)
	}

	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "fail"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(textOf(t, res), `"exit_code":3`) || !strings.Contains(textOf(t, res), "boom") {
		t.Fatalf("fail result = %+v %s", res, textOf(t, res))
	}

	for _, args := range []map[string]any{
		{},
		{"text": "x", "executable": "/bin/sh"},
		{"text": "-rf"},
		{"text": "x", "mode": "z"},
	} {
		res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "echo", Arguments: args})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(textOf(t, res), "invalid arguments") {
			t.Fatalf("args %v: result = %s", args, textOf(t, res))
		}
	}

	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "sh", Arguments: map[string]any{}}); err == nil {
		t.Fatal("undeclared tool must be a protocol error")
	}
}

func TestMCPClientCancellationKillsChild(t *testing.T) {
	t.Parallel()
	s := testSpec()
	cs := connect(t, newTestRunner(t, s, RunnerOptions{KillGrace: 200 * time.Millisecond}))
	pidfile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "spawn", Arguments: map[string]any{"pidfile": pidfile}})
		errc <- err
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, err := os.ReadFile(pidfile); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("spawn did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-errc; err == nil {
		t.Fatal("canceled call returned no error")
	}
	waitDead(t, readPID(t, pidfile))
}

func sortedCopy(in []string) []string {
	return slices.Sorted(slices.Values(in))
}
