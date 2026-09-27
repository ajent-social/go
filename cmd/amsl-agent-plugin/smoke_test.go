//go:build unix

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestExternalPluginSmoke starts the MCP server exactly as a generated host
// plugin's .mcp.json declares (installed binaries resolved from PATH) and runs
// the calls listed in a JSON file. It is skipped unless both variables are set:
//
//	AMSL_AGENT_PLUGIN_SMOKE_PLUGIN=path/to/generated/<host>
//	AMSL_AGENT_PLUGIN_SMOKE_CALLS=path/to/calls.json
//
// calls.json: {"cwd": DIR, "calls": [{"tool": NAME, "arguments": {...},
// "want_error": BOOL, "want_text": SUBSTRING, "background": BOOL,
// "delay_ms": N}]}. A background call runs concurrently with later calls and
// is checked at the end; delay_ms waits before issuing a call.
func TestExternalPluginSmoke(t *testing.T) {
	pluginDir := os.Getenv("AMSL_AGENT_PLUGIN_SMOKE_PLUGIN")
	callsPath := os.Getenv("AMSL_AGENT_PLUGIN_SMOKE_CALLS")
	if pluginDir == "" || callsPath == "" {
		t.Skip("set AMSL_AGENT_PLUGIN_SMOKE_PLUGIN and AMSL_AGENT_PLUGIN_SMOKE_CALLS to run")
	}
	raw, err := os.ReadFile(filepath.Join(pluginDir, ".mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || len(cfg.MCPServers) != 1 {
		t.Fatalf(".mcp.json: %v (%d servers)", err, len(cfg.MCPServers))
	}
	var plan struct {
		Cwd   string `json:"cwd"`
		Calls []struct {
			Tool       string         `json:"tool"`
			Arguments  map[string]any `json:"arguments"`
			WantError  bool           `json:"want_error"`
			WantText   string         `json:"want_text"`
			Background bool           `json:"background"`
			DelayMS    int            `json:"delay_ms"`
		} `json:"calls"`
	}
	rawCalls, err := os.ReadFile(callsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawCalls, &plan); err != nil {
		t.Fatal(err)
	}
	for name, srv := range cfg.MCPServers {
		cmd := exec.Command(srv.Command, srv.Args...)
		cmd.Dir = plan.Cwd
		cmd.Stderr = os.Stderr
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cs, err := mcp.NewClient(&mcp.Implementation{Name: "external-smoke", Version: "0"}, nil).
			Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
		if err != nil {
			t.Fatalf("connect %s: %v", name, err)
		}
		defer cs.Close()
		tools, err := cs.ListTools(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, tool := range tools.Tools {
			names = append(names, tool.Name)
		}
		t.Logf("server %s (%s) tools: %s", name, cs.InitializeResult().ServerInfo.Version, strings.Join(names, ","))
		var wg sync.WaitGroup
		for i, c := range plan.Calls {
			time.Sleep(time.Duration(c.DelayMS) * time.Millisecond)
			call := func() {
				start := time.Now()
				res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: c.Tool, Arguments: c.Arguments})
				if err != nil {
					t.Errorf("call %d %s: protocol error %v", i, c.Tool, err)
					return
				}
				var text strings.Builder
				for _, content := range res.Content {
					if tc, ok := content.(*mcp.TextContent); ok {
						text.WriteString(tc.Text)
					}
				}
				summary := text.String()
				if len(summary) > 600 {
					summary = summary[:600] + "..."
				}
				t.Logf("call %d %s is_error=%t after %v: %s", i, c.Tool, res.IsError, time.Since(start).Round(time.Millisecond), summary)
				if res.IsError != c.WantError {
					t.Errorf("call %d %s: is_error=%t, want %t", i, c.Tool, res.IsError, c.WantError)
				}
				if c.WantText != "" && !strings.Contains(text.String(), c.WantText) {
					t.Errorf("call %d %s: output lacks %q", i, c.Tool, c.WantText)
				}
			}
			if c.Background {
				wg.Add(1)
				go func() {
					defer wg.Done()
					call()
				}()
				continue
			}
			call()
		}
		wg.Wait()
	}
}
