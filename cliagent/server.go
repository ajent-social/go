package cliagent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// resultSchema is the output schema of every tool.
var resultSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"argv":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"exit_code":  map[string]any{"type": "integer"},
		"stdout":     map[string]any{"type": "string"},
		"stderr":     map[string]any{"type": "string"},
		"truncated":  map[string]any{"type": "boolean"},
		"timed_out":  map[string]any{"type": "boolean"},
		"canceled":   map[string]any{"type": "boolean"},
		"wait_error": map[string]any{"type": "string"},
	},
	"required": []string{"argv", "exit_code", "stdout", "stderr", "truncated", "timed_out", "canceled"},
}

// NewServer returns an MCP server advertising exactly the tools declared in
// the runner's spec. Argument errors, busy rejections and process failures are
// tool results with IsError set, so the calling model sees them.
func NewServer(r *Runner) *mcp.Server {
	s := r.spec
	server := mcp.NewServer(&mcp.Implementation{
		Name:    s.Plugin.Name,
		Title:   displayName(s),
		Version: s.Plugin.Version,
	}, &mcp.ServerOptions{
		Instructions: fmt.Sprintf("%s Tools run the installed %s CLI without a shell. Annotations are declared hints, not enforcement.",
			s.Skill.Description, s.CLI.Executable),
		Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
	})
	for _, t := range s.Tools {
		server.AddTool(mcpTool(t), toolHandler(r, t.Name))
	}
	return server
}

func mcpTool(t *Tool) *mcp.Tool {
	destructive := t.Effects.Destructive
	network := t.Effects.Network
	title := t.Title
	if title == "" {
		title = t.Name
	}
	return &mcp.Tool{
		Name:         t.Name,
		Title:        title,
		Description:  t.Description,
		InputSchema:  t.InputSchema(),
		OutputSchema: resultSchema,
		Annotations: &mcp.ToolAnnotations{
			Title:           title,
			ReadOnlyHint:    t.Effects.ReadOnly,
			DestructiveHint: &destructive,
			IdempotentHint:  t.Effects.Idempotent,
			OpenWorldHint:   &network,
		},
	}
}

func toolHandler(r *Runner, name string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		res, err := r.Call(ctx, name, req.Params.Arguments)
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
			}, nil
		}
		body, err := json.Marshal(res)
		if err != nil {
			return nil, err
		}
		return &mcp.CallToolResult{
			IsError:           res.Failed(),
			Content:           []mcp.Content{&mcp.TextContent{Text: string(body)}},
			StructuredContent: res,
		}, nil
	}
}
