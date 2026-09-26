// Package cliagent turns an explicit, reviewed description of an existing
// command-line tool into coding-agent host plugins (Codex, Claude Code and
// Cursor) and serves that description as a stdio MCP server.
//
// The package does not infer capabilities. A [Spec] names one canonical
// executable, a version probe, and a finite list of tools. Each tool is a fixed
// argv prefix followed by named, typed inputs rendered as flags or positional
// arguments. Anything the specification does not declare cannot be invoked:
// there is no shell, no generic command tool and no executable chosen by tool
// arguments.
//
// [Render] produces deterministic plugin files, [Generate] writes them to an
// absent or empty directory without overwriting, and [Check] detects drift
// read-only. [NewRunner] resolves and probes the installed CLI, and
// [NewServer] exposes the declared tools through the official MCP Go SDK.
//
// Tool annotations and input schemas describe declared effects; they are not
// authorization, sandboxing or approval. The CLI runs with the caller's
// environment and the same trust as invoking it directly, and its output may
// contain anything the CLI prints, including secrets. See
// docs/cli-agent-plugins.md for the contract, limits and evidence.
package cliagent
