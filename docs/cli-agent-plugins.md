# delivery.cli-agent-plugins

Status: proposed, not a CANDIDATE yet. Package:
`github.com/ajent-social/go/cliagent`; command: `cmd/amsl-agent-plugin`.

This implements the reusable part of the capabilities repository's
`docs/protocols/cli-agent-plugin.md` contract: turn an existing, separately
installed CLI into Codex, Claude Code and Cursor plugins, with a stdio MCP
server for the CLI's declared commands. It was added under an explicit
maintainer assignment that widened bootstrap scope for this component only.
That assignment does not authorize maturity promotion or publication.

## Boundary

The input is a reviewed, versioned JSON spec. Nothing is inferred: no LLM, no
parsing of `--help`, no trial execution. Any CLI can be described if each
operation is a **fixed argv prefix followed by named, typed inputs** (string,
boolean or integer; flag or positional; required or optional; optional string
enum or integer bounds). CLIs whose operations need variadic lists, stdin,
interactive prompts, environment-variable inputs or subcommands chosen at run
time are out of scope until a real consumer needs them.

The CLI stays canonical. The server resolves the bare executable name once on
`PATH`, runs the spec's version probe (argv plus required output text, exit 0)
and refuses to start otherwise. There is no fallback executable.

## Spec (schema_version 1)

- `plugin`: kebab-case name, semver version, description, author, optional
  https homepage/repository/author URL, SPDX-style license, keywords.
- `cli`: `executable` (bare name), `install` guidance, `version_probe`.
- `skill`: kebab-case name, description, Markdown workflow instructions.
- `limits`: `timeout_seconds` (1..600), `max_output_bytes` (1..1 MiB, shared by
  stdout and stderr of one call), `max_concurrent` (1..16).
- `tools`: 1..64 tools with `[a-z][a-z0-9_]*` names, description, fixed `argv`
  prefix, ordered `inputs`, optional per-tool `timeout_seconds`, and `effects`
  (`read_only`, `destructive`, `idempotent`, `network`, `cost`: none|possible,
  `notes`).

Parsing rejects unknown fields, duplicate keys at any depth, trailing values,
oversize input (256 KiB source or 96 KiB canonical inline JSON), malformed identifiers and URLs, control characters, duplicate
tool/input names and flags, flag+positional ambiguity, boolean positionals,
positional enum values or integers that could start with `-`, and
`read_only && destructive`. A spec is rejected before anything is written or
executed.

## Runtime

`amsl-agent-plugin serve (--spec FILE | --spec-json JSON) [--workspace DIR]`:

- Uses the official `github.com/modelcontextprotocol/go-sdk/mcp` v1.8.0 over
  stdio. Stdout carries protocol only; diagnostics go to stderr. No HTTP.
- Advertises exactly the declared tools with closed input schemas
  (`additionalProperties: false`) and annotations mapped from `effects`. The
  server re-validates every call: undeclared arguments, missing required
  inputs, wrong types, enum or bound violations, empty or control-character
  strings and positional values starting with `-` are tool errors and no
  process starts.
- Builds argv as prefix + inputs in declaration order; each value is exactly
  one argument; `exec.CommandContext`, never a shell.
- Child cwd is `--workspace` or the server's startup directory (hosts usually
  start it in the project). The environment is inherited unchanged: the CLI
  runs with the same trust and configuration as calling it directly. The
  server never reads or serializes secret values.
- Each call runs in its own process group. Timeout or MCP cancellation sends
  SIGTERM to the group, then Wait stops after a 5 s grace and SIGKILLs; any
  group members left after Wait are SIGKILLed. Output beyond the shared cap is
  drained and discarded with `truncated: true`.
- Concurrency is a fixed slot count; calls over the limit are rejected
  immediately, not queued.
- Results are `{argv, exit_code, stdout, stderr, truncated, timed_out,
  canceled}` as structured content plus JSON text, with `isError` for non-zero
  exit, timeout or cancellation. A failed process wait adds `wait_error` and
  also sets `isError`, including when a successful child leaves output pipes
  open past the collection grace period. No usage or cost is reported because the
  server does not know it.

Unix only (process groups). Other platforms compile and fail at startup.

What this is not: schemas and annotations are declared hints, not
authorization, sandboxing or approval. The CLI can print anything, including
secrets, and output is returned unredacted. Keep host tool-approval settings.

## Generated layout

`amsl-agent-plugin generate --spec FILE --out DIR` writes three independent
host folders and one local Codex marketplace catalog:

| Host | Manifest | Notes |
| --- | --- | --- |
| `codex/` | `.codex-plugin/plugin.json` | declares `skills` and `mcpServers: ./.mcp.json`; skill has `agents/openai.yaml` with `allow_implicit_invocation: false` |
| `claude-code/` | `.claude-plugin/plugin.json` | root `skills/` and `.mcp.json` are auto-discovered, so they are not declared twice |
| `cursor/` | `.cursor-plugin/plugin.json` | declares `skills` and `mcpServers: ./.mcp.json` |

Every folder also has `skills/<name>/SKILL.md` (same body on every host;
`disable-model-invocation: true` on Claude Code and Cursor), `.mcp.json`
running `amsl-agent-plugin serve --spec-json <canonical spec>`, the bundled
canonical spec, a README and `amsl-provenance.json` (spec SHA-256 and every
file's SHA-256). No hooks, installers, binaries or global config.

`DIR/.agents/plugins/marketplace.json` makes `DIR` a local Codex marketplace
source. The marketplace and its single plugin entry are both named after
`plugin.name`; the entry is `source: {source: "local", path: "./codex"}`,
`policy: {installation: AVAILABLE, authentication: ON_INSTALL}`, category
`Developer Tools`. The path is relative to `DIR`, never a URL. The codex
provenance records the catalog's SHA-256 under `output_root_files`
(`generator_format` 2). Install, with both `amsl-agent-plugin` and the CLI on
`PATH`:

```sh
codex plugin marketplace add DIR
codex plugin add NAME@NAME
```

Both commands write the invoking user's Codex configuration and copy the codex
folder into Codex's plugin cache; re-run `codex plugin add` after regenerating.

Output is a pure function of the spec: no clock, environment or local paths.
`DIR` must be absent or an empty real directory. Files are staged in a sibling
temp directory and moved with one rename; an empty `DIR` is removed with rmdir
first (macOS refuses to rename onto it). Existing content, symlinks and files
are refused and left untouched, and concurrent generators produce exactly one
winner. `check` is read-only and reports changed, missing and unexpected
files, unexpected directories, symlinks and non-regular entries. `files`
prints the exact relative paths `generate` writes, for callers that must
declare write scopes.

## Decisions

- **Inline spec in `.mcp.json`.** Plugin-root variables differ by host
  (`${CLAUDE_PLUGIN_ROOT}`, `${CURSOR_PLUGIN_ROOT}`, none documented for
  Codex). Passing the canonical spec inline avoids inventing interpolation;
  the bundled file is the same bytes indented, for review.
- **Codex compatibility layout.** Locally installed Codex plugins (Codex CLI
  0.157.1) use `.codex-plugin/plugin.json` with `skills` and
  `mcpServers: ./.mcp.json`. The portable root `plugin.json` + `mcp.json`
  format was not emitted because its stdio server shape was not verified
  locally.
- **One local marketplace at the output root.** The OpenAI plugin build guide
  documents `$ROOT/.agents/plugins/marketplace.json` with `./`-prefixed
  `source.path` resolved from the marketplace root and requires
  `policy.installation`, `policy.authentication` and `category` on each entry.
  Naming the marketplace after the plugin keeps the install selector
  deterministic (`NAME@NAME`) and derived only from validated spec fields.
  Claude Code and Cursor marketplace files are not generated; distribution for
  those hosts stays with the repository that ships the folders.
- **Low-level `Server.AddTool`.** The typed `mcp.AddTool` infers schemas from
  Go types; tools here are data-defined, so the server supplies the schema and
  validates arguments itself.
- **Reject, don't queue, over the concurrency limit.** A queued call could
  wait past the host's own timeout with no visible reason.
- **SIGTERM before SIGKILL.** CLIs that journal state (for example, marking an
  attempt uncertain on cancellation) need a chance to record it.
- **No array inputs.** The one consumer did not need them.

## Tests (offline)

`go test ./cliagent/ ./cmd/amsl-agent-plugin/` uses a `/bin/sh` fake CLI in
temp directories. Covered: 8 malformed-JSON and 47 invalid-spec cases; argv
construction with shell metacharacters, quoting and leading dashes; 21
invalid-argument cases; deterministic three-host rendering, identical skill
bodies, inline/bundled spec round-trip, provenance digests, the marketplace
entry resolving to the codex manifest of the same name, no embedded
environment values or local paths; generate into absent/empty directories,
refusal of non-empty/hidden-file/file/symlink targets without modification,
invalid spec writes nothing, eight concurrent generators with one winner;
check detecting changed/missing/extra files (including a redirected
marketplace source), extra directories, symlinked
files and roots, and spec changes, read-only; subprocess success, non-zero
exit, unknown tool, missing executable (injected and real `PATH`), relative
resolution, version mismatch and failing probe; inherited environment and cwd;
timeout killing a grandchild; SIGKILL escalation for a SIGTERM-ignoring child;
cancellation delivering SIGTERM; shared output cap; concurrency rejection and
slot release. MCP tests use the official SDK client in memory
(initialize, list, annotations, call success, tool errors, invalid arguments,
unknown tool, client cancellation killing the child process group) and one
real stdio subprocess started with the exact argv from a generated
`.mcp.json`, plus startup failure with clean stdout when the CLI is missing.

`TestExternalPluginSmoke` is skipped unless `AMSL_AGENT_PLUGIN_SMOKE_PLUGIN`
and `AMSL_AGENT_PLUGIN_SMOKE_CALLS` point at a generated host folder and a
call plan; it starts the installed binaries exactly as the folder's
`.mcp.json` declares.

## Consumer evidence

One product-local consumer generated its own plugins by dispatching this
command through its own harness, and exercised the MCP server against its
real CLI. That evidence is restricted maintainer evidence and cannot be
verified by readers. It is not independent adoption.

Host qualification completed so far, and what remains, is tracked gate by
gate in [cli-agent-plugins-plan.md](cli-agent-plugins-plan.md). In short:
Codex CLI 0.157.1 registered a generated output root as a marketplace,
installed and enabled the plugin into an isolated Codex home with outbound
network denied, and listed its MCP server; `claude plugin validate` accepted
the Claude Code folder. No generated plugin has been invoked from a live host
session or UI. Generator and MCP tests are packaging and protocol checks, not
host usage evidence.

## Dependencies

`github.com/modelcontextprotocol/go-sdk` v1.8.0 (latest stable in module
metadata at the time of writing; Apache-2.0 for new contributions, MIT for
older ones, per its LICENSE). It brings `github.com/google/jsonschema-go`,
`github.com/segmentio/encoding`, `github.com/yosida95/uritemplate/v3`,
`golang.org/x/sync` and `golang.org/x/time`.
