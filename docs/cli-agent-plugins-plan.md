# delivery.cli-agent-plugins: plan and decision record

Status: proposed. This record does not promote maturity, publish a release or
accept any consumer's generated output. Contract and runtime details are in
[cli-agent-plugins.md](cli-agent-plugins.md).

## Decision

Generate host plugins from a reviewed declarative spec with one deterministic
renderer, and serve the declared CLI commands through one stdio MCP server
(`amsl-agent-plugin serve`) built on the official MCP Go SDK. Do not infer
commands, do not add HTTP transport, and do not install anything into a host.

Rejected alternatives:

- Per-host hand-written plugins: three copies drift and cannot be checked
  byte for byte.
- `--help` parsing or LLM inference: output would not be reviewable or
  reproducible.
- Wrapping the CLI in a shell: argument injection and quoting bugs.
- Plugin-root variable interpolation in `.mcp.json`: undocumented for Codex;
  the canonical spec is passed inline instead.
- Portable Codex root manifest: its stdio server shape was not verified; the
  `.codex-plugin/plugin.json` compatibility layout is used.
- Remote marketplace sources: generated catalogs only reference `./codex`
  relative to the output root, so nothing points at unpublished branches.

## Implementation steps (done)

1. `cliagent` spec parser and validator with strict decoding.
2. Argv builder with closed input schemas and per-call revalidation.
3. Renderer for `codex/`, `claude-code/`, `cursor/` and
   `.agents/plugins/marketplace.json`, with per-host provenance.
4. No-clobber `generate`, read-only `check`, and `files` for write scopes.
5. Runner with process groups, SIGTERM then SIGKILL, shared output cap and
   concurrency rejection; MCP server mapping effects to annotations.
6. `cmd/amsl-agent-plugin` with `generate`, `check`, `files`, `serve`.
7. Offline tests: fake CLI, in-memory SDK client, one stdio subprocess.

## Host qualification gates

Each gate lists how to run it and what counts as a pass. Record the tool
version, date, exact commands and outcome. Maintainer-run evidence is
restricted and unverified by readers unless its artifacts are published.

| Gate | State |
| --- | --- |
| G1 Spec validation and deterministic rendering | complete (offline tests) |
| G2 No-clobber generate and read-only drift check | complete (offline tests) |
| G3 MCP protocol: SDK client in memory and stdio subprocess | complete (offline tests) |
| G4 Consumer self-application through its own dispatch harness | complete (restricted maintainer evidence) |
| G5 Independent stdio probe of a generated Codex `.mcp.json` | complete (restricted maintainer evidence) |
| G6 Codex marketplace registration and install, isolated | complete (restricted maintainer evidence) |
| G7 Claude Code manifest validation | complete (restricted maintainer evidence) |
| G8 Codex live session use | remaining |
| G9 Claude Code live session use | remaining |
| G10 Cursor load and use | remaining |
| G11 Full-module vet and race tests | complete (local qualification and PR CI with PostgreSQL) |
| G12 Maintainer review of source and consumer generated output | complete (coordinator inspection, headless review and regression corrections) |
| G13 Catalog promotion | not started; needs independent consumer evidence |

### G5: stdio probe

Start the command and arguments from `codex/.mcp.json` with the official SDK
client. Pass: the declared tool count lists, a read-only tool succeeds, and a
failing call returns `isError` with the CLI's stderr.

### G6: Codex marketplace, isolated (Codex CLI 0.157.1)

Run with an empty, throwaway `CODEX_HOME` and `HOME`, outbound network denied
(for example with macOS `sandbox-exec`), and `env -i PATH=/usr/bin:/bin`:

```sh
codex plugin marketplace add DIR --json
codex plugin marketplace list
codex plugin add NAME@NAME --json
codex plugin list
codex mcp list
```

Observed pass: marketplace `NAME` registered with root `DIR`; plugin
`NAME@NAME` installed at version `plugin.version` (cache path
`plugins/cache/NAME/NAME/VERSION`, not `local` as the guide states for local
plugins) and listed as installed and enabled with source `DIR/codex`; the
cached copy was byte-identical to `DIR/codex`; `codex mcp list` showed server
`NAME` running `amsl-agent-plugin serve --spec-json ...`. No user or global
Codex configuration was touched. This does not start a model session.

### G7: Claude Code validation

`claude plugin validate --json DIR/claude-code`. Pass: valid with no errors.

### G8: Codex live session (remaining)

With both binaries on `PATH`, install as in G6 into the maintainer's normal
Codex home, start a session in a trusted project, and confirm: the plugin is
enabled, the skill is listed and only runs when invoked by name, the MCP tools
list, one read-only tool call succeeds, and one failing call surfaces the
CLI's stderr. Then remove the plugin and marketplace
(`codex plugin remove NAME@NAME`, `codex plugin marketplace remove NAME`).
This needs the maintainer's authenticated account and is not automated.

### G9: Claude Code live session (remaining)

`claude --plugin-dir DIR/claude-code` in a trusted project. Pass: `/mcp`
shows server `NAME` connected with the declared tools, the skill is
user-invocable only, and the same read-only and failing calls behave as in G8.

### G10: Cursor (remaining)

Copy `DIR/cursor` to `~/.cursor/plugins/local/NAME` and reload. Pass: the
plugin, skill and MCP server appear, tools list, and the G8 calls behave the
same. Remove the folder afterwards. No Cursor manifest validator is known.

### G11 and G12

Run the full module suite, including race tests, under the shared build lease.
Review the source change and the consumer's generated output; only then may
the consumer commit its generated folders.

## Known limits

Unix only for tool execution. No array, stdin or environment-variable inputs.
A CLI that exits while a background process holds stdout makes the call wait
up to the output-collection grace period, then return a `wait_error`. Tool annotations are hints, not authorization. Output is
returned unredacted.
