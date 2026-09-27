# CLI agent plugin qualification — 2026-09-26

Local macOS arm64 / Go 1.27.1 evidence for the proposed implementation. This
record does not promote the capability catalog or claim independent adoption.

- `gofmt -l cliagent cmd`: clean. `go vet ./...`: passed.
- `go test -race -count=1 -timeout 240s -json ./...`: 348 passing test/subtest
  records, 36 passing test packages, no failures; remaining packages had no
  tests. One opt-in external-consumer smoke test skipped in the default suite.
- The full race run initially found an unsynchronized stderr buffer in the
  command's protocol test. A synchronized test-only writer fixes it; five
  repeated race runs of the command package and the full suite passed afterward.
- `go build ./cmd/amsl-agent-plugin`: passed. Production execution code was
  unchanged by the test-buffer correction.
- The generated Codex marketplace was registered and installed by the real
  Codex CLI in temporary settings with network access blocked. The real user
  profile was unchanged by that test. Claude Code's strict plugin validator
  passed without warnings.
- Separate stdio clients started the generated configurations for all three
  hosts, initialized MCP, listed tools and exercised success and failure paths.
  Missing, undeclared and incorrectly typed arguments were rejected;
  shell-looking values remained literal arguments. A local consumer catalog
  call succeeded. These protocol probes are separate from interactive host use.

Downstream consumer source and raw journals are local maintainer evidence, not
publicly reproducible adoption evidence from this repository. No interactive
Codex/Claude Code/Cursor agent invocation or remote CI is claimed. Runtime
commands require Unix and installed executables; the adapter is not a sandbox.

## Review corrections and PR qualification

Three executable regressions reproduced failures before correction:

- publication could unlink a competing writer's file after its final check;
- a child exiting zero with inherited output pipes left open could be reported
  as successful after `exec.ErrWaitDelay`;
- a validated specification could render an inline JSON argument larger than
  Linux accepts.

Publication now uses directory-only removal. Results preserve wait errors and
MCP reports them as tool failures. Validation caps the canonical, escaped
inline specification at 96 KiB. Four focused regression tests passed under the
race detector, including a real MCP client/server error assertion. The full
`cliagent` and command package race suites, package vet and command build also
passed after these corrections. Generated downstream output remained identical,
and independent stdio probes of all three host configurations passed again.

[PR #15](https://github.com/ajent-social/go/pull/15) ran full-module vet and race
tests with PostgreSQL enabled, the storage cross-compilation matrix and the
Windows unsupported-platform test successfully. The non-PostgreSQL alternative
job is intentionally skipped when the PostgreSQL job runs. This supersedes the
initial local-only CI limitation above; live host agent/UI use remains unverified.
