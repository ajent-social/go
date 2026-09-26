package cliagent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Hosts rendered by [Render], in output order.
const (
	HostCodex      = "codex"
	HostClaudeCode = "claude-code"
	HostCursor     = "cursor"
)

// Hosts lists every rendered host directory.
var Hosts = []string{HostCodex, HostClaudeCode, HostCursor}

// ServerCommand is the executable host MCP configuration starts. It must be
// installed on PATH alongside the described CLI.
const ServerCommand = "amsl-agent-plugin"

const (
	generatorID     = "github.com/ajent-social/go/cliagent"
	generatorFormat = 1
	bundledSpecName = "amsl-agent-plugin.spec.json"
	provenanceName  = "amsl-provenance.json"
)

// File is one rendered artifact. Path is slash-separated and relative to the
// output directory.
type File struct {
	Path string
	Data []byte
}

// Render returns every generated file for all hosts, sorted by path. Output is
// a pure function of the validated spec: no clock, environment, or local paths.
func Render(s *Spec) ([]File, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	canonical, err := s.Canonical()
	if err != nil {
		return nil, err
	}
	specDigest := sha256Hex(canonical)
	bundled, err := indentJSON(canonical)
	if err != nil {
		return nil, err
	}
	mcpConfig, err := marshalJSON(map[string]any{
		"mcpServers": map[string]any{
			s.Plugin.Name: map[string]any{
				"command": ServerCommand,
				"args":    []string{"serve", "--spec-json", string(canonical)},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	body := skillBody(s)
	var out []File
	for _, host := range Hosts {
		manifestPath, manifest, err := hostManifest(s, host)
		if err != nil {
			return nil, err
		}
		files := []File{
			{manifestPath, manifest},
			{".mcp.json", mcpConfig},
			{"skills/" + s.Skill.Name + "/SKILL.md", skillFile(s, host, body)},
			{bundledSpecName, bundled},
			{"README.md", readme(s, host)},
		}
		if host == HostCodex {
			files = append(files, File{"skills/" + s.Skill.Name + "/agents/openai.yaml", codexSkillPolicy(s)})
		}
		prov, err := provenance(s, host, specDigest, files)
		if err != nil {
			return nil, err
		}
		files = append(files, File{provenanceName, prov})
		for _, f := range files {
			out = append(out, File{Path: host + "/" + f.Path, Data: f.Data})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func hostManifest(s *Spec, host string) (string, []byte, error) {
	p := s.Plugin
	author := map[string]any{"name": p.Author.Name}
	if p.Author.URL != "" {
		author["url"] = p.Author.URL
	}
	m := orderedObject{
		{"name", p.Name},
		{"version", p.Version},
		{"description", p.Description},
		{"author", author},
	}
	m = m.addIf("homepage", p.Homepage)
	m = m.addIf("repository", p.Repository)
	m = m.addIf("license", p.License)
	if len(p.Keywords) > 0 {
		m = append(m, kv{"keywords", p.Keywords})
	}
	var path string
	switch host {
	case HostCodex:
		path = ".codex-plugin/plugin.json"
		capabilities := []string{"Read"}
		if hasWritingTool(s) {
			capabilities = append(capabilities, "Write")
		}
		m = append(m,
			kv{"skills", "./skills/"},
			kv{"mcpServers", "./.mcp.json"},
			kv{"interface", orderedObject{
				{"displayName", displayName(s)},
				{"shortDescription", p.Description},
				{"longDescription", s.Skill.Description},
				{"developerName", p.Author.Name},
				{"category", "Developer Tools"},
				{"capabilities", capabilities},
			}},
		)
	case HostClaudeCode:
		// Claude Code discovers skills/ and .mcp.json at the plugin root.
		path = ".claude-plugin/plugin.json"
	case HostCursor:
		path = ".cursor-plugin/plugin.json"
		if p.DisplayName != "" {
			m = append(m[:1], append(orderedObject{{"displayName", p.DisplayName}}, m[1:]...)...)
		}
		m = append(m, kv{"skills", "./skills/"}, kv{"mcpServers", "./.mcp.json"})
	default:
		return "", nil, fmt.Errorf("cliagent: unknown host %q", host)
	}
	data, err := marshalJSON(m)
	return path, data, err
}

func hasWritingTool(s *Spec) bool {
	for _, t := range s.Tools {
		if !t.Effects.ReadOnly {
			return true
		}
	}
	return false
}

func displayName(s *Spec) string {
	if s.Plugin.DisplayName != "" {
		return s.Plugin.DisplayName
	}
	return s.Plugin.Name
}

func skillFile(s *Spec, host string, body string) []byte {
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("name: " + s.Skill.Name + "\n")
	b.WriteString("description: " + yamlString(s.Skill.Description) + "\n")
	if host != HostCodex {
		b.WriteString("disable-model-invocation: true\n")
	}
	b.WriteString("---\n\n")
	b.WriteString(body)
	return []byte(b.String())
}

func codexSkillPolicy(s *Spec) []byte {
	return []byte("interface:\n" +
		"  display_name: " + yamlString(displayName(s)) + "\n" +
		"  short_description: " + yamlString(s.Plugin.Description) + "\n" +
		"policy:\n" +
		"  allow_implicit_invocation: false\n")
}

// skillBody is the canonical workflow shared byte-for-byte by every host.
func skillBody(s *Spec) string {
	var b strings.Builder
	b.WriteString(strings.TrimRight(s.Skill.Instructions, "\n") + "\n\n")
	b.WriteString("## MCP tools\n\n")
	fmt.Fprintf(&b, "The `%s` MCP server (`%s serve`) exposes only these declared commands of the installed `%s` CLI. "+
		"Each call runs `%s` directly, without a shell, in the directory where the host started the server. "+
		"Every argument value becomes exactly one command-line argument.\n\n",
		s.Plugin.Name, ServerCommand, s.CLI.Executable, s.CLI.Executable)
	writeToolList(&b, s)
	b.WriteString("\n## Boundaries\n\n")
	fmt.Fprintf(&b, "- Tool schemas and annotations describe declared effects. They are not authorization, a sandbox or an approval step. Keep the host's normal tool-approval settings.\n")
	fmt.Fprintf(&b, "- `%s` runs with this session's environment and configuration, exactly as if invoked directly. Its stdout and stderr are returned verbatim up to %d bytes combined (truncation is flagged) and may contain anything it prints, including secrets. Never place secret values in arguments.\n", s.CLI.Executable, s.Limits.MaxOutputBytes)
	fmt.Fprintf(&b, "- If the server fails to start because `%s` is missing or incompatible, or a call fails, report the error. Do not substitute another tool or simulate a result.\n", s.CLI.Executable)
	fmt.Fprintf(&b, "- Calls stop after at most %d seconds (the process group is terminated). At most %d calls run at once; extra calls are rejected, not queued.\n", s.Limits.TimeoutSeconds, s.Limits.MaxConcurrent)
	return b.String()
}

func writeToolList(b *strings.Builder, s *Spec) {
	for _, t := range s.Tools {
		fmt.Fprintf(b, "- `%s`: runs `%s %s`", t.Name, s.CLI.Executable, strings.Join(t.Argv, " "))
		if len(t.Inputs) > 0 {
			var parts []string
			for _, in := range t.Inputs {
				shape := "positional"
				if in.Flag != "" {
					shape = in.Flag
				}
				req := "optional"
				if in.Required {
					req = "required"
				}
				parts = append(parts, fmt.Sprintf("`%s` (%s %s, %s)", in.Name, req, in.Type, shape))
			}
			fmt.Fprintf(b, " with %s", strings.Join(parts, ", "))
		}
		fmt.Fprintf(b, ". %s\n", oneLine(t.Description))
		fmt.Fprintf(b, "  Effects: %s. Timeout %ds.", effectsSummary(t.Effects), s.timeoutFor(t))
		if t.Effects.Notes != "" {
			fmt.Fprintf(b, " %s", oneLine(t.Effects.Notes))
		}
		b.WriteString("\n")
	}
}

func effectsSummary(e Effects) string {
	var parts []string
	if e.ReadOnly {
		parts = append(parts, "read-only")
	} else {
		parts = append(parts, "writes")
	}
	if e.Destructive {
		parts = append(parts, "destructive")
	}
	if e.Idempotent {
		parts = append(parts, "idempotent")
	}
	if e.Network {
		parts = append(parts, "may use the network")
	} else {
		parts = append(parts, "no network declared")
	}
	if e.Cost == CostPossible {
		parts = append(parts, "may incur cost")
	} else {
		parts = append(parts, "no cost declared")
	}
	return strings.Join(parts, ", ")
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func readme(s *Spec, host string) []byte {
	var b strings.Builder
	name := displayName(s)
	fmt.Fprintf(&b, "# %s for %s\n\n", name, hostTitle(host))
	fmt.Fprintf(&b, "%s\n\n", s.Plugin.Description)
	fmt.Fprintf(&b, "Generated by `%s` from `%s`. Do not edit by hand; change the source spec and regenerate into a fresh directory.\n\n", ServerCommand, bundledSpecName)
	b.WriteString("## Requirements\n\n")
	fmt.Fprintf(&b, "Both executables must be installed on `PATH` for the host process:\n\n")
	fmt.Fprintf(&b, "- `%s`: the canonical CLI. %s\n", s.CLI.Executable, oneLine(s.CLI.Install))
	fmt.Fprintf(&b, "- `%s`: the stdio MCP server. Build it from a checkout of the AMSL Go module (`github.com/ajent-social/go`) that contains `cmd/%s`: `go build -o \"$HOME/.local/bin/%s\" ./cmd/%s` (any directory on `PATH` works). No tagged release is claimed.\n\n", ServerCommand, ServerCommand, ServerCommand, ServerCommand)
	fmt.Fprintf(&b, "At startup the server resolves `%s` on `PATH` and runs `%s %s`, which must exit 0 and print `%s`. If that fails the server exits with the error on stderr and the host shows it as failed.\n\n",
		s.CLI.Executable, s.CLI.Executable, strings.Join(s.CLI.VersionProbe.Argv, " "), s.CLI.VersionProbe.RequireOutput)
	b.WriteString("## Install\n\n")
	b.WriteString(installText(s, host))
	b.WriteString("\nInstallation in this host has not been verified by the generator. Confirm the plugin loads, the skill appears and the MCP tools list before relying on it.\n\n")
	b.WriteString("## Tools\n\n")
	writeToolList(&b, s)
	b.WriteString("\n## Boundaries\n\n")
	fmt.Fprintf(&b, "The `%s` skill is user-invoked only. The MCP tools are callable whenever the server is enabled; the host's tool-approval settings apply. "+
		"Annotations are hints, not enforcement. `%s` inherits the host environment and may print secrets, which are returned unredacted. "+
		"There are no hooks, installers, background services or credential handling in this package.\n\n", s.Skill.Name, s.CLI.Executable)
	b.WriteString("## Verify\n\n")
	fmt.Fprintf(&b, "`%s` records the SHA-256 of the canonical spec and of every file in this folder. Check the generated folders against the source spec with:\n\n", provenanceName)
	fmt.Fprintf(&b, "```sh\n%s check --spec path/to/source.spec.json --out path/to/generated\n```\n", ServerCommand)
	return []byte(b.String())
}

func hostTitle(host string) string {
	switch host {
	case HostCodex:
		return "Codex"
	case HostClaudeCode:
		return "Claude Code"
	default:
		return "Cursor"
	}
}

func installText(s *Spec, host string) string {
	n := s.Plugin.Name
	switch host {
	case HostCodex:
		return "Codex installs plugins from marketplaces (`codex plugin marketplace add SOURCE`, then `codex plugin add " + n + "@MARKETPLACE`). " +
			"This folder uses the `.codex-plugin/plugin.json` layout, which declares `skills` and `mcpServers: ./.mcp.json`. " +
			"It ships no marketplace file; the repository that distributes it must list this folder in its marketplace.\n"
	case HostClaudeCode:
		return "For local use, start Claude Code with `claude --plugin-dir path/to/claude-code`. " +
			"For distribution, list this folder in a Claude Code plugin marketplace and run `claude plugin install " + n + "@MARKETPLACE`. " +
			"Claude Code discovers `skills/` and `.mcp.json` at the plugin root.\n"
	default:
		return "For local use, copy this folder to `~/.cursor/plugins/local/" + n + "` and reload Cursor. " +
			"`.cursor-plugin/plugin.json` declares `skills` and `mcpServers: ./.mcp.json`.\n"
	}
}

func provenance(s *Spec, host, specDigest string, files []File) ([]byte, error) {
	digests := map[string]string{}
	for _, f := range files {
		digests[f.Path] = sha256Hex(f.Data)
	}
	return marshalJSON(orderedObject{
		{"schema_version", 1},
		{"generator", generatorID},
		{"generator_format", generatorFormat},
		{"host", host},
		{"plugin", orderedObject{{"name", s.Plugin.Name}, {"version", s.Plugin.Version}}},
		{"spec_sha256", specDigest},
		{"files", digests},
	})
}

// yamlString quotes s as a YAML double-quoted scalar. JSON string syntax is a
// subset of YAML 1.2 double-quoted scalars.
func yamlString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(buf.String(), "\n")
}

type kv struct {
	Key   string
	Value any
}

// orderedObject marshals as a JSON object preserving key order, so manifests
// read naturally while staying deterministic.
type orderedObject []kv

func (o orderedObject) addIf(key, value string) orderedObject {
	if value == "" {
		return o
	}
	return append(o, kv{key, value})
}

func (o orderedObject) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, e := range o {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, err := marshalCompact(e.Key)
		if err != nil {
			return nil, err
		}
		v, err := marshalCompact(e.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(k)
		buf.WriteByte(':')
		buf.Write(v)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// marshalJSON renders v as two-space indented JSON with a trailing newline.
func marshalJSON(v any) ([]byte, error) {
	compact, err := marshalCompact(v)
	if err != nil {
		return nil, err
	}
	return indentJSON(compact)
}

func indentJSON(compact []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := json.Indent(&out, compact, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
