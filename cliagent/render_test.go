package cliagent

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func renderMap(t *testing.T, s *Spec) map[string][]byte {
	t.Helper()
	files, err := Render(s)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	m := map[string][]byte{}
	for _, f := range files {
		m[f.Path] = f.Data
	}
	return m
}

func TestRenderIsDeterministicAcrossThreeHosts(t *testing.T) {
	t.Parallel()
	a, err := Render(testSpec())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Render(testSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatal("Render output differs between runs")
	}
	var paths []string
	for _, f := range a {
		paths = append(paths, f.Path)
	}
	want := []string{
		".agents/plugins/marketplace.json",
		"claude-code/.claude-plugin/plugin.json",
		"claude-code/.mcp.json",
		"claude-code/README.md",
		"claude-code/amsl-agent-plugin.spec.json",
		"claude-code/amsl-provenance.json",
		"claude-code/skills/fake-cli/SKILL.md",
		"codex/.codex-plugin/plugin.json",
		"codex/.mcp.json",
		"codex/README.md",
		"codex/amsl-agent-plugin.spec.json",
		"codex/amsl-provenance.json",
		"codex/skills/fake-cli/SKILL.md",
		"codex/skills/fake-cli/agents/openai.yaml",
		"cursor/.cursor-plugin/plugin.json",
		"cursor/.mcp.json",
		"cursor/README.md",
		"cursor/amsl-agent-plugin.spec.json",
		"cursor/amsl-provenance.json",
		"cursor/skills/fake-cli/SKILL.md",
	}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("paths =\n%s\nwant\n%s", strings.Join(paths, "\n"), strings.Join(want, "\n"))
	}
}

func TestRenderHostManifestsAndSharedWorkflow(t *testing.T) {
	t.Parallel()
	s := testSpec()
	m := renderMap(t, s)
	canonical, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}

	var bodies []string
	for _, host := range Hosts {
		skill := string(m[host+"/skills/fake-cli/SKILL.md"])
		parts := strings.SplitN(skill, "\n---\n\n", 2)
		if len(parts) != 2 || !strings.HasPrefix(parts[0], "---\nname: fake-cli\ndescription: \"Use the fake CLI in tests.\"") {
			t.Fatalf("%s SKILL.md front matter malformed:\n%s", host, skill)
		}
		manualOnly := strings.Contains(parts[0], "disable-model-invocation: true")
		if manualOnly == (host == HostCodex) {
			t.Fatalf("%s disable-model-invocation presence wrong", host)
		}
		bodies = append(bodies, parts[1])

		var mcpCfg struct {
			MCPServers map[string]struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"mcpServers"`
		}
		if err := decodeStrict(m[host+"/.mcp.json"], &mcpCfg); err != nil {
			t.Fatalf("%s .mcp.json: %v", host, err)
		}
		srv, ok := mcpCfg.MCPServers["fake-cli"]
		if !ok || srv.Command != ServerCommand || len(srv.Args) != 3 || srv.Args[0] != "serve" || srv.Args[1] != "--spec-json" {
			t.Fatalf("%s .mcp.json server = %+v", host, mcpCfg)
		}
		if srv.Args[2] != string(canonical) {
			t.Fatalf("%s inline spec is not the canonical spec", host)
		}
		inline, err := ParseSpec([]byte(srv.Args[2]))
		if err != nil || !reflect.DeepEqual(inline, s) {
			t.Fatalf("%s inline spec does not round-trip: %v", host, err)
		}
		bundled, err := ParseSpec(m[host+"/amsl-agent-plugin.spec.json"])
		if err != nil || !reflect.DeepEqual(bundled, s) {
			t.Fatalf("%s bundled spec does not round-trip: %v", host, err)
		}

		var prov struct {
			SchemaVersion   int               `json:"schema_version"`
			Generator       string            `json:"generator"`
			GeneratorFormat int               `json:"generator_format"`
			Host            string            `json:"host"`
			Plugin          map[string]string `json:"plugin"`
			SpecSHA256      string            `json:"spec_sha256"`
			Files           map[string]string `json:"files"`
			OutputRootFiles map[string]string `json:"output_root_files"`
		}
		if err := decodeStrict(m[host+"/amsl-provenance.json"], &prov); err != nil {
			t.Fatalf("%s provenance: %v", host, err)
		}
		if prov.Host != host || prov.SpecSHA256 != sha256Hex(canonical) || prov.GeneratorFormat != 2 {
			t.Fatalf("%s provenance identity = %+v", host, prov)
		}
		wantRoot := map[string]string(nil)
		if host == HostCodex {
			wantRoot = map[string]string{CodexMarketplacePath: sha256Hex(m[CodexMarketplacePath])}
		}
		if !reflect.DeepEqual(prov.OutputRootFiles, wantRoot) {
			t.Fatalf("%s provenance output_root_files = %v, want %v", host, prov.OutputRootFiles, wantRoot)
		}
		for path, data := range m {
			rel, ok := strings.CutPrefix(path, host+"/")
			if !ok || rel == "amsl-provenance.json" {
				continue
			}
			if prov.Files[rel] != sha256Hex(data) {
				t.Fatalf("%s provenance digest for %s mismatches", host, rel)
			}
			delete(prov.Files, rel)
		}
		if len(prov.Files) != 0 {
			t.Fatalf("%s provenance lists unknown files %v", host, prov.Files)
		}
	}
	if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatal("skill workflow body differs between hosts")
	}
	for _, want := range []string{"Run the fake CLI when asked.", "`echo`: runs `fakecli echo`", "not authorization, a sandbox or an approval step", "including secrets", "may incur cost"} {
		if !strings.Contains(bodies[0], want) {
			t.Fatalf("skill body missing %q", want)
		}
	}

	var codex map[string]any
	if err := decodeStrict(m["codex/.codex-plugin/plugin.json"], &codex); err != nil {
		t.Fatal(err)
	}
	if codex["skills"] != "./skills/" || codex["mcpServers"] != "./.mcp.json" || codex["name"] != "fake-cli" {
		t.Fatalf("codex manifest = %v", codex)
	}
	iface := codex["interface"].(map[string]any)
	if !reflect.DeepEqual(iface["capabilities"], []any{"Read", "Write"}) {
		t.Fatalf("codex capabilities = %v", iface["capabilities"])
	}
	if !bytes.Contains(m["codex/skills/fake-cli/agents/openai.yaml"], []byte("allow_implicit_invocation: false")) {
		t.Fatal("codex skill policy must disable implicit invocation")
	}
	if !bytes.Contains(m["codex/README.md"], []byte("codex plugin marketplace add path/to/generated\ncodex plugin add fake-cli@fake-cli\n")) {
		t.Fatal("codex README must document the marketplace install commands")
	}
	var claude map[string]any
	if err := decodeStrict(m["claude-code/.claude-plugin/plugin.json"], &claude); err != nil {
		t.Fatal(err)
	}
	if _, ok := claude["mcpServers"]; ok {
		t.Fatal("claude manifest must rely on root .mcp.json discovery, not declare it twice")
	}
	var cursor map[string]any
	if err := decodeStrict(m["cursor/.cursor-plugin/plugin.json"], &cursor); err != nil {
		t.Fatal(err)
	}
	if cursor["skills"] != "./skills/" || cursor["mcpServers"] != "./.mcp.json" || cursor["displayName"] != "Fake CLI" {
		t.Fatalf("cursor manifest = %v", cursor)
	}
}

func TestRenderCodexMarketplaceListsLocalCodexFolder(t *testing.T) {
	t.Parallel()
	m := renderMap(t, testSpec())
	type entry struct {
		Name   string `json:"name"`
		Source struct {
			Source string `json:"source"`
			Path   string `json:"path"`
		} `json:"source"`
		Policy struct {
			Installation   string `json:"installation"`
			Authentication string `json:"authentication"`
		} `json:"policy"`
		Category string `json:"category"`
	}
	var mk struct {
		Name      string `json:"name"`
		Interface struct {
			DisplayName string `json:"displayName"`
		} `json:"interface"`
		Plugins []entry `json:"plugins"`
	}
	if err := decodeStrict(m[CodexMarketplacePath], &mk); err != nil {
		t.Fatal(err)
	}
	if mk.Name != "fake-cli" || mk.Interface.DisplayName != "Fake CLI" || len(mk.Plugins) != 1 {
		t.Fatalf("marketplace = %+v", mk)
	}
	p := mk.Plugins[0]
	if p.Name != "fake-cli" || p.Source.Source != "local" || p.Source.Path != "./codex" ||
		p.Policy.Installation != "AVAILABLE" || p.Policy.Authentication != "ON_INSTALL" || p.Category != "Developer Tools" {
		t.Fatalf("marketplace entry = %+v", p)
	}
	var codex struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(m[strings.TrimPrefix(p.Source.Path, "./")+"/.codex-plugin/plugin.json"], &codex); err != nil || codex.Name != p.Name {
		t.Fatalf("marketplace source does not resolve to the codex manifest named %q: %v", p.Name, err)
	}
}

func TestRenderEmbedsNoLocalPathsOrEnvironment(t *testing.T) {
	const secret = "sk-test-SHOULD-NOT-APPEAR-0123456789"
	t.Setenv("FAKECLI_SECRET", secret)
	home, _ := os.UserHomeDir()
	wd, _ := os.Getwd()
	files, err := Render(testSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		for _, needle := range []string{secret, home, wd, os.TempDir()} {
			if needle != "" && bytes.Contains(f.Data, []byte(needle)) {
				t.Fatalf("%s embeds %q", f.Path, needle)
			}
		}
	}
}
