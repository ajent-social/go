package cliagent

import (
	"errors"
	"strings"
	"testing"
)

func TestParseSpecAcceptsValidSpec(t *testing.T) {
	t.Parallel()
	s, err := ParseSpec(specJSON(t, nil))
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if s.Tool("echo") == nil || s.Tool("missing") != nil {
		t.Fatal("Tool lookup mismatch")
	}
	again, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSpec(again); err != nil {
		t.Fatalf("canonical form does not round-trip: %v", err)
	}
}

func TestParseSpecRejectsMalformedJSON(t *testing.T) {
	t.Parallel()
	valid := string(specJSON(t, nil))
	cases := []struct {
		name string
		data string
	}{
		{"unknown top-level field", strings.Replace(valid, `{"schema_version":1`, `{"schema_version":1,"extra":true`, 1)},
		{"unknown nested field", strings.Replace(valid, `"read_only":true`, `"read_only":true,"sandboxed":true`, 1)},
		{"duplicate top-level key", strings.Replace(valid, `{"schema_version":1`, `{"schema_version":1,"schema_version":1`, 1)},
		{"duplicate nested key", strings.Replace(valid, `"name":"echo"`, `"name":"echo","name":"echo"`, 1)},
		{"trailing value", valid + ` {}`},
		{"not an object", `[]`},
		{"empty", ``},
		{"oversize", `{"x":"` + strings.Repeat("a", MaxSpecBytes) + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseSpec([]byte(tc.data)); !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("want ErrInvalidSpec, got %v", err)
			}
		})
	}
}

func TestValidateRejectsUnsafeSpecs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*Spec)
	}{
		{"schema version", func(s *Spec) { s.SchemaVersion = 2 }},
		{"plugin name traversal", func(s *Spec) { s.Plugin.Name = "../evil" }},
		{"plugin name uppercase", func(s *Spec) { s.Plugin.Name = "Fake" }},
		{"skill name slash", func(s *Spec) { s.Skill.Name = "a/b" }},
		{"version", func(s *Spec) { s.Plugin.Version = "v1" }},
		{"description newline", func(s *Spec) { s.Plugin.Description = "a\nb" }},
		{"http url", func(s *Spec) { s.Plugin.Homepage = "http://example.com" }},
		{"url credentials", func(s *Spec) { s.Plugin.Repository = "https://user:pw@example.com" }},
		{"license", func(s *Spec) { s.Plugin.License = "MIT OR Apache" }},
		{"absolute executable", func(s *Spec) { s.CLI.Executable = "/bin/sh" }},
		{"relative executable", func(s *Spec) { s.CLI.Executable = "../fakecli" }},
		{"executable with space", func(s *Spec) { s.CLI.Executable = "fake cli" }},
		{"empty probe output", func(s *Spec) { s.CLI.VersionProbe.RequireOutput = "" }},
		{"probe control char", func(s *Spec) { s.CLI.VersionProbe.Argv = []string{"--ver\x00sion"} }},
		{"instructions front matter", func(s *Spec) { s.Skill.Instructions = "---\nname: x\n---\n" }},
		{"timeout too long", func(s *Spec) { s.Limits.TimeoutSeconds = MaxTimeoutSeconds + 1 }},
		{"timeout zero", func(s *Spec) { s.Limits.TimeoutSeconds = 0 }},
		{"output too large", func(s *Spec) { s.Limits.MaxOutputBytes = MaxOutputBytes + 1 }},
		{"no concurrency", func(s *Spec) { s.Limits.MaxConcurrent = 0 }},
		{"too much concurrency", func(s *Spec) { s.Limits.MaxConcurrent = MaxConcurrent + 1 }},
		{"no tools", func(s *Spec) { s.Tools = nil }},
		{"null tool", func(s *Spec) { s.Tools = append(s.Tools, nil) }},
		{"duplicate tool", func(s *Spec) { s.Tools = append(s.Tools, s.Tools[0]) }},
		{"tool name dash", func(s *Spec) { s.Tools[0].Name = "bad-name" }},
		{"tool name traversal", func(s *Spec) { s.Tools[0].Name = "../x" }},
		{"empty argv", func(s *Spec) { s.Tools[0].Argv = nil }},
		{"empty argv element", func(s *Spec) { s.Tools[0].Argv = []string{""} }},
		{"tool timeout over limit", func(s *Spec) { s.Tools[0].TimeoutSeconds = s.Limits.TimeoutSeconds + 1 }},
		{"read only and destructive", func(s *Spec) { s.Tools[0].Effects.Destructive = true }},
		{"unknown cost", func(s *Spec) { s.Tools[0].Effects.Cost = "cheap" }},
		{"duplicate input", func(s *Spec) { s.Tools[0].Inputs = append(s.Tools[0].Inputs, s.Tools[0].Inputs[0]) }},
		{"duplicate flag", func(s *Spec) { s.Tools[0].Inputs[3].Flag = "--mode" }},
		{"null input", func(s *Spec) { s.Tools[0].Inputs = append(s.Tools[0].Inputs, nil) }},
		{"flag and positional", func(s *Spec) { s.Tools[0].Inputs[0].Positional = true }},
		{"neither flag nor positional", func(s *Spec) { s.Tools[0].Inputs[4].Positional = false }},
		{"bad flag", func(s *Spec) { s.Tools[0].Inputs[0].Flag = "mode" }},
		{"flag with equals", func(s *Spec) { s.Tools[0].Inputs[0].Flag = "--mode=x" }},
		{"unknown type", func(s *Spec) { s.Tools[0].Inputs[0].Type = "array" }},
		{"boolean positional", func(s *Spec) {
			s.Tools[0].Inputs[2].Flag = ""
			s.Tools[0].Inputs[2].Positional = true
		}},
		{"boolean required", func(s *Spec) { s.Tools[0].Inputs[2].Required = true }},
		{"duplicate enum", func(s *Spec) { s.Tools[0].Inputs[0].Enum = []string{"a", "a"} }},
		{"positional enum dash", func(s *Spec) { s.Tools[0].Inputs[4].Enum = []string{"-rf"} }},
		{"integer enum", func(s *Spec) { s.Tools[0].Inputs[1].Enum = []string{"1"} }},
		{"integer min over max", func(s *Spec) { s.Tools[0].Inputs[1].Minimum = i64(9) }},
		{"positional integer without minimum", func(s *Spec) {
			s.Tools[1].Inputs = []*Input{{Name: "n", Type: TypeInteger, Positional: true, Description: "n"}}
		}},
		{"string with bounds", func(s *Spec) { s.Tools[0].Inputs[0].Minimum = i64(1) }},
		{"max length too large", func(s *Spec) { s.Tools[0].Inputs[3].MaxLength = MaxStringInput + 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := testSpec()
			tc.mutate(s)
			if err := s.Validate(); !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("want ErrInvalidSpec, got %v", err)
			}
			if _, err := Render(s); !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("Render must reject invalid spec, got %v", err)
			}
		})
	}
}
