package cliagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SchemaVersion is the only accepted Spec.SchemaVersion.
const SchemaVersion = 1

// Bounds enforced by [Spec.Validate]. They are deliberately small: a spec is
// reviewed by a person and embedded inline in host MCP configuration.
const (
	MaxSpecBytes       = 256 << 10
	MaxTimeoutSeconds  = 600
	MaxOutputBytes     = 1 << 20
	MaxConcurrent      = 16
	MaxTools           = 64
	MaxInputsPerTool   = 32
	MaxArgvPrefix      = 16
	MaxArgLength       = 256
	MaxStringInput     = 64 << 10
	DefaultStringInput = 4096
	MaxEnumValues      = 64
	MaxInstructions    = 64 << 10
)

// ErrInvalidSpec wraps every specification validation failure.
var ErrInvalidSpec = errors.New("cliagent: invalid spec")

// Spec is the reviewed, declarative description of one CLI. It contains no
// secrets and is bundled verbatim (in canonical form) with generated plugins.
type Spec struct {
	SchemaVersion int     `json:"schema_version"`
	Plugin        Plugin  `json:"plugin"`
	CLI           CLI     `json:"cli"`
	Skill         Skill   `json:"skill"`
	Limits        Limits  `json:"limits"`
	Tools         []*Tool `json:"tools"`
}

// Plugin is host-facing package metadata.
type Plugin struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name,omitempty"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Author      Author   `json:"author"`
	Homepage    string   `json:"homepage,omitempty"`
	Repository  string   `json:"repository,omitempty"`
	License     string   `json:"license,omitempty"`
	Keywords    []string `json:"keywords,omitempty"`
}

// Author identifies the plugin author.
type Author struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

// CLI names the canonical executable and how compatibility is checked.
type CLI struct {
	// Executable is a bare command name resolved once through PATH at startup.
	Executable string `json:"executable"`
	// Install is human setup guidance rendered into README files.
	Install      string       `json:"install"`
	VersionProbe VersionProbe `json:"version_probe"`
}

// VersionProbe runs Executable with Argv before serving. The probe passes only
// when the process exits 0 and its combined output contains RequireOutput.
type VersionProbe struct {
	Argv          []string `json:"argv"`
	RequireOutput string   `json:"require_output"`
}

// Skill is the user-invoked workflow rendered identically for every host.
type Skill struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Instructions string `json:"instructions"`
}

// Limits bound every tool invocation.
type Limits struct {
	TimeoutSeconds int `json:"timeout_seconds"`
	// MaxOutputBytes is shared by stdout and stderr of one invocation.
	MaxOutputBytes int `json:"max_output_bytes"`
	// MaxConcurrent bounds simultaneous invocations; excess calls are rejected.
	MaxConcurrent int `json:"max_concurrent"`
}

// Tool is one fixed CLI command exposed as an MCP tool.
type Tool struct {
	Name           string   `json:"name"`
	Title          string   `json:"title,omitempty"`
	Description    string   `json:"description"`
	Argv           []string `json:"argv"`
	Inputs         []*Input `json:"inputs,omitempty"`
	Effects        Effects  `json:"effects"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

// Input is one named argument. Exactly one of Flag or Positional is set.
type Input struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description"`
	Flag        string   `json:"flag,omitempty"`
	Positional  bool     `json:"positional,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Enum        []string `json:"enum,omitempty"`
	MaxLength   int      `json:"max_length,omitempty"`
	Minimum     *int64   `json:"minimum,omitempty"`
	Maximum     *int64   `json:"maximum,omitempty"`
}

// Input types.
const (
	TypeString  = "string"
	TypeBoolean = "boolean"
	TypeInteger = "integer"
)

// Effects declares what a tool may do. They become MCP annotations and README
// text; they are hints for hosts and people, never enforcement.
type Effects struct {
	ReadOnly    bool   `json:"read_only"`
	Destructive bool   `json:"destructive"`
	Idempotent  bool   `json:"idempotent"`
	Network     bool   `json:"network"`
	Cost        string `json:"cost"`
	Notes       string `json:"notes"`
}

// Cost values.
const (
	CostNone     = "none"
	CostPossible = "possible"
)

var (
	pluginNameRE = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)
	identRE      = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	semverRE     = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)
	executableRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	flagRE       = regexp.MustCompile(`^--?[A-Za-z0-9][A-Za-z0-9-]*$`)
	licenseRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+-]*$`)
)

// ParseSpec strictly decodes and validates a spec. Unknown fields, duplicate
// object keys, trailing values and oversize input are rejected.
func ParseSpec(data []byte) (*Spec, error) {
	if len(data) > MaxSpecBytes {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrInvalidSpec, MaxSpecBytes)
	}
	var s Spec
	if err := decodeStrict(data, &s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSpec, err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// LoadSpec reads a regular spec file (symlinks rejected) and parses it.
func LoadSpec(path string) (*Spec, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("reading spec: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrInvalidSpec, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading spec: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxSpecBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading spec: %w", err)
	}
	return ParseSpec(data)
}

// Canonical returns the deterministic compact JSON form of the spec used for
// inline MCP startup, bundling and digests.
func (s *Spec) Canonical() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Tool returns the named tool or nil.
func (s *Spec) Tool(name string) *Tool {
	for _, t := range s.Tools {
		if t.Name == name {
			return t
		}
	}
	return nil
}

func (s *Spec) timeoutFor(t *Tool) int {
	if t.TimeoutSeconds > 0 {
		return t.TimeoutSeconds
	}
	return s.Limits.TimeoutSeconds
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}

// Validate checks every field. It is called by ParseSpec; callers that build a
// Spec in code must call it before Render, Generate or NewRunner.
func (s *Spec) Validate() error {
	if s == nil {
		return invalid("spec is nil")
	}
	if s.SchemaVersion != SchemaVersion {
		return invalid("schema_version must be %d", SchemaVersion)
	}
	if err := s.Plugin.validate(); err != nil {
		return err
	}
	if err := s.CLI.validate(); err != nil {
		return err
	}
	if err := s.Skill.validate(); err != nil {
		return err
	}
	l := s.Limits
	if l.TimeoutSeconds < 1 || l.TimeoutSeconds > MaxTimeoutSeconds {
		return invalid("limits.timeout_seconds must be 1..%d", MaxTimeoutSeconds)
	}
	if l.MaxOutputBytes < 1 || l.MaxOutputBytes > MaxOutputBytes {
		return invalid("limits.max_output_bytes must be 1..%d", MaxOutputBytes)
	}
	if l.MaxConcurrent < 1 || l.MaxConcurrent > MaxConcurrent {
		return invalid("limits.max_concurrent must be 1..%d", MaxConcurrent)
	}
	if len(s.Tools) == 0 || len(s.Tools) > MaxTools {
		return invalid("tools must list 1..%d tools", MaxTools)
	}
	seen := map[string]bool{}
	for i, t := range s.Tools {
		if t == nil {
			return invalid("tools[%d] is null", i)
		}
		if err := t.validate(l); err != nil {
			return fmt.Errorf("%w (tools[%d])", err, i)
		}
		if seen[t.Name] {
			return invalid("duplicate tool name %q", t.Name)
		}
		seen[t.Name] = true
	}
	return nil
}

func (p Plugin) validate() error {
	if len(p.Name) > 64 || !pluginNameRE.MatchString(p.Name) {
		return invalid("plugin.name must be lowercase kebab-case (max 64)")
	}
	if p.DisplayName != "" {
		if err := checkText("plugin.display_name", p.DisplayName, 100, false); err != nil {
			return err
		}
	}
	if !semverRE.MatchString(p.Version) || len(p.Version) > 64 {
		return invalid("plugin.version must be semantic MAJOR.MINOR.PATCH")
	}
	if err := checkText("plugin.description", p.Description, 500, false); err != nil {
		return err
	}
	if err := checkText("plugin.author.name", p.Author.Name, 200, false); err != nil {
		return err
	}
	for field, v := range map[string]string{"plugin.author.url": p.Author.URL, "plugin.homepage": p.Homepage, "plugin.repository": p.Repository} {
		if v != "" {
			if err := checkHTTPSURL(field, v); err != nil {
				return err
			}
		}
	}
	if p.License != "" && (len(p.License) > 64 || !licenseRE.MatchString(p.License)) {
		return invalid("plugin.license must be an SPDX-style identifier")
	}
	if len(p.Keywords) > 20 {
		return invalid("plugin.keywords allows at most 20 entries")
	}
	seen := map[string]bool{}
	for _, k := range p.Keywords {
		if len(k) > 40 || !pluginNameRE.MatchString(k) || seen[k] {
			return invalid("plugin.keywords entries must be unique lowercase kebab-case (max 40)")
		}
		seen[k] = true
	}
	return nil
}

func (c CLI) validate() error {
	if len(c.Executable) > 64 || !executableRE.MatchString(c.Executable) {
		return invalid("cli.executable must be a bare command name without path separators")
	}
	if err := checkText("cli.install", c.Install, 2000, true); err != nil {
		return err
	}
	if len(c.VersionProbe.Argv) > MaxArgvPrefix {
		return invalid("cli.version_probe.argv allows at most %d arguments", MaxArgvPrefix)
	}
	for i, a := range c.VersionProbe.Argv {
		if err := checkArg(fmt.Sprintf("cli.version_probe.argv[%d]", i), a); err != nil {
			return err
		}
	}
	if err := checkText("cli.version_probe.require_output", c.VersionProbe.RequireOutput, 1024, false); err != nil {
		return err
	}
	return nil
}

func (k Skill) validate() error {
	if len(k.Name) > 64 || !pluginNameRE.MatchString(k.Name) {
		return invalid("skill.name must be lowercase kebab-case (max 64)")
	}
	if err := checkText("skill.description", k.Description, 1024, false); err != nil {
		return err
	}
	if err := checkText("skill.instructions", k.Instructions, MaxInstructions, true); err != nil {
		return err
	}
	if strings.HasPrefix(strings.TrimSpace(k.Instructions), "---") {
		return invalid("skill.instructions must not start with front matter")
	}
	return nil
}

func (t *Tool) validate(l Limits) error {
	if len(t.Name) > 64 || !identRE.MatchString(t.Name) {
		return invalid("tool name %q must match [a-z][a-z0-9_]* (max 64)", t.Name)
	}
	if t.Title != "" {
		if err := checkText("tool "+t.Name+" title", t.Title, 100, false); err != nil {
			return err
		}
	}
	if err := checkText("tool "+t.Name+" description", t.Description, 1024, true); err != nil {
		return err
	}
	if len(t.Argv) == 0 || len(t.Argv) > MaxArgvPrefix {
		return invalid("tool %s argv must have 1..%d fixed arguments", t.Name, MaxArgvPrefix)
	}
	for i, a := range t.Argv {
		if err := checkArg(fmt.Sprintf("tool %s argv[%d]", t.Name, i), a); err != nil {
			return err
		}
	}
	if t.TimeoutSeconds < 0 || t.TimeoutSeconds > l.TimeoutSeconds {
		return invalid("tool %s timeout_seconds must be 0..limits.timeout_seconds", t.Name)
	}
	if err := t.Effects.validate(t.Name); err != nil {
		return err
	}
	if len(t.Inputs) > MaxInputsPerTool {
		return invalid("tool %s allows at most %d inputs", t.Name, MaxInputsPerTool)
	}
	names := map[string]bool{}
	flags := map[string]bool{}
	for i, in := range t.Inputs {
		if in == nil {
			return invalid("tool %s inputs[%d] is null", t.Name, i)
		}
		if err := in.validate(t.Name); err != nil {
			return err
		}
		if names[in.Name] {
			return invalid("tool %s has duplicate input %q", t.Name, in.Name)
		}
		names[in.Name] = true
		if in.Flag != "" {
			if flags[in.Flag] {
				return invalid("tool %s has duplicate flag %q", t.Name, in.Flag)
			}
			flags[in.Flag] = true
		}
	}
	return nil
}

func (e Effects) validate(tool string) error {
	if e.ReadOnly && e.Destructive {
		return invalid("tool %s cannot be both read_only and destructive", tool)
	}
	if e.Cost != CostNone && e.Cost != CostPossible {
		return invalid("tool %s effects.cost must be %q or %q", tool, CostNone, CostPossible)
	}
	return checkText("tool "+tool+" effects.notes", e.Notes, 1024, true)
}

func (in *Input) validate(tool string) error {
	where := fmt.Sprintf("tool %s input %q", tool, in.Name)
	if len(in.Name) > 64 || !identRE.MatchString(in.Name) {
		return invalid("%s: name must match [a-z][a-z0-9_]* (max 64)", where)
	}
	if err := checkText(where+" description", in.Description, 512, false); err != nil {
		return err
	}
	switch {
	case in.Flag != "" && in.Positional:
		return invalid("%s: set exactly one of flag or positional", where)
	case in.Flag == "" && !in.Positional:
		return invalid("%s: set exactly one of flag or positional", where)
	case in.Flag != "" && (len(in.Flag) > 64 || !flagRE.MatchString(in.Flag)):
		return invalid("%s: flag must look like -x or --name", where)
	}
	switch in.Type {
	case TypeString:
		if in.Minimum != nil || in.Maximum != nil {
			return invalid("%s: minimum/maximum apply only to integers", where)
		}
		if in.MaxLength < 0 || in.MaxLength > MaxStringInput {
			return invalid("%s: max_length must be 0..%d", where, MaxStringInput)
		}
		if len(in.Enum) > MaxEnumValues {
			return invalid("%s: enum allows at most %d values", where, MaxEnumValues)
		}
		seen := map[string]bool{}
		for _, v := range in.Enum {
			if err := checkArg(where+" enum value", v); err != nil {
				return err
			}
			if in.Positional && strings.HasPrefix(v, "-") {
				return invalid("%s: positional enum value %q starts with '-'", where, v)
			}
			if seen[v] {
				return invalid("%s: duplicate enum value %q", where, v)
			}
			seen[v] = true
		}
	case TypeBoolean:
		if in.Positional || in.Required || len(in.Enum) > 0 || in.MaxLength != 0 || in.Minimum != nil || in.Maximum != nil {
			return invalid("%s: boolean inputs are optional flags without enum or bounds", where)
		}
	case TypeInteger:
		if len(in.Enum) > 0 || in.MaxLength != 0 {
			return invalid("%s: enum and max_length apply only to strings", where)
		}
		if in.Minimum != nil && in.Maximum != nil && *in.Minimum > *in.Maximum {
			return invalid("%s: minimum exceeds maximum", where)
		}
		if in.Positional && (in.Minimum == nil || *in.Minimum < 0) {
			return invalid("%s: positional integers need minimum >= 0 so values cannot start with '-'", where)
		}
	default:
		return invalid("%s: type must be string, boolean or integer", where)
	}
	return nil
}

func (in *Input) maxLength() int {
	if in.MaxLength > 0 {
		return in.MaxLength
	}
	return DefaultStringInput
}

// checkArg validates one fixed argv element.
func checkArg(field, v string) error {
	if v == "" || len(v) > MaxArgLength || !utf8.ValidString(v) {
		return invalid("%s must be 1..%d bytes of UTF-8", field, MaxArgLength)
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return invalid("%s must not contain control characters", field)
		}
	}
	return nil
}

// checkText validates human text. Multiline text may contain newlines and tabs.
func checkText(field, v string, max int, multiline bool) error {
	if strings.TrimSpace(v) == "" || len(v) > max || !utf8.ValidString(v) {
		return invalid("%s must be 1..%d bytes of UTF-8", field, max)
	}
	for _, r := range v {
		if r == '\n' || r == '\t' {
			if multiline {
				continue
			}
		}
		if unicode.IsControl(r) {
			return invalid("%s must not contain control characters", field)
		}
	}
	return nil
}

func checkHTTPSURL(field, v string) error {
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(v) > 512 {
		return invalid("%s must be an https URL without credentials", field)
	}
	return nil
}

// decodeStrict decodes exactly one JSON value into dst, rejecting duplicate
// keys, unknown fields and trailing data.
func decodeStrict(data []byte, dst any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

// rejectDuplicateKeys walks the token stream and fails on a repeated key in
// any object. encoding/json silently keeps the last duplicate.
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			keys := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				k, _ := kt.(string)
				if keys[k] {
					return fmt.Errorf("duplicate key %q", k)
				}
				keys[k] = true
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
		return nil
	}
	return walk()
}
