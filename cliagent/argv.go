package cliagent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrInvalidArguments wraps every tool-argument validation failure.
var ErrInvalidArguments = errors.New("cliagent: invalid arguments")

func badArgs(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidArguments, fmt.Sprintf(format, args...))
}

// BuildArgv validates raw MCP tool arguments against the tool's declared
// inputs and returns the argv that follows the executable: the fixed prefix,
// then inputs in declaration order. Each value is exactly one argv element; no
// shell parsing or splitting happens anywhere.
func (t *Tool) BuildArgv(raw json.RawMessage) ([]string, error) {
	values := map[string]json.RawMessage{}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
		if err := rejectDuplicateKeys(trimmed); err != nil {
			return nil, badArgs("%v", err)
		}
		if trimmed[0] != '{' {
			return nil, badArgs("arguments must be a JSON object")
		}
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		if err := dec.Decode(&values); err != nil {
			return nil, badArgs("arguments must be a JSON object: %v", err)
		}
	}
	declared := map[string]*Input{}
	for _, in := range t.Inputs {
		declared[in.Name] = in
	}
	for name := range values {
		if declared[name] == nil {
			return nil, badArgs("undeclared argument %q", name)
		}
	}
	argv := append([]string(nil), t.Argv...)
	for _, in := range t.Inputs {
		v, ok := values[in.Name]
		if !ok {
			if in.Required {
				return nil, badArgs("missing required argument %q", in.Name)
			}
			continue
		}
		parts, err := in.render(v)
		if err != nil {
			return nil, err
		}
		argv = append(argv, parts...)
	}
	return argv, nil
}

func (in *Input) render(v json.RawMessage) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(v))
	dec.UseNumber()
	var val any
	if err := dec.Decode(&val); err != nil {
		return nil, badArgs("argument %q: %v", in.Name, err)
	}
	switch in.Type {
	case TypeBoolean:
		b, ok := val.(bool)
		if !ok {
			return nil, badArgs("argument %q must be a boolean", in.Name)
		}
		if !b {
			return nil, nil
		}
		return []string{in.Flag}, nil
	case TypeInteger:
		num, ok := val.(json.Number)
		if !ok {
			return nil, badArgs("argument %q must be an integer", in.Name)
		}
		n, err := strconv.ParseInt(num.String(), 10, 64)
		if err != nil {
			return nil, badArgs("argument %q must be an integer", in.Name)
		}
		if in.Minimum != nil && n < *in.Minimum {
			return nil, badArgs("argument %q must be >= %d", in.Name, *in.Minimum)
		}
		if in.Maximum != nil && n > *in.Maximum {
			return nil, badArgs("argument %q must be <= %d", in.Name, *in.Maximum)
		}
		return in.place(strconv.FormatInt(n, 10)), nil
	case TypeString:
		s, ok := val.(string)
		if !ok {
			return nil, badArgs("argument %q must be a string", in.Name)
		}
		if err := checkValue(in, s); err != nil {
			return nil, err
		}
		return in.place(s), nil
	}
	return nil, badArgs("argument %q has unsupported type %q", in.Name, in.Type)
}

func (in *Input) place(value string) []string {
	if in.Positional {
		return []string{value}
	}
	return []string{in.Flag, value}
}

func checkValue(in *Input, s string) error {
	if s == "" {
		return badArgs("argument %q must not be empty", in.Name)
	}
	if len(s) > in.maxLength() {
		return badArgs("argument %q exceeds %d bytes", in.Name, in.maxLength())
	}
	if !utf8.ValidString(s) {
		return badArgs("argument %q must be valid UTF-8", in.Name)
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return badArgs("argument %q must not contain control characters", in.Name)
		}
	}
	if in.Positional && strings.HasPrefix(s, "-") {
		return badArgs("positional argument %q must not start with '-'", in.Name)
	}
	if len(in.Enum) > 0 {
		for _, e := range in.Enum {
			if s == e {
				return nil
			}
		}
		return badArgs("argument %q must be one of %s", in.Name, strings.Join(in.Enum, ", "))
	}
	return nil
}

// InputSchema returns the JSON Schema object advertised for the tool.
// additionalProperties is false; the server re-validates every call itself.
func (t *Tool) InputSchema() map[string]any {
	props := map[string]any{}
	required := []string{}
	for _, in := range t.Inputs {
		p := map[string]any{"type": in.Type, "description": in.Description}
		switch in.Type {
		case TypeString:
			p["minLength"] = 1
			p["maxLength"] = in.maxLength()
			if len(in.Enum) > 0 {
				p["enum"] = append([]string(nil), in.Enum...)
			}
		case TypeInteger:
			if in.Minimum != nil {
				p["minimum"] = *in.Minimum
			}
			if in.Maximum != nil {
				p["maximum"] = *in.Maximum
			}
		}
		props[in.Name] = p
		if in.Required {
			required = append(required, in.Name)
		}
	}
	schema := map[string]any{
		"type":                 "object",
		"properties":           props,
		"additionalProperties": false,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}
