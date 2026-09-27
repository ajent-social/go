package cliagent

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestBuildArgvPreservesValuesAsSingleArguments(t *testing.T) {
	t.Parallel()
	echo := testSpec().Tool("echo")
	cases := []struct {
		name string
		args string
		want []string
	}{
		{"required only", `{"text":"hello"}`, []string{"echo", "hello"}},
		{"null arguments means none", `null`, nil},
		{"declaration order", `{"text":"x","verbose":true,"mode":"b","count":3}`,
			[]string{"echo", "--mode", "b", "--count", "3", "--verbose", "x"}},
		{"false boolean omitted", `{"text":"x","verbose":false}`, []string{"echo", "x"}},
		{"shell metacharacters stay literal", `{"text":"$(rm -rf /); echo 'hi' | cat > f"}`,
			[]string{"echo", "$(rm -rf /); echo 'hi' | cat > f"}},
		{"spaces and quotes", `{"text":"a b \"c\""}`, []string{"echo", `a b "c"`}},
		{"flag value may start with dash", `{"text":"x","label":"--help"}`, []string{"echo", "--label", "--help", "x"}},
		{"integer zero", `{"text":"x","count":0}`, []string{"echo", "--count", "0", "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := echo.BuildArgv([]byte(tc.args))
			if tc.want == nil {
				if !errors.Is(err, ErrInvalidArguments) {
					t.Fatalf("want missing required error, got %v %v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildArgv: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("argv = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildArgvRejectsInvalidArguments(t *testing.T) {
	t.Parallel()
	echo := testSpec().Tool("echo")
	cases := []struct {
		name string
		args string
	}{
		{"missing required", `{}`},
		{"undeclared argument", `{"text":"x","executable":"/bin/sh"}`},
		{"duplicate key", `{"text":"x","text":"y"}`},
		{"array arguments", `["x"]`},
		{"string arguments", `"x"`},
		{"null value", `{"text":null}`},
		{"string as integer", `{"text":"x","count":"3"}`},
		{"fractional integer", `{"text":"x","count":1.5}`},
		{"exponent integer", `{"text":"x","count":1e2}`},
		{"integer below minimum", `{"text":"x","count":-1}`},
		{"integer above maximum", `{"text":"x","count":6}`},
		{"boolean as string", `{"text":"x","verbose":"true"}`},
		{"number as string", `{"text":1}`},
		{"enum violation", `{"text":"x","mode":"c"}`},
		{"positional leading dash", `{"text":"--delete"}`},
		{"positional single dash", `{"text":"-"}`},
		{"empty string", `{"text":""}`},
		{"too long", `{"text":"x","label":"` + strings.Repeat("a", 17) + `"}`},
		{"control character", `{"text":"a\nb"}`},
		{"nul byte", `{"text":"a\u0000b"}`},
		{"malformed json", `{"text":`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got, err := echo.BuildArgv([]byte(tc.args)); !errors.Is(err, ErrInvalidArguments) {
				t.Fatalf("want ErrInvalidArguments, got %q %v", got, err)
			}
		})
	}
}

func TestInputSchemaIsClosed(t *testing.T) {
	t.Parallel()
	schema := testSpec().Tool("echo").InputSchema()
	if schema["type"] != "object" || schema["additionalProperties"] != false {
		t.Fatalf("schema not closed: %v", schema)
	}
	if !reflect.DeepEqual(schema["required"], []string{"text"}) {
		t.Fatalf("required = %v", schema["required"])
	}
	props := schema["properties"].(map[string]any)
	mode := props["mode"].(map[string]any)
	if !reflect.DeepEqual(mode["enum"], []string{"a", "b"}) {
		t.Fatalf("mode enum = %v", mode["enum"])
	}
	if _, ok := testSpec().Tool("fail").InputSchema()["required"]; ok {
		t.Fatal("tool without inputs must not list required")
	}
}
