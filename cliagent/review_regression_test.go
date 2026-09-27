package cliagent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicationRemovalPreservesConcurrentFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "output")
	// A competing writer creates a file after Generate's last emptiness check.
	if err := requireAbsentOrEmpty(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("other writer"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removeEmptyOutput(target); err == nil {
		t.Fatal("publication removed another writer's file")
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != "other writer" {
		t.Fatalf("competing file changed: %q, %v", got, err)
	}
}

func TestSpecRejectsOversizedInlineArgument(t *testing.T) {
	s := testSpec()
	// Legal instruction text grows past Linux's single-argument exec bound
	// after JSON escaping, even though the source fits MaxSpecBytes.
	s.Skill.Instructions = strings.Repeat("\\", MaxInstructions)
	raw, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 128<<10 || len(raw) > MaxSpecBytes {
		t.Fatalf("unexpected fixture size %d", len(raw))
	}
	if err := s.Validate(); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("oversized inline spec accepted: %v", err)
	}
	if _, err := ParseSpec(raw); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("oversized parsed spec accepted: %v", err)
	}
	if _, err := Render(s); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("oversized plugin rendered: %v", err)
	}
}
