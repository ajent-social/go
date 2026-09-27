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

func TestGeneratePreservesCurrentDirectory(t *testing.T) {
	for _, spelling := range []string{"dot", "absolute", "symlinked parent"} {
		t.Run(spelling, func(t *testing.T) {
			parent := t.TempDir()
			cwd := filepath.Join(parent, "output")
			if err := os.Mkdir(cwd, 0700); err != nil {
				t.Fatal(err)
			}
			out := "."
			if spelling == "absolute" {
				out = cwd
			}
			if spelling == "symlinked parent" {
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(parent, alias); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				out = filepath.Join(alias, "output")
			}
			t.Chdir(cwd)
			if err := Generate(testSpec(), out); !errors.Is(err, ErrOutputExists) {
				t.Fatalf("current working directory must be refused: %v", err)
			}
			if _, err := os.Getwd(); err != nil {
				t.Fatalf("working directory detached: %v", err)
			}
			entries, err := os.ReadDir(".")
			if err != nil || len(entries) != 0 {
				t.Fatalf("working directory modified: %v, %v", entries, err)
			}
		})
	}
}

func TestCheckRejectsSymlinkRootSpellings(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "generated")
	if err := Generate(testSpec(), out); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(out, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for _, root := range []string{link, link + string(os.PathSeparator), link + string(os.PathSeparator) + "."} {
		if err := Check(testSpec(), root); !errors.Is(err, ErrDrift) {
			t.Errorf("symlink root %q accepted: %v", root, err)
		}
	}
}
