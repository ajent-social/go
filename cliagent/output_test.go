package cliagent

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// snapshot records every entry under root (mode and content) for
// before/after comparisons.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		info, err := d.Info()
		if err != nil {
			return err
		}
		v := info.Mode().String()
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += ":" + string(b)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			target, _ := os.Readlink(p)
			v += "->" + target
		}
		out[rel] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func noStagingLeft(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".amsl-agent-plugin-stage-") {
			t.Fatalf("staging directory left behind: %s", e.Name())
		}
	}
}

func TestGenerateThenCheck(t *testing.T) {
	t.Parallel()
	for _, precreate := range []bool{false, true} {
		parent := t.TempDir()
		out := filepath.Join(parent, "generated")
		if precreate {
			if err := os.Mkdir(out, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		s := testSpec()
		if err := Generate(s, out); err != nil {
			t.Fatalf("Generate(precreate=%t): %v", precreate, err)
		}
		if err := Check(s, out); err != nil {
			t.Fatalf("Check after Generate: %v", err)
		}
		noStagingLeft(t, parent)
		var walked []string
		_ = filepath.WalkDir(out, func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				rel, _ := filepath.Rel(out, p)
				walked = append(walked, filepath.ToSlash(rel))
			}
			return err
		})
		sort.Strings(walked)
		paths, err := Paths(s)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(walked, paths) {
			t.Fatalf("written files %v != Paths %v", walked, paths)
		}
	}
}

func TestGenerateRefusesExistingContent(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		setup func(t *testing.T, out string)
	}{
		{"non-empty directory", func(t *testing.T, out string) {
			if err := os.MkdirAll(out, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, "notes.md"), []byte("keep me"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"hidden file only", func(t *testing.T, out string) {
			if err := os.MkdirAll(out, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, ".keep"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"regular file", func(t *testing.T, out string) {
			if err := os.WriteFile(out, []byte("keep me"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink to empty directory", func(t *testing.T, out string) {
			target := filepath.Join(filepath.Dir(out), "target")
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, out); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			out := filepath.Join(parent, "generated")
			tc.setup(t, out)
			before := snapshot(t, parent)
			if err := Generate(testSpec(), out); !errors.Is(err, ErrOutputExists) {
				t.Fatalf("want ErrOutputExists, got %v", err)
			}
			if after := snapshot(t, parent); !reflect.DeepEqual(before, after) {
				t.Fatalf("Generate modified existing content:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

func TestGenerateRejectsInvalidSpecBeforeWriting(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	s := testSpec()
	s.Tools[0].Name = "../escape"
	if err := Generate(s, filepath.Join(parent, "generated")); !errors.Is(err, ErrInvalidSpec) {
		t.Fatalf("want ErrInvalidSpec, got %v", err)
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 0 {
		t.Fatalf("invalid spec wrote %v", entries)
	}
}

func TestConcurrentGenerateHasOneWinner(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	out := filepath.Join(parent, "generated")
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = Generate(testSpec(), out)
		}()
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, ErrOutputExists):
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("%d generators succeeded, want exactly 1", wins)
	}
	if err := Check(testSpec(), out); err != nil {
		t.Fatalf("Check after concurrent generate: %v", err)
	}
	noStagingLeft(t, parent)
}

func TestCheckDetectsDriftReadOnly(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		tamper func(t *testing.T, out string)
		want   string
	}{
		{"changed file", func(t *testing.T, out string) {
			appendFile(t, filepath.Join(out, "codex", "README.md"), "\nextra")
		}, "changed: codex/README.md"},
		{"changed inline spec", func(t *testing.T, out string) {
			p := filepath.Join(out, "cursor", ".mcp.json")
			b, _ := os.ReadFile(p)
			writeFile(t, p, strings.Replace(string(b), "fakecli", "evilcli", 1))
		}, "changed: cursor/.mcp.json"},
		{"missing file", func(t *testing.T, out string) {
			if err := os.Remove(filepath.Join(out, "claude-code", "skills", "fake-cli", "SKILL.md")); err != nil {
				t.Fatal(err)
			}
		}, "missing: claude-code/skills/fake-cli/SKILL.md"},
		{"extra file", func(t *testing.T, out string) {
			writeFile(t, filepath.Join(out, "codex", "hooks.json"), "{}")
		}, "unexpected file: codex/hooks.json"},
		{"extra directory", func(t *testing.T, out string) {
			if err := os.MkdirAll(filepath.Join(out, "cursor", "rules"), 0o755); err != nil {
				t.Fatal(err)
			}
		}, "unexpected directory: cursor/rules"},
		{"symlink replacing file", func(t *testing.T, out string) {
			p := filepath.Join(out, "codex", "README.md")
			copyPath := filepath.Join(filepath.Dir(out), "readme-copy")
			b, _ := os.ReadFile(p)
			writeFile(t, copyPath, string(b))
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(copyPath, p); err != nil {
				t.Fatal(err)
			}
		}, "symlink: codex/README.md"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			out := filepath.Join(parent, "generated")
			if err := Generate(testSpec(), out); err != nil {
				t.Fatal(err)
			}
			tc.tamper(t, out)
			before := snapshot(t, parent)
			err := Check(testSpec(), out)
			if !errors.Is(err, ErrDrift) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want drift %q, got %v", tc.want, err)
			}
			if after := snapshot(t, parent); !reflect.DeepEqual(before, after) {
				t.Fatal("Check modified the output directory")
			}
		})
	}
}

func TestCheckRejectsSymlinkedOutputRoot(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	real := filepath.Join(parent, "real")
	if err := Generate(testSpec(), real); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := Check(testSpec(), link); !errors.Is(err, ErrDrift) {
		t.Fatalf("want ErrDrift for symlinked root, got %v", err)
	}
}

func TestCheckDetectsSpecChange(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "generated")
	if err := Generate(testSpec(), out); err != nil {
		t.Fatal(err)
	}
	changed := testSpec()
	changed.Tools[0].Description = "A different description."
	if err := Check(changed, out); !errors.Is(err, ErrDrift) {
		t.Fatalf("want ErrDrift after spec change, got %v", err)
	}
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}
