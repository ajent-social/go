package cliagent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// ErrOutputExists reports that the output directory is not absent or empty.
var ErrOutputExists = errors.New("cliagent: output directory must be absent or empty")

// ErrDrift reports that generated output differs from the spec's rendering.
var ErrDrift = errors.New("cliagent: generated output drift")

// Paths returns the slash-separated relative paths Generate writes, sorted.
func Paths(s *Spec) ([]string, error) {
	files, err := Render(s)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Path
	}
	return out, nil
}

// Generate renders s into outDir. outDir must be absent or an empty real
// directory; nothing existing is overwritten or deleted. Files are staged in a
// sibling temporary directory and moved into place with a single rename, so a
// failure leaves no partial output and a concurrent writer cannot be clobbered.
// An existing empty outDir is removed with rmdir (which fails if it gained
// content) immediately before the rename; rename never replaces a non-empty
// directory.
func Generate(s *Spec, outDir string) error {
	files, err := Render(s)
	if err != nil {
		return err
	}
	if outDir == "" {
		return errors.New("cliagent: output directory is required")
	}
	outDir = filepath.Clean(outDir)
	if err := requireAbsentOrEmpty(outDir); err != nil {
		return err
	}
	parent := filepath.Dir(outDir)
	pfi, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("cliagent: output parent: %w", err)
	}
	if !pfi.IsDir() {
		return fmt.Errorf("cliagent: output parent %s is not a directory", parent)
	}
	stage, err := os.MkdirTemp(parent, ".amsl-agent-plugin-stage-")
	if err != nil {
		return fmt.Errorf("cliagent: creating staging directory: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(stage)
		}
	}()
	if err := os.Chmod(stage, 0o755); err != nil {
		return fmt.Errorf("cliagent: staging directory: %w", err)
	}
	for _, f := range files {
		if err := writeStaged(stage, f); err != nil {
			return err
		}
	}
	if err := requireAbsentOrEmpty(outDir); err != nil {
		return err
	}
	// Some platforms (macOS) refuse to rename onto an empty directory.
	// Use rmdir directly: os.Remove could unlink a file created after the check.
	if err := removeEmptyOutput(outDir); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s: %v", ErrOutputExists, outDir, err)
	}
	if err := os.Rename(stage, outDir); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrOutputExists, outDir, err)
	}
	committed = true
	return nil
}

func requireAbsentOrEmpty(dir string) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cliagent: output directory: %w", err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrOutputExists, dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrOutputExists, dir)
	}
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("cliagent: output directory: %w", err)
	}
	defer f.Close()
	if _, err := f.Readdirnames(1); !errors.Is(err, io.EOF) {
		if err != nil {
			return fmt.Errorf("cliagent: output directory: %w", err)
		}
		return fmt.Errorf("%w: %s", ErrOutputExists, dir)
	}
	return nil
}

func writeStaged(stage string, f File) error {
	if !safeRelPath(f.Path) {
		return fmt.Errorf("cliagent: unsafe rendered path %q", f.Path)
	}
	target := filepath.Join(stage, filepath.FromSlash(f.Path))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("cliagent: staging %s: %w", f.Path, err)
	}
	fh, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("cliagent: staging %s: %w", f.Path, err)
	}
	if _, err := fh.Write(f.Data); err != nil {
		fh.Close()
		return fmt.Errorf("cliagent: staging %s: %w", f.Path, err)
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		return fmt.Errorf("cliagent: staging %s: %w", f.Path, err)
	}
	if err := fh.Close(); err != nil {
		return fmt.Errorf("cliagent: staging %s: %w", f.Path, err)
	}
	return nil
}

func safeRelPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || path.Clean(p) != p {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return false
		}
	}
	return true
}

// Check compares outDir with the rendering of s without modifying anything. It
// reports missing, changed and unexpected files, symlinks and non-regular
// entries, and returns an error wrapping ErrDrift listing every problem.
func Check(s *Spec, outDir string) error {
	files, err := Render(s)
	if err != nil {
		return err
	}
	fi, err := os.Lstat(outDir)
	if err != nil {
		return fmt.Errorf("cliagent: output directory: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory (symlinks are rejected)", ErrDrift, outDir)
	}
	want := map[string][]byte{}
	wantDirs := map[string]bool{}
	for _, f := range files {
		want[f.Path] = f.Data
		for d := path.Dir(f.Path); d != "."; d = path.Dir(d) {
			wantDirs[d] = true
		}
	}
	var problems []string
	seen := map[string]bool{}
	walkErr := filepath.WalkDir(outDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == outDir {
			return nil
		}
		rel, err := filepath.Rel(outDir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		mode := d.Type()
		switch {
		case mode&fs.ModeSymlink != 0:
			problems = append(problems, "symlink: "+rel)
			return nil
		case d.IsDir():
			if !wantDirs[rel] {
				problems = append(problems, "unexpected directory: "+rel)
				return fs.SkipDir
			}
			return nil
		case !mode.IsRegular():
			problems = append(problems, "not a regular file: "+rel)
			return nil
		}
		data, ok := want[rel]
		if !ok {
			problems = append(problems, "unexpected file: "+rel)
			return nil
		}
		seen[rel] = true
		got, err := readBounded(p, int64(len(data))+1)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, data) {
			problems = append(problems, "changed: "+rel)
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("cliagent: checking %s: %w", outDir, walkErr)
	}
	for p := range want {
		if !seen[p] {
			problems = append(problems, "missing: "+p)
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("%w:\n  %s", ErrDrift, strings.Join(problems, "\n  "))
	}
	return nil
}

func readBounded(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit))
}

// removeEmptyOutput removes only an empty output directory before publication.
func removeEmptyOutput(dir string) error { return syscall.Rmdir(dir) }
