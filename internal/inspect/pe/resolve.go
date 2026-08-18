// Dependency resolution: the documented Windows DLL search order, applied
// by file existence. No subprocesses, no registry access.
package pe

import (
	"os"
	"path/filepath"
	"strings"
)

// resolver holds the precomputed search state for one Inspect call.
type resolver struct {
	known     map[string]bool // lowercase DLL names in the KnownDLLs list
	systemDir string          // machine-appropriate system directory
	dirs      []string        // deduplicated search dirs after the KnownDLL step
}

// newResolver builds the search state for target on machine. The search
// order is: KnownDLLs (system directory only) -> application directory ->
// System32/SysWOW64 -> current directory -> PATH -> Options.SearchDirs.
func newResolver(target, machine string, opts Options) *resolver {
	root := systemRoot(opts)
	systemDir := filepath.Join(root, "System32")
	if machine == "x86" {
		// x86 processes load from SysWOW64 when it exists.
		if st, err := os.Stat(filepath.Join(root, "SysWOW64")); err == nil && st.IsDir() {
			systemDir = filepath.Join(root, "SysWOW64")
		}
	}

	known := map[string]bool{}
	list := opts.KnownDLLs
	if len(list) == 0 {
		list = defaultKnownDLLs
	}
	for _, d := range list {
		known[strings.ToLower(filepath.Base(d))] = true
	}

	dirs := []string{filepath.Dir(target), systemDir}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd)
	}
	for _, p := range filepath.SplitList(os.Getenv("PATH")) {
		if p != "" {
			dirs = append(dirs, p)
		}
	}
	dirs = append(dirs, opts.SearchDirs...)
	return &resolver{known: known, systemDir: systemDir, dirs: dedup(dirs)}
}

// resolve finds dll on disk, returning the resolved absolute path. A DLL on
// the KnownDLLs list is resolved from the system directory ONLY — KnownDLLs
// never fall back to the application directory, CWD or PATH.
func (r *resolver) resolve(dll string) (string, bool) {
	name := filepath.Base(dll)
	if r.known[strings.ToLower(name)] {
		p := filepath.Join(r.systemDir, name)
		if fileExists(p) {
			return absPath(p), true
		}
		return "", false
	}
	for _, dir := range r.dirs {
		p := filepath.Join(dir, name)
		if fileExists(p) {
			return absPath(p), true
		}
	}
	return "", false
}

// fileExists reports whether path names an existing file.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// absPath returns the absolute form of path, falling back to path itself.
func absPath(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// dedup removes empty and duplicate directories, preserving first-seen
// order.
func dedup(dirs []string) []string {
	seen := map[string]bool{}
	out := dirs[:0]
	for _, d := range dirs {
		if d == "" {
			continue
		}
		d = filepath.Clean(d)
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}
