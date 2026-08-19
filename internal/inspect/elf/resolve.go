package elf

import (
	"os"
	"path/filepath"
	"strings"
)

// inspector carries state across the recursive resolution.
type inspector struct {
	opts      Options
	env       map[string]string
	target    *parsedFile
	graph     *Graph
	seen      map[string]bool // absolute paths already fully processed
	nodeIndex map[string]int
	edgeSet   map[Edge]bool
}

// addInterp stats the interpreter path and records the node + edge.
func (ins *inspector) addInterp(f *parsedFile) {
	st := StatusInterpMissing
	if _, err := os.Stat(f.interp); err == nil {
		st = StatusPresent
	}
	ins.addNode(f.interp, st, "interp", "")
	ins.addEdge(f.path, f.interp)
}

// addNode appends a node unless its module already exists.
func (ins *inspector) addNode(module string, status Status, source, arch string) {
	if _, ok := ins.nodeIndex[module]; ok {
		return
	}
	ins.nodeIndex[module] = len(ins.graph.Nodes)
	ins.graph.Nodes = append(ins.graph.Nodes, Node{Module: module, Status: status, Source: source, Arch: arch})
}

// addEdge appends an edge unless it already exists.
func (ins *inspector) addEdge(from, to string) {
	e := Edge{from, to}
	if ins.edgeSet[e] {
		return
	}
	ins.edgeSet[e] = true
	ins.graph.Edges = append(ins.graph.Edges, e)
}

// resolveDeps resolves each DT_NEEDED soname of f and recurses into found,
// same-arch dependencies. ancestors is the chain from the target down to f's
// parent (exclusive of f), used for inherited-RPATH lookups.
func (ins *inspector) resolveDeps(f *parsedFile, ancestors []*parsedFile, depth int) {
	if depth >= ins.opts.MaxDepth {
		return
	}
	for _, soname := range f.needed {
		resolved, source := ins.resolve(soname, f, ancestors)
		if resolved == "" {
			ins.addNode(soname, StatusMissing, "", "")
			ins.addEdge(f.path, soname)
			continue
		}
		abs, err := filepath.Abs(resolved)
		if err != nil {
			abs = resolved
		}
		if ins.seen[abs] {
			ins.addEdge(f.path, abs) // cycle: node already exists
			continue
		}
		child, err := parseFile(abs)
		if err != nil {
			// Exists but is not parseable as ELF: treat as missing.
			ins.addNode(soname, StatusMissing, "", "")
			ins.addEdge(f.path, soname)
			continue
		}
		ins.seen[abs] = true
		ins.addNode(abs, StatusPresent, source, child.arch)
		ins.addEdge(f.path, abs)
		if child.arch != ins.target.arch || child.class != ins.target.class {
			// Wrong-arch dependency: it exists but the loader could not
			// load it, so its own dependencies are not expanded.
			continue
		}
		ins.resolveDeps(child, append(ancestors, f), depth+1)
	}
}

// resolve maps a soname to a file path following the glibc loader order:
// literal paths, DT_RPATH of the loading object, inherited DT_RPATHs,
// LD_LIBRARY_PATH, DT_RUNPATH of the loading object, then the standard
// library directories. It returns "" when the soname cannot be satisfied,
// and the source label describing which step found it.
func (ins *inspector) resolve(soname string, f *parsedFile, ancestors []*parsedFile) (path, source string) {
	// A soname containing '/' is a literal path.
	if strings.Contains(soname, "/") {
		if _, err := os.Stat(soname); err == nil {
			return soname, "literal"
		}
		return "", ""
	}

	// 1. DT_RPATH of the loading object (ignored when DT_RUNPATH is present).
	if f.runpath == "" && f.rpath != "" {
		if p := ins.searchDirs(f.rpath, soname); p != "" {
			return p, "rpath"
		}
	}
	// 2. Inherited DT_RPATHs of ancestors (each only when it has no RUNPATH),
	// innermost first, matching ld.so's l_loader walk.
	for i := len(ancestors) - 1; i >= 0; i-- {
		a := ancestors[i]
		if a.runpath != "" || a.rpath == "" {
			continue
		}
		if p := ins.searchDirs(a.rpath, soname); p != "" {
			return p, "rpath-inherited"
		}
	}
	// 3. LD_LIBRARY_PATH.
	if ld := ins.env["LD_LIBRARY_PATH"]; ld != "" {
		if p := ins.searchDirs(ld, soname); p != "" {
			return p, "ldpath"
		}
	}
	// 4. DT_RUNPATH of the loading object (direct dependencies only).
	if f.runpath != "" {
		if p := ins.searchDirs(f.runpath, soname); p != "" {
			return p, "runpath"
		}
	}
	// 5. Standard library directories.
	for _, dir := range defaultLibDirs {
		if p := ins.searchDirs(dir, soname); p != "" {
			return p, "system"
		}
	}
	return "", ""
}

// searchDirs splits list on ':' (glibc path-list semantics; empty entries
// mean the current directory) and returns the first existing file named
// soname, or "".
func (ins *inspector) searchDirs(list, soname string) string {
	for _, dir := range splitPathList(list) {
		p := filepath.Join(dir, soname)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// splitPathList splits a glibc-style ':' path list; empty entries map to ".".
func splitPathList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ":")
	for i, p := range parts {
		if p == "" {
			parts[i] = "."
		}
	}
	return parts
}

// envMap indexes an environment slice by upper-cased key.
func envMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		m[strings.ToUpper(kv[:i])] = kv[i+1:]
	}
	return m
}
