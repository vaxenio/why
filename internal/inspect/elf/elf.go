// Package elf inspects ELF binaries statically. It parses the EI_CLASS and
// e_machine of the header, reads the interpreter path from PT_INTERP, and
// walks the dynamic dependency list (DT_NEEDED, DT_RPATH, DT_RUNPATH) to
// build a dependency graph whose nodes report whether each module exists on
// disk (present), could not be resolved (missing), or points at an
// interpreter that does not exist (missing-interp). Everything is parsed with
// the standard library's debug/elf and resolved by file existence: the
// inspector never executes the target and never shells out to ldd.
package elf

import (
	"os"
	"path/filepath"
)

// Status is the state of one node in an ELF dependency graph.
type Status string

const (
	// StatusPresent marks a module (target, dependency, or interpreter) that
	// exists on disk.
	StatusPresent Status = "present"
	// StatusMissing marks a DT_NEEDED soname that could not be resolved to an
	// existing file via DT_RPATH/DT_RUNPATH/LD_LIBRARY_PATH or the standard
	// library directories.
	StatusMissing Status = "missing"
	// StatusInterpMissing marks a PT_INTERP path that does not exist on disk.
	StatusInterpMissing Status = "missing-interp"
)

// Node is one vertex of the dependency graph. Module is the target path, the
// resolved absolute path of a found dependency, the soname of a missing
// dependency, or the interpreter path for an interpreter node. Source is how
// a found dependency resolved ("literal", "rpath", "rpath-inherited",
// "ldpath", "runpath", "system"); Arch is the dependency's e_machine name.
// The shape mirrors evidence.Node (module/status) so the graph serializes
// directly.
type Node struct {
	Module string `json:"module"`
	Status Status `json:"status"`
	Source string `json:"source,omitempty"`
	Arch   string `json:"arch,omitempty"`
}

// Edge is a directed dependency edge {from, to} using the node Modules.
type Edge [2]string

// Graph is the result of Inspect. Nodes[0] is always the target with
// StatusPresent. Besides the graph itself it exposes the raw header facts the
// inspect command reports: EI_CLASS, e_machine, PT_INTERP, DT_NEEDED,
// DT_RPATH and DT_RUNPATH.
type Graph struct {
	Target      string   // path passed to Inspect
	TargetArch  string   // e_machine name: "amd64", "x86", ...
	TargetClass string   // EI_CLASS: "32" or "64"
	Interp      string   // PT_INTERP path, "" when the binary has none
	Needed      []string // DT_NEEDED sonames in order
	RPATH       string   // DT_RPATH, "" when absent
	RUNPATH     string   // DT_RUNPATH, "" when absent
	Nodes       []Node
	Edges       []Edge
}

// Options controls dependency resolution.
type Options struct {
	// Env is the environment to read LD_LIBRARY_PATH from. nil uses the
	// process environment. Entries are ':'-separated per glibc.
	Env []string
	// MaxDepth caps recursion into found dependencies. 0 means 64.
	MaxDepth int
}

// Error is the structured error returned by Inspect when the target cannot
// be opened or parsed. Dependency-level problems are reported as nodes with
// StatusMissing / StatusInterpMissing, never as errors.
type Error struct {
	Path string // the target path
	Op   string // "open"
	Err  error  // underlying error, may be nil
}

func (e *Error) Error() string {
	if e.Err != nil {
		return "elf: " + e.Op + " " + e.Path + ": " + e.Err.Error()
	}
	return "elf: " + e.Op + " " + e.Path
}

// Unwrap exposes the underlying error.
func (e *Error) Unwrap() error { return e.Err }

const defaultMaxDepth = 64

// defaultLibDirs are searched after DT_RPATH/DT_RUNPATH/LD_LIBRARY_PATH,
// mirroring glibc's fallback list.
var defaultLibDirs = []string{"/lib", "/usr/lib", "/lib64", "/usr/lib64", "/usr/local/lib"}

// Inspect parses the ELF at path and returns its dependency graph, resolving
// each DT_NEEDED soname against DT_RPATH/DT_RUNPATH, LD_LIBRARY_PATH and the
// standard library directories. The target is always Nodes[0] with
// StatusPresent. A corrupt or unreadable target yields a *Error;
// dependency-level problems are represented as node statuses, not errors. No
// subprocesses are ever spawned.
func Inspect(path string, opts Options) (*Graph, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = defaultMaxDepth
	}
	if opts.Env == nil {
		opts.Env = os.Environ()
	}

	root, err := parseFile(path)
	if err != nil {
		return nil, &Error{Path: path, Op: "open", Err: err}
	}

	ins := &inspector{
		opts:   opts,
		env:    envMap(opts.Env),
		target: root,
		graph: &Graph{
			Target:      path,
			TargetArch:  root.arch,
			TargetClass: root.class,
			Interp:      root.interp,
			Needed:      root.needed,
			RPATH:       root.rpath,
			RUNPATH:     root.runpath,
		},
		seen:      map[string]bool{},
		nodeIndex: map[string]int{},
		edgeSet:   map[Edge]bool{},
	}
	if abs, err := filepath.Abs(path); err == nil {
		ins.seen[abs] = true // a dep pointing back at the target is a cycle
	}

	ins.addNode(root.path, StatusPresent, "target", root.arch)
	if root.interp != "" {
		ins.addInterp(root)
	}
	ins.resolveDeps(root, nil, 0)
	return ins.graph, nil
}
