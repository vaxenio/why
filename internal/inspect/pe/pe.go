// Package pe inspects PE binaries statically. It parses the machine type and
// subsystem from the COFF/optional headers, reads the import table (DLL
// names + imported functions), and builds a one-level dependency graph whose
// nodes report whether each imported DLL exists on disk (present) or could
// not be resolved (missing). Resolution follows the documented Windows
// search order: KnownDLLs (system directory only), the application
// directory, System32/SysWOW64, the current directory, PATH, then any extra
// search directories. Everything is parsed with the standard library's
// debug/pe and resolved by file existence: the inspector never executes the
// target and never shells out.
package pe

import (
	"os"
	"path/filepath"
)

// Status is the state of one node in a PE dependency graph.
type Status string

const (
	// StatusPresent marks a module (target or imported DLL) that exists on
	// disk.
	StatusPresent Status = "present"
	// StatusMissing marks an imported DLL that could not be resolved to an
	// existing file via the documented search order.
	StatusMissing Status = "missing"
)

// Node is one vertex of the dependency graph. Module is the target path or
// the resolved absolute path of a found DLL, or the DLL name of a missing
// one. The shape mirrors evidence.Node (module/status) so the graph
// serializes directly.
type Node struct {
	Module string `json:"module"`
	Status Status `json:"status"`
}

// Edge is a directed dependency edge {from, to} using the node Modules.
type Edge [2]string

// Import is one imported DLL with the functions taken from it, in import
// order and deduplicated.
type Import struct {
	DLL       string   `json:"dll"`
	Functions []string `json:"functions"`
}

// Graph is the result of Inspect. Nodes[0] is always the target with
// StatusPresent. The graph is one level deep: only the target's direct
// imports are resolved, never their own dependencies (api-ms-* stubs are
// virtual on modern Windows and would pollute a recursive graph). Besides
// the graph itself it exposes the raw header facts the inspect command
// reports: machine type, subsystem and the grouped import table.
type Graph struct {
	Target    string   // path passed to Inspect
	Machine   string   // machine name: "amd64", "x86", ...
	Subsystem string   // subsystem name: "windows-cui", "windows-gui", ...
	Imports   []Import // imported DLLs grouped by DLL, in import order
	Nodes     []Node
	Edges     []Edge
}

// Options controls dependency resolution.
type Options struct {
	// SystemRoot overrides the Windows directory the system dirs are
	// derived from. Empty uses os.Getenv("SystemRoot"), falling back to
	// C:\Windows. Tests point this at a temp dir for determinism.
	SystemRoot string
	// KnownDLLs overrides the static KnownDLL snapshot. Empty uses the
	// default list. KnownDLLs resolve from the system directory ONLY.
	KnownDLLs []string
	// SearchDirs appends extra directories to the end of the search order.
	SearchDirs []string
}

// Error is the structured error returned by Inspect when the target cannot
// be opened or parsed. Dependency-level problems are reported as nodes with
// StatusMissing, never as errors.
type Error struct {
	Path string // the target path
	Op   string // "open" (pe.Open) or "imports" (import table)
	Err  error  // underlying error, may be nil
}

func (e *Error) Error() string {
	if e.Err != nil {
		return "pe: " + e.Op + " " + e.Path + ": " + e.Err.Error()
	}
	return "pe: " + e.Op + " " + e.Path
}

// Unwrap exposes the underlying error.
func (e *Error) Unwrap() error { return e.Err }

// defaultKnownDLLs is a static snapshot of the Windows KnownDLLs list
// (documented set of DLLs the loader always resolves from the system
// directory, never from the application directory). Overridable via
// Options.KnownDLLs.
var defaultKnownDLLs = []string{
	"kernel32.dll", "ntdll.dll", "user32.dll", "gdi32.dll",
	"advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll",
	"comdlg32.dll", "comctl32.dll", "shlwapi.dll", "version.dll",
	"winmm.dll", "ws2_32.dll", "wsock32.dll", "imm32.dll",
	"mpr.dll", "netapi32.dll", "rpcrt4.dll", "secur32.dll",
	"crypt32.dll", "wininet.dll", "urlmon.dll", "oleacc.dll",
	"winspool.drv", "uxtheme.dll", "dnsapi.dll", "iphlpapi.dll",
	"setupapi.dll", "dwmapi.dll", "normaliz.dll", "propsys.dll",
	"wtsapi32.dll", "userenv.dll", "devobj.dll", "gdiplus.dll",
	"msvcrt.dll", "ucrtbase.dll",
}

// Inspect parses the PE at path and returns its one-level dependency graph,
// resolving each imported DLL against the documented search order (KnownDLLs
// from the system directory only, then the application directory,
// System32/SysWOW64, the current directory, PATH, then Options.SearchDirs).
// The target is always Nodes[0] with StatusPresent. A corrupt or unreadable
// target yields a *Error; dependency-level problems are represented as node
// statuses, not errors. No subprocesses are ever spawned.
func Inspect(path string, opts Options) (*Graph, error) {
	root, err := parseFile(path)
	if err != nil {
		return nil, err
	}

	r := newResolver(path, root.machine, opts)
	g := &Graph{
		Target:    path,
		Machine:   root.machine,
		Subsystem: root.subsystem,
		Imports:   root.imports,
		Nodes:     []Node{{Module: path, Status: StatusPresent}},
	}
	seen := map[string]bool{path: true}
	edgeSet := map[Edge]bool{}
	for _, imp := range root.imports {
		module, status := imp.DLL, StatusMissing
		if resolved, ok := r.resolve(imp.DLL); ok {
			module, status = resolved, StatusPresent
		}
		if !seen[module] {
			seen[module] = true
			g.Nodes = append(g.Nodes, Node{Module: module, Status: status})
		}
		e := Edge{path, module}
		if !edgeSet[e] {
			edgeSet[e] = true
			g.Edges = append(g.Edges, e)
		}
	}
	return g, nil
}

// systemRoot returns the effective Windows directory for opts.
func systemRoot(opts Options) string {
	if opts.SystemRoot != "" {
		return opts.SystemRoot
	}
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return filepath.Join("C:", string(filepath.Separator), "Windows")
}
