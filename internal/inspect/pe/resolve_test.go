// Deterministic resolver tests. Every scenario builds a synthetic PE with a
// controllable import table and a temp-dir file layout, so the tests pass on
// any host without touching the real C:\Windows. PATH is pinned with
// t.Setenv and CWD with t.Chdir.
package pe

import (
	"debug/pe"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// imp returns a dllImport with one placeholder function. A DLL entry with no
// functions would produce an empty thunk array and thus no import at all.
func imp(dll string) dllImport { return dllImport{dll: dll, fns: []string{"Fn"}} }

// stub writes an empty file at path (creating parent dirs).
func stub(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("write stub %s: %v", path, err)
	}
}

// inspectPEIn builds a synthetic PE importing the given DLLs into dir and
// inspects it. PATH is emptied so the host environment cannot leak DLLs.
func inspectPEIn(t *testing.T, dir string, spec peSpec, opts Options) *Graph {
	t.Helper()
	t.Setenv("PATH", "")
	target := buildPE(t, dir, "target.exe", spec)
	g, err := Inspect(target, opts)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	return g
}

// inspectPE is inspectPEIn with a fresh temp dir for the target.
func inspectPE(t *testing.T, spec peSpec, opts Options) *Graph {
	t.Helper()
	return inspectPEIn(t, t.TempDir(), spec, opts)
}

// nodeByModule returns the node with the given Module, or nil.
func nodeByModule(g *Graph, module string) *Node {
	for i := range g.Nodes {
		if g.Nodes[i].Module == module {
			return &g.Nodes[i]
		}
	}
	return nil
}

func TestResolveKnownDLLFromSystemDir(t *testing.T) {
	root := t.TempDir()
	stub(t, filepath.Join(root, "System32", "kernel32.dll"))
	g := inspectPE(t, peSpec{imports: []dllImport{imp("kernel32.dll")}}, Options{SystemRoot: root})
	n := nodeByModule(g, filepath.Join(root, "System32", "kernel32.dll"))
	if n == nil || n.Status != StatusPresent {
		t.Fatalf("kernel32 node = %+v, want present at System32 stub", n)
	}
}

func TestResolveKnownDLLNeverFallsBack(t *testing.T) {
	// kernel32.dll is a KnownDLL: it must resolve from the system dir ONLY.
	// A stub in the app dir must NOT satisfy it.
	root := t.TempDir()
	dir := t.TempDir()
	stub(t, filepath.Join(dir, "kernel32.dll"))
	g := inspectPEIn(t, dir, peSpec{imports: []dllImport{imp("kernel32.dll")}}, Options{SystemRoot: root})
	n := nodeByModule(g, "kernel32.dll")
	if n == nil || n.Status != StatusMissing {
		t.Fatalf("kernel32 node = %+v, want missing (KnownDLLs never fall back)", n)
	}
}

func TestResolveAppDir(t *testing.T) {
	root := t.TempDir()
	dir := t.TempDir()
	stub(t, filepath.Join(dir, "appdll.dll"))
	g := inspectPEIn(t, dir, peSpec{imports: []dllImport{imp("appdll.dll")}}, Options{SystemRoot: root})
	want := filepath.Join(dir, "appdll.dll")
	if n := nodeByModule(g, want); n == nil || n.Status != StatusPresent {
		t.Fatalf("appdll node = %+v, want present at %s", n, want)
	}
}

func TestResolveSystem32Fallback(t *testing.T) {
	// Non-KnownDLL found in System32 (no SysWOW64 present).
	root := t.TempDir()
	stub(t, filepath.Join(root, "System32", "sysdll.dll"))
	g := inspectPE(t, peSpec{imports: []dllImport{imp("sysdll.dll")}}, Options{SystemRoot: root})
	want := filepath.Join(root, "System32", "sysdll.dll")
	if n := nodeByModule(g, want); n == nil || n.Status != StatusPresent {
		t.Fatalf("sysdll node = %+v, want present at %s", n, want)
	}
}

func TestResolveX86PrefersSysWOW64(t *testing.T) {
	// x86 machine: SysWOW64 wins when it exists, even though System32 also
	// has the DLL.
	root := t.TempDir()
	stub(t, filepath.Join(root, "System32", "sysdll.dll"))
	stub(t, filepath.Join(root, "SysWOW64", "sysdll.dll"))
	g := inspectPE(t, peSpec{machine: 0x14c, imports: []dllImport{imp("sysdll.dll")}},
		Options{SystemRoot: root})
	want := filepath.Join(root, "SysWOW64", "sysdll.dll")
	if n := nodeByModule(g, want); n == nil || n.Status != StatusPresent {
		t.Fatalf("sysdll node = %+v, want present at %s", n, want)
	}
}

func TestResolveX86SysWOW64AbsentUsesSystem32(t *testing.T) {
	root := t.TempDir()
	stub(t, filepath.Join(root, "System32", "sysdll.dll"))
	g := inspectPE(t, peSpec{machine: 0x14c, imports: []dllImport{imp("sysdll.dll")}},
		Options{SystemRoot: root})
	want := filepath.Join(root, "System32", "sysdll.dll")
	if n := nodeByModule(g, want); n == nil || n.Status != StatusPresent {
		t.Fatalf("sysdll node = %+v, want present at %s", n, want)
	}
}

func TestResolveCWD(t *testing.T) {
	root := t.TempDir()
	cwd := t.TempDir()
	stub(t, filepath.Join(cwd, "cwddll.dll"))
	t.Chdir(cwd)
	g := inspectPE(t, peSpec{imports: []dllImport{imp("cwddll.dll")}}, Options{SystemRoot: root})
	want := filepath.Join(cwd, "cwddll.dll")
	if n := nodeByModule(g, want); n == nil || n.Status != StatusPresent {
		t.Fatalf("cwddll node = %+v, want present at %s", n, want)
	}
}

func TestResolvePATH(t *testing.T) {
	root := t.TempDir()
	pathDir := t.TempDir()
	stub(t, filepath.Join(pathDir, "pathdll.dll"))
	t.Setenv("PATH", pathDir)
	// Inspect directly: inspectPEIn pins PATH to "" for isolation.
	dir := t.TempDir()
	target := buildPE(t, dir, "target.exe", peSpec{imports: []dllImport{imp("pathdll.dll")}})
	g, err := Inspect(target, Options{SystemRoot: root})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	want := filepath.Join(pathDir, "pathdll.dll")
	if n := nodeByModule(g, want); n == nil || n.Status != StatusPresent {
		t.Fatalf("pathdll node = %+v, want present at %s", n, want)
	}
}

func TestResolveSearchDirs(t *testing.T) {
	root := t.TempDir()
	extra := t.TempDir()
	stub(t, filepath.Join(extra, "extradll.dll"))
	g := inspectPE(t, peSpec{imports: []dllImport{imp("extradll.dll")}},
		Options{SystemRoot: root, SearchDirs: []string{extra}})
	want := filepath.Join(extra, "extradll.dll")
	if n := nodeByModule(g, want); n == nil || n.Status != StatusPresent {
		t.Fatalf("extradll node = %+v, want present at %s", n, want)
	}
}

func TestResolveMissingFallthrough(t *testing.T) {
	root := t.TempDir()
	g := inspectPE(t, peSpec{imports: []dllImport{imp("nowhere.dll")}}, Options{SystemRoot: root})
	n := nodeByModule(g, "nowhere.dll")
	if n == nil || n.Status != StatusMissing {
		t.Fatalf("nowhere node = %+v, want missing", n)
	}
}

func TestResolveKnownDLLOverride(t *testing.T) {
	// A non-empty KnownDLLs override replaces the default list: kernel32.dll
	// is no longer known, so it resolves from the app dir instead.
	root := t.TempDir()
	dir := t.TempDir()
	stub(t, filepath.Join(dir, "kernel32.dll"))
	g := inspectPEIn(t, dir, peSpec{imports: []dllImport{imp("kernel32.dll")}},
		Options{SystemRoot: root, KnownDLLs: []string{"custom.dll"}})
	want := filepath.Join(dir, "kernel32.dll")
	if n := nodeByModule(g, want); n == nil || n.Status != StatusPresent {
		t.Fatalf("kernel32 node = %+v, want present at app dir %s", n, want)
	}
	// The override's own entry resolves from the system dir.
	stub(t, filepath.Join(root, "System32", "custom.dll"))
	g2 := inspectPE(t, peSpec{imports: []dllImport{imp("custom.dll")}},
		Options{SystemRoot: root, KnownDLLs: []string{"custom.dll"}})
	want2 := filepath.Join(root, "System32", "custom.dll")
	if n := nodeByModule(g2, want2); n == nil || n.Status != StatusPresent {
		t.Fatalf("custom node = %+v, want present at %s", n, want2)
	}
}

func TestResolveEmptyKnownDLLsUsesDefault(t *testing.T) {
	// An empty KnownDLLs override means "use the default list": kernel32.dll
	// stays known and resolves from the system dir.
	root := t.TempDir()
	stub(t, filepath.Join(root, "System32", "kernel32.dll"))
	g := inspectPE(t, peSpec{imports: []dllImport{imp("kernel32.dll")}},
		Options{SystemRoot: root, KnownDLLs: []string{}})
	want := filepath.Join(root, "System32", "kernel32.dll")
	if n := nodeByModule(g, want); n == nil || n.Status != StatusPresent {
		t.Fatalf("kernel32 node = %+v, want present at %s", n, want)
	}
}

func TestResolveDefaultSystemRoot(t *testing.T) {
	// With SystemRoot unset and the env var empty, the resolver falls back
	// to C:\Windows (never consulted here: the DLL is missing everywhere).
	t.Setenv("SystemRoot", "")
	g := inspectPE(t, peSpec{imports: []dllImport{imp("nowhere.dll")}}, Options{})
	if n := nodeByModule(g, "nowhere.dll"); n == nil || n.Status != StatusMissing {
		t.Fatalf("nowhere node = %+v, want missing", n)
	}
}

func TestResolveDedupDirs(t *testing.T) {
	// The same directory listed twice (PATH + SearchDirs) must be searched
	// once; resolution still succeeds.
	root := t.TempDir()
	dir := t.TempDir()
	stub(t, filepath.Join(dir, "dup.dll"))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+dir)
	// Inspect directly: inspectPEIn pins PATH to "" for isolation.
	target := buildPE(t, dir, "target.exe", peSpec{imports: []dllImport{imp("dup.dll")}})
	g, err := Inspect(target, Options{SystemRoot: root, SearchDirs: []string{dir}})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	want := filepath.Join(dir, "dup.dll")
	if n := nodeByModule(g, want); n == nil || n.Status != StatusPresent {
		t.Fatalf("dup node = %+v, want present at %s", n, want)
	}
}

func TestNoImports(t *testing.T) {
	g := inspectPE(t, peSpec{}, Options{SystemRoot: t.TempDir()})
	if len(g.Imports) != 0 {
		t.Errorf("Imports = %+v, want none", g.Imports)
	}
	if len(g.Nodes) != 1 || g.Nodes[0].Status != StatusPresent {
		t.Errorf("Nodes = %+v, want only the target present", g.Nodes)
	}
	if len(g.Edges) != 0 {
		t.Errorf("Edges = %+v, want none", g.Edges)
	}
}

func TestInspectBadImportTable(t *testing.T) {
	dir := t.TempDir()
	target := buildPE(t, dir, "target.exe", peSpec{badThunk: true, imports: []dllImport{imp("kernel32.dll")}})
	_, err := Inspect(target, Options{SystemRoot: t.TempDir()})
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v (%T), want *Error", err, err)
	}
	if e.Op != "imports" {
		t.Errorf("Op = %q, want imports", e.Op)
	}
}

func TestMachineName(t *testing.T) {
	cases := []struct {
		m    uint16
		want string
	}{
		{0x14c, "x86"},
		{0x8664, "amd64"},
		{0xaa64, "arm64"},
		{0x1c4, "armnt"},
		{0x1c0, "arm"},
		{0x200, "ia64"},
		{0x5032, "riscv32"},
		{0x5064, "riscv64"},
		{0x5128, "riscv128"},
		{0x1234, "unknown-0x1234"},
	}
	for _, c := range cases {
		if got := machineName(c.m); got != c.want {
			t.Errorf("machineName(0x%x) = %q, want %q", c.m, got, c.want)
		}
	}
}

func TestSubsystemName(t *testing.T) {
	if got := subsystemName(nil); got != "unknown" {
		t.Errorf("subsystemName(nil) = %q, want unknown", got)
	}
	if got := subsystemName(&pe.OptionalHeader32{Subsystem: 0x1234}); got != "unknown-0x1234" {
		t.Errorf("subsystemName(0x1234) = %q, want unknown-0x1234", got)
	}
	if got := subsystemName(&pe.OptionalHeader64{Subsystem: pe.IMAGE_SUBSYSTEM_WINDOWS_GUI}); got != "windows-gui" {
		t.Errorf("subsystemName(windows-gui) = %q, want windows-gui", got)
	}
}

func TestGroupImports(t *testing.T) {
	got := groupImports([]string{"A:one.dll", "B:one.dll", "C:two.dll", "A:one.dll", "nodcolon"})
	want := []Import{
		{DLL: "one.dll", Functions: []string{"A", "B"}},
		{DLL: "two.dll", Functions: []string{"C"}},
	}
	if len(got) != len(want) {
		t.Fatalf("groupImports = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].DLL != want[i].DLL || len(got[i].Functions) != len(want[i].Functions) {
			t.Errorf("group %d = %+v, want %+v", i, got[i], want[i])
			continue
		}
		for j := range want[i].Functions {
			if got[i].Functions[j] != want[i].Functions[j] {
				t.Errorf("group %d fn %d = %q, want %q", i, j, got[i].Functions[j], want[i].Functions[j])
			}
		}
	}
}

func TestDedup(t *testing.T) {
	got := dedup([]string{"a", "b", "a", "", "c", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("dedup = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dedup[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
