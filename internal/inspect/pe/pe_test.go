// Acceptance tests for Inspect against the committed PE fixtures in
// test/fixtures/bin. All tests are host-independent: resolution never relies
// on the real C:\Windows — Options.SystemRoot points at a temp dir holding
// only the stub files the scenario needs, and PATH is emptied so the host
// environment cannot leak DLLs into the search.
package pe

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixturePath returns the path of a committed fixture binary, relative to
// the package directory (internal/inspect/pe -> test/fixtures/bin).
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "test", "fixtures", "bin", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("fixture %s: %v", p, err)
	}
	return p
}

// writeStub creates an empty file at path (creating parent dirs).
func writeStub(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("write stub %s: %v", path, err)
	}
}

// systemRoot returns a temp dir with a System32\kernel32.dll stub, the
// minimal system-dir setup the acceptance scenarios need.
func fixtureSystemRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeStub(t, filepath.Join(root, "System32", "kernel32.dll"))
	return root
}

func TestInspectHelloX64(t *testing.T) {
	t.Setenv("PATH", "")
	target := fixturePath(t, "hello-x64.exe")
	root := fixtureSystemRoot(t)
	g, err := Inspect(target, Options{SystemRoot: root})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if g.Target != target {
		t.Errorf("Target = %q, want %q", g.Target, target)
	}
	if g.Machine != "amd64" {
		t.Errorf("Machine = %q, want amd64", g.Machine)
	}
	if g.Subsystem != "windows-cui" {
		t.Errorf("Subsystem = %q, want windows-cui", g.Subsystem)
	}
	// One import group: kernel32.dll (a KnownDLL, resolved from System32).
	if len(g.Imports) != 1 || g.Imports[0].DLL != "kernel32.dll" {
		t.Fatalf("Imports = %+v, want one kernel32.dll group", g.Imports)
	}
	if len(g.Imports[0].Functions) == 0 {
		t.Fatal("kernel32.dll group has no functions")
	}
	// The Go runtime imports GetProcAddress twice; grouping must dedupe.
	if n := count(g.Imports[0].Functions, "GetProcAddress"); n != 1 {
		t.Errorf("GetProcAddress appears %d times, want 1", n)
	}
	// Nodes: target + kernel32, both present.
	if len(g.Nodes) != 2 {
		t.Fatalf("len(Nodes) = %d, want 2: %+v", len(g.Nodes), g.Nodes)
	}
	if g.Nodes[0] != (Node{Module: target, Status: StatusPresent}) {
		t.Errorf("Nodes[0] = %+v, want target present", g.Nodes[0])
	}
	wantKernel := filepath.Join(root, "System32", "kernel32.dll")
	if g.Nodes[1].Module != wantKernel || g.Nodes[1].Status != StatusPresent {
		t.Errorf("Nodes[1] = %+v, want %q present", g.Nodes[1], wantKernel)
	}
	// One edge: target -> kernel32.
	if len(g.Edges) != 1 || g.Edges[0] != (Edge{target, wantKernel}) {
		t.Errorf("Edges = %+v, want [%q %q]", g.Edges, target, wantKernel)
	}
}

func TestInspectMissingDLL(t *testing.T) {
	t.Setenv("PATH", "")
	target := fixturePath(t, "missing-dll-x64.exe")
	root := fixtureSystemRoot(t)
	g, err := Inspect(target, Options{SystemRoot: root})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if g.Machine != "amd64" {
		t.Errorf("Machine = %q, want amd64", g.Machine)
	}
	// kernel32.dll present via KnownDLL; DefinitelyMissing.dll missing.
	if len(g.Nodes) != 3 {
		t.Fatalf("len(Nodes) = %d, want 3: %+v", len(g.Nodes), g.Nodes)
	}
	if g.Nodes[1].Module != filepath.Join(root, "System32", "kernel32.dll") ||
		g.Nodes[1].Status != StatusPresent {
		t.Errorf("Nodes[1] = %+v, want kernel32 present", g.Nodes[1])
	}
	if g.Nodes[2] != (Node{Module: "DefinitelyMissing.dll", Status: StatusMissing}) {
		t.Errorf("Nodes[2] = %+v, want DefinitelyMissing.dll missing", g.Nodes[2])
	}
	if len(g.Edges) != 2 {
		t.Errorf("len(Edges) = %d, want 2", len(g.Edges))
	}
	// The missing DLL is reported in the import table too.
	if len(g.Imports) != 2 || g.Imports[1].DLL != "DefinitelyMissing.dll" {
		t.Errorf("Imports = %+v, want kernel32.dll + DefinitelyMissing.dll", g.Imports)
	}
}

func TestInspectWrongArch(t *testing.T) {
	t.Setenv("PATH", "")
	g, err := Inspect(fixturePath(t, "wrong-arch.exe"), Options{SystemRoot: fixtureSystemRoot(t)})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if g.Machine != "x86" {
		t.Errorf("Machine = %q, want x86", g.Machine)
	}
}

func TestInspectHelloX86(t *testing.T) {
	t.Setenv("PATH", "")
	g, err := Inspect(fixturePath(t, "hello-x86.exe"), Options{SystemRoot: fixtureSystemRoot(t)})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if g.Machine != "x86" {
		t.Errorf("Machine = %q, want x86", g.Machine)
	}
	if g.Subsystem != "windows-cui" {
		t.Errorf("Subsystem = %q, want windows-cui", g.Subsystem)
	}
}

func TestInspectTruncated(t *testing.T) {
	_, err := Inspect(fixturePath(t, "truncated-hello-x64.exe"), Options{})
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v (%T), want *Error", err, err)
	}
	if e.Op != "open" {
		t.Errorf("Op = %q, want open", e.Op)
	}
	if e.Path != fixturePath(t, "truncated-hello-x64.exe") {
		t.Errorf("Path = %q, want fixture path", e.Path)
	}
	if e.Err == nil {
		t.Error("Err is nil, want underlying EOF")
	}
	if !strings.Contains(e.Error(), "pe: open") {
		t.Errorf("Error() = %q, want pe: open prefix", e.Error())
	}
	if e.Unwrap() == nil {
		t.Error("Unwrap() = nil, want underlying error")
	}
}

func count(xs []string, want string) int {
	n := 0
	for _, x := range xs {
		if x == want {
			n++
		}
	}
	return n
}
