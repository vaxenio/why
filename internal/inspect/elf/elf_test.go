package elf

import (
	"os"
	"path/filepath"
	"testing"
)

// fixturesBin is the committed golden-fixture directory, relative to this
// package (internal/inspect/elf -> repo root is three levels up).
const fixturesBin = "../../../test/fixtures/bin"

// fixturePath returns the path of a committed fixture, failing the test when
// it is missing.
func fixturePath(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(fixturesBin, name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("fixture %s missing: %v", p, err)
	}
	return p
}

// TestInspectHelloStatic pins the healthy x86_64 fixture: static Go binary
// with no PT_INTERP and no DT_NEEDED, so the graph is exactly one present
// node with the target's EI_CLASS and e_machine exposed.
func TestInspectHelloStatic(t *testing.T) {
	root := fixturePath(t, "hello-linux-x86_64")
	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if g.Target != root {
		t.Errorf("Target = %q, want %q", g.Target, root)
	}
	if g.TargetArch != "amd64" {
		t.Errorf("TargetArch = %q, want amd64", g.TargetArch)
	}
	if g.TargetClass != "64" {
		t.Errorf("TargetClass = %q, want 64", g.TargetClass)
	}
	if g.Interp != "" {
		t.Errorf("Interp = %q, want empty (static binary)", g.Interp)
	}
	if len(g.Needed) != 0 {
		t.Errorf("Needed = %v, want none (static binary)", g.Needed)
	}
	if len(g.Nodes) != 1 {
		t.Fatalf("nodes = %v, want exactly the target", modules(g))
	}
	n := g.Nodes[0]
	if n.Module != root || n.Status != StatusPresent {
		t.Errorf("root node = %+v, want {module:%q status:present}", n, root)
	}
	if len(g.Edges) != 0 {
		t.Errorf("edges = %v, want none", g.Edges)
	}
}

// TestInspectWrongArch32 pins the ELF32 i386 fixture: EI_CLASS 32 + e_machine
// x86, static, single present node.
func TestInspectWrongArch32(t *testing.T) {
	root := fixturePath(t, "wrong-arch-linux")
	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if g.TargetClass != "32" {
		t.Errorf("TargetClass = %q, want 32", g.TargetClass)
	}
	if g.TargetArch != "x86" {
		t.Errorf("TargetArch = %q, want x86", g.TargetArch)
	}
	if len(g.Nodes) != 1 || g.Nodes[0].Status != StatusPresent {
		t.Errorf("nodes = %v, want single present target", g.Nodes)
	}
}

// TestInspectMissingSO pins the missing-.so fixture: the unique-suffix soname
// libdefinitelymissing.so.1 can never resolve, so it is a missing node with a
// root edge. The interpreter node exists; its status is host-dependent
// (present on glibc hosts) so only presence is pinned.
func TestInspectMissingSO(t *testing.T) {
	root := fixturePath(t, "missing-so")
	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if g.Interp != "/lib64/ld-linux-x86-64.so.2" {
		t.Errorf("Interp = %q, want /lib64/ld-linux-x86-64.so.2", g.Interp)
	}
	if len(g.Needed) != 1 || g.Needed[0] != "libdefinitelymissing.so.1" {
		t.Fatalf("Needed = %v, want [libdefinitelymissing.so.1]", g.Needed)
	}
	n := nodeByModule(t, g, "libdefinitelymissing.so.1")
	if n.Status != StatusMissing {
		t.Errorf("dep node = %+v, want missing", n)
	}
	if !hasEdge(g, root, "libdefinitelymissing.so.1") {
		t.Errorf("edge root->soname missing: %v", g.Edges)
	}
	nodeByModule(t, g, "/lib64/ld-linux-x86-64.so.2")
}

// TestInspectBadInterp pins the bad-interpreter fixture: the PT_INTERP path
// /nonexistent/ld-linux-why.so never exists, so its node is missing-interp
// with a root edge.
func TestInspectBadInterp(t *testing.T) {
	root := fixturePath(t, "bad-interp")
	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if g.Interp != "/nonexistent/ld-linux-why.so" {
		t.Errorf("Interp = %q, want /nonexistent/ld-linux-why.so", g.Interp)
	}
	n := nodeByModule(t, g, "/nonexistent/ld-linux-why.so")
	if n.Status != StatusInterpMissing {
		t.Errorf("interp node = %+v, want missing-interp", n)
	}
	if !hasEdge(g, root, "/nonexistent/ld-linux-why.so") {
		t.Errorf("edge root->interp missing: %v", g.Edges)
	}
}

// TestInspectMuslShape pins the musl-shaped fixture: PT_INTERP
// /lib/ld-musl-x86_64.so.1 + DT_NEEDED libc.musl-x86_64.so.1. libc.musl
// resolution is host-dependent; only the interpreter node is pinned.
func TestInspectMuslShape(t *testing.T) {
	root := fixturePath(t, "musl-hello")
	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if g.Interp != "/lib/ld-musl-x86_64.so.1" {
		t.Errorf("Interp = %q, want /lib/ld-musl-x86_64.so.1", g.Interp)
	}
	if len(g.Needed) != 1 || g.Needed[0] != "libc.musl-x86_64.so.1" {
		t.Errorf("Needed = %v, want [libc.musl-x86_64.so.1]", g.Needed)
	}
	nodeByModule(t, g, "/lib/ld-musl-x86_64.so.1")
}

// TestInspectMangledMagic pins the corrupt fixture: byte 0 flipped to 0x00
// must surface as a typed *Error, never a panic.
func TestInspectMangledMagic(t *testing.T) {
	root := fixturePath(t, "mangled-elf-magic")
	_, err := Inspect(root, Options{})
	if err == nil {
		t.Fatal("Inspect(mangled-elf-magic): expected error, got nil")
	}
	var se *Error
	if !errorsAs(err, &se) {
		t.Fatalf("error %T %v is not *elf.Error", err, err)
	}
	if se.Path != root {
		t.Errorf("Error.Path = %q, want %q", se.Path, root)
	}
	if se.Op != "open" {
		t.Errorf("Error.Op = %q, want open", se.Op)
	}
	if se.Err == nil {
		t.Error("Error.Err is nil")
	}
}

// TestInspectNotAnELF covers a plain text file: typed error, no panic.
func TestInspectNotAnELF(t *testing.T) {
	dir := depDir(t)
	p := filepath.Join(dir, "not-elf")
	if err := os.WriteFile(p, []byte("this is not an ELF at all"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Inspect(p, Options{}); err == nil {
		t.Error("Inspect(garbage): expected error")
	}
}

// TestInspectNonexistentAndDir covers missing paths and directories.
func TestInspectNonexistentAndDir(t *testing.T) {
	dir := depDir(t)
	if _, err := Inspect(filepath.Join(dir, "nope"), Options{}); err == nil {
		t.Error("Inspect(nonexistent): expected error")
	}
	if _, err := Inspect(dir, Options{}); err == nil {
		t.Error("Inspect(dir): expected error")
	}
}

// ---- pure helpers -----------------------------------------------------------

func TestMachineName(t *testing.T) {
	cases := []struct {
		m    uint16
		want string
	}{
		{0x3e, "amd64"},
		{0x03, "x86"},
		{0xb7, "arm64"},
		{0x28, "arm"},
		{0xf3, "riscv64"},
		{0x15, "ppc64"},
		{0x16, "s390x"},
		{0x08, "mips"},
		{0x102, "loongarch64"},
		{0x999, "arch-0x999"},
	}
	for _, tc := range cases {
		if got := machineName(tc.m); got != tc.want {
			t.Errorf("machineName(0x%x) = %q, want %q", tc.m, got, tc.want)
		}
	}
}

func TestSplitPathList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"a", []string{"a"}},
		{"a:b::c", []string{"a", "b", ".", "c"}},
		{":", []string{".", "."}},
	}
	for _, tc := range cases {
		got := splitPathList(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitPathList(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitPathList(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}
}

func TestEnvMap(t *testing.T) {
	m := envMap([]string{"LD_LIBRARY_PATH=/a:/b", "FOO=bar", "novalue", "=x"})
	if m["LD_LIBRARY_PATH"] != "/a:/b" {
		t.Errorf("LD_LIBRARY_PATH = %q", m["LD_LIBRARY_PATH"])
	}
	if m["FOO"] != "bar" {
		t.Errorf("FOO = %q", m["FOO"])
	}
	if _, ok := m["NOVALUE"]; ok {
		t.Error("novalue should not be present")
	}
	if _, ok := m[""]; ok {
		t.Error("empty key should not be present")
	}
}
