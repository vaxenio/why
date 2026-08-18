package elf

import (
	debugelf "debug/elf"
	"os"
	"path/filepath"
	"testing"
)

// ---- resolution via DT_RPATH / DT_RUNPATH / LD_LIBRARY_PATH -----------------

func TestInspectRpathResolution(t *testing.T) {
	dir := depDir(t)
	buildFixture(t, dir, "libx.so.1", fixtureSpec{})
	root := buildFixture(t, dir, "app", fixtureSpec{rpath: dir, needed: []string{"libx.so.1"}})

	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	p := abs(t, filepath.Join(dir, "libx.so.1"))
	if n := nodeByModule(t, g, p); n.Status != StatusPresent {
		t.Errorf("dep = %+v, want present via RPATH; nodes: %v", n, modules(g))
	}
	if !hasEdge(g, root, p) {
		t.Errorf("edge root->libx missing: %v", g.Edges)
	}
}

func TestInspectRunpathResolution(t *testing.T) {
	dir := depDir(t)
	buildFixture(t, dir, "liby.so.1", fixtureSpec{})
	root := buildFixture(t, dir, "app", fixtureSpec{runpath: dir, needed: []string{"liby.so.1"}})

	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	p := abs(t, filepath.Join(dir, "liby.so.1"))
	if n := nodeByModule(t, g, p); n.Status != StatusPresent {
		t.Errorf("dep = %+v, want present via RUNPATH", n)
	}
}

func TestInspectRpathIgnoredWhenRunpath(t *testing.T) {
	dirA, dirB := depDir(t), depDir(t)
	buildFixture(t, dirA, "libx.so.1", fixtureSpec{})
	root := buildFixture(t, dirA, "app", fixtureSpec{rpath: dirA, runpath: dirB, needed: []string{"libx.so.1"}})

	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if n := nodeByModule(t, g, "libx.so.1"); n.Status != StatusMissing {
		t.Errorf("dep = %+v, want missing (RPATH ignored when RUNPATH present)", n)
	}
}

func TestInspectRpathBeatsLD(t *testing.T) {
	dirA, dirB := depDir(t), depDir(t)
	buildFixture(t, dirA, "libx.so.1", fixtureSpec{})
	buildFixture(t, dirB, "libx.so.1", fixtureSpec{})
	root := buildFixture(t, dirA, "app", fixtureSpec{rpath: dirA, needed: []string{"libx.so.1"}})

	g, err := Inspect(root, Options{Env: []string{"LD_LIBRARY_PATH=" + dirB}})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if n := nodeByModule(t, g, abs(t, filepath.Join(dirA, "libx.so.1"))); n.Status != StatusPresent {
		t.Errorf("want libx from RPATH dir; nodes: %v", modules(g))
	}
}

func TestInspectLDBeatsRunpath(t *testing.T) {
	dirA, dirB := depDir(t), depDir(t)
	buildFixture(t, dirA, "libx.so.1", fixtureSpec{})
	buildFixture(t, dirB, "libx.so.1", fixtureSpec{})
	root := buildFixture(t, dirA, "app", fixtureSpec{runpath: dirA, needed: []string{"libx.so.1"}})

	g, err := Inspect(root, Options{Env: []string{"LD_LIBRARY_PATH=" + dirB}})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if n := nodeByModule(t, g, abs(t, filepath.Join(dirB, "libx.so.1"))); n.Status != StatusPresent {
		t.Errorf("want libx from LD_LIBRARY_PATH; nodes: %v", modules(g))
	}
}

// ---- transitive resolution ---------------------------------------------------

func TestInspectRpathTransitive(t *testing.T) {
	dir := depDir(t)
	buildFixture(t, dir, "libbar.so.2", fixtureSpec{})
	buildFixture(t, dir, "libfoo.so.1", fixtureSpec{needed: []string{"libbar.so.2"}})
	root := buildFixture(t, dir, "app", fixtureSpec{rpath: dir, needed: []string{"libfoo.so.1"}})

	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	foo := abs(t, filepath.Join(dir, "libfoo.so.1"))
	bar := abs(t, filepath.Join(dir, "libbar.so.2"))
	if n := nodeByModule(t, g, foo); n.Status != StatusPresent {
		t.Errorf("libfoo = %+v, want present", n)
	}
	if n := nodeByModule(t, g, bar); n.Status != StatusPresent {
		t.Errorf("libbar = %+v, want present (RPATH inherited by descendants)", n)
	}
	if !hasEdge(g, foo, bar) {
		t.Errorf("edge foo->bar missing: %v", g.Edges)
	}
}

func TestInspectRunpathNotTransitive(t *testing.T) {
	dir := depDir(t)
	buildFixture(t, dir, "libbar.so.2", fixtureSpec{})
	buildFixture(t, dir, "libfoo.so.1", fixtureSpec{needed: []string{"libbar.so.2"}})
	root := buildFixture(t, dir, "app", fixtureSpec{runpath: dir, needed: []string{"libfoo.so.1"}})

	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	foo := abs(t, filepath.Join(dir, "libfoo.so.1"))
	if n := nodeByModule(t, g, foo); n.Status != StatusPresent {
		t.Errorf("libfoo = %+v, want present", n)
	}
	if n := nodeByModule(t, g, "libbar.so.2"); n.Status != StatusMissing {
		t.Errorf("libbar = %+v, want missing (RUNPATH is direct-deps only)", n)
	}
	if !hasEdge(g, foo, "libbar.so.2") {
		t.Errorf("edge foo->libbar(missing) absent: %v", g.Edges)
	}
}

// ---- missing / unparsable / wrong-arch dependencies -------------------------

func TestInspectMissingWithoutSearchPath(t *testing.T) {
	dir := depDir(t)
	root := buildFixture(t, dir, "app", fixtureSpec{needed: []string{"libmissing_why.so.1"}})

	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	n := nodeByModule(t, g, "libmissing_why.so.1")
	if n.Status != StatusMissing {
		t.Errorf("dep = %+v, want missing", n)
	}
	if !hasEdge(g, root, "libmissing_why.so.1") {
		t.Errorf("edge root->soname missing")
	}
}

func TestInspectUnparsableDependency(t *testing.T) {
	dir := depDir(t)
	if err := os.WriteFile(filepath.Join(dir, "garbage.so"), []byte("not an elf at all"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	root := buildFixture(t, dir, "app", fixtureSpec{needed: []string{"garbage.so"}})

	g, err := Inspect(root, Options{Env: []string{"LD_LIBRARY_PATH=" + dir}})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	n := nodeByModule(t, g, "garbage.so")
	if n.Status != StatusMissing {
		t.Errorf("dep = %+v, want missing (exists but not parseable)", n)
	}
}

func TestInspectWrongArchDependency(t *testing.T) {
	dir := depDir(t)
	// ELF32 lib (wrong EI_CLASS for the ELF64 target) in the search path.
	buildFixture(t, dir, "lib32.so.1", fixtureSpec{class: debugelf.ELFCLASS32})
	root := buildFixture(t, dir, "app", fixtureSpec{needed: []string{"lib32.so.1"}})

	g, err := Inspect(root, Options{Env: []string{"LD_LIBRARY_PATH=" + dir}})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	p := abs(t, filepath.Join(dir, "lib32.so.1"))
	n := nodeByModule(t, g, p)
	if n.Status != StatusPresent {
		t.Errorf("dep = %+v, want present (exists on disk)", n)
	}
	// Wrong-arch dependencies are not expanded: root + lib32 only.
	if len(g.Nodes) != 2 {
		t.Errorf("nodes = %v, want 2 (no expansion of wrong-arch dep)", modules(g))
	}
}

// ---- literal-path sonames ----------------------------------------------------

func TestInspectLiteralPathSoname(t *testing.T) {
	dir := depDir(t)
	buildFixture(t, dir, "absx.so", fixtureSpec{})
	// A soname containing '/' is a literal path (glibc). Forward slash keeps
	// the check host-independent.
	soname := dir + "/absx.so"
	root := buildFixture(t, dir, "app", fixtureSpec{needed: []string{soname}})

	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	p := abs(t, soname)
	if n := nodeByModule(t, g, p); n.Status != StatusPresent {
		t.Errorf("dep = %+v, want present via literal path", n)
	}
	if !hasEdge(g, root, p) {
		t.Errorf("edge root->absx missing")
	}
}

// ---- interpreter -------------------------------------------------------------

func TestInspectInterpPresent(t *testing.T) {
	dir := depDir(t)
	buildFixture(t, dir, "ld-why.so", fixtureSpec{})
	ip := filepath.Join(dir, "ld-why.so")
	root := buildFixture(t, dir, "app", fixtureSpec{interp: ip})

	g, err := Inspect(root, Options{})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if n := nodeByModule(t, g, ip); n.Status != StatusPresent {
		t.Errorf("interp node = %+v, want present", n)
	}
	if !hasEdge(g, root, ip) {
		t.Errorf("edge root->interp missing")
	}
}

// ---- cycles / dedupe / depth limit -------------------------------------------

func TestInspectCycle(t *testing.T) {
	dir := depDir(t)
	buildFixture(t, dir, "liba.so.1", fixtureSpec{needed: []string{"libb.so.1"}})
	buildFixture(t, dir, "libb.so.1", fixtureSpec{needed: []string{"liba.so.1"}})
	root := buildFixture(t, dir, "app", fixtureSpec{needed: []string{"liba.so.1"}})

	g, err := Inspect(root, Options{Env: []string{"LD_LIBRARY_PATH=" + dir}})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	for _, m := range []string{root, abs(t, filepath.Join(dir, "liba.so.1")), abs(t, filepath.Join(dir, "libb.so.1"))} {
		if n := nodeByModule(t, g, m); n.Status != StatusPresent {
			t.Errorf("node %q = %+v, want present", m, n)
		}
	}
	if len(g.Nodes) != 3 {
		t.Errorf("nodes = %v, want 3", modules(g))
	}
	if len(g.Edges) != 3 { // root->a, a->b, b->a
		t.Errorf("edges = %v, want 3", g.Edges)
	}
}

func TestInspectSelfCycle(t *testing.T) {
	dir := depDir(t)
	buildFixture(t, dir, "libs.so.1", fixtureSpec{needed: []string{"libs.so.1"}})
	root := buildFixture(t, dir, "app", fixtureSpec{needed: []string{"libs.so.1"}})

	g, err := Inspect(root, Options{Env: []string{"LD_LIBRARY_PATH=" + dir}})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	p := abs(t, filepath.Join(dir, "libs.so.1"))
	if len(g.Nodes) != 2 {
		t.Errorf("nodes = %v, want 2", modules(g))
	}
	if !hasEdge(g, p, p) {
		t.Errorf("self-loop edge libs->libs missing: %v", g.Edges)
	}
}

func TestInspectDuplicateNeeded(t *testing.T) {
	dir := depDir(t)
	buildFixture(t, dir, "libd.so.1", fixtureSpec{})
	root := buildFixture(t, dir, "app", fixtureSpec{needed: []string{"libd.so.1", "libd.so.1"}})

	g, err := Inspect(root, Options{Env: []string{"LD_LIBRARY_PATH=" + dir}})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	p := abs(t, filepath.Join(dir, "libd.so.1"))
	if len(g.Nodes) != 2 {
		t.Errorf("nodes = %v, want 2", modules(g))
	}
	if len(g.Edges) != 1 || !hasEdge(g, root, p) {
		t.Errorf("edges = %v, want single root->libd", g.Edges)
	}
}

func TestInspectDepthLimit(t *testing.T) {
	dir := depDir(t)
	buildFixture(t, dir, "libc.so.1", fixtureSpec{})
	buildFixture(t, dir, "libb.so.1", fixtureSpec{needed: []string{"libc.so.1"}})
	buildFixture(t, dir, "liba.so.1", fixtureSpec{needed: []string{"libb.so.1"}})
	root := buildFixture(t, dir, "app", fixtureSpec{needed: []string{"liba.so.1"}})

	g, err := Inspect(root, Options{Env: []string{"LD_LIBRARY_PATH=" + dir}, MaxDepth: 2})
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	// Depth 0 = root, 1 = liba, 2 = libb; libc is beyond MaxDepth and must
	// not appear (and must not be reported missing).
	for _, m := range []string{root, abs(t, filepath.Join(dir, "liba.so.1")), abs(t, filepath.Join(dir, "libb.so.1"))} {
		nodeByModule(t, g, m)
	}
	if len(g.Nodes) != 3 {
		t.Errorf("nodes = %v, want 3 (libc not expanded)", modules(g))
	}
}
