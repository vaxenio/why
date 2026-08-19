package fixtures

// Host-aware golden-fixture determinism guard.
//
// The binaries in test/fixtures/bin are versioned test inputs: their exact
// bytes are part of the test contract. This test re-builds the fixtures the
// CURRENT host can build and byte-compares them against the committed
// goldens; cross-OS fixtures (ELF on Windows, PE on Linux) are NOT rebuilt —
// the rebuild is skipped with an explicit log line and the committed
// artifact is instead parse-asserted (magic + header; see
// parse_assert_test.go) so that silent byte corruption fails loudly either
// way.
//
// Rebuild flags match the provenance in test/fixtures/README.md:
// -trimpath, -ldflags=-buildid=, -buildvcs=false, CGO_ENABLED=0.

import (
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	machineAmd64 = 0x8664 // IMAGE_FILE_MACHINE_AMD64
	machineI386  = 0x14c  // IMAGE_FILE_MACHINE_I386
	machineArm64 = 0xAA64 // IMAGE_FILE_MACHINE_ARM64
)

// peFixture is a PE golden rebuilt with `go build` on a Windows host.
type peFixture struct {
	name string // committed file name under bin/
	arch string // GOARCH for the rebuild
	src  string // generator source under src/
}

var peFixtures = []peFixture{
	{"hello-x64.exe", "amd64", "hello.go"},
	{"hello-x86.exe", "386", "hello.go"},
	{"wrong-arch.exe", "386", "hello.go"},
	{"missing-dll-x64.exe", "amd64", "missing_dll.go"},
	{"wrong-arch-arm64.exe", "arm64", "hello.go"},
	{"port-bind.exe", "amd64", "port_bind.go"},
	{"cwd-check.exe", "amd64", "cwd_check.go"},
	{"env-check.exe", "amd64", "env_check.go"},
}

// elfFixture is an ELF golden; goarch names the GOARCH for go-built ones,
// src the build source ("" = hello.go); synthetic marks the byte-builder
// fixtures.
type elfFixture struct {
	name        string
	goarch      string // non-empty: go build for this GOARCH
	src         string // go build source under src/; "" = hello.go
	synthetic   bool   // emitted by src/generate_elfs.go
	wantClass   elf.Class
	wantMachine elf.Machine
	wantInterp  string // PT_INTERP path; "" = none expected
	wantNeeded  []string
}

var elfFixtures = []elfFixture{
	{"hello-linux-x86_64", "amd64", "", false, elf.ELFCLASS64, elf.EM_X86_64, "", nil},
	{"wrong-arch-linux", "386", "", false, elf.ELFCLASS32, elf.EM_386, "", nil},
	{"missing-so", "", "", true, elf.ELFCLASS64, elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2", []string{"libdefinitelymissing.so.1"}},
	{"bad-interp", "", "", true, elf.ELFCLASS64, elf.EM_X86_64, "/nonexistent/ld-linux-why.so", []string{"libc.so.6"}},
	{"musl-hello", "", "", true, elf.ELFCLASS64, elf.EM_X86_64, "/lib/ld-musl-x86_64.so.1", []string{"libc.musl-x86_64.so.1"}},
	{"port-bind", "amd64", "port_bind.go", false, elf.ELFCLASS64, elf.EM_X86_64, "", nil},
	{"cwd-check", "amd64", "cwd_check.go", false, elf.ELFCLASS64, elf.EM_X86_64, "", nil},
	{"env-check", "amd64", "env_check.go", false, elf.ELFCLASS64, elf.EM_X86_64, "", nil},
}

func Test_FixtureDeterminism_rebuildsHostBuildableFixtures(t *testing.T) {
	root := repoRoot(t)
	bin := filepath.Join(root, "test", "fixtures", "bin")
	tmp := t.TempDir()

	switch runtime.GOOS {
	case "windows":
		rebuildPE(t, root, tmp)
		t.Logf("skipping ELF rebuilds on %s host: ELF fixtures are cross-OS golden artifacts, rebuilt only on a linux host; parse-asserted below", runtime.GOOS)
	case "linux":
		rebuildELF(t, root, tmp)
		t.Logf("skipping PE rebuilds on %s host: PE fixtures are cross-OS golden artifacts, rebuilt only on a windows host; parse-asserted below", runtime.GOOS)
	default:
		t.Logf("host %s: no fixture rebuilds performed; committed binaries parse-asserted below", runtime.GOOS)
	}

	// Parse asserts run on every host: a committed golden that loses its
	// magic bytes or header shape fails here loudly.
	for _, f := range peFixtures {
		assertPE(t, filepath.Join(bin, f.name), f.arch)
	}
	for _, f := range elfFixtures {
		assertELF(t, filepath.Join(bin, f.name), f)
	}
	assertTruncatedPE(t, filepath.Join(bin, "truncated-hello-x64.exe"))
	assertMangledELF(t, filepath.Join(bin, "mangled-elf-magic"))
}

// rebuildPE rebuilds the PE goldens from source and byte-compares.
func rebuildPE(t *testing.T, root, tmp string) {
	t.Logf("host %s: rebuilding PE fixtures from test/fixtures/src", runtime.GOOS)
	for _, f := range peFixtures {
		out := filepath.Join(tmp, f.name)
		cmd := exec.Command("go", "build",
			"-trimpath", "-ldflags=-buildid=", "-buildvcs=false",
			"-o", out,
			filepath.Join(root, "test", "fixtures", "src", f.src))
		cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH="+f.arch, "CGO_ENABLED=0")
		if outBytes, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("rebuild %s: %v\n%s", f.name, err, outBytes)
		}
		assertByteIdentical(t, filepath.Join(tmp, f.name), filepath.Join(root, "test", "fixtures", "bin", f.name))
	}
}

// rebuildELF rebuilds the ELF goldens from source and byte-compares.
func rebuildELF(t *testing.T, root, tmp string) {
	t.Logf("host %s: rebuilding ELF fixtures from test/fixtures/src", runtime.GOOS)
	for _, f := range elfFixtures {
		var out string
		if f.synthetic {
			cmd := exec.Command("go", "run",
				filepath.Join(root, "test", "fixtures", "src", "generate_elfs.go"), tmp)
			if outBytes, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("generate_elfs: %v\n%s", err, outBytes)
			}
			out = filepath.Join(tmp, f.name)
		} else {
			out = filepath.Join(tmp, f.name)
			src := f.src
			if src == "" {
				src = "hello.go"
			}
			cmd := exec.Command("go", "build",
				"-trimpath", "-ldflags=-buildid=", "-buildvcs=false",
				"-o", out,
				filepath.Join(root, "test", "fixtures", "src", src))
			cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+f.goarch, "CGO_ENABLED=0")
			if outBytes, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("rebuild %s: %v\n%s", f.name, err, outBytes)
			}
		}
		assertByteIdentical(t, out, filepath.Join(root, "test", "fixtures", "bin", f.name))
	}
}

// assertByteIdentical fails unless the rebuilt and committed files match.
func assertByteIdentical(t *testing.T, rebuilt, committed string) {
	t.Helper()
	got, err := os.ReadFile(rebuilt)
	if err != nil {
		t.Fatalf("read rebuilt %s: %v", rebuilt, err)
	}
	want, err := os.ReadFile(committed)
	if err != nil {
		t.Fatalf("read committed %s: %v", committed, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("fixture %s: rebuilt %d bytes != committed %d bytes (determinism broken)", filepath.Base(committed), len(got), len(want))
		return
	}
	t.Logf("fixture %s: rebuilt %d bytes, byte-identical", filepath.Base(committed), len(got))
}

// repoRoot walks up from the working directory to the module root (go.mod).
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}
