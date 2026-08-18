package fixtures

// Host-aware golden-fixture determinism guard.
//
// The binaries in test/fixtures/bin are versioned test inputs: their exact
// bytes are part of the test contract. This test re-builds the fixtures the
// CURRENT host can build and byte-compares them against the committed
// goldens; cross-OS fixtures (ELF on Windows, PE on Linux) are NOT rebuilt —
// the rebuild is skipped with an explicit log line and the committed
// artifact is instead parse-asserted (magic + header) so that silent byte
// corruption fails loudly either way.
//
// Rebuild flags match the provenance in test/fixtures/README.md:
// -trimpath, -ldflags=-buildid=, -buildvcs=false, CGO_ENABLED=0.

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	machineAmd64 = 0x8664 // IMAGE_FILE_MACHINE_AMD64
	machineI386  = 0x14c  // IMAGE_FILE_MACHINE_I386
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
}

// elfFixture is an ELF golden; goELF names the generator arch for
// go-built ones, synthetic marks the byte-builder fixtures.
type elfFixture struct {
	name        string
	goarch      string // non-empty: go build from src/hello.go
	synthetic   bool   // emitted by src/generate_elfs.go
	wantClass   elf.Class
	wantMachine elf.Machine
	wantInterp  string // PT_INTERP path; "" = none expected
	wantNeeded  []string
}

var elfFixtures = []elfFixture{
	{"hello-linux-x86_64", "amd64", false, elf.ELFCLASS64, elf.EM_X86_64, "", nil},
	{"wrong-arch-linux", "386", false, elf.ELFCLASS32, elf.EM_386, "", nil},
	{"missing-so", "", true, elf.ELFCLASS64, elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2", []string{"libdefinitelymissing.so.1"}},
	{"bad-interp", "", true, elf.ELFCLASS64, elf.EM_X86_64, "/nonexistent/ld-linux-why.so", []string{"libc.so.6"}},
	{"musl-hello", "", true, elf.ELFCLASS64, elf.EM_X86_64, "/lib/ld-musl-x86_64.so.1", []string{"libc.musl-x86_64.so.1"}},
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
			cmd := exec.Command("go", "build",
				"-trimpath", "-ldflags=-buildid=", "-buildvcs=false",
				"-o", out,
				filepath.Join(root, "test", "fixtures", "src", "hello.go"))
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

// assertPE parses the committed PE and checks magic, machine, and (for the
// missing-DLL fixture) the import table contract.
func assertPE(t *testing.T, path, wantArch string) {
	t.Helper()
	b := readFixture(t, path)
	if !bytes.HasPrefix(b, []byte("MZ")) {
		t.Errorf("fixture %s: missing MZ magic", filepath.Base(path))
		return
	}
	e := binary.LittleEndian.Uint32(b[0x3C:])
	if e+24 > uint32(len(b)) || !bytes.Equal(b[e:e+4], []byte("PE\x00\x00")) {
		t.Errorf("fixture %s: PE signature missing at e_lfanew=0x%x", filepath.Base(path), e)
		return
	}
	mach := binary.LittleEndian.Uint16(b[e+4:])
	want := uint16(machineI386)
	if wantArch == "amd64" {
		want = machineAmd64
	}
	if mach != want {
		t.Errorf("fixture %s: machine=0x%x, want 0x%x (%s)", filepath.Base(path), mach, want, wantArch)
		return
	}
	if filepath.Base(path) == "missing-dll-x64.exe" && !hasPEImport(t, b, "DefinitelyMissing.dll") {
		t.Errorf("fixture missing-dll-x64.exe: import table must name DefinitelyMissing.dll")
	}
}

// hasPEImport walks the import directory looking for dllName.
func hasPEImport(t *testing.T, b []byte, dllName string) bool {
	t.Helper()
	e := binary.LittleEndian.Uint32(b[0x3C:])
	opt := e + 24
	magic := binary.LittleEndian.Uint16(b[opt:])
	dd := uint64(opt) + 112 // PE32+ data directory offset
	if magic == 0x10b {
		dd = uint64(opt) + 96 // PE32
	}
	impRVA := binary.LittleEndian.Uint32(b[dd+8:])
	numSec := int(binary.LittleEndian.Uint16(b[e+6:]))
	secOff := e + 24 + uint32(binary.LittleEndian.Uint16(b[e+20:]))
	rva2off := func(rva uint32) (uint32, bool) {
		for i := 0; i < numSec; i++ {
			s := secOff + uint32(i)*40
			va := binary.LittleEndian.Uint32(b[s+12:])
			vs := binary.LittleEndian.Uint32(b[s+8:])
			rp := binary.LittleEndian.Uint32(b[s+20:])
			if rva >= va && rva < va+vs {
				return rp + (rva - va), true
			}
		}
		return 0, false
	}
	off, ok := rva2off(impRVA)
	if !ok {
		return false
	}
	for j := 0; j < 32; j++ {
		d := off + uint32(j)*20
		nameRVA := binary.LittleEndian.Uint32(b[d+12:])
		if nameRVA == 0 && binary.LittleEndian.Uint32(b[d:]) == 0 {
			break // null descriptor terminates the array
		}
		no, ok := rva2off(nameRVA)
		if !ok {
			continue
		}
		end := int(no)
		for b[end] != 0 {
			end++
		}
		if string(b[no:end]) == dllName {
			return true
		}
	}
	return false
}

// assertELF parses the committed ELF and checks class, machine, PT_INTERP,
// and DT_NEEDED against the fixture contract.
func assertELF(t *testing.T, path string, f elfFixture) {
	t.Helper()
	b := readFixture(t, path)
	if !bytes.HasPrefix(b, []byte{0x7f, 'E', 'L', 'F'}) {
		t.Errorf("fixture %s: missing ELF magic", filepath.Base(path))
		return
	}
	fh, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		t.Errorf("fixture %s: parse failed: %v", filepath.Base(path), err)
		return
	}
	defer fh.Close()
	if fh.Class != f.wantClass {
		t.Errorf("fixture %s: class=%s, want %s", filepath.Base(path), fh.Class, f.wantClass)
	}
	if fh.Machine != f.wantMachine {
		t.Errorf("fixture %s: machine=%s, want %s", filepath.Base(path), fh.Machine, f.wantMachine)
	}
	if got := interpOf(t, fh); got != f.wantInterp {
		t.Errorf("fixture %s: PT_INTERP=%q, want %q", filepath.Base(path), got, f.wantInterp)
	}
	if got, err := fh.DynString(elf.DT_NEEDED); err != nil || !equalStrings(got, f.wantNeeded) {
		t.Errorf("fixture %s: DT_NEEDED=%v (err=%v), want %v", filepath.Base(path), got, err, f.wantNeeded)
	}
}

// interpOf returns the PT_INTERP path (without the trailing NUL).
func interpOf(t *testing.T, f *elf.File) string {
	t.Helper()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			d := make([]byte, p.Filesz)
			if _, err := p.ReadAt(d, 0); err != nil {
				t.Fatalf("read PT_INTERP: %v", err)
			}
			return string(bytes.TrimRight(d, "\x00"))
		}
	}
	return ""
}

// assertTruncatedPE checks the committed static bytes stay truncated: MZ
// present, PE signature absent (the file ends inside the DOS header).
func assertTruncatedPE(t *testing.T, path string) {
	t.Helper()
	b := readFixture(t, path)
	if len(b) != 64 {
		t.Errorf("fixture truncated-hello-x64.exe: length=%d, want 64 (static truncation contract)", len(b))
	}
	if !bytes.HasPrefix(b, []byte("MZ")) {
		t.Errorf("fixture truncated-hello-x64.exe: must keep the MZ prefix")
	}
	if bytes.Contains(b, []byte("PE\x00\x00")) {
		t.Errorf("fixture truncated-hello-x64.exe: must NOT contain the PE signature (truncation contract)")
	}
}

// assertMangledELF checks the committed static bytes stay mangled: no ELF
// magic, and debug/elf rejects the file.
func assertMangledELF(t *testing.T, path string) {
	t.Helper()
	b := readFixture(t, path)
	if bytes.HasPrefix(b, []byte{0x7f, 'E', 'L', 'F'}) {
		t.Errorf("fixture mangled-elf-magic: magic must stay corrupted (first byte must not be 0x7f)")
	}
	if _, err := elf.Open(path); err == nil {
		t.Errorf("fixture mangled-elf-magic: debug/elf must reject the corrupted magic")
	}
}

// readFixture reads a committed fixture, failing the test on I/O errors.
func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return b
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
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
