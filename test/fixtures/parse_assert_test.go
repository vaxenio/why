package fixtures

// Parse assertions for the committed golden fixtures, run on every host.
//
// The rebuild side (determinism_test.go) byte-compares host-buildable
// fixtures and skips cross-OS ones; these functions assert the parse
// contract of every committed binary (PE/ELF magic + header, fixture-
// specific shape) so that silent corruption of any golden fails loudly on
// any host.

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

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
	if got, err := fh.DynString(elf.DT_NEEDED); err != nil || !slices.Equal(got, f.wantNeeded) {
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
