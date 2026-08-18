// Synthetic ELF fixture builder for tests.
//
// The committed fixtures in test/fixtures/bin cover the required scenarios,
// but DT_RPATH/DT_RUNPATH/transitive/cycle/depth-limit cases need
// controllable on-disk dependency sets, so this builder emits minimal
// little-endian ELF binaries directly (no C toolchain):
//
//   - ELF header
//   - PT_LOAD + optional PT_DYNAMIC + optional PT_INTERP program headers
//   - .dynstr/.dynamic/.shstrtab section headers (debug/elf.DynString reads
//     DT_* strings through the SHT_DYNAMIC section's sh_link)
//
// Fixture files are written into a RELATIVE temp dir inside the package
// directory (e.g. ".why-deps-123") so RPATH/RUNPATH strings embedded in the
// binaries contain no ':' (Windows drive letters) and split cleanly on
// glibc's ':' separator.
package elf

import (
	debugelf "debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

const (
	emX86_64 = 0x3e // EM_X86_64
	// fixtureBase is the vaddr of file offset 0 in fixtures.
	fixtureBase = 0x400000
)

// fixtureSpec describes a minimal synthetic ELF to emit.
type fixtureSpec struct {
	class   debugelf.Class // 0 => ELFCLASS64
	machine uint16         // 0 => EM_X86_64
	interp  string         // PT_INTERP path; "" = no interpreter
	needed  []string       // DT_NEEDED sonames, in order
	rpath   string         // DT_RPATH
	runpath string         // DT_RUNPATH
}

// depDir creates a relative temp dir inside the package directory so that
// paths embedded in fixture binaries have no drive-letter colons.
func depDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(".", ".why-deps-*")
	if err != nil {
		t.Fatalf("depDir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// buildFixture writes a synthetic ELF named name into dir and returns the
// joined (relative) path.
func buildFixture(t *testing.T, dir, name string, spec fixtureSpec) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, fixtureBytes(spec), 0o755); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
	return path
}

// fixtureBytes returns the bytes of the synthetic ELF described by spec.
func fixtureBytes(spec fixtureSpec) []byte {
	if spec.class == debugelf.ELFCLASS32 {
		return fixtureBytes32(spec)
	}
	return fixtureBytes64(spec)
}

// fixtureBytes32 emits a minimal ELFCLASS32 (header + PT_LOAD). It is only
// used to exercise wrong-arch dependency detection, so no dynamic section is
// needed.
func fixtureBytes32(spec fixtureSpec) []byte {
	le := binary.LittleEndian
	if spec.machine == 0 {
		spec.machine = emX86_64
	}
	const ehsize, phentsize = 52, 32
	total := ehsize + phentsize
	b := make([]byte, total)
	copy(b[0:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4] = 1                               // ELFCLASS32
	b[5] = 1                               // little-endian
	b[6] = 1                               // EI_VERSION
	le.PutUint16(b[16:18], 2)              // ET_EXEC
	le.PutUint16(b[18:20], spec.machine)   // e_machine
	le.PutUint32(b[20:24], 1)              // e_version
	le.PutUint32(b[28:32], uint32(ehsize)) // e_phoff
	le.PutUint16(b[40:42], uint16(ehsize)) // e_ehsize
	le.PutUint16(b[42:44], uint16(phentsize))
	le.PutUint16(b[44:46], 1) // e_phnum
	po := ehsize
	le.PutUint32(b[po+0:po+4], 1) // PT_LOAD
	le.PutUint32(b[po+4:po+8], 5)
	le.PutUint32(b[po+8:po+12], 0)
	le.PutUint32(b[po+12:po+16], uint32(fixtureBase))
	le.PutUint32(b[po+16:po+20], uint32(fixtureBase))
	le.PutUint32(b[po+20:po+24], uint32(total))
	le.PutUint32(b[po+24:po+28], uint32(total))
	le.PutUint32(b[po+28:po+32], 0x1000)
	return b
}

// fixtureBytes64 emits a complete little-endian ELF64 with program headers
// and, when the spec has any dynamic content, the section headers that
// debug/elf.DynString needs.
func fixtureBytes64(spec fixtureSpec) []byte {
	le := binary.LittleEndian
	if spec.machine == 0 {
		spec.machine = emX86_64
	}

	// Dynamic string table (offsets referenced by DT_* entries).
	strtab := []byte{0}
	offs := map[string]uint64{}
	addStr := func(s string) uint64 {
		if o, ok := offs[s]; ok {
			return o
		}
		o := uint64(len(strtab))
		offs[s] = o
		strtab = append(strtab, s...)
		strtab = append(strtab, 0)
		return o
	}
	for _, n := range spec.needed {
		addStr(n)
	}
	if spec.rpath != "" {
		addStr(spec.rpath)
	}
	if spec.runpath != "" {
		addStr(spec.runpath)
	}
	hasDynamic := len(strtab) > 1

	// Dynamic entries as (tag, value) pairs, sorted per ELF spec.
	var dyn []uint64
	dynTag := func(tag, val uint64) { dyn = append(dyn, tag, val) }
	if hasDynamic {
		for _, n := range spec.needed {
			dynTag(1, offs[n]) // DT_NEEDED
		}
		dynTag(5, fixtureBase) // DT_STRTAB (vaddr filled in below)
		dynTag(10, 0)          // DT_STRSZ (filled in below)
		if spec.rpath != "" {
			dynTag(15, offs[spec.rpath]) // DT_RPATH
		}
		if spec.runpath != "" {
			dynTag(29, offs[spec.runpath]) // DT_RUNPATH
		}
		dynTag(0, 0) // DT_NULL
	}

	// Layout: ehdr | phdrs | dynstr | dynamic | interp | shdrs
	const ehsize, phentsize = 64, 56
	phnum := 2
	if spec.interp != "" {
		phnum++
	}
	phoff := uint64(ehsize)
	dynstrOff := phoff + uint64(phnum*phentsize)
	dynamicOff := dynstrOff + uint64(len(strtab))
	interpOff := dynamicOff + uint64(len(dyn)*8)
	total := interpOff
	if spec.interp != "" {
		total += uint64(len(spec.interp)) + 1
	}
	shstr := "\x00.dynstr\x00.dynamic\x00.shstrtab\x00"
	var shOff uint64
	shnum, shstrndx := 0, 0
	if hasDynamic {
		shOff = total
		shnum, shstrndx = 4, 3 // index 0 is the required null section
		total += uint64(4*64 + len(shstr))
	}

	b := make([]byte, total)
	put16 := func(o int, v uint16) { le.PutUint16(b[o:o+2], v) }
	put32 := func(o int, v uint32) { le.PutUint32(b[o:o+4], v) }
	put64 := func(o int, v uint64) { le.PutUint64(b[o:o+8], v) }

	copy(b[0:4], []byte{0x7f, 'E', 'L', 'F'})
	b[4] = 2     // ELFCLASS64
	b[5] = 1     // little-endian
	b[6] = 1     // EI_VERSION
	put16(16, 2) // ET_EXEC
	put16(18, spec.machine)
	put32(20, 1) // e_version
	put64(24, 0) // e_entry
	put64(32, phoff)
	put64(40, shOff)
	put32(48, 0) // e_flags
	put16(52, ehsize)
	put16(54, phentsize)
	put16(56, uint16(phnum))
	put16(58, 64) // e_shentsize
	put16(60, uint16(shnum))
	put16(62, uint16(shstrndx))

	// Program headers.
	po := int(phoff)
	ph := func(typ, flags uint32, off, size uint64) {
		put32(po+0, typ)
		put32(po+4, flags)
		put64(po+8, off)
		put64(po+16, fixtureBase+off)
		put64(po+24, fixtureBase+off)
		put64(po+32, size)
		put64(po+40, size)
		put64(po+48, 0x1000)
		po += 56
	}
	ph(1, 5, 0, total) // PT_LOAD, R+X
	if hasDynamic {
		ph(2, 6, dynamicOff, uint64(len(dyn)*8)) // PT_DYNAMIC, RW
	}
	if spec.interp != "" {
		ph(3, 4, interpOff, uint64(len(spec.interp))+1) // PT_INTERP, R
	}

	copy(b[dynstrOff:], strtab)
	// DT_STRTAB / DT_STRSZ values point at the dynstr vaddr / size.
	for i := 0; i+1 < len(dyn); i += 2 {
		o := int(dynamicOff) + i*8
		tag := dyn[i]
		val := dyn[i+1]
		switch tag {
		case 5:
			val = fixtureBase + dynstrOff
		case 10:
			val = uint64(len(strtab))
		}
		put64(o, tag)
		put64(o+8, val)
	}
	if spec.interp != "" {
		copy(b[interpOff:], spec.interp)
		b[interpOff+uint64(len(spec.interp))] = 0
	}

	if hasDynamic {
		// Section headers at shOff..shOff+256, .shstrtab content after them.
		link := uint32(1) // .dynstr (section index 1)
		// Section 0 is the null section (all zeros, already in the buffer).
		// .dynstr:   name=1 type=SHT_STRTAB(3) flags=SHF_ALLOC(2)
		putShdr64(b, int(shOff)+64, 1, 3, 2, fixtureBase+dynstrOff, dynstrOff, uint64(len(strtab)), 0, 0, 1, 0)
		// .dynamic:  name=9 type=SHT_DYNAMIC(6) flags=3 link=.dynstr entsize=16
		putShdr64(b, int(shOff)+128, 9, 6, 3, fixtureBase+dynamicOff, dynamicOff, uint64(len(dyn)*8), link, 0, 8, 16)
		// .shstrtab: name=18 type=SHT_STRTAB(3)
		putShdr64(b, int(shOff)+192, 18, 3, 0, 0, shOff+256, uint64(len(shstr)), 0, 0, 1, 0)
		copy(b[shOff+256:], shstr)
	}
	return b
}

// putShdr64 writes a 64-bit ELF section header at offset o.
func putShdr64(b []byte, o int, name, typ uint32, flags, addr, offset, size uint64, link, info uint32, align, entsize uint64) {
	le := binary.LittleEndian
	le.PutUint32(b[o+0:o+4], name)
	le.PutUint32(b[o+4:o+8], typ)
	le.PutUint64(b[o+8:o+16], flags)
	le.PutUint64(b[o+16:o+24], addr)
	le.PutUint64(b[o+24:o+32], offset)
	le.PutUint64(b[o+32:o+40], size)
	le.PutUint32(b[o+40:o+44], link)
	le.PutUint32(b[o+44:o+48], info)
	le.PutUint64(b[o+48:o+56], align)
	le.PutUint64(b[o+56:o+64], entsize)
}
