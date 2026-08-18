// Synthetic PE fixture builder for tests.
//
// The committed fixtures in test/fixtures/bin cover the required scenarios,
// but the resolver tests need controllable on-disk dependency sets and
// machine/subsystem combinations, so this builder emits minimal PE binaries
// directly (no C toolchain):
//
//   - DOS header + "PE\0\0" signature
//   - COFF file header (machine, one section)
//   - PE32+ or PE32 optional header with a 16-entry data directory
//   - one .rdata section holding the import directory: descriptors, DLL
//     name strings, thunk arrays and hint/name entries
//
// The layout matches what debug/pe's ImportedSymbols() reads (see
// $GOROOT/src/debug/pe/file.go): descriptors are 20-byte records terminated
// by a zero descriptor, thunks are 8-byte (PE32+) or 4-byte (PE32) RVAs of
// hint/name entries, and each hint/name entry is a 2-byte hint followed by a
// NUL-terminated function name.
package pe

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

const (
	// peBase is the VirtualAddress of the single .rdata section.
	peBase = 0x1000
	// peRaw is the PointerToRawData (file offset) of the section.
	peRaw = 0x200
	// peSectionSize is both VirtualSize and SizeOfRawData of the section.
	peSectionSize = 0x400
)

// dllImport describes one imported DLL with its function names.
type dllImport struct {
	dll string
	fns []string
}

// peSpec describes a minimal synthetic PE to emit.
type peSpec struct {
	machine   uint16 // 0 => amd64 (0x8664, PE32+); 0x14c => x86 (PE32)
	subsystem uint16 // 0 => windows-cui (3)
	imports   []dllImport
	badThunk  bool // corrupt the first descriptor's OriginalFirstThunk
}

// buildPE writes a synthetic PE named name into dir and returns the path.
func buildPE(t *testing.T, dir, name string, spec peSpec) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, peBytes(spec), 0o755); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
	return path
}

// peBytes returns the bytes of the synthetic PE described by spec.
func peBytes(spec peSpec) []byte {
	le := binary.LittleEndian
	if spec.machine == 0 {
		spec.machine = 0x8664 // IMAGE_FILE_MACHINE_AMD64
	}
	if spec.subsystem == 0 {
		spec.subsystem = 3 // IMAGE_SUBSYSTEM_WINDOWS_CUI
	}
	pe64 := spec.machine != 0x14c
	ohSize := 0xF0 // OptionalHeader64
	if !pe64 {
		ohSize = 0xE0 // OptionalHeader32
	}
	thunkSize := 8
	if !pe64 {
		thunkSize = 4
	}

	// Section data layout: descriptors, then per-DLL name strings, thunk
	// arrays and hint/name entries. All offsets are relative to the section.
	off := 20 * (len(spec.imports) + 1)
	nameOff := make([]int, len(spec.imports))
	for i, imp := range spec.imports {
		nameOff[i] = off
		off += len(imp.dll) + 1
	}
	thunkOff := make([]int, len(spec.imports))
	for i, imp := range spec.imports {
		thunkOff[i] = off
		off += (len(imp.fns) + 1) * thunkSize
	}
	hintOff := make([][]int, len(spec.imports))
	for i, imp := range spec.imports {
		for _, fn := range imp.fns {
			hintOff[i] = append(hintOff[i], off)
			off += 2 + len(fn) + 1
		}
	}

	sec := make([]byte, peSectionSize)
	// Import descriptors.
	for i := range spec.imports {
		o := i * 20
		oft := uint32(peBase + thunkOff[i])
		if spec.badThunk && i == 0 {
			oft = 0x7FFFFFFF // out of section -> ImportedSymbols error
		}
		le.PutUint32(sec[o+0:o+4], oft)                          // OriginalFirstThunk
		le.PutUint32(sec[o+12:o+16], uint32(peBase+nameOff[i]))  // Name
		le.PutUint32(sec[o+16:o+20], uint32(peBase+thunkOff[i])) // FirstThunk
	}
	// DLL name strings.
	for i, imp := range spec.imports {
		copy(sec[nameOff[i]:], imp.dll)
	}
	// Thunk arrays (RVA of each hint/name entry, zero-terminated).
	for i, imp := range spec.imports {
		o := thunkOff[i]
		for j := range imp.fns {
			if pe64 {
				le.PutUint64(sec[o:o+8], uint64(peBase+hintOff[i][j]))
			} else {
				le.PutUint32(sec[o:o+4], uint32(peBase+hintOff[i][j]))
			}
			o += thunkSize
		}
	}
	// Hint/name entries: 2-byte hint + NUL-terminated function name.
	for i, imp := range spec.imports {
		for j, fn := range imp.fns {
			o := hintOff[i][j]
			le.PutUint16(sec[o:o+2], 0)
			copy(sec[o+2:], fn)
		}
	}

	// Assemble the file: DOS header, PE signature, COFF header, optional
	// header, section header, section data.
	total := peRaw + peSectionSize
	b := make([]byte, total)
	copy(b[0:2], "MZ")
	le.PutUint32(b[0x3C:0x40], 0x40)       // e_lfanew
	copy(b[0x40:0x44], "\x50\x45\x00\x00") // "PE\0\0"
	coff := 0x44
	le.PutUint16(b[coff+0:coff+2], spec.machine)
	le.PutUint16(b[coff+2:coff+4], 1) // NumberOfSections
	le.PutUint16(b[coff+16:coff+18], uint16(ohSize))
	le.PutUint16(b[coff+18:coff+20], 0x22) // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
	oh := coff + 20
	put16 := func(o int, v uint16) { le.PutUint16(b[o:o+2], v) }
	put32 := func(o int, v uint32) { le.PutUint32(b[o:o+4], v) }
	put64 := func(o int, v uint64) { le.PutUint64(b[o:o+8], v) }
	if pe64 {
		put16(oh+0, 0x20b)        // PE32+ magic
		put32(oh+16, peBase)      // AddressOfEntryPoint
		put32(oh+20, peBase)      // BaseOfCode
		put64(oh+24, 0x140000000) // ImageBase
		put32(oh+32, 0x1000)      // SectionAlignment
		put32(oh+36, 0x200)       // FileAlignment
		put16(oh+40, 6)           // MajorOperatingSystemVersion
		put16(oh+48, 6)           // MajorSubsystemVersion
		put32(oh+56, 0x2000)      // SizeOfImage
		put32(oh+60, 0x200)       // SizeOfHeaders
		put16(oh+68, spec.subsystem)
		put64(oh+72, 0x100000) // SizeOfStackReserve
		put64(oh+80, 0x1000)   // SizeOfStackCommit
		put64(oh+88, 0x100000) // SizeOfHeapReserve
		put64(oh+96, 0x1000)   // SizeOfHeapCommit
		put32(oh+108, 16)      // NumberOfRvaAndSizes
	} else {
		put16(oh+0, 0x10b)     // PE32 magic
		put32(oh+16, peBase)   // AddressOfEntryPoint
		put32(oh+20, peBase)   // BaseOfCode
		put32(oh+24, peBase)   // BaseOfData
		put32(oh+28, 0x400000) // ImageBase
		put32(oh+32, 0x1000)   // SectionAlignment
		put32(oh+36, 0x200)    // FileAlignment
		put16(oh+40, 6)        // MajorOperatingSystemVersion
		put16(oh+48, 6)        // MajorSubsystemVersion
		put32(oh+56, 0x2000)   // SizeOfImage
		put32(oh+60, 0x200)    // SizeOfHeaders
		put16(oh+68, spec.subsystem)
		put32(oh+72, 0x100000) // SizeOfStackReserve
		put32(oh+76, 0x1000)   // SizeOfStackCommit
		put32(oh+80, 0x100000) // SizeOfHeapReserve
		put32(oh+84, 0x1000)   // SizeOfHeapCommit
		put32(oh+92, 16)       // NumberOfRvaAndSizes
	}
	// Import data directory entry (index 1).
	dd := oh + 112 // PE32+ DataDirectory offset
	if !pe64 {
		dd = oh + 96 // PE32 DataDirectory offset
	}
	if len(spec.imports) > 0 {
		put32(dd+8, peBase)                            // VirtualAddress
		put32(dd+12, uint32(20*(len(spec.imports)+1))) // Size
	}
	// Section header.
	sh := oh + ohSize
	copy(b[sh+0:sh+8], ".rdata")
	put32(sh+8, peSectionSize)  // VirtualSize
	put32(sh+12, peBase)        // VirtualAddress
	put32(sh+16, peSectionSize) // SizeOfRawData
	put32(sh+20, peRaw)         // PointerToRawData
	put32(sh+36, 0x40000040)    // INITIALIZED_DATA | READ
	copy(b[peRaw:], sec)
	return b
}
