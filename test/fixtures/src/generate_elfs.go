//go:build ignore

// Command generate_elfs regenerates the synthetic ELF fixtures in
// test/fixtures/bin: missing-so, bad-interp, musl-hello.
//
// There is no Linux C toolchain on the development hosts, so the
// missing-library / bad-interpreter / musl scenarios are exercised against
// hand-crafted minimal ELF64 binaries. The builder emits a valid
// little-endian ELF64 (ET_EXEC, EM_X86_64) with:
//
//   - ELF header
//   - PT_LOAD + PT_DYNAMIC + PT_INTERP program headers
//   - .dynstr / .dynamic / .shstrtab section headers (debug/elf.DynString
//     reads DT_* strings through the SHT_DYNAMIC section's sh_link)
//
// Output is fully deterministic: no timestamps, no build IDs, no paths.
// Sonames use the unique "why" suffix so resolution results are identical
// on every host (no real lib or ld.so.cache can contain them).
//
// Fixture contract (consumed by internal/inspect/elf):
//
//	missing-so   PT_INTERP /lib64/ld-linux-x86-64.so.2 (present on glibc
//	             hosts), DT_NEEDED libdefinitelymissing.so.1 -> missing lib
//	bad-interp   PT_INTERP /nonexistent/ld-linux-why.so (never present),
//	             DT_NEEDED libc.so.6 -> missing interpreter
//	musl-hello   PT_INTERP /lib/ld-musl-x86_64.so.1 + DT_NEEDED
//	             libc.musl-x86_64.so.1 -> musl-shaped binary (interp
//	             absent on glibc hosts). A real musl toolchain build is
//	             deferred to CI; the synthetic shape exercises the same
//	             PT_INTERP/DT_NEEDED parse contract.
//
// Usage (from the repo root):
//
//	go run ./test/fixtures/src/generate_elfs.go [output-dir]
//
// The default output directory is test/fixtures/bin. Committed binaries
// were generated 2026-08-18; sha256 of each output in test/fixtures/README.md.
package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

const (
	emX86_64    = 0x3e // EM_X86_64
	fixtureBase = 0x400000
)

// fixtureSpec describes a minimal synthetic ELF to emit.
type fixtureSpec struct {
	interp string   // PT_INTERP path; "" = no interpreter
	needed []string // DT_NEEDED sonames, in order
}

func main() {
	out := "test/fixtures/bin"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		fail("mkdir %s: %v", out, err)
	}

	fixtures := []struct {
		name string
		spec fixtureSpec
	}{
		{"missing-so", fixtureSpec{
			interp: "/lib64/ld-linux-x86-64.so.2",
			needed: []string{"libdefinitelymissing.so.1"},
		}},
		{"bad-interp", fixtureSpec{
			interp: "/nonexistent/ld-linux-why.so",
			needed: []string{"libc.so.6"},
		}},
		{"musl-hello", fixtureSpec{
			interp: "/lib/ld-musl-x86_64.so.1",
			needed: []string{"libc.musl-x86_64.so.1"},
		}},
	}
	for _, f := range fixtures {
		path := filepath.Join(out, f.name)
		if err := os.WriteFile(path, fixtureBytes(f.spec), 0o644); err != nil {
			fail("write %s: %v", path, err)
		}
		fmt.Printf("wrote %s (%d bytes)\n", path, len(fixtureBytes(f.spec)))
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "generate_elfs: "+format+"\n", args...)
	os.Exit(1)
}

// fixtureBytes returns the bytes of the synthetic ELF64 described by spec.
func fixtureBytes(spec fixtureSpec) []byte {
	le := binary.LittleEndian

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
		dynTag(0, 0)           // DT_NULL
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
	b[4] = 2 // ELFCLASS64
	b[5] = 1 // little-endian
	b[6] = 1 // EI_VERSION
	put16(16, uint16(elf.ET_EXEC))
	put16(18, emX86_64)
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
		// .dynstr:   name=1 type=SHT_STRTAB(3)  flags=SHF_ALLOC(2)
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
