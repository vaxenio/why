package elf

import (
	debugelf "debug/elf"
	"fmt"
	"strings"
)

// maxInterpSize guards against absurd PT_INTERP filesz on corrupt files.
const maxInterpSize = 1 << 20

// parsedFile is the header-level view of an ELF file the resolver needs.
type parsedFile struct {
	path    string
	arch    string   // e_machine name ("amd64", "x86", ...)
	class   string   // EI_CLASS: "32" or "64"
	interp  string   // PT_INTERP path, "" when absent
	needed  []string // DT_NEEDED sonames in order
	rpath   string   // DT_RPATH, "" when absent
	runpath string   // DT_RUNPATH, "" when absent
}

// parseFile parses path with debug/elf. It never panics: malformed content
// surfaces as an error. Dynamic-string reads degrade gracefully (a corrupt
// string table yields empty fields, not a failure).
func parseFile(path string) (*parsedFile, error) {
	f, err := debugelf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	pf := &parsedFile{path: path, arch: machineName(uint16(f.Machine))}
	switch f.Class {
	case debugelf.ELFCLASS32:
		pf.class = "32"
	case debugelf.ELFCLASS64:
		pf.class = "64"
	default:
		pf.class = "?"
	}

	// PT_INTERP: read the interpreter path.
	for _, p := range f.Progs {
		if p.Type != debugelf.PT_INTERP || p.Filesz == 0 || p.Filesz > maxInterpSize {
			continue
		}
		buf := make([]byte, p.Filesz)
		if _, err := p.ReadAt(buf, 0); err != nil {
			continue
		}
		pf.interp = strings.TrimRight(string(buf), "\x00")
		break
	}

	// Dynamic entries: only present when the file has a SHT_DYNAMIC section
	// (debug/elf reads DT_* strings through it).
	if f.SectionByType(debugelf.SHT_DYNAMIC) != nil {
		if v, _ := f.DynString(debugelf.DT_NEEDED); v != nil {
			pf.needed = v
		}
		if v, _ := f.DynString(debugelf.DT_RPATH); len(v) > 0 {
			pf.rpath = v[0]
		}
		if v, _ := f.DynString(debugelf.DT_RUNPATH); len(v) > 0 {
			pf.runpath = v[0]
		}
	}
	return pf, nil
}

// machineName maps an e_machine value to a canonical name: amd64 (0x3e),
// x86 (0x03), arm64 (0xb7) plus the common architectures, falling back to a
// hex tag.
func machineName(m uint16) string {
	switch m {
	case 0x3e: // EM_X86_64
		return "amd64"
	case 0x03: // EM_386
		return "x86"
	case 0xb7: // EM_AARCH64
		return "arm64"
	case 0x28: // EM_ARM
		return "arm"
	case 0xf3: // EM_RISCV
		return "riscv64"
	case 0x15: // EM_PPC64
		return "ppc64"
	case 0x16: // EM_S390
		return "s390x"
	case 0x08: // EM_MIPS
		return "mips"
	case 0x102: // EM_LOONGARCH
		return "loongarch64"
	default:
		return fmt.Sprintf("arch-0x%x", m)
	}
}
