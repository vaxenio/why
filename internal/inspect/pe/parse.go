// Parsing of PE headers and the import table via the standard library's
// debug/pe. All errors surface as *Error with Op "open" (pe.Open) or
// "imports" (import table); nothing here panics on malformed input.
package pe

import (
	"debug/pe"
	"fmt"
	"strings"
)

// parsedFile is the raw header facts extracted from a PE.
type parsedFile struct {
	path      string
	machine   string
	subsystem string
	imports   []Import
}

// parseFile opens path and extracts machine, subsystem and the grouped
// import table. A truncated or corrupt file yields a *Error.
func parseFile(path string) (*parsedFile, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, &Error{Path: path, Op: "open", Err: err}
	}
	defer f.Close()

	pf := &parsedFile{
		path:      path,
		machine:   machineName(f.Machine),
		subsystem: subsystemName(f.OptionalHeader),
	}
	syms, err := f.ImportedSymbols()
	if err != nil {
		return nil, &Error{Path: path, Op: "imports", Err: err}
	}
	pf.imports = groupImports(syms)
	return pf, nil
}

// machineName maps an IMAGE_FILE_MACHINE_* value to its canonical name.
func machineName(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_ARMNT:
		return "armnt"
	case pe.IMAGE_FILE_MACHINE_ARM:
		return "arm"
	case pe.IMAGE_FILE_MACHINE_IA64:
		return "ia64"
	case pe.IMAGE_FILE_MACHINE_RISCV32:
		return "riscv32"
	case pe.IMAGE_FILE_MACHINE_RISCV64:
		return "riscv64"
	case pe.IMAGE_FILE_MACHINE_RISCV128:
		return "riscv128"
	}
	return fmt.Sprintf("unknown-0x%x", m)
}

// subsystemName maps an IMAGE_SUBSYSTEM_* value to its canonical name. A nil
// optional header (no PE32/PE32+ header) yields "unknown".
func subsystemName(oh any) string {
	var s uint16
	switch v := oh.(type) {
	case *pe.OptionalHeader32:
		s = v.Subsystem
	case *pe.OptionalHeader64:
		s = v.Subsystem
	default:
		return "unknown"
	}
	switch s {
	case pe.IMAGE_SUBSYSTEM_NATIVE:
		return "native"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_GUI:
		return "windows-gui"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_CUI:
		return "windows-cui"
	case pe.IMAGE_SUBSYSTEM_OS2_CUI:
		return "os2-cui"
	case pe.IMAGE_SUBSYSTEM_POSIX_CUI:
		return "posix-cui"
	case pe.IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:
		return "windows-ce-gui"
	case pe.IMAGE_SUBSYSTEM_EFI_APPLICATION:
		return "efi-application"
	case pe.IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
		return "efi-boot-service-driver"
	case pe.IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
		return "efi-runtime-driver"
	case pe.IMAGE_SUBSYSTEM_EFI_ROM:
		return "efi-rom"
	case pe.IMAGE_SUBSYSTEM_XBOX:
		return "xbox"
	}
	return fmt.Sprintf("unknown-0x%x", s)
}

// groupImports converts debug/pe's "FuncName:DLL.dll" entries into Import
// groups keyed by DLL, preserving first-seen DLL order and per-DLL function
// order, deduplicating repeated (DLL, function) pairs. Entries without a
// colon are skipped defensively.
func groupImports(syms []string) []Import {
	var out []Import
	index := map[string]int{}
	seen := map[string]bool{}
	for _, s := range syms {
		i := strings.LastIndexByte(s, ':')
		if i < 0 {
			continue
		}
		fn, dll := s[:i], s[i+1:]
		key := dll + "\x00" + fn
		if seen[key] {
			continue
		}
		seen[key] = true
		if idx, ok := index[dll]; ok {
			out[idx].Functions = append(out[idx].Functions, fn)
			continue
		}
		index[dll] = len(out)
		out = append(out, Import{DLL: dll, Functions: []string{fn}})
	}
	return out
}
