//go:build ignore

// Command missing_dll is the source of bin/missing-dll-x64.exe: a healthy
// amd64 PE whose import table names the deliberately absent
// DefinitelyMissing.dll, so:
//
//   - static inspection (internal/inspect/pe) sees the missing dependency
//     in the import table, and
//   - the Windows loader fails to start the process (STATUS_DLL_NOT_FOUND),
//     which is the missing-DLL scenario for the tracer.
//
// Two mechanisms cooperate:
//
//  1. //go:cgo_import_dynamic main.DefinitelyMissingImport
//     DefinitelyMissingFunction "DefinitelyMissing.dll" — cmd/link converts
//     the package-level var (SBSS) into an SDYNIMPORT symbol and emits a
//     DefinitelyMissing.dll import descriptor (ld/pe.go initdynimport).
//     The local name MUST be package-qualified ("main." prefix), matching
//     how runtime/os_windows.go imports kernel32.
//  2. The conditional read of the var keeps the SDYNIMPORT symbol
//     reachable; a bare `_ = x` blank assignment is optimized away and the
//     import descriptor silently disappears.
//
// The syscall.NewLazyDLL call documents the runtime-load path (it is never
// reached in practice because the loader fails first).
//
// Rebuild (Windows host, pinned toolchain + flags, see README.md):
//
//	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/missing-dll-x64.exe test/fixtures/src/missing_dll.go
//
// Committed binary built 2026-08-18 with go1.26.5 windows/amd64,
// CGO_ENABLED=0; sha256 in test/fixtures/README.md.
package main

import (
	"fmt"
	"syscall"
)

//go:cgo_import_dynamic main.DefinitelyMissingImport DefinitelyMissingFunction "DefinitelyMissing.dll"

var DefinitelyMissingImport uintptr

func main() {
	if DefinitelyMissingImport != 0 {
		println("unreachable: import thunk referenced")
	}
	dll := syscall.NewLazyDLL("DefinitelyMissing.dll")
	proc := dll.NewProc("DefinitelyMissingFunction")
	r1, _, err := proc.Call()
	fmt.Printf("call returned r1=%d err=%v\n", r1, err)
}
