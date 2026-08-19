// missing.go implements the missing-library rules: generic missing DLL / SO
// and their specializations (VC runtime, .NET / system runtime, ELF
// interpreter). The specializations fire on the same missing node but carry
// a more specific cause, so they suppress the generic rule via the engine.
package rules

import (
	"fmt"
	"strings"

	"why/internal/diagnose"
	"why/internal/evidence"
)

// missingDLL fires when a PE imports a DLL that is neither a VC runtime nor
// a .NET runtime DLL and cannot be resolved on disk.
type missingDLL struct{}

func (*missingDLL) ID() string           { return "missing-dll" }
func (*missingDLL) Suppresses() []string { return nil }

func (*missingDLL) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	if ev.Kind != evidence.KindPE {
		return nil, false
	}
	var missing []string
	for _, n := range ev.MissingNodes() {
		b := base(n.Module)
		if !isVCRuntime(b) && !isDotNetRuntime(b) {
			missing = append(missing, n.Module)
		}
	}
	if len(missing) == 0 {
		return nil, false
	}

	var runtime string
	if sf, ok := ev.StartFailed(); ok {
		if sf.ErrorCode == winErrModNotFound || sf.ErrorCode == winErrProcNotFound {
			runtime = fmt.Sprintf("start failed with win32 error %d (module not found)", sf.ErrorCode)
		}
	}
	if ex, ok := ev.Exit(); ok && ex.ExitCode == ntDLLNotFound {
		runtime = "process exited with 0xC0000135 (STATUS_DLL_NOT_FOUND)"
	}
	evidence := []string{
		"the import table references " + strings.Join(missing, ", ") +
			", which was not found in the application directory, System32, CWD or PATH",
	}
	if runtime != "" {
		evidence = append(evidence, runtime)
	}
	return diag(
		"missing-dll",
		"missing DLL",
		"the program imports a DLL that does not exist anywhere the Windows loader searches.",
		"install the DLL alongside the executable, or install the package that provides it.",
		diagnose.ConfHigh, evidence...,
	), true
}

// missingSO fires when an ELF DT_NEEDED soname that is not a system runtime
// library cannot be resolved.
type missingSO struct{}

func (*missingSO) ID() string           { return "missing-so" }
func (*missingSO) Suppresses() []string { return nil }

func (*missingSO) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	if ev.Kind != evidence.KindELF {
		return nil, false
	}
	var missing []string
	for _, n := range ev.MissingNodes() {
		if n.Status != "missing" || isSystemLib(base(n.Module)) {
			continue
		}
		missing = append(missing, n.Module)
	}
	if len(missing) == 0 {
		return nil, false
	}

	evidence := []string{
		"the dynamic section references " + strings.Join(missing, ", ") +
			", which was not found in DT_RPATH/DT_RUNPATH, LD_LIBRARY_PATH or the standard library directories",
	}
	if msg := findMatchingOutputLine(ev, "Error loading shared library", "not found"); msg != "" {
		evidence = append(evidence, "loader reported: "+msg)
	}
	return diag(
		"missing-so",
		"missing shared library",
		"the program needs a shared library (.so) that the dynamic loader cannot find.",
		"install the library with your package manager, or set LD_LIBRARY_PATH to the directory containing it.",
		diagnose.ConfHigh, evidence...,
	), true
}

// missingVCRuntime fires when a missing PE import is a VC++ 2015-2022
// runtime DLL. It subsumes the generic missing-dll for the same node.
type missingVCRuntime struct{}

func (*missingVCRuntime) ID() string           { return "missing-vc-runtime" }
func (*missingVCRuntime) Suppresses() []string { return []string{"missing-dll"} }

func (*missingVCRuntime) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	if ev.Kind != evidence.KindPE {
		return nil, false
	}
	var missing []string
	for _, n := range ev.MissingNodes() {
		if isVCRuntime(base(n.Module)) {
			missing = append(missing, n.Module)
		}
	}
	if len(missing) == 0 {
		return nil, false
	}
	return diag(
		"missing-vc-runtime",
		"missing VC++ runtime",
		"the program imports a DLL from the Microsoft Visual C++ 2015-2022 runtime, which is not installed.",
		"install the VC++ 2015-2022 redistributable (vc_redist.x64.exe / vc_redist.x86.exe) from Microsoft.",
		diagnose.ConfHigh,
		"the import table references the VC runtime DLL "+strings.Join(missing, ", ")+", which is not present on this system",
	), true
}

// missingRuntime fires when a missing dependency is a language or system
// runtime: a .NET native DLL on Windows, or a glibc/musl C/C++ runtime
// library on Linux. It subsumes the corresponding generic missing-library
// rule.
type missingRuntime struct{}

func (*missingRuntime) ID() string           { return "missing-runtime" }
func (*missingRuntime) Suppresses() []string { return []string{"missing-dll", "missing-so"} }

func (*missingRuntime) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	switch ev.Kind {
	case evidence.KindPE:
		var missing []string
		for _, n := range ev.MissingNodes() {
			if isDotNetRuntime(base(n.Module)) {
				missing = append(missing, n.Module)
			}
		}
		if len(missing) == 0 {
			return nil, false
		}
		return diag(
			"missing-runtime",
			"missing .NET runtime",
			"the program needs the .NET runtime (its native host DLLs are missing), so it cannot start.",
			"install the matching .NET runtime (dotnet.microsoft.com/download) for the framework the program targets.",
			diagnose.ConfHigh,
			"the import table references the .NET host DLL "+strings.Join(missing, ", ")+", which is not installed",
		), true
	case evidence.KindELF:
		var missing []string
		for _, n := range ev.MissingNodes() {
			if isSystemLib(base(n.Module)) {
				missing = append(missing, n.Module)
			}
		}
		if len(missing) == 0 {
			return nil, false
		}
		return diag(
			"missing-runtime",
			"missing system C/C++ runtime",
			"the program needs a system C or C++ runtime library that is not installed, or the program was built for a different libc (musl vs glibc).",
			"install the system's libc/libstdc++ packages, or rebuild the program for this libc.",
			diagnose.ConfHigh,
			"the dynamic section references the runtime library "+strings.Join(missing, ", ")+", which is not present",
		), true
	}
	return nil, false
}

// missingInterp fires when an ELF's PT_INTERP interpreter path does not
// exist on disk (missing dynamic loader).
type missingInterp struct{}

func (*missingInterp) ID() string           { return "missing-interp" }
func (*missingInterp) Suppresses() []string { return nil }

func (*missingInterp) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	if ev.Kind != evidence.KindELF {
		return nil, false
	}
	for _, n := range ev.MissingNodes() {
		if n.Status != "missing-interp" {
			continue
		}
		return diag(
			"missing-interp",
			"missing ELF interpreter",
			"the program's dynamic linker (from PT_INTERP) does not exist, so the kernel cannot start it.",
			"install or relocate the dynamic linker the program was linked against (ld-linux / ld-musl).",
			diagnose.ConfHigh,
			"PT_INTERP points at "+n.Module+", which does not exist on this system",
		), true
	}
	return nil, false
}
