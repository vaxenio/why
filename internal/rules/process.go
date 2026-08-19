// process.go implements the start/teardown rules: start failures (permission
// denied, elevation required), loader-teardown failures (entry-point,
// DLL-init) and the immediate-crash fallback.
package rules

import (
	"fmt"

	"why/internal/diagnose"
	"why/internal/evidence"
)

// permissionDenied fires when the target could not be started because of
// missing execute permission / access denied.
type permissionDenied struct{}

func (*permissionDenied) ID() string           { return "permission-denied" }
func (*permissionDenied) Suppresses() []string { return nil }

func (*permissionDenied) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	sf, ok := ev.StartFailed()
	if !ok {
		return nil, false
	}
	switch {
	case sf.ErrorCode == linuxErrAcces:
		return diag(
			"permission-denied",
			"permission denied / no execute permission",
			"the operating system refused to execute the program: the file is not executable, or the process lacks permission.",
			"chmod +x the binary (and check its parent directories' permissions), or run as an allowed user.",
			diagnose.ConfHigh, "start failed with EACCES (permission denied)",
		), true
	case sf.ErrorCode == winErrAccessDenied:
		// On Windows, ERROR_ACCESS_DENIED at CreateProcess is access-denied
		// or elevation. The elevation rule handles 740 specifically; a bare 5
		// is ambiguous, hence medium confidence.
		return diag(
			"permission-denied",
			"permission denied",
			"Windows refused to create the process (access denied). If the binary's manifest requests elevation, that is the cause instead.",
			"run from an account with access, or (if the manifest requests elevation) run from an elevated prompt.",
			diagnose.ConfMedium, "start failed with win32 error 5 (access denied)",
		), true
	}
	return nil, false
}

// elevationRequired fires when CreateProcess fails with
// ERROR_ELEVATION_REQUIRED (the manifest requests admin rights).
type elevationRequired struct{}

func (*elevationRequired) ID() string           { return "elevation-required" }
func (*elevationRequired) Suppresses() []string { return nil }

func (*elevationRequired) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	sf, ok := ev.StartFailed()
	if !ok || sf.ErrorCode != winErrElevation {
		return nil, false
	}
	return diag(
		"elevation-required",
		"elevation required",
		"the program requests administrator privileges (its manifest declares requireAdministrator) and the current process is not elevated.",
		"launch it from an elevated (administrator) terminal or with 'Run as administrator'.",
		diagnose.ConfHigh, "start failed with win32 error 740 (elevation required)",
	), true
}

// entryPointFailure fires on STATUS_ENTRYPOINT_NOT_FOUND: an imported symbol
// is missing from a DLL the loader did load.
type entryPointFailure struct{}

func (*entryPointFailure) ID() string           { return "entry-point-failure" }
func (*entryPointFailure) Suppresses() []string { return nil }

func (*entryPointFailure) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	var code uint32
	var codeSet bool
	if sf, ok := ev.StartFailed(); ok {
		code, codeSet = sf.ErrorCode, true
	}
	if ex, ok := ev.Exit(); ok {
		code, codeSet = ex.ExitCode, true
	}
	if !codeSet || code != ntEntryPointNotFound {
		return nil, false
	}
	return diag(
		"entry-point-failure",
		"entry-point failure",
		"the program or a DLL it loads references an exported symbol that does not exist in the loaded DLL (STATUS_ENTRYPOINT_NOT_FOUND).",
		"update or reinstall the DLLs the program loads; a version mismatch between the program and a DLL is the usual cause.",
		diagnose.ConfHigh, "process failed with 0xC0000139 (STATUS_ENTRYPOINT_NOT_FOUND)",
	), true
}

// dllInitFailure fires on STATUS_DLL_INIT_FAILED: a loaded DLL's DllMain
// returned FALSE during initialization.
type dllInitFailure struct{}

func (*dllInitFailure) ID() string           { return "dll-init-failure" }
func (*dllInitFailure) Suppresses() []string { return nil }

func (*dllInitFailure) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	ex, ok := ev.Exit()
	if !ok || ex.ExitCode != ntDLLInitFailed {
		return nil, false
	}
	return diag(
		"dll-init-failure",
		"DLL initialization failure",
		"a DLL the program loads failed to initialize (its DllMain returned FALSE), terminating the process during load.",
		"find which DLL fails to initialize (run under a debugger or check the event log) and update or remove it.",
		diagnose.ConfHigh, "process exited with 0xC0000142 (STATUS_DLL_INIT_FAILED)",
	), true
}

// crash fires when the process died from an exception (a crash) that no
// more-specific rule claims. It is deliberately the fallback: the loader,
// arch, entry-point and DLL-init rules own their specific NTSTATUS codes, so
// crash only claims unclaimed exception exits.
type crash struct{}

func (*crash) ID() string           { return "crash" }
func (*crash) Suppresses() []string { return nil }

func (*crash) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	ex, ok := ev.Exit()
	if !ok {
		return nil, false
	}
	if ex.Signal != 0 {
		return diag(
			"crash",
			"immediate crash",
			"the program was terminated by a signal, indicating a crash rather than a normal exit.",
			"run it under a debugger (gdb) or with a core dump to find the faulting instruction.",
			diagnose.ConfMedium, fmt.Sprintf("process terminated by signal %d", ex.Signal),
		), true
	}
	if !isNTSTATUS(ex.ExitCode) {
		return nil, false
	}
	// Codes claimed by more-specific rules are not crashes of this class.
	switch ex.ExitCode {
	case ntDLLNotFound, ntEntryPointNotFound, ntDLLInitFailed, ntInvalidImage:
		return nil, false
	}
	return diag(
		"crash",
		"immediate crash",
		"the program exited with an exception status code, meaning it crashed during startup or execution.",
		"run it under a debugger (WinDbg / Visual Studio) to capture the faulting exception and module.",
		diagnose.ConfMedium, fmt.Sprintf("process exited with 0x%08X (exception status)", ex.ExitCode),
	), true
}
