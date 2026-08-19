// Package rules implements the v0.1 deterministic diagnosis rules. Rules are
// pure functions of evidence.Evidence: they never probe the system (the
// inspectors, collectors and tracers already recorded the facts). The
// engine (internal/diagnose) applies them; this package only defines and
// registers them.
//
// False positives are worse than CAUSE UNKNOWN: a rule fires only when its
// required evidence is present, and its confidence never exceeds what the
// evidence supports. Output-based rules (port-in-use, wrong-cwd,
// missing-env-var) are low/medium confidence because they attribute a cause
// from the target's own text.
package rules

import (
	"path/filepath"
	"regexp"
	"strings"

	"why/internal/diagnose"
	"why/internal/evidence"
)

// Windows NTSTATUS values that surface as process exit codes when the loader
// or an exception terminates the target.
const (
	ntDLLNotFound        uint32 = 0xC0000135 // STATUS_DLL_NOT_FOUND
	ntEntryPointNotFound uint32 = 0xC0000139 // STATUS_ENTRYPOINT_NOT_FOUND
	ntDLLInitFailed      uint32 = 0xC0000142 // STATUS_DLL_INIT_FAILED
	ntInvalidImage       uint32 = 0xC000007B // STATUS_INVALID_IMAGE_FORMAT
	ntAccessViolation    uint32 = 0xC0000005 // STATUS_ACCESS_VIOLATION
)

// Windows win32 start-failure codes (StartFailed.ErrorCode).
const (
	winErrFileNotFound    uint32 = 2
	winErrAccessDenied    uint32 = 5
	winErrModNotFound     uint32 = 126
	winErrProcNotFound    uint32 = 127
	winErrBadExeFormat    uint32 = 193
	winErrMachineMismatch uint32 = 216
	winErrElevation       uint32 = 740
)

// Linux errno start-failure codes (StartFailed.ErrorCode).
const (
	linuxErrNoent  uint32 = 2  // ENOENT
	linuxErrNoexec uint32 = 8  // ENOEXEC
	linuxErrAcces  uint32 = 13 // EACCES
)

// isNTSTATUS reports whether code is in the NTSTATUS failure range (a
// process exit code in 0xC0000000-0xCFFFFFFF is an exception or loader
// failure, not a normal exit).
func isNTSTATUS(code uint32) bool {
	return code&0xFFFF0000 == 0xC0000000
}

// vcRuntimeDLLs are the DLLs shipped by the VC++ 2015-2022 redistributable.
// A missing one of these is the "missing VC runtime" diagnosis, more
// specific than the generic missing-dll.
var vcRuntimeDLLs = map[string]bool{
	"vcruntime140.dll":         true,
	"vcruntime140_1.dll":       true,
	"msvcp140.dll":             true,
	"msvcp140_1.dll":           true,
	"msvcp140_2.dll":           true,
	"msvcp140_atomic_wait.dll": true,
	"msvcp140_codecvt_ids.dll": true,
	"concrt140.dll":            true,
	"vccorlib140.dll":          true,
	"vcamp140.dll":             true,
	"vcomp140.dll":             true,
}

// dotnetDLLs are the native DLLs of the .NET runtime. A missing one of these
// means the .NET (host) runtime is not installed — the "missing runtime"
// diagnosis.
var dotnetDLLs = map[string]bool{
	"hostfxr.dll":    true,
	"hostpolicy.dll": true,
	"coreclr.dll":    true,
	"clr.dll":        true,
	"mscoree.dll":    true,
}

// glibcLibs are the C/C++ system libraries of a glibc-based Linux system. A
// missing one (e.g. libstdc++.so.6) is a system-level "missing runtime".
var glibcLibs = map[string]bool{
	"libc.so.6":            true,
	"ld-linux-x86-64.so.2": true,
	"ld-linux.so.2":        true,
	"libstdc++.so.6":       true,
	"libgcc_s.so.1":        true,
}

// muslLibs are the equivalents on a musl-based system. A musl target loaded
// on a glibc host (or vice versa) surfaces as a missing musl libc.
var muslLibs = map[string]bool{
	"libc.musl-x86_64.so.1": true,
	"libc.musl-i386.so.1":   true,
}

// isVCRuntime reports whether dllName is a VC++ runtime DLL.
func isVCRuntime(dllName string) bool { return vcRuntimeDLLs[strings.ToLower(dllName)] }

// isDotNetRuntime reports whether dllName is a .NET runtime DLL.
func isDotNetRuntime(dllName string) bool { return dotnetDLLs[strings.ToLower(dllName)] }

// isSystemLib reports whether soname is a glibc or musl system C++/C runtime
// library.
func isSystemLib(soname string) bool {
	base := strings.ToLower(soname)
	return glibcLibs[base] || muslLibs[base]
}

// peRunnable reports whether a PE of machine runs on a host of the given
// GOARCH. x86 runs on amd64 Windows via WOW64; nothing else crosses.
func peRunnable(machine, host string) bool {
	switch host {
	case "amd64":
		return machine == "amd64" || machine == "x86"
	case "386":
		return machine == "x86"
	case "arm64":
		return machine == "arm64" || machine == "armnt" || machine == "arm"
	default:
		return machine == host
	}
}

// elfRunnable reports whether an ELF of arch/class runs on a host of the
// given GOARCH. An amd64 kernel runs 32-bit x86 ELF via the compat layer.
func elfRunnable(arch, class, host string) bool {
	switch host {
	case "amd64":
		return arch == "amd64" || (arch == "x86" && class == "32")
	case "386":
		return arch == "x86"
	case "arm64":
		return arch == "arm64"
	default:
		return arch == host
	}
}

// diag builds a *diagnose.Diagnosis with the standard field order. Evidence
// lines are copied so later callers cannot alias the caller's slice.
func diag(id, cause, why, fix string, conf diagnose.Confidence, evidence ...string) *diagnose.Diagnosis {
	return &diagnose.Diagnosis{
		RuleID:     id,
		Cause:      cause,
		Why:        why,
		Evidence:   append([]string(nil), evidence...),
		Fix:        fix,
		Confidence: conf,
	}
}

// All returns the v0.1 rule set in the canonical registration order.
// Specific rules precede the generic ones they subsume; the engine resolves
// overlap via suppression, so order only breaks equal-confidence ties.
func All() []diagnose.Rule {
	return []diagnose.Rule{
		&missingVCRuntime{},
		&missingRuntime{},
		&missingInterp{},
		&missingDLL{},
		&missingSO{},
		&wrongArch{},
		&elevationRequired{},
		&entryPointFailure{},
		&dllInitFailure{},
		&invalidFormat{},
		&permissionDenied{},
		&pathConflict{},
		&missingEnvVar{},
		&portInUse{},
		&wrongCWD{},
		&crash{},
	}
}

// base returns the file name of module, lower-cased.
func base(module string) string { return strings.ToLower(filepath.Base(module)) }

// findMatchingOutputLine returns the first captured stdout/stderr line that
// contains any needle, for evidence quoting. Empty when none matches.
func findMatchingOutputLine(ev *evidence.Evidence, needles ...string) string {
	for _, stream := range []string{"stdout", "stderr"} {
		text, _ := ev.Output(stream)
		for _, line := range strings.Split(text, "\n") {
			for _, n := range needles {
				if n != "" && strings.Contains(line, n) {
					return strings.TrimSpace(line)
				}
			}
		}
	}
	return ""
}

var (
	envVarRe  = regexp.MustCompile(`(?i)(?:environment variable|env(?:ironment)? var(?:iable)?)\s+([A-Za-z_][A-Za-z0-9_]*)`)
	envSetRe  = regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\s+(?:is not set|not set|is not defined|not defined)`)
	cwdFileRe = regexp.MustCompile(`(?i)(?:open|read|load|cannot find|can't find|unable to (?:open|find|read|load)|no such file)\s+([^/\\][^/\\\s:]*)`)
)
