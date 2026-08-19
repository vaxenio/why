// arch.go implements the wrong-arch and invalid-format rules. wrong-arch
// fires when the target's machine cannot run on this host; invalid-format
// fires when the loader rejects the image format itself. They overlap on
// error code 0xC000007B (STATUS_INVALID_IMAGE_FORMAT): wrong-arch suppresses
// invalid-format when a static arch mismatch confirms the arch explanation.
package rules

import (
	"fmt"

	"why/internal/diagnose"
	"why/internal/evidence"
)

// wrongArch fires when the target's architecture cannot run on this host.
// The static mismatch alone is a medium-confidence fact; a loader refusal
// (0xC000007B / 216 / ENOEXEC) raises it to high.
type wrongArch struct{}

func (*wrongArch) ID() string           { return "wrong-arch" }
func (*wrongArch) Suppresses() []string { return []string{"invalid-format"} }

func (*wrongArch) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	host := ev.Env.Arch
	if host == "" || ev.TargetArch == "" {
		return nil, false
	}
	var mismatch bool
	var label string
	switch ev.Kind {
	case evidence.KindPE:
		mismatch = !peRunnable(ev.TargetArch, host)
		label = fmt.Sprintf("the binary is %s; this host runs %s", ev.TargetArch, host)
	case evidence.KindELF:
		mismatch = !elfRunnable(ev.TargetArch, ev.TargetClass, host)
		label = fmt.Sprintf("the binary is %s/%s-bit ELF; this host runs %s", ev.TargetArch, ev.TargetClass, host)
	default:
		return nil, false
	}
	if !mismatch {
		return nil, false
	}

	// A loader refusal makes the diagnosis high-confidence; without one the
	// mismatch is a medium-confidence fact (the loader may still reject it).
	refused := false
	if sf, ok := ev.StartFailed(); ok {
		refused = sf.ErrorCode == winErrBadExeFormat || sf.ErrorCode == winErrMachineMismatch ||
			sf.ErrorCode == linuxErrNoexec
	}
	if ex, ok := ev.Exit(); ok {
		refused = refused || ex.ExitCode == ntInvalidImage
	}
	conf := diagnose.ConfMedium
	if refused {
		conf = diagnose.ConfHigh
	}
	return diag(
		"wrong-arch",
		"architecture mismatch",
		"the binary's architecture cannot run on this host (or its loader refuses it), so the program cannot start.",
		"run the program on a machine of the matching architecture, or obtain a build for "+host+".",
		conf, label,
	), true
}

// invalidFormat fires when the loader or inspector rejects the image format:
// a non-executable format (ENOEXEC), a Windows bad-image error with no arch
// explanation (0xC000007B / 193 / 216), or a binary the inspector could not
// even parse as PE/ELF.
type invalidFormat struct{}

func (*invalidFormat) ID() string           { return "invalid-format" }
func (*invalidFormat) Suppresses() []string { return nil }

func (*invalidFormat) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	// A file the inspector could not parse as PE/ELF is a malformed image.
	// Only the inspector's parse failures count here — the tracer's
	// LoaderError events (captured library-search stderr) are evidence for
	// other rules, not "invalid executable format", so filtering on Source
	// avoids a false positive when the target itself prints "not found".
	for _, le := range ev.LoaderErrors() {
		if le.Src != evidence.SourceInspect {
			continue
		}
		return diag(
			"invalid-format",
			"invalid executable format",
			"the file is not a valid "+string(ev.Kind)+" image, or is corrupted.",
			"re-download or rebuild the program; the file bytes do not form a valid executable.",
			diagnose.ConfHigh, "the inspector failed to parse the image: "+le.Message,
		), true
	}

	var code uint32
	var codeSet bool
	if sf, ok := ev.StartFailed(); ok {
		code, codeSet = sf.ErrorCode, true
	}
	if ex, ok := ev.Exit(); ok {
		code, codeSet = ex.ExitCode, true
	}
	if !codeSet {
		return nil, false
	}

	switch {
	case code == linuxErrNoexec:
		return diag(
			"invalid-format",
			"invalid executable format",
			"the kernel refused to execute the file (exec format error); it is not a valid executable for this host.",
			"verify the file is a real executable for "+ev.Env.OS+"/"+ev.Env.Arch+"; a PE cannot run on Linux and an ELF cannot run on Windows.",
			diagnose.ConfHigh, "start failed with ENOEXEC (exec format error)",
		), true
	case code == winErrBadExeFormat || code == winErrMachineMismatch:
		return diag(
			"invalid-format",
			"invalid executable format",
			"Windows rejected the image format ("+fmt.Sprintf("win32 error %d", code)+").",
			"verify the file is a valid PE for this Windows architecture; corrupt or non-PE files give this error.",
			diagnose.ConfHigh, "start failed with "+fmt.Sprintf("win32 error %d", code),
		), true
	case code == ntInvalidImage:
		// 0xC000007B is most often a wrong-arch dependency (a 32-bit DLL in a
		// 64-bit process) even when the target itself matches the host arch.
		return diag(
			"invalid-format",
			"invalid image format",
			"the loader rejected an image with STATUS_INVALID_IMAGE_FORMAT; this commonly means a dependency is the wrong architecture.",
			"ensure every DLL alongside the executable matches its architecture (32 vs 64-bit).",
			diagnose.ConfMedium, "process exited with 0xC000007B (STATUS_INVALID_IMAGE_FORMAT)",
		), true
	}
	return nil, false
}
