package rules

import (
	"testing"
	"time"

	"why/internal/diagnose"
	"why/internal/evidence"
)

func at() time.Time { return time.Date(2026, 8, 19, 10, 0, 0, 0, time.UTC) }

func startFailed(code uint32, msg string) evidence.Event {
	return evidence.StartFailed{Common: evidence.Common{Kind: evidence.EventStartFailed, Time: at(), Src: evidence.SourceCLI}, ErrorCode: code, Message: msg}
}

func exitEv(code uint32, sig int) evidence.Event {
	return evidence.Exit{Common: evidence.Common{Kind: evidence.EventExit, Time: at(), Src: evidence.SourceTrace}, ExitCode: code, Signal: sig}
}

func loaderErr(msg string) evidence.Event {
	return evidence.LoaderError{Common: evidence.Common{Kind: evidence.EventLoaderError, Time: at(), Src: evidence.SourceInspect}, Path: "t", Message: msg}
}

// loaderErrTrace is a tracer-produced LoaderError (captured stderr), distinct
// from an inspector parse failure.
func loaderErrTrace(msg string) evidence.Event {
	return evidence.LoaderError{Common: evidence.Common{Kind: evidence.EventLoaderError, Time: at(), Src: evidence.SourceTrace}, Path: "t", Message: msg}
}

func output(stream string, lines ...string) evidence.Event {
	return evidence.Output{Common: evidence.Common{Kind: evidence.EventOutput, Time: at(), Src: evidence.SourceTrace}, Stream: stream, Lines: lines}
}

func baseEvidence(kind evidence.Kind, host, arch string) *evidence.Evidence {
	return &evidence.Evidence{
		Kind:     kind,
		Env:      evidence.Env{OS: host, Arch: arch},
		DepNodes: []evidence.Node{{Module: "target", Status: "present"}},
	}
}

// runEngine applies the full rule set and returns surviving rule IDs.
func runEngine(ev *evidence.Evidence) []string {
	var ids []string
	for _, d := range diagnose.NewEngine(All()).Evaluate(ev) {
		ids = append(ids, d.RuleID)
	}
	return ids
}

func wantFired(t *testing.T, ev *evidence.Evidence, want string) {
	t.Helper()
	for _, id := range runEngine(ev) {
		if id == want {
			return
		}
	}
	t.Errorf("rule %q did not fire", want)
}

func wantNotFired(t *testing.T, ev *evidence.Evidence, notWant string) {
	t.Helper()
	for _, id := range runEngine(ev) {
		if id == notWant {
			t.Errorf("rule %q fired, want not fired", notWant)
		}
	}
}

func TestMissingDLL(t *testing.T) {
	ev := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev.DepNodes = append(ev.DepNodes, evidence.Node{Module: "foo.dll", Status: "missing"})
	ev.Events = []evidence.Event{startFailed(winErrModNotFound, "not found")}
	wantFired(t, ev, "missing-dll")

	// Negative: no missing nodes.
	wantNotFired(t, baseEvidence(evidence.KindPE, "windows", "amd64"), "missing-dll")
	// Negative: a VC runtime DLL is not claimed by the generic rule.
	evVC := baseEvidence(evidence.KindPE, "windows", "amd64")
	evVC.DepNodes = append(evVC.DepNodes, evidence.Node{Module: "vcruntime140.dll", Status: "missing"})
	wantNotFired(t, evVC, "missing-dll")
	wantFired(t, evVC, "missing-vc-runtime")

	// Negative: not a PE.
	evELF := baseEvidence(evidence.KindELF, "linux", "amd64")
	evELF.DepNodes = append(evELF.DepNodes, evidence.Node{Module: "foo.so.1", Status: "missing"})
	wantNotFired(t, evELF, "missing-dll")

	// Exit code evidence path.
	ev2 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev2.DepNodes = append(ev2.DepNodes, evidence.Node{Module: "foo.dll", Status: "missing"})
	ev2.Events = []evidence.Event{exitEv(ntDLLNotFound, 0)}
	wantFired(t, ev2, "missing-dll")
}

func TestMissingSO(t *testing.T) {
	ev := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev.DepNodes = append(ev.DepNodes, evidence.Node{Module: "libfoo.so.1", Status: "missing"})
	ev.Events = []evidence.Event{output("stderr", "Error loading shared library libfoo.so.1: No such file")}
	wantFired(t, ev, "missing-so")

	// Negative: system lib is claimed by missing-runtime, not missing-so.
	evSys := baseEvidence(evidence.KindELF, "linux", "amd64")
	evSys.DepNodes = append(evSys.DepNodes, evidence.Node{Module: "libc.so.6", Status: "missing"})
	wantNotFired(t, evSys, "missing-so")
	wantFired(t, evSys, "missing-runtime")
}

func TestMissingVCRuntime(t *testing.T) {
	ev := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev.DepNodes = append(ev.DepNodes, evidence.Node{Module: "msvcp140.dll", Status: "missing"})
	wantFired(t, ev, "missing-vc-runtime")

	ev2 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev2.DepNodes = append(ev2.DepNodes, evidence.Node{Module: "vcruntime140_1.dll", Status: "missing"})
	wantFired(t, ev2, "missing-vc-runtime")

	wantNotFired(t, baseEvidence(evidence.KindPE, "windows", "amd64"), "missing-vc-runtime")
}

func TestMissingRuntime(t *testing.T) {
	// PE .NET runtime.
	ev := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev.DepNodes = append(ev.DepNodes, evidence.Node{Module: "hostfxr.dll", Status: "missing"})
	wantFired(t, ev, "missing-runtime")
	// ELF glibc.
	ev2 := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev2.DepNodes = append(ev2.DepNodes, evidence.Node{Module: "libstdc++.so.6", Status: "missing"})
	wantFired(t, ev2, "missing-runtime")
	// ELF musl.
	ev3 := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev3.DepNodes = append(ev3.DepNodes, evidence.Node{Module: "libc.musl-x86_64.so.1", Status: "missing"})
	wantFired(t, ev3, "missing-runtime")
}

func TestMissingInterp(t *testing.T) {
	ev := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev.DepNodes = append(ev.DepNodes, evidence.Node{Module: "/nonexistent/ld-linux-why.so", Status: "missing-interp"})
	wantFired(t, ev, "missing-interp")

	ev2 := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev2.DepNodes = append(ev2.DepNodes, evidence.Node{Module: "/lib64/ld-linux-x86-64.so.2", Status: "present"})
	wantNotFired(t, ev2, "missing-interp")
}

func TestWrongArchPE(t *testing.T) {
	// amd64 binary on a 386 host cannot run.
	ev := baseEvidence(evidence.KindPE, "windows", "386")
	ev.TargetArch = "amd64"
	ev.Events = []evidence.Event{startFailed(winErrBadExeFormat, "bad format")}
	wantFired(t, ev, "wrong-arch")

	// x86 binary on amd64 host runs via WOW64: not a mismatch.
	ev2 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev2.TargetArch = "x86"
	ev2.Events = []evidence.Event{exitEv(ntInvalidImage, 0)}
	wantNotFired(t, ev2, "wrong-arch")

	// Static mismatch without loader refusal is medium, still fires.
	ev3 := baseEvidence(evidence.KindPE, "windows", "386")
	ev3.TargetArch = "amd64"
	wantFired(t, ev3, "wrong-arch")
}

func TestWrongArchELF(t *testing.T) {
	// amd64 ELF on a 386 host.
	ev := baseEvidence(evidence.KindELF, "linux", "386")
	ev.TargetArch = "amd64"
	ev.TargetClass = "64"
	wantFired(t, ev, "wrong-arch")

	// i386 ELF on amd64 host runs via the compat layer: not a mismatch
	// (the wrong-arch-linux fixture).
	ev2 := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev2.TargetArch = "x86"
	ev2.TargetClass = "32"
	wantNotFired(t, ev2, "wrong-arch")
}

func TestInvalidFormat(t *testing.T) {
	// Inspector could not parse: malformed image.
	ev := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev.Events = []evidence.Event{loaderErr("bad magic")}
	wantFired(t, ev, "invalid-format")

	// Linux ENOEXEC.
	ev2 := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev2.Events = []evidence.Event{startFailed(linuxErrNoexec, "exec format error")}
	wantFired(t, ev2, "invalid-format")

	// Windows 193.
	ev3 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev3.Events = []evidence.Event{startFailed(winErrBadExeFormat, "not a valid application")}
	wantFired(t, ev3, "invalid-format")

	// 0xC000007B with no static mismatch is invalid-format (medium).
	ev4 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev4.TargetArch = "amd64"
	ev4.Events = []evidence.Event{exitEv(ntInvalidImage, 0)}
	wantFired(t, ev4, "invalid-format")

	wantNotFired(t, baseEvidence(evidence.KindELF, "linux", "amd64"), "invalid-format")

	// A tracer LoaderError (captured library-search stderr) must NOT fire
	// invalid-format: only an inspector parse failure is an invalid image.
	// This guards against a false positive when the target itself prints
	// "not found".
	evTracer := baseEvidence(evidence.KindELF, "linux", "amd64")
	evTracer.DepNodes = append(evTracer.DepNodes, evidence.Node{Module: "libfoo.so.1", Status: "missing"})
	evTracer.Events = []evidence.Event{loaderErrTrace("libfoo.so.1 not found")}
	wantNotFired(t, evTracer, "invalid-format")
	wantFired(t, evTracer, "missing-so")
}

func TestWrongArchSuppressesInvalidFormat(t *testing.T) {
	// amd64-on-386 with 0xC000007B: wrong-arch fires and invalid-format must
	// not (the arch explanation wins).
	ev := baseEvidence(evidence.KindPE, "windows", "386")
	ev.TargetArch = "amd64"
	ev.Events = []evidence.Event{exitEv(ntInvalidImage, 0)}
	ids := runEngine(ev)
	if contains(ids, "wrong-arch") && contains(ids, "invalid-format") {
		t.Errorf("both wrong-arch and invalid-format fired: %v", ids)
	}
	wantFired(t, ev, "wrong-arch")
}

func TestPermissionDenied(t *testing.T) {
	ev := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev.Events = []evidence.Event{startFailed(linuxErrAcces, "permission denied")}
	wantFired(t, ev, "permission-denied")

	ev2 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev2.Events = []evidence.Event{startFailed(winErrAccessDenied, "access denied")}
	wantFired(t, ev2, "permission-denied")

	// 740 is elevation, not permission-denied.
	ev3 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev3.Events = []evidence.Event{startFailed(winErrElevation, "elevation")}
	wantNotFired(t, ev3, "permission-denied")
	wantFired(t, ev3, "elevation-required")
}

func TestElevationRequired(t *testing.T) {
	ev := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev.Events = []evidence.Event{startFailed(winErrElevation, "requires elevation")}
	wantFired(t, ev, "elevation-required")

	ev2 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev2.Events = []evidence.Event{startFailed(winErrAccessDenied, "access denied")}
	wantNotFired(t, ev2, "elevation-required")
}

func TestEntryPointFailure(t *testing.T) {
	ev := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev.Events = []evidence.Event{exitEv(ntEntryPointNotFound, 0)}
	wantFired(t, ev, "entry-point-failure")

	ev2 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev2.Events = []evidence.Event{startFailed(ntEntryPointNotFound, "")}
	wantFired(t, ev2, "entry-point-failure")

	ev3 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev3.Events = []evidence.Event{exitEv(ntAccessViolation, 0)}
	wantNotFired(t, ev3, "entry-point-failure")
}

func TestDLLInitFailure(t *testing.T) {
	ev := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev.Events = []evidence.Event{exitEv(ntDLLInitFailed, 0)}
	wantFired(t, ev, "dll-init-failure")

	ev2 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev2.Events = []evidence.Event{exitEv(ntAccessViolation, 0)}
	wantNotFired(t, ev2, "dll-init-failure")
}

func TestCrash(t *testing.T) {
	// Unclaimed NTSTATUS exit is a crash.
	ev := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev.Events = []evidence.Event{exitEv(ntAccessViolation, 0)}
	wantFired(t, ev, "crash")

	// Normal (non-exception) exit is not a crash.
	ev2 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev2.Events = []evidence.Event{exitEv(2, 0)}
	wantNotFired(t, ev2, "crash")

	// Loader-owned code is not claimed by crash.
	ev3 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev3.DepNodes = append(ev3.DepNodes, evidence.Node{Module: "foo.dll", Status: "missing"})
	ev3.Events = []evidence.Event{exitEv(ntDLLNotFound, 0)}
	wantFired(t, ev3, "missing-dll")
	wantNotFired(t, ev3, "crash")

	// Linux signal death is a crash.
	ev4 := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev4.Events = []evidence.Event{exitEv(0, 11)} // SIGSEGV
	wantFired(t, ev4, "crash")
}

func TestPathConflict(t *testing.T) {
	ev := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev.DepNodes = append(ev.DepNodes, evidence.Node{Module: `C:\Tools\my.dll`, Status: "present", Source: "path"})
	wantFired(t, ev, "path-conflict")

	// Resolved from system/app dir is not a conflict.
	ev2 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev2.DepNodes = append(ev2.DepNodes, evidence.Node{Module: `C:\app\my.dll`, Status: "present", Source: "appdir"})
	wantNotFired(t, ev2, "path-conflict")

	// Not a PE: never fires.
	ev3 := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev3.DepNodes = append(ev3.DepNodes, evidence.Node{Module: "/usr/lib/foo.so", Status: "present", Source: "system"})
	wantNotFired(t, ev3, "path-conflict")
}

func TestMissingEnvVar(t *testing.T) {
	ev := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev.Events = []evidence.Event{output("stderr", "environment variable WHY_TEST_VAR is not set"), exitEv(1, 0)}
	ev.Env.Vars = map[string]string{"PATH": "/bin"}
	wantFired(t, ev, "missing-env-var")

	// Negative: the variable IS set.
	ev2 := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev2.Events = []evidence.Event{output("stderr", "environment variable WHY_TEST_VAR is not set"), exitEv(1, 0)}
	ev2.Env.Vars = map[string]string{"why_test_var": "present"}
	wantNotFired(t, ev2, "missing-env-var")

	// Negative: no matching output.
	ev3 := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev3.Events = []evidence.Event{output("stdout", "all good"), exitEv(0, 0)}
	wantNotFired(t, ev3, "missing-env-var")
}

func TestPortInUse(t *testing.T) {
	ev := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev.Events = []evidence.Event{output("stderr", "listen tcp :8080: bind: address already in use"), exitEv(1, 0)}
	ev.Env.Ports = []evidence.PortInfo{{Port: 8080, Owner: "1234"}}
	wantFired(t, ev, "port-in-use")

	ev2 := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev2.Events = []evidence.Event{output("stdout", "server started"), exitEv(0, 0)}
	wantNotFired(t, ev2, "port-in-use")
}

func TestWrongCWD(t *testing.T) {
	ev := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev.Events = []evidence.Event{output("stderr", "open config.json: no such file or directory"), exitEv(1, 0)}
	wantFired(t, ev, "wrong-cwd")

	// Negative: exit 0 means no failure.
	ev2 := baseEvidence(evidence.KindELF, "linux", "amd64")
	ev2.Events = []evidence.Event{output("stderr", "open config.json: no such file or directory"), exitEv(0, 0)}
	wantNotFired(t, ev2, "wrong-cwd")

	// Negative: absolute path (a Windows drive path) is not a cwd problem.
	ev3 := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev3.Events = []evidence.Event{output("stderr", "open C:\\data\\config.json: no such file"), exitEv(1, 0)}
	wantNotFired(t, ev3, "wrong-cwd")
}

// TestSuppressionIntegration exercises the full engine over overlapping
// evidence: a VC runtime missing node must yield only missing-vc-runtime, not
// the generic missing-dll.
func TestSuppressionIntegration(t *testing.T) {
	ev := baseEvidence(evidence.KindPE, "windows", "amd64")
	ev.DepNodes = append(ev.DepNodes,
		evidence.Node{Module: "vcruntime140.dll", Status: "missing"},
		evidence.Node{Module: "other.dll", Status: "missing"},
	)
	ev.Events = []evidence.Event{startFailed(winErrModNotFound, "not found")}
	ids := runEngine(ev)
	if contains(ids, "missing-dll") {
		t.Errorf("missing-dll fired alongside missing-vc-runtime: %v", ids)
	}
	wantFired(t, ev, "missing-vc-runtime")
}

func TestAllRulesValidDiagnoses(t *testing.T) {
	// Every rule, exercised over empty evidence, must return no diagnosis
	// (empty evidence can never trigger a fact-based rule).
	ev := baseEvidence(evidence.KindPE, "windows", "amd64")
	if got := diagnose.NewEngine(All()).Evaluate(ev); len(got) != 0 {
		t.Errorf("empty evidence produced %d diagnoses: %v", len(got), got)
	}
}

func contains(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
