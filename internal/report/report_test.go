package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"why/internal/diagnose"
	"why/internal/evidence"
)

// testEvidence returns a deterministic evidence fixture for the golden
// tests: a PE target that was inspected and run on a Windows amd64 host.
func testEvidence() *evidence.Evidence {
	return &evidence.Evidence{
		Kind:       evidence.KindPE,
		SourcePath: `C:\app\demo.exe`,
		TargetPath: `C:\app\demo.exe`,
		TargetArch: "amd64",
		Env: evidence.Env{
			OS:        "windows",
			Arch:      "amd64",
			GoVersion: "go1.26.5",
			CWD:       `C:\app`,
		},
	}
}

func exitEvent(code uint32, signal int) evidence.Event {
	return evidence.Exit{
		Common:   evidence.Common{Kind: evidence.EventExit, Time: time.Now(), Src: evidence.SourceTrace},
		ExitCode: code,
		Signal:   signal,
	}
}

func startFailedEvent(message string) evidence.Event {
	return evidence.StartFailed{
		Common:  evidence.Common{Kind: evidence.EventStartFailed, Time: time.Now(), Src: evidence.SourceTrace},
		Message: message,
	}
}

// compareReport fails the test unless got and want are byte-identical.
func compareReport(t *testing.T, name string, got, want []byte) {
	t.Helper()
	if bytes.Compare(got, want) != 0 {
		t.Errorf("%s: output mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestRenderHumanOneDiagnosis(t *testing.T) {
	ev := testEvidence()
	diags := []*diagnose.Diagnosis{
		{
			RuleID:     "missing-dll",
			Cause:      "missing dependency vcruntime140.dll",
			Why:        "the dependency graph lists vcruntime140.dll as missing, but the loader resolved every other dependency",
			Evidence:   []string{"vcruntime140.dll: missing (search failed)"},
			Fix:        "install the Microsoft Visual C++ Redistributable for Visual Studio 2015-2022",
			Confidence: diagnose.ConfHigh,
		},
	}

	var buf bytes.Buffer
	RenderHuman(&buf, ev, diags)

	want := `why report -- C:\app\demo.exe
host: windows/amd64 (Go go1.26.5)  cwd: C:\app
kind: pe  machine: amd64
Diagnosis 1: missing dependency vcruntime140.dll
  WHY: the dependency graph lists vcruntime140.dll as missing, but the loader resolved every other dependency
  EVIDENCE:
    - vcruntime140.dll: missing (search failed)
  LIKELY FIX: install the Microsoft Visual C++ Redistributable for Visual Studio 2015-2022
  CONFIDENCE: high
`
	compareReport(t, "human one diagnosis", buf.Bytes(), []byte(want))
}

func TestRenderHumanTwoDiagnoses(t *testing.T) {
	ev := testEvidence()
	ev.Events = []evidence.Event{exitEvent(3, 0)}
	diags := []*diagnose.Diagnosis{
		{
			RuleID:     "missing-dll",
			Cause:      "missing dependency vcruntime140.dll",
			Why:        "the dependency graph lists vcruntime140.dll as missing, but the loader resolved every other dependency",
			Evidence:   []string{"vcruntime140.dll: missing (search failed)"},
			Fix:        "install the Microsoft Visual C++ Redistributable for Visual Studio 2015-2022",
			Confidence: diagnose.ConfHigh,
		},
		{
			RuleID:     "early-exit",
			Cause:      "process exited before main ran",
			Why:        "the target exited with code 3 after loading only the CRT",
			Evidence:   []string{"exit code 3 observed at 0.012s", "last module loaded: ucrtbase.dll"},
			Fix:        "run the target under a debugger to find the early exit",
			Confidence: diagnose.ConfMedium,
		},
	}

	var buf bytes.Buffer
	RenderHuman(&buf, ev, diags)

	want := `why report -- C:\app\demo.exe
host: windows/amd64 (Go go1.26.5)  cwd: C:\app
kind: pe  machine: amd64
Diagnosis 1: missing dependency vcruntime140.dll
  WHY: the dependency graph lists vcruntime140.dll as missing, but the loader resolved every other dependency
  EVIDENCE:
    - vcruntime140.dll: missing (search failed)
  LIKELY FIX: install the Microsoft Visual C++ Redistributable for Visual Studio 2015-2022
  CONFIDENCE: high

Diagnosis 2: process exited before main ran
  WHY: the target exited with code 3 after loading only the CRT
  EVIDENCE:
    - exit code 3 observed at 0.012s
    - last module loaded: ucrtbase.dll
  LIKELY FIX: run the target under a debugger to find the early exit
  CONFIDENCE: medium
`
	compareReport(t, "human two diagnoses", buf.Bytes(), []byte(want))
}

func TestRenderHumanUnknownExit(t *testing.T) {
	ev := testEvidence()
	ev.Events = []evidence.Event{exitEvent(3, 0)}

	var buf bytes.Buffer
	RenderHuman(&buf, ev, nil)

	want := `why report -- C:\app\demo.exe
host: windows/amd64 (Go go1.26.5)  cwd: C:\app
kind: pe  machine: amd64
CAUSE UNKNOWN
  WHY: the run completed but no known cause matched the collected evidence.
  FACTS:
    - process exited with code 3
`
	compareReport(t, "human unknown exit", buf.Bytes(), []byte(want))
}

func TestRenderHumanUnknownExitSignal(t *testing.T) {
	ev := testEvidence()
	ev.Events = []evidence.Event{exitEvent(0, 11)}

	var buf bytes.Buffer
	RenderHuman(&buf, ev, nil)

	want := `why report -- C:\app\demo.exe
host: windows/amd64 (Go go1.26.5)  cwd: C:\app
kind: pe  machine: amd64
CAUSE UNKNOWN
  WHY: the run completed but no known cause matched the collected evidence.
  FACTS:
    - process exited with code 0; signal 11
`
	compareReport(t, "human unknown exit signal", buf.Bytes(), []byte(want))
}

func TestRenderHumanUnknownStartFailed(t *testing.T) {
	ev := testEvidence()
	ev.Events = []evidence.Event{startFailedEvent("STATUS_DLL_NOT_FOUND")}

	var buf bytes.Buffer
	RenderHuman(&buf, ev, nil)

	want := `why report -- C:\app\demo.exe
host: windows/amd64 (Go go1.26.5)  cwd: C:\app
kind: pe  machine: amd64
CAUSE UNKNOWN
  WHY: the run completed but no known cause matched the collected evidence.
  FACTS:
    - process could not start: STATUS_DLL_NOT_FOUND
`
	compareReport(t, "human unknown start failed", buf.Bytes(), []byte(want))
}

func TestRenderHumanUnknownNoEvents(t *testing.T) {
	ev := testEvidence()

	var buf bytes.Buffer
	RenderHuman(&buf, ev, nil)

	want := `why report -- C:\app\demo.exe
host: windows/amd64 (Go go1.26.5)  cwd: C:\app
kind: pe  machine: amd64
CAUSE UNKNOWN
  WHY: the run completed but no known cause matched the collected evidence.
  FACTS:
    - no process start or exit was observed
`
	compareReport(t, "human unknown no events", buf.Bytes(), []byte(want))
}

func TestRenderHumanUsesSourcePathWhenNoTarget(t *testing.T) {
	ev := testEvidence()
	ev.TargetPath = ""

	var buf bytes.Buffer
	RenderHuman(&buf, ev, nil)

	want := `why report -- C:\app\demo.exe
host: windows/amd64 (Go go1.26.5)  cwd: C:\app
kind: pe  machine: amd64
CAUSE UNKNOWN
  WHY: the run completed but no known cause matched the collected evidence.
  FACTS:
    - no process start or exit was observed
`
	compareReport(t, "human source path fallback", buf.Bytes(), []byte(want))
}

func TestRenderJSONOneDiagnosis(t *testing.T) {
	ev := testEvidence()
	diags := []*diagnose.Diagnosis{
		{
			RuleID:     "missing-dll",
			Cause:      "missing dependency vcruntime140.dll",
			Why:        "the dependency graph lists vcruntime140.dll as missing, but the loader resolved every other dependency",
			Evidence:   []string{"vcruntime140.dll: missing (search failed)"},
			Fix:        "install the Microsoft Visual C++ Redistributable for Visual Studio 2015-2022",
			Confidence: diagnose.ConfHigh,
		},
	}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, ev, diags); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	want := `{
  "tool": "why",
  "version": "dev",
  "target": {
    "path": "C:\\app\\demo.exe",
    "kind": "pe",
    "machine": "amd64"
  },
  "host": {
    "os": "windows",
    "arch": "amd64",
    "go_version": "go1.26.5",
    "cwd": "C:\\app"
  },
  "diagnoses": [
    {
      "rule": "missing-dll",
      "cause": "missing dependency vcruntime140.dll",
      "why": "the dependency graph lists vcruntime140.dll as missing, but the loader resolved every other dependency",
      "evidence": [
        "vcruntime140.dll: missing (search failed)"
      ],
      "fix": "install the Microsoft Visual C++ Redistributable for Visual Studio 2015-2022",
      "confidence": "high"
    }
  ],
  "unknown": false
}
`
	compareReport(t, "json one diagnosis", buf.Bytes(), []byte(want))
}

func TestRenderJSONUnknown(t *testing.T) {
	ev := testEvidence()

	var buf bytes.Buffer
	if err := RenderJSON(&buf, ev, nil); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	want := `{
  "tool": "why",
  "version": "dev",
  "target": {
    "path": "C:\\app\\demo.exe",
    "kind": "pe",
    "machine": "amd64"
  },
  "host": {
    "os": "windows",
    "arch": "amd64",
    "go_version": "go1.26.5",
    "cwd": "C:\\app"
  },
  "diagnoses": [],
  "unknown": true
}
`
	compareReport(t, "json unknown", buf.Bytes(), []byte(want))
}

func TestRenderJSONClassPresent(t *testing.T) {
	ev := testEvidence()
	ev.Kind = evidence.KindELF
	ev.TargetArch = "x86-64"
	ev.TargetClass = "64"

	var buf bytes.Buffer
	if err := RenderJSON(&buf, ev, nil); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}

	want := `{
  "tool": "why",
  "version": "dev",
  "target": {
    "path": "C:\\app\\demo.exe",
    "kind": "elf",
    "machine": "x86-64",
    "class": "64"
  },
  "host": {
    "os": "windows",
    "arch": "amd64",
    "go_version": "go1.26.5",
    "cwd": "C:\\app"
  },
  "diagnoses": [],
  "unknown": true
}
`
	compareReport(t, "json elf class", buf.Bytes(), []byte(want))
}

func TestRenderJSONWriteError(t *testing.T) {
	// A writer that always fails must surface as an error.
	ev := testEvidence()
	err := RenderJSON(failingWriter{}, ev, nil)
	if err == nil {
		t.Fatal("RenderJSON: expected error from failing writer, got nil")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("RenderJSON: unexpected error %v", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errBoom }

var errBoom = &boomError{}

type boomError struct{}

func (e *boomError) Error() string { return "boom" }
