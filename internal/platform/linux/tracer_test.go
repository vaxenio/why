//go:build linux

package linux

import (
	"os"
	"slices"
	"strings"
	"testing"

	"why/internal/evidence"
)

// assertValid fails the test unless every event conforms to the .rdr schema.
func assertValid(t *testing.T, events []evidence.Event) {
	t.Helper()
	for _, e := range events {
		if err := evidence.Validate(e); err != nil {
			t.Fatalf("event %v is not schema-valid: %v", e, err)
		}
	}
}

// lastExit returns the most recent Exit event, if any.
func lastExit(events []evidence.Event) (evidence.Exit, bool) {
	for i := len(events) - 1; i >= 0; i-- {
		if ex, ok := events[i].(evidence.Exit); ok {
			return ex, true
		}
	}
	return evidence.Exit{}, false
}

func TestParseLoaderStderr(t *testing.T) {
	lines := []string{
		"      find library=libc.so.6 [0]; searching",
		"        search path=/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu		(SYSTEM)",
		"        trying file=/usr/lib/x86_64-linux-gnu/libc.so.6",
		"        trying file=/lib/x86_64-linux-gnu/libc.so.6",
		"        trying file=/lib/libc.so.6",
		"        calling init: /lib/x86_64-linux-gnu/libc.so.6",
		"      find library=libsuperseded.so.2 [0]; searching",
		"        trying file=/usr/lib/libsuperseded.so.2",
		"      find library=libmissing.so.1 [0]; searching",
		"        search path=/usr/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu		(SYSTEM)",
		"        trying file=/usr/lib/x86_64-linux-gnu/libmissing.so.1",
		"        trying file=/lib/x86_64-linux-gnu/libmissing.so.1",
	}
	events := parseLoaderStderr("/app/app", lines)
	assertValid(t, events)
	if len(events) != 3 {
		t.Fatalf("got %d events, want 3: %v", len(events), events)
	}

	loaded, ok := events[0].(evidence.ModuleLoaded)
	if !ok {
		t.Fatalf("events[0] = %T, want ModuleLoaded", events[0])
	}
	if loaded.Path != "/lib/x86_64-linux-gnu/libc.so.6" || !loaded.Found {
		t.Fatalf("ModuleLoaded = %+v, want path /lib/x86_64-linux-gnu/libc.so.6, found", loaded)
	}

	superseded, ok := events[1].(evidence.SearchFailed)
	if !ok {
		t.Fatalf("events[1] = %T, want SearchFailed", events[1])
	}
	if superseded.Library != "libsuperseded.so.2" {
		t.Fatalf("SearchFailed.Library = %q, want libsuperseded.so.2", superseded.Library)
	}
	wantOne := []string{"/usr/lib/libsuperseded.so.2"}
	if len(superseded.SearchPaths) != len(wantOne) || superseded.SearchPaths[0] != wantOne[0] {
		t.Fatalf("SearchFailed.SearchPaths = %v, want %v", superseded.SearchPaths, wantOne)
	}

	missing, ok := events[2].(evidence.SearchFailed)
	if !ok {
		t.Fatalf("events[2] = %T, want SearchFailed", events[2])
	}
	if missing.Library != "libmissing.so.1" {
		t.Fatalf("SearchFailed.Library = %q, want libmissing.so.1", missing.Library)
	}
	wantPaths := []string{"/usr/lib/x86_64-linux-gnu/libmissing.so.1", "/lib/x86_64-linux-gnu/libmissing.so.1"}
	if len(missing.SearchPaths) != len(wantPaths) {
		t.Fatalf("SearchFailed.SearchPaths = %v, want %v", missing.SearchPaths, wantPaths)
	}
	for i := range wantPaths {
		if missing.SearchPaths[i] != wantPaths[i] {
			t.Fatalf("SearchFailed.SearchPaths = %v, want %v", missing.SearchPaths, wantPaths)
		}
	}
}

func TestParseLoaderStderrMusl(t *testing.T) {
	line := "Error loading shared library libfoo.so.1: No such file or directory (needed by /app/app)"
	events := parseLoaderStderr("/app/app", []string{line})
	assertValid(t, events)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %v", len(events), events)
	}
	le, ok := events[0].(evidence.LoaderError)
	if !ok {
		t.Fatalf("events[0] = %T, want LoaderError", events[0])
	}
	if le.Path != "/app/app" {
		t.Fatalf("LoaderError.Path = %q, want /app/app", le.Path)
	}
	if le.Message != line {
		t.Fatalf("LoaderError.Message = %q, want %q", le.Message, line)
	}
}

func TestRunTrueExitsZero(t *testing.T) {
	if _, err := os.Stat("/bin/true"); err != nil {
		t.Skip("/bin/true not available")
	}
	tr, err := New("/bin/true")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := tr.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	events := tr.Events()
	assertValid(t, events)
	if len(events) == 0 {
		t.Fatal("no events recorded")
	}
	if _, ok := events[0].(evidence.ProcessStart); !ok {
		t.Fatalf("first event = %T, want ProcessStart", events[0])
	}
	ex, ok := lastExit(events)
	if !ok {
		t.Fatal("no Exit event")
	}
	if ex.ExitCode != 0 || ex.Signal != 0 {
		t.Fatalf("Exit = %+v, want exit code 0, no signal", ex)
	}
	// Output events for both streams must close the sequence.
	for _, stream := range []string{"stdout", "stderr"} {
		found := false
		for _, e := range events {
			if o, ok := e.(evidence.Output); ok && o.Stream == stream {
				found = true
			}
		}
		if !found {
			t.Fatalf("no Output event for %q", stream)
		}
	}
}

func TestRunMissingTarget(t *testing.T) {
	tr, err := New("/nonexistent/why-missing-target")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := tr.Run(); err != nil {
		t.Fatalf("Run returned %v for a missing target, want nil", err)
	}
	events := tr.Events()
	assertValid(t, events)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1: %v", len(events), events)
	}
	sf, ok := events[0].(evidence.StartFailed)
	if !ok {
		t.Fatalf("events[0] = %T, want StartFailed", events[0])
	}
	if sf.ErrorCode != 2 {
		t.Fatalf("StartFailed.ErrorCode = %d, want 2 (ENOENT)", sf.ErrorCode)
	}
	if sf.Message == "" {
		t.Fatal("StartFailed.Message is empty")
	}
}

func TestRunShellExitCode(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("/bin/sh not available")
	}
	tr, err := New("/bin/sh", "-c", "exit 3")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := tr.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	events := tr.Events()
	assertValid(t, events)
	ex, ok := lastExit(events)
	if !ok {
		t.Fatal("no Exit event")
	}
	if ex.ExitCode != 3 || ex.Signal != 0 {
		t.Fatalf("Exit = %+v, want exit code 3, no signal", ex)
	}
}

func TestStreamBounds(t *testing.T) {
	s := &stream{}
	for range 250 {
		s.add("x")
	}
	if got := len(s.snapshot()); got != maxStreamLines {
		t.Fatalf("kept %d lines, want %d", got, maxStreamLines)
	}
	if !s.wasTruncated() {
		t.Fatal("line bound exceeded but truncated not set")
	}

	s = &stream{}
	big := strings.Repeat("y", 1024)
	for range 100 {
		s.add(big)
	}
	// 100 KiB total exceeds the 64 KiB bound; the tail keeps the newest
	// 64 lines (64 KiB).
	if got := len(s.snapshot()); got != 64 {
		t.Fatalf("kept %d big lines, want 64", got)
	}
	if !s.wasTruncated() {
		t.Fatal("byte bound exceeded but truncated not set")
	}
}

// TestRunCapturesOutput exercises output capture end-to-end: the target
// writes to stdout and stderr and exits 1; both streams must appear in the
// Output events (rules like wrong-cwd and missing-env-var depend on it).
func TestRunCapturesOutput(t *testing.T) {
	tr, err := New("/bin/sh", "-c", "echo to-stdout; echo to-stderr 1>&2; exit 1")
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Run(); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr []string
	for _, e := range tr.Events() {
		if o, ok := e.(evidence.Output); ok {
			if o.Stream == "stdout" {
				stdout = append(stdout, o.Lines...)
			} else {
				stderr = append(stderr, o.Lines...)
			}
		}
	}
	t.Logf("stdout=%q stderr=%q", stdout, stderr)
	if !slices.Contains(stdout, "to-stdout") {
		t.Errorf("stdout not captured: %q", stdout)
	}
	if !slices.Contains(stderr, "to-stderr") {
		t.Errorf("stderr not captured: %q", stderr)
	}
}
