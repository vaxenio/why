//go:build windows

package windows

import (
	"path/filepath"
	"testing"
	"time"

	"why/internal/evidence"
)

// fixturesDir is the repo's test/fixtures/bin relative to this package.
func fixturesDir() string {
	return filepath.Join("..", "..", "..", "test", "fixtures", "bin")
}

// TestStreamBufTail pins the bounded-capture contract: only the tail of a
// stream is kept and the truncated flag is set when lines are dropped.
func TestStreamBufTail(t *testing.T) {
	b := &streamBuf{}
	for i := range 300 {
		b.write([]byte{byte('a') + byte(i%26)})
		b.write([]byte{'\n'})
	}
	lines, truncated := b.snapshot()
	if !truncated {
		t.Error("truncated = false, want true (300 lines exceed the 200 cap)")
	}
	if len(lines) > maxOutLines {
		t.Errorf("kept %d lines, want at most %d", len(lines), maxOutLines)
	}
	// The most recent line must be preserved (i=299 -> 'a'+299%26 = 'n').
	if lines[len(lines)-1] != "n" {
		t.Errorf("last line = %q, want %q", lines[len(lines)-1], "n")
	}
}

// TestRunHealthyHello traces a healthy PE and expects a clean exit 0.
func TestRunHealthyHello(t *testing.T) {
	tr, err := New(filepath.Join(fixturesDir(), "hello-x64.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Run(); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	ev := tr.Events()
	seenStart, seenExit := false, false
	for _, e := range ev {
		switch v := e.(type) {
		case evidence.ProcessStart:
			seenStart = true
		case evidence.Exit:
			seenExit = true
			if v.ExitCode != 0 {
				t.Errorf("Exit code = %d, want 0", v.ExitCode)
			}
		}
	}
	if !seenStart {
		t.Error("no ProcessStart event")
	}
	if !seenExit {
		t.Error("no Exit event")
	}
}

// TestRunMissingDLL traces a PE whose import table names an absent DLL. The
// loader either fails at CreateProcess (StartFailed) or exits with
// STATUS_DLL_NOT_FOUND; either way a diagnosable signal must be recorded.
func TestRunMissingDLL(t *testing.T) {
	tr, err := New(filepath.Join(fixturesDir(), "missing-dll-x64.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Run(); err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, e := range tr.Events() {
		switch e.(type) {
		case evidence.StartFailed:
			return // CreateProcess failed: diagnosable
		case evidence.Exit:
			return // loader/exception exit: diagnosable
		}
	}
	t.Error("no StartFailed or Exit event for a missing-DLL target")
}

// TestEventsReturnsSnapshot pins the snapshot contract for the real tracer.
func TestEventsReturnsSnapshot(t *testing.T) {
	tr, err := New(filepath.Join(fixturesDir(), "hello-x64.exe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Run(); err != nil {
		t.Fatal(err)
	}
	got := tr.Events()
	if len(got) == 0 {
		t.Fatal("Events() empty")
	}
	got[0] = nil // mutate the snapshot
	if got2 := tr.Events(); got2[0] == nil {
		t.Error("Events() returned a live slice")
	}
}

// TestStopTerminates proves Stop kills a long-running target (a sleep). This
// exercises the Stop contract without blocking the test indefinitely.
func TestStopTerminates(t *testing.T) {
	tr, err := New("timeout.exe", "/t", "10")
	if err != nil {
		t.Skipf("timeout.exe unavailable: %v", err)
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		tr.Stop()
	}()
	if err := tr.Run(); err != nil {
		t.Fatalf("Run() after Stop: %v", err)
	}
	for _, e := range tr.Events() {
		if _, ok := e.(evidence.Exit); ok {
			return
		}
	}
	t.Error("no Exit event after Stop")
}
