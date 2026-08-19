//go:build linux

// Package linux implements the exec-based tracer for why on Linux. The
// target runs with LD_DEBUG=libs so the dynamic loader reports library
// resolution on stderr; the tracer parses that stream into loader events and
// captures bounded tails of stdout/stderr for rules to quote as evidence.
package linux

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"why/internal/evidence"
)

// Capture bounds for each target stream. A stream keeps at most maxStreamLines
// lines and maxStreamBytes bytes; when more arrives the oldest lines are
// dropped and the Output event's Truncated flag is set.
const (
	maxStreamLines = 200
	maxStreamBytes = 64 << 10 // 64 KiB
)

// Tracer runs a target process with its dynamic-loader activity traced and
// records the resulting evidence events.
type Tracer struct {
	mu     sync.Mutex
	target string
	cmd    *exec.Cmd
	stop   bool
	events []evidence.Event

	stdoutR, stdoutW *os.File
	stderrR, stderrW *os.File
	stdout, stderr   *stream
}

// New builds a tracer for target. The command runs with LD_DEBUG=libs forced
// in its environment and its stdout/stderr piped into bounded capture tails.
func New(target string, args ...string) (*Tracer, error) {
	if target == "" {
		return nil, errors.New("linux: empty target")
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("linux: stdout pipe: %w", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		outR.Close()
		outW.Close()
		return nil, fmt.Errorf("linux: stderr pipe: %w", err)
	}
	cmd := exec.Command(target, args...)
	cmd.Env = ldDebugEnv()
	cmd.Stdin = nil
	cmd.Stdout = outW
	cmd.Stderr = errW
	return &Tracer{
		target:  target,
		cmd:     cmd,
		stdoutR: outR, stdoutW: outW,
		stderrR: errR, stderrW: errW,
		stdout: &stream{},
		stderr: &stream{},
	}, nil
}

// Run executes the target, blocking until it exits or tracing fails. A target
// that fails to start is recorded as a StartFailed event and Run returns nil
// (a diagnosable outcome, not a tracer failure). A tracer failure records a
// LoaderError event and returns the error.
func (t *Tracer) Run() error {
	var wg sync.WaitGroup
	wg.Add(2)
	go capture(t.stdoutR, t.stdout, &wg)
	go capture(t.stderrR, t.stderr, &wg)

	t.mu.Lock()
	startErr := t.cmd.Start()
	t.mu.Unlock()
	if startErr != nil {
		// The child never started, so closing the write ends unblocks the
		// readers with EOF.
		t.stdoutW.Close()
		t.stderrW.Close()
		wg.Wait()
		t.stdoutR.Close()
		t.stderrR.Close()
		return t.startFailed(startErr)
	}

	t.record(evidence.ProcessStart{Common: common(evidence.EventProcessStart)})

	// The parent's copies of the write ends must close or the readers never
	// see EOF; the child holds its own duplicates.
	t.stdoutW.Close()
	t.stderrW.Close()

	waitErr := t.cmd.Wait()
	wg.Wait()
	t.stdoutR.Close()
	t.stderrR.Close()

	// Event order is pinned by the tracer contract: ProcessStart, then loader
	// events in parse order, then Exit, then Output events.
	for _, e := range parseLoaderStderr(t.target, t.stderr.snapshot()) {
		t.record(e)
	}
	if waitErr != nil {
		ev, ok := exitEvent(waitErr)
		if !ok {
			t.record(evidence.LoaderError{Common: common(evidence.EventLoaderError), Path: t.target, Message: waitErr.Error()})
			return waitErr
		}
		t.record(ev)
	} else {
		t.record(evidence.Exit{Common: common(evidence.EventExit)})
	}
	t.record(evidence.Output{Common: common(evidence.EventOutput), Stream: "stdout", Lines: t.stdout.snapshot(), Truncated: t.stdout.wasTruncated()})
	t.record(evidence.Output{Common: common(evidence.EventOutput), Stream: "stderr", Lines: t.stderr.snapshot(), Truncated: t.stderr.wasTruncated()})
	return nil
}

// Stop requests termination of a running trace: it sets the stop flag and
// kills the target process if it is running. Safe to call from another
// goroutine; Run then observes the kill as a normal signaled Exit event.
func (t *Tracer) Stop() {
	t.mu.Lock()
	t.stop = true
	proc := t.cmd.Process
	t.mu.Unlock()
	if proc != nil {
		// The process may already have exited; that is not an error here.
		_ = proc.Kill()
	}
}

// Events returns a snapshot of the events collected so far, in order.
func (t *Tracer) Events() []evidence.Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]evidence.Event, len(t.events))
	copy(out, t.events)
	return out
}

// startFailed records the outcome of a failed Start. Errors identifying a
// target-side problem (missing file, permission denied, wrong format, ...)
// become a StartFailed event and nil is returned; any other error is a tracer
// failure, recorded as a LoaderError and returned.
func (t *Tracer) startFailed(err error) error {
	code, ok := startErrno(err)
	if !ok {
		t.record(evidence.LoaderError{Common: common(evidence.EventLoaderError), Path: t.target, Message: err.Error()})
		return err
	}
	t.record(evidence.StartFailed{Common: common(evidence.EventStartFailed), ErrorCode: code, Message: err.Error()})
	return nil
}

// exitEvent converts a Wait error into an Exit event. ok is false when the
// error is not an *exec.ExitError, i.e. a tracing failure rather than a
// target exit.
func exitEvent(err error) (evidence.Event, bool) {
	if err == nil {
		return evidence.Exit{Common: common(evidence.EventExit)}, true
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return nil, false
	}
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return evidence.Exit{Common: common(evidence.EventExit), Signal: int(ws.Signal())}, true
	}
	return evidence.Exit{Common: common(evidence.EventExit), ExitCode: uint32(ee.ExitCode())}, true
}

// startErrno reports the StartFailed error code for a Start error and whether
// the error identifies a target-side failure. The listed error kinds are the
// classic target-side start failures; errno-less variants (an executable not
// found in PATH) map to ENOENT (2).
func startErrno(err error) (uint32, bool) {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errnoCode(errno), true
	}
	switch {
	case errors.As(err, new(*exec.Error)),
		errors.As(err, new(*os.PathError)),
		errors.As(err, new(*exec.ExitError)):
		return 2, true
	}
	return 0, false
}

// errnoCode maps a start-time syscall errno to the StartFailed error code.
func errnoCode(errno syscall.Errno) uint32 {
	switch errno {
	case syscall.ENOENT:
		return 2
	case syscall.EACCES:
		return 13
	case syscall.ENOEXEC:
		return 8
	case syscall.ENOTDIR:
		return 20
	case syscall.ELOOP:
		return 40
	case syscall.EISDIR:
		return 21
	case syscall.ETXTBSY:
		return 26
	default:
		return uint32(errno)
	}
}

// ldDebugEnv returns os.Environ() with any LD_DEBUG entry replaced by
// LD_DEBUG=libs.
func ldDebugEnv() []string {
	env := os.Environ()
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if strings.HasPrefix(kv, "LD_DEBUG=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "LD_DEBUG=libs")
}

func (t *Tracer) record(e evidence.Event) {
	t.mu.Lock()
	t.events = append(t.events, e)
	t.mu.Unlock()
}

func common(kind evidence.EventType) evidence.Common {
	return evidence.Common{Kind: kind, Time: time.Now(), Src: evidence.SourceTrace}
}

// stream is a bounded, line-oriented capture of one target stream.
type stream struct {
	mu        sync.Mutex
	lines     []string
	bytes     int
	truncated bool
}

// add appends one line, dropping the oldest while either capture bound is
// exceeded.
func (s *stream) add(line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, line)
	s.bytes += len(line)
	for len(s.lines) > 1 && (len(s.lines) > maxStreamLines || s.bytes > maxStreamBytes) {
		dropped := s.lines[0]
		s.lines = s.lines[1:]
		s.bytes -= len(dropped)
		s.truncated = true
	}
}

func (s *stream) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func (s *stream) wasTruncated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.truncated
}

// capture reads r line by line into s until EOF.
func capture(r io.Reader, s *stream, wg *sync.WaitGroup) {
	defer wg.Done()
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			s.add(strings.TrimSuffix(line, "\n"))
		}
		if err != nil {
			return
		}
	}
}

// parseLoaderStderr converts the captured stderr tail into loader events.
//
// glibc LD_DEBUG=libs reports each library search as a "find library=" line
// followed by "trying file=" attempts and, on success, "calling init:". A
// search that never reaches "calling init:" — superseded by the next find or
// left open at end of input — failed and becomes a SearchFailed. musl has no
// LD_DEBUG support and reports failures as a single "Error loading shared
// library ..." line, handled by the generic "not found" / "Error loading
// shared library" rule below.
func parseLoaderStderr(target string, lines []string) []evidence.Event {
	var events []evidence.Event
	var lib string
	var tried []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "not found") || strings.Contains(trimmed, "Error loading shared library") {
			events = append(events, evidence.LoaderError{
				Common:  common(evidence.EventLoaderError),
				Path:    target,
				Message: trimmed,
			})
			continue
		}

		switch {
		case strings.Contains(trimmed, "find library="):
			if lib != "" {
				events = append(events, evidence.SearchFailed{
					Common:      common(evidence.EventSearchFailed),
					Library:     lib,
					SearchPaths: tried,
				})
			}
			lib, tried = libraryName(trimmed), nil
		case strings.Contains(trimmed, "trying file="):
			if lib != "" {
				tried = append(tried, strings.TrimSpace(strings.TrimPrefix(trimmed, "trying file=")))
			}
		case strings.Contains(trimmed, "calling init:"):
			events = append(events, evidence.ModuleLoaded{
				Common: common(evidence.EventModuleLoaded),
				Path:   strings.TrimSpace(strings.TrimPrefix(trimmed, "calling init:")),
				Found:  true,
			})
			lib, tried = "", nil
		}
		// "search path=" lines and anything unrecognized are ignored.
	}
	if lib != "" {
		events = append(events, evidence.SearchFailed{
			Common:      common(evidence.EventSearchFailed),
			Library:     lib,
			SearchPaths: tried,
		})
	}
	return events
}

// libraryName extracts the library name from a "find library=" line such as
// "find library=libc.so.6 [0]; searching".
func libraryName(line string) string {
	rest := strings.TrimPrefix(strings.TrimSpace(line), "find library=")
	if i := strings.Index(rest, " ["); i >= 0 {
		rest = rest[:i]
	} else if i := strings.Index(rest, ";"); i >= 0 {
		rest = rest[:i]
	}
	return strings.TrimSpace(rest)
}
