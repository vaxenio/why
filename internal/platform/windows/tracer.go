//go:build windows

// Package windows implements the Windows debugger-mode tracer. It spawns the
// target with DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS and drives the Win32
// debug API directly (WaitForDebugEvent / ContinueDebugEvent), recording
// LOAD_DLL_DEBUG_EVENTs and the final EXIT_PROCESS exit code. It never hooks
// the loader (the v0.2 LdrLoadDll seam is documented in internal/trace) and
// never injects into the target.
package windows

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"why/internal/evidence"
	"why/internal/trace"
)

// Compile-time assertion: *Tracer satisfies trace.Tracer.
var _ trace.Tracer = (*Tracer)(nil)

// Win32 debug-event codes.
const (
	createProcessDebugEvent = 3
	loadDLLDebugEvent       = 6
	exitProcessDebugEvent   = 5
	exceptionDebugEvent     = 1
)

// ContinueDebugEvent statuses.
const (
	dbgContinue            = 0x00010002
	dbgExceptionNotHandled = 0x80010001
)

// Win32 debug APIs not present in x/sys/windows are bound lazily here. They
// are plain system calls, not magic.
var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procWaitForDebugEvent  = kernel32.NewProc("WaitForDebugEvent")
	procContinueDebugEvent = kernel32.NewProc("ContinueDebugEvent")
	procReadProcessMemory  = kernel32.NewProc("ReadProcessMemory")
	procIsWow64Process     = kernel32.NewProc("IsWow64Process")
	procGetExitCodeProcess = kernel32.NewProc("GetExitCodeProcess")
)

// errInvalidHandle is ERROR_INVALID_HANDLE, which WaitForDebugEvent returns
// when the debug session has already ended because the debuggee terminated.
const errInvalidHandle = 6

// waitTimeout is ERROR_SEM_TIMEOUT (121), which WaitForDebugEvent returns
// when no event arrives within the poll window.
const waitTimeout = 121

// waitPoll is the WaitForDebugEvent poll window. A short, finite timeout
// (instead of INFINITE) lets the loop detect a debuggee that exited without
// delivering EXIT_PROCESS — the debuggee-exit race that otherwise hangs or
// errors the session.
const waitPoll = 100

// waitForDebugEvent blocks until a debug event or a timeout, returning
// whether an event was delivered and the failure code on failure.
func waitForDebugEvent(ev *debugEvent, timeout uint32) (bool, error) {
	r, _, err := procWaitForDebugEvent.Call(uintptr(unsafe.Pointer(ev)), uintptr(timeout))
	return r != 0, err
}

// continueDebugEvent resumes the debuggee after handling a debug event.
func continueDebugEvent(pid, tid, status uint32) {
	procContinueDebugEvent.Call(uintptr(pid), uintptr(tid), uintptr(status))
}

// win32Code extracts the raw Win32 error code from an error, or 0.
func win32Code(err error) uint32 {
	var errno syscall.Errno
	if err != nil && errors.As(err, &errno) {
		return uint32(errno)
	}
	return 0
}

// debugEvent mirrors DEBUG_EVENT. The U union is sized to its largest member,
// EXCEPTION_DEBUG_INFO (152 bytes on x64, rounded to 160); a larger buffer
// than the kernel writes is always safe.
type debugEvent struct {
	DebugEventCode uint32
	ProcessID      uint32
	ThreadID       uint32
	U              [20]uint64
}

// loadDLLDebugInfo mirrors LOAD_DLL_DEBUG_INFO with natural alignment for
// both 32 and 64-bit.
type loadDLLDebugInfo struct {
	hFile                 uintptr
	lpBaseOfDll           uintptr
	dwDebugInfoFileOffset uint32
	nDebugInfoSize        uint32
	lpImageName           uintptr
	fUnicode              uint16
}

// createProcessDebugInfo mirrors CREATE_PROCESS_DEBUG_INFO.
type createProcessDebugInfo struct {
	hFile                 uintptr
	hProcess              uintptr
	hThread               uintptr
	lpBaseOfImage         uintptr
	dwDebugInfoFileOffset uint32
	nDebugInfoSize        uint32
	lpThreadLocalBase     uintptr
	lpStartAddress        uintptr
	lpImageName           uintptr
	fUnicode              uint16
}

// streamBuf holds the bounded tail of one captured output stream.
type streamBuf struct {
	mu        sync.Mutex
	lines     []string
	truncated bool
	bytes     int
}

const (
	maxOutLines = 200
	maxOutBytes = 64 * 1024
)

// write appends raw bytes, keeping at most maxOutLines / maxOutBytes of the
// tail. Earlier lines are dropped and the truncated flag set.
func (b *streamBuf) write(p []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Split on \n, handling a trailing partial line by carrying it.
	text := string(p)
	start := 0
	for {
		i := strings.IndexByte(text[start:], '\n')
		if i < 0 {
			if rest := text[start:]; rest != "" {
				b.push(rest)
			}
			return
		}
		line := text[start : start+i]
		start += i + 1
		if line != "" {
			b.push(line)
		}
	}
}

func (b *streamBuf) push(line string) {
	b.lines = append(b.lines, line)
	b.bytes += len(line)
	for b.bytes > maxOutBytes || len(b.lines) > maxOutLines {
		dropped := b.lines[0]
		b.lines = b.lines[1:]
		b.bytes -= len(dropped)
		b.truncated = true
	}
}

// snapshot returns the captured lines and truncated flag.
func (b *streamBuf) snapshot() ([]string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.lines...), b.truncated
}

// Tracer is the Windows debugger-mode tracer.
type Tracer struct {
	target string
	args   []string

	mu     sync.Mutex
	events []evidence.Event
	proc   windows.Handle // child process handle for Stop/name reads

	stdout *streamBuf
	stderr *streamBuf
}

// New returns a Tracer for target. The target is not started until Run.
func New(target string, args ...string) (*Tracer, error) {
	return &Tracer{
		target: target,
		args:   args,
		stdout: &streamBuf{},
		stderr: &streamBuf{},
	}, nil
}

// add appends an event under the lock.
func (t *Tracer) add(e evidence.Event) {
	t.mu.Lock()
	t.events = append(t.events, e)
	t.mu.Unlock()
}

// Events returns a snapshot of the collected events in order.
func (t *Tracer) Events() []evidence.Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]evidence.Event(nil), t.events...)
}

// Run executes the target under the debugger, blocking until it exits.
//
// Attaching a debugger to a freshly created process is racy on Windows:
// when debuggees are created back-to-back (e.g. `why run` in a loop, or
// integration tests), the first WaitForDebugEvent can transiently fail to
// receive the queued CREATE_PROCESS event, leaving the target suspended and
// the session dead. Run retries the whole trace on that attach failure so
// the caller sees a complete run instead of a spurious error.
func (t *Tracer) Run() error {
	const attempts = 3
	var lastErr error
	for i := range attempts {
		if i > 0 {
			// Give the previous debug session's port time to release.
			// Attach failures cluster: a failed attempt means the system is
			// mid-teardown, so back off increasingly.
			time.Sleep(time.Duration(i) * 300 * time.Millisecond)
		}
		err := t.runOnce()
		if err == nil {
			return nil
		}
		if !errors.Is(err, errAttachFailed) {
			return err
		}
		lastErr = err
	}
	return lastErr
}

// errAttachFailed marks a trace attempt that never attached to the target
// (no debug event was ever delivered); it is retried by Run.
var errAttachFailed = errors.New("trace: failed to attach debugger to target")

// runOnce is one trace attempt: create the process, run the debug loop, and
// return the result. An attempt that never receives a debug event returns
// errAttachFailed after cleaning up; Run retries it.
func (t *Tracer) runOnce() error {
	// Each attempt is a fresh trace: a failed attempt's partial events and
	// captured streams must not leak into the retry or the result.
	t.mu.Lock()
	t.events = nil
	t.stdout = &streamBuf{}
	t.stderr = &streamBuf{}
	t.proc = 0
	t.mu.Unlock()

	outR, outW, err := os.Pipe()
	if err != nil {
		return t.tracerFail("create stdout pipe: " + err.Error())
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		return t.tracerFail("create stderr pipe: " + err.Error())
	}

	si := new(windows.StartupInfo)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags |= windows.STARTF_USESTDHANDLES
	si.StdOutput = windows.Handle(outW.Fd())
	si.StdErr = windows.Handle(errW.Fd())
	if devnull, e := os.Open(os.DevNull); e == nil {
		defer devnull.Close()
		si.StdInput = windows.Handle(devnull.Fd())
	}

	cmdline, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{t.target}, t.args...)))
	if err != nil {
		return t.tracerFail("build command line: " + err.Error())
	}

	var pi windows.ProcessInformation
	creationFlags := uint32(windows.DEBUG_PROCESS | windows.DEBUG_ONLY_THIS_PROCESS |
		windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_PROCESS_GROUP)
	err = windows.CreateProcess(nil, cmdline, nil, nil, true, creationFlags, nil, nil, si, &pi)
	if err != nil {
		t.add(evidence.StartFailed{
			Common:    common(evidence.EventStartFailed, evidence.SourceCLI),
			ErrorCode: win32Code(err),
			Message:   err.Error(),
		})
		return nil // target-side failure, not a tracer failure
	}
	// The child inherited its own copies of the write ends; close ours so the
	// capture goroutines see EOF when the child exits.
	outW.Close()
	errW.Close()
	windows.CloseHandle(pi.Thread)

	t.mu.Lock()
	t.proc = pi.Process
	t.mu.Unlock()
	t.add(evidence.ProcessStart{Common: common(evidence.EventProcessStart, evidence.SourceTrace)})

	outDone := make(chan struct{})
	errDone := make(chan struct{})
	go copyStream(outR, t.stdout, outDone)
	go copyStream(errR, t.stderr, errDone)

	// complete ends a trace attempt: ensure the child is dead (so the capture
	// goroutines reach EOF and the output is complete), append the Output
	// events, release the process handle, and return ret.
	complete := func(ret error) error {
		windows.TerminateProcess(pi.Process, 1)
		drainAndClose(outDone, outR)
		drainAndClose(errDone, errR)
		t.finalizeOutputs()
		windows.CloseHandle(pi.Process)
		t.mu.Lock()
		t.proc = 0
		t.mu.Unlock()
		return ret
	}
	defer func() {
		// Safety for every return path. TerminateProcess first so the child's
		// write ends close and the capture goroutines reach EOF; only then is
		// it safe to close the read ends. Closing a read end while a Read is
		// pending can deadlock or crash the Go runtime on Windows, so if the
		// child refuses to die, leak the goroutine and the file instead of
		// closing (the process is doomed anyway).
		windows.TerminateProcess(pi.Process, 1)
		drainAndClose(outDone, outR)
		drainAndClose(errDone, errR)
		windows.CloseHandle(pi.Process)
		t.mu.Lock()
		t.proc = 0
		t.mu.Unlock()
	}()

	wow64 := false
	var de debugEvent
	seenCreate := false
	polls := 0
	for {
		ok, werr := waitForDebugEvent(&de, waitPoll)
		if ok {
			polls = 0
			switch de.DebugEventCode {
			case createProcessDebugEvent:
				seenCreate = true
				info := (*createProcessDebugInfo)(unsafe.Pointer(&de.U))
				closeHandle(info.hFile)
				closeHandle(info.hProcess)
				closeHandle(info.hThread)
				wow64 = t.isWow64(pi.Process)
			case loadDLLDebugEvent:
				info := (*loadDLLDebugInfo)(unsafe.Pointer(&de.U))
				closeHandle(info.hFile)
				if name := t.readModuleName(pi.Process, wow64, info); name != "" {
					t.add(evidence.ModuleLoaded{Common: common(evidence.EventModuleLoaded, evidence.SourceTrace),
						Path: name, Found: true})
				}
			case exitProcessDebugEvent:
				code := *(*uint32)(unsafe.Pointer(&de.U))
				t.add(evidence.Exit{Common: common(evidence.EventExit, evidence.SourceTrace),
					ExitCode: code, Signal: 0})
				continueDebugEvent(de.ProcessID, de.ThreadID, dbgContinue)
				return complete(nil)
			case exceptionDebugEvent:
				// Continue the initial loader breakpoint; let every other
				// first-chance exception reach the target (its exit status
				// carries the crash we diagnose).
				var status uint32 = dbgExceptionNotHandled
				if isBreakpoint(*(*uint32)(unsafe.Pointer(&de.U))) {
					status = dbgContinue
				}
				continueDebugEvent(de.ProcessID, de.ThreadID, status)
				continue
			default:
				continueDebugEvent(de.ProcessID, de.ThreadID, dbgContinue)
				continue
			}
			continueDebugEvent(de.ProcessID, de.ThreadID, dbgContinue)
			continue
		}

		// No event within the poll window: either a timeout or a real
		// failure. The debuggee-exit race means a terminated process may
		// deliver no EXIT_PROCESS, so a missing/invalid session or a dead
		// process is a completed trace, not a tracer failure — unless the
		// process is stuck (the debugger never attached).
		code := win32Code(werr)
		switch {
		case code == waitTimeout:
			polls++
			if !seenCreate && polls > 10 {
				// No debug event within ~1s of creation: the debugger never
				// attached (a known race when debuggees are created
				// back-to-back). The target is suspended at the loader
				// breakpoint; kill it and let Run retry.
				windows.TerminateProcess(pi.Process, 1)
				t.add(evidence.LoaderError{Common: common(evidence.EventLoaderError, evidence.SourceTrace),
					Path: t.target, Message: "debugger did not attach; retrying"})
				return complete(errAttachFailed)
			}
			if polls > 50 {
				// No progress for ~5s even though the process was created:
				// the debug session stalled (rare). Kill the target and let
				// Run retry rather than surface a spurious error.
				windows.TerminateProcess(pi.Process, 1)
				t.add(evidence.LoaderError{Common: common(evidence.EventLoaderError, evidence.SourceTrace),
					Path: t.target, Message: "debug session stalled; retrying"})
				return complete(errAttachFailed)
			}
			if t.processGone(pi.Process) {
				t.add(evidence.Exit{Common: common(evidence.EventExit, evidence.SourceTrace),
					ExitCode: t.exitCode(pi.Process), Signal: 0})
				return complete(nil)
			}
			continue // still running: keep waiting
		case code == errInvalidHandle:
			// The debuggee terminated before we drained its events. If it
			// really exited, GetExitCodeProcess yields its code; if it is
			// stuck at the loader breakpoint (attach race), it stays
			// STILL_ACTIVE and this attempt must be retried.
			ex, alive := t.exitState(pi.Process)
			if alive {
				windows.TerminateProcess(pi.Process, 1)
				t.add(evidence.LoaderError{Common: common(evidence.EventLoaderError, evidence.SourceTrace),
					Path: t.target, Message: "debugger did not attach; retrying"})
				return complete(errAttachFailed)
			}
			t.add(evidence.Exit{Common: common(evidence.EventExit, evidence.SourceTrace),
				ExitCode: ex, Signal: 0})
			return complete(nil)
		default:
			// Unexpected WaitForDebugEvent failure. The child may still be
			// alive; kill it so the defer's pipe cleanup does not deadlock.
			windows.TerminateProcess(pi.Process, 1)
			t.add(evidence.LoaderError{Common: common(evidence.EventLoaderError, evidence.SourceTrace),
				Path: t.target, Message: "debug session failed: " + winErr(code)})
			return complete(t.tracerFail(fmt.Sprintf("WaitForDebugEvent failed: %s", winErr(code))))
		}
	}
}

// isBreakpoint reports whether an exception code is a loader/entry
// breakpoint that the debugger must continue as handled.
func isBreakpoint(code uint32) bool {
	return code == 0x80000003 || code == 0x4000001F
}

// processGone reports whether the debuggee process has exited (GetExitCodeProcess
// no longer returns STILL_ACTIVE).
func (t *Tracer) processGone(proc windows.Handle) bool {
	var code uint32
	r, _, _ := procGetExitCodeProcess.Call(uintptr(proc), uintptr(unsafe.Pointer(&code)))
	if r == 0 {
		return true // cannot query: treat as gone
	}
	return code != 259 // STILL_ACTIVE
}

// Stop requests termination of the traced target.
func (t *Tracer) Stop() {
	t.mu.Lock()
	proc := t.proc
	t.mu.Unlock()
	if proc != 0 {
		windows.TerminateProcess(proc, 1)
	}
}

// tracerFail records a LoaderError for the failure and returns an error (the
// tracer-failure contract). The message is reported once via the event and
// once via the returned error.
func (t *Tracer) tracerFail(msg string) error {
	t.add(evidence.LoaderError{Common: common(evidence.EventLoaderError, evidence.SourceTrace),
		Path: t.target, Message: msg})
	return &traceError{msg}
}

// traceError is a why tracer tool failure.
type traceError struct{ msg string }

func (e *traceError) Error() string { return "trace: " + e.msg }

// exitState returns the target's exit code and whether the process is still
// alive (STILL_ACTIVE). A process stuck at the loader breakpoint after a
// failed debugger attach stays STILL_ACTIVE forever; a process that really
// exited yields its exit code within the retry window.
func (t *Tracer) exitState(proc windows.Handle) (uint32, bool) {
	for i := 0; i < 5; i++ {
		var code uint32
		r, _, _ := procGetExitCodeProcess.Call(uintptr(proc), uintptr(unsafe.Pointer(&code)))
		if r != 0 && code != 259 { // STILL_ACTIVE
			return code, false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return 0, true
}

// exitCode returns the target's exit code via GetExitCodeProcess. During the
// process-exit transition GetExitCodeProcess can transiently fail or report
// STILL_ACTIVE, so it is retried briefly before giving up (0).
func (t *Tracer) exitCode(proc windows.Handle) uint32 {
	code, alive := t.exitState(proc)
	if alive {
		return 0
	}
	return code
}

// finalizeOutputs appends the captured stdout/stderr as Output events.
func (t *Tracer) finalizeOutputs() {
	for _, pair := range []struct {
		stream string
		buf    *streamBuf
	}{
		{"stdout", t.stdout},
		{"stderr", t.stderr},
	} {
		lines, truncated := pair.buf.snapshot()
		if len(lines) == 0 {
			continue
		}
		t.add(evidence.Output{Common: common(evidence.EventOutput, evidence.SourceTrace),
			Stream: pair.stream, Lines: lines, Truncated: truncated})
	}
}

// isWow64 reports whether the child is a 32-bit process on a 64-bit host
// (its LOAD_DLL lpImageName is a 32-bit pointer).
func (t *Tracer) isWow64(proc windows.Handle) bool {
	var wow64 bool
	r, _, _ := procIsWow64Process.Call(uintptr(proc), uintptr(unsafe.Pointer(&wow64)))
	return r != 0 && wow64
}

// readModuleName resolves the LOAD_DLL_DEBUG_EVENT image name from the remote
// process's address space.
func (t *Tracer) readModuleName(proc windows.Handle, wow64 bool, info *loadDLLDebugInfo) string {
	if info.lpImageName == 0 {
		return ""
	}
	var namePtr uintptr
	if wow64 {
		var p uint32
		if !t.readMem(proc, info.lpImageName, unsafe.Pointer(&p), 4) {
			return ""
		}
		namePtr = uintptr(p)
	} else {
		if !t.readMem(proc, info.lpImageName, unsafe.Pointer(&namePtr), unsafe.Sizeof(namePtr)) {
			return ""
		}
	}
	if namePtr == 0 {
		return ""
	}
	if info.fUnicode != 0 {
		return t.readUTF16(proc, namePtr)
	}
	return t.readANSI(proc, namePtr)
}

// readMem reads n bytes from addr in the target process.
func (t *Tracer) readMem(proc windows.Handle, addr uintptr, dst unsafe.Pointer, n uintptr) bool {
	var read uintptr
	r, _, _ := procReadProcessMemory.Call(uintptr(proc), addr, uintptr(dst), n, uintptr(unsafe.Pointer(&read)))
	return r != 0 && read == n
}

// readUTF16 reads a NUL-terminated UTF-16 string from the target.
func (t *Tracer) readUTF16(proc windows.Handle, addr uintptr) string {
	var buf [1024]uint16
	ok := t.readMem(proc, addr, unsafe.Pointer(&buf[0]), uintptr(len(buf))*2)
	if !ok {
		return ""
	}
	for i, u := range buf {
		if u == 0 {
			return syscall.UTF16ToString(buf[:i])
		}
	}
	return ""
}

// readANSI reads a NUL-terminated byte string from the target.
func (t *Tracer) readANSI(proc windows.Handle, addr uintptr) string {
	var buf [2048]byte
	ok := t.readMem(proc, addr, unsafe.Pointer(&buf[0]), uintptr(len(buf)))
	if !ok {
		return ""
	}
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return ""
}

// copyStream copies r into b until EOF, then closes done.
func copyStream(r io.Reader, b *streamBuf, done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			b.write(buf[:n])
		}
		if err != nil {
			return
		}
	}
}

// drainAndClose waits for a capture goroutine to finish (EOF), then closes
// its read end. If the goroutine is still blocked in Read after the timeout
// (the child refused to die), the read end is NOT closed: closing it would
// deadlock or crash the Go runtime on Windows, and the goroutine leaks
// instead — acceptable for the pathological stuck-child case.
func drainAndClose(done <-chan struct{}, f *os.File) {
	select {
	case <-done:
		f.Close()
	case <-time.After(2 * time.Second):
	}
}

// closeHandle closes a Win32 handle, ignoring errors (kernel-owned handles
// from debug events may already be invalid).
func closeHandle(h uintptr) {
	if h != 0 {
		windows.CloseHandle(windows.Handle(h))
	}
}

// winErr renders a Win32 error code with its numeric value, so failures are
// always diagnosable.
func winErr(code uint32) string {
	if code == 0 {
		return "error 0"
	}
	return fmt.Sprintf("error %d (%s)", code, syscall.Errno(code).Error())
}

// common builds a schema-1.0 event envelope with the current time.
func common(kind evidence.EventType, src evidence.Source) evidence.Common {
	return evidence.Common{Kind: kind, Time: time.Now(), Src: src}
}
