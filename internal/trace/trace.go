// Package trace defines the Tracer interface implemented by the platform
// tracers (internal/platform/windows, internal/platform/linux) and the
// per-GOOS factory that selects one for the current host.
package trace

import (
	"errors"
	"runtime"

	"why/internal/evidence"
)

// ErrUnsupportedPlatform is returned by New when the platform tracer for the
// current GOOS is not yet implemented. It is a typed sentinel so callers can
// distinguish "no tracer for this platform" from a trace-time failure.
var ErrUnsupportedPlatform = errors.New("trace: platform tracer not implemented for this GOOS")

// # Seam: Windows LdrLoadDll hooking (v0.2 — NOT implemented in v0.1)
//
// v0.1 traces the target with the debugger API (DEBUG_PROCESS +
// LOAD_DLL_DEBUG_EVENT, see internal/platform/windows) and does NOT hook the
// loader. The v0.2 Windows tracer will observe module resolution inside the
// target process by installing a detour on ntdll's LdrLoadDll before the
// process entry point runs: the target is spawned with CREATE_SUSPENDED, the
// detour is installed early, and the process is resumed. The hook writes
// observations into a shared ring buffer that is drained by the tracer
// goroutine, which maps them to events:
//
//	caller-directed path resolution  -> ModuleLoaded{Found: true}
//	loader search-path fallback      -> ModuleLoaded{Found: false}
//	resolution failed                -> SearchFailed{...} with the search
//	                                    paths tried; the underlying
//	                                    STATUS_DLL_NOT_FOUND is surfaced
//	                                    as LoaderError
//
// The .rdr schema stays at version 1.0: ModuleLoaded, SearchFailed and
// LoaderError already carry every field the hook emits, so hooking is purely
// a backend concern. v0.1 does NOT implement this seam; it is documented here
// to pin the contract the v0.2 backend must satisfy.
//
// Tracer runs a target process and records the ordered sequence of
// diagnostic events produced during execution.
type Tracer interface {
	// Run executes the target process, blocking until it exits. A non-nil
	// error is returned when the process cannot be started (the tracer
	// records a StartFailed event) or when tracing itself fails (a
	// LoaderError event is recorded first).
	Run() error

	// Stop requests termination of a running trace and its target. It is
	// safe to call from another goroutine.
	Stop()

	// Events returns the events collected so far, in chronological order.
	// The returned slice is a snapshot copy; callers must treat it as
	// read-only.
	Events() []evidence.Event
}

// New returns the Tracer for the current host, selected per GOOS. The
// platform tracers land in later waves (internal/platform/windows for
// Windows, internal/platform/linux for Linux); until they do, New returns
// ErrUnsupportedPlatform on every GOOS.
func New() (Tracer, error) {
	switch runtime.GOOS {
	case "windows":
		return newWindows()
	case "linux":
		return newLinux()
	default:
		return nil, ErrUnsupportedPlatform
	}
}

// newWindows returns the Windows tracer. Not implemented until the
// debugger-mode tracer lands (T13).
func newWindows() (Tracer, error) { return nil, ErrUnsupportedPlatform }

// newLinux returns the Linux tracer. Not implemented until the LD_DEBUG
// tracer lands (T15).
func newLinux() (Tracer, error) { return nil, ErrUnsupportedPlatform }
