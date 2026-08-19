// Package trace defines the Tracer interface implemented by the platform
// tracers (internal/platform/windows, internal/platform/linux) and the
// per-GOOS factory that selects one for the current host.
package trace

import (
	"errors"

	"why/internal/evidence"
)

// ErrUnsupportedPlatform is returned when no tracer exists for the current
// GOOS. It is a typed sentinel so callers can distinguish "no tracer for
// this platform" from a trace-time failure.
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
//
// Run's error semantics are part of the contract: a non-nil error is
// returned ONLY when tracing itself fails (a LoaderError event is recorded
// first). A target that fails to start is NOT a tracing failure — it is a
// diagnosable outcome recorded as a StartFailed event, and Run returns nil
// so the rule engine can diagnose it. This keeps why's exit code distinct:
// a target-side problem yields diagnoses (exit 2), a tracer failure is a why
// tool failure (exit 1).
type Tracer interface {
	// Run executes the target process, blocking until it exits or tracing
	// fails. On a tracer failure it records a LoaderError event and returns
	// a non-nil error; a target that cannot start records a StartFailed
	// event and returns nil.
	Run() error

	// Stop requests termination of a running trace and its target. It is
	// safe to call from another goroutine.
	Stop()

	// Events returns the events collected so far, in chronological order.
	// The returned slice is a snapshot copy; callers must treat it as
	// read-only.
	Events() []evidence.Event
}

// The per-GOOS tracer factory lives in cmd/why (build-tagged os_windows.go /
// os_linux.go), not here, so this package can define the Tracer interface
// without importing the platform implementations (which in turn import the
// interface — a cycle). cmd selects the platform tracer and returns
// ErrUnsupportedPlatform on an unsupported GOOS.
