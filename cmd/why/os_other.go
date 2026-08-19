//go:build !windows && !linux

package main

import (
	"why/internal/evidence"
	"why/internal/trace"
)

// newTracer reports that v0.1 has no tracer for this GOOS.
func newTracer(target string, args ...string) (trace.Tracer, error) {
	return nil, trace.ErrUnsupportedPlatform
}

// platformChecks returns no platform-specific doctor checks on unsupported
// GOOS.
func platformChecks(env evidence.Env) []check { return nil }
