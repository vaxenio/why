//go:build linux

package main

import (
	"os"
	"strconv"

	"why/internal/evidence"
	"why/internal/platform/linux"
	"why/internal/trace"
)

// newTracer returns the Linux exec/LD_DEBUG tracer for target.
func newTracer(target string, args ...string) (trace.Tracer, error) {
	return linux.New(target, args...)
}

// platformChecks returns the Linux-specific doctor prerequisites: /proc
// readability and the shared-library presence snapshot.
func platformChecks(env evidence.Env) []check {
	_, procErr := os.ReadDir("/proc")
	out := []check{{"procfs readable", procErr == nil, "/proc"}}
	missing := 0
	for _, present := range env.SharedLibs {
		if !present {
			missing++
		}
	}
	if len(env.SharedLibs) == 0 {
		out = append(out, check{"system libraries", false, "no shared-library snapshot"})
	} else {
		out = append(out, check{"system libraries", missing == 0, "missing " + strconv.Itoa(missing) + " of " + strconv.Itoa(len(env.SharedLibs))})
	}
	return out
}
