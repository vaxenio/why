//go:build !windows && !linux

package collect

import "why/internal/evidence"

// collectPlatform is a no-op on unsupported GOOS: v0.1 only targets Windows
// and Linux, but the package must still build elsewhere.
func collectPlatform(e *evidence.Env) {}
