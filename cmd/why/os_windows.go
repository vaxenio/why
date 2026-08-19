//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strconv"

	"why/internal/evidence"
	"why/internal/platform/windows"
	"why/internal/trace"
)

// newTracer returns the Windows debugger-mode tracer for target.
func newTracer(target string, args ...string) (trace.Tracer, error) {
	return windows.New(target, args...)
}

// platformChecks returns the Windows-specific doctor prerequisites: the
// system directory and the VC++ runtime.
func platformChecks(env evidence.Env) []check {
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	var out []check
	if _, err := os.Stat(filepath.Join(sys, "System32")); err == nil {
		out = append(out, check{"system directory", true, sys + `\System32`})
	} else {
		out = append(out, check{"system directory", false, "missing " + sys + `\System32`})
	}
	missing := 0
	for _, present := range env.VCRuntime {
		if !present {
			missing++
		}
	}
	out = append(out, check{"VC++ runtime", missing == 0, vcDetail(env.VCRuntime)})
	return out
}

func vcDetail(runtime map[string]bool) string {
	if runtime == nil {
		return "no VC runtime snapshot"
	}
	present, total := 0, 0
	for _, p := range runtime {
		total++
		if p {
			present++
		}
	}
	return "present: " + strconv.Itoa(present) + "/" + strconv.Itoa(total)
}
