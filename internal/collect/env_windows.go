//go:build windows

package collect

import (
	"os"
	"path/filepath"

	"why/internal/evidence"
)

// collectPlatform fills the Windows-specific Env fields: listening ports and
// VC++ runtime presence. Display is irrelevant on Windows.
func collectPlatform(e *evidence.Env) {
	e.Ports = windowsPorts()
	e.VCRuntime = windowsVCRuntime()
}

// windowsVCRuntime reports which VC++ runtime DLLs exist in the system
// directory. A missing one is the "missing VC runtime" diagnosis.
func windowsVCRuntime() map[string]bool {
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	sys32 := filepath.Join(sys, "System32")
	runtimes := []string{"vcruntime140.dll", "vcruntime140_1.dll", "msvcp140.dll"}
	out := map[string]bool{}
	for _, dll := range runtimes {
		_, err := os.Stat(filepath.Join(sys32, dll))
		out[dll] = err == nil
	}
	return out
}
