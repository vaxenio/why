//go:build linux

package collect

import (
	"os"
	"strings"

	"why/internal/evidence"
)

// collectPlatform fills the Linux-specific Env fields: listening ports,
// shared-library presence and the X DISPLAY variable.
func collectPlatform(e *evidence.Env) {
	e.Ports = linuxPorts()
	e.SharedLibs = linuxSharedLibs()
	e.Display = os.Getenv("DISPLAY")
}

// linuxSharedLibs reports whether common system C/C++ runtime libraries are
// present. Locations vary by distro, so a library is "present" if it exists
// in any of the standard directories.
func linuxSharedLibs() map[string]bool {
	dirs := []string{"/lib", "/usr/lib", "/lib64", "/usr/lib64", "/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu"}
	libs := []string{"libc.so.6", "ld-linux-x86-64.so.2", "libstdc++.so.6"}
	out := map[string]bool{}
	for _, lib := range libs {
		present := false
		for _, dir := range dirs {
			if _, err := os.Stat(strings.TrimSuffix(dir, "/") + "/" + lib); err == nil {
				present = true
				break
			}
		}
		out[lib] = present
	}
	return out
}
