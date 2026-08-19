// Package collect assembles the evidence.Env snapshot of the current host:
// OS/arch/toolchain identity, working directory, PATH, the full environment,
// open listening ports, and platform library presence. It is the v0.1
// environment collector backing both the run pipeline and doctor.
//
// Privacy: the full environment (including secrets like API keys) is only
// ever written to a .rdr file when the user explicitly passes --rdr. The
// report commands never print environment values, only diagnosis facts.
package collect

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"why/internal/evidence"
)

// CollectEnv returns the current host environment snapshot. Platform-specific
// fields (ports, library presence, display) are filled by the build-tagged
// collectPlatform helper.
func CollectEnv() evidence.Env {
	env := evidence.Env{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		Paths:     filepath.SplitList(os.Getenv("PATH")),
		Vars:      environ(),
	}
	if cwd, err := os.Getwd(); err == nil {
		env.CWD = cwd
	}
	collectPlatform(&env)
	return env
}

// environ snapshots the full process environment as a map, dropping entries
// without a '='.
func environ() map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		env[kv[:i]] = kv[i+1:]
	}
	return env
}
