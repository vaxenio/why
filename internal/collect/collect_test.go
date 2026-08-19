package collect

import (
	"runtime"
	"testing"
)

// TestCollectEnvCommon pins the cross-platform Env fields every host must
// report: identity, working directory, PATH and the PATH variable itself.
func TestCollectEnvCommon(t *testing.T) {
	env := CollectEnv()
	if env.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", env.OS, runtime.GOOS)
	}
	if env.Arch != runtime.GOARCH {
		t.Errorf("Arch = %q, want %q", env.Arch, runtime.GOARCH)
	}
	if env.GoVersion == "" {
		t.Error("GoVersion is empty")
	}
	if env.CWD == "" {
		t.Error("CWD is empty")
	}
	if len(env.Paths) == 0 {
		t.Error("Paths is empty")
	}
	if env.Vars == nil {
		t.Error("Vars is nil")
	}
	if _, ok := env.Vars["PATH"]; !ok {
		t.Error("Vars is missing PATH")
	}
}
