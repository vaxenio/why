//go:build windows

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunHealthyHello(t *testing.T) {
	expectNoDiagnosis(t, "hello-x64.exe")
}

func TestRunMissingDLL(t *testing.T) {
	expectRule(t, "missing-dll-x64.exe", "missing-dll")
}

func TestRunTruncatedPE(t *testing.T) {
	expectRule(t, "truncated-hello-x64.exe", "invalid-format")
}

// TestRunWrongArchArm64 pins the true architecture-mismatch case: an arm64
// PE cannot run on an amd64 host (unlike the x86 fixture, which runs via
// WOW64).
func TestRunWrongArchArm64(t *testing.T) {
	expectRule(t, "wrong-arch-arm64.exe", "wrong-arch")
}

func TestRunWrongCWD(t *testing.T) {
	expectRule(t, "cwd-check.exe", "wrong-cwd")
}

func TestRunMissingEnvVar(t *testing.T) {
	expectRule(t, "env-check.exe", "missing-env-var")
}

// TestRunEnvVarSet is the negative case for missing-env-var: with the
// variable set, the program succeeds and no diagnosis is emitted.
func TestRunEnvVarSet(t *testing.T) {
	t.Setenv("WHY_TEST_VAR", "present")
	expectNoDiagnosis(t, "env-check.exe")
}

func TestRunPortInUse(t *testing.T) {
	// port-bind binds 127.0.0.1:45679 twice; the second bind must fail.
	expectRule(t, "port-bind.exe", "port-in-use", "45679")
}

func TestRunMissingTargetFile(t *testing.T) {
	_, code := why(t, "run", "does-not-exist.exe")
	if code != 1 {
		t.Errorf("run missing target: exit code = %d, want 1 (tool failure)", code)
	}
}

func TestInspectHealthyHello(t *testing.T) {
	out, code := why(t, "inspect", "hello-x64.exe")
	if code != 0 {
		t.Errorf("inspect exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "kernel32.dll") {
		t.Errorf("inspect output missing kernel32.dll: %s", out)
	}
}

func TestDoctorOK(t *testing.T) {
	out, code := why(t, "doctor")
	if code != 0 {
		t.Errorf("doctor exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "all prerequisites OK") {
		t.Errorf("doctor output missing OK banner: %s", out)
	}
}
func TestOfflineReport(t *testing.T) {
	rdr := filepath.Join(t.TempDir(), "run.rdr")
	if _, code := why(t, "run", "--rdr", rdr, "missing-dll-x64.exe"); code != 2 {
		t.Fatalf("run --rdr exit code = %d, want 2", code)
	}
	if _, err := os.Stat(rdr); err != nil {
		t.Fatalf(".rdr not written: %v", err)
	}
	out, code := why(t, "report", "--json", rdr)
	if code != 2 {
		t.Errorf("offline report exit code = %d, want 2", code)
	}
	var d jsonDiag
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("offline report: invalid JSON: %v\n%s", err, out)
	}
	found := false
	for _, dg := range d.Diagnoses {
		if dg.Rule == "missing-dll" {
			found = true
		}
	}
	if !found {
		t.Errorf("offline report lost the missing-dll diagnosis: %+v", d.Diagnoses)
	}
}
