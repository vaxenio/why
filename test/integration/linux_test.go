//go:build linux

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunHealthyHello(t *testing.T) {
	expectNoDiagnosis(t, "hello-linux-x86_64")
}

func TestRunMissingSO(t *testing.T) {
	expectRule(t, "missing-so", "missing-so")
}

func TestRunBadInterp(t *testing.T) {
	expectRule(t, "bad-interp", "missing-interp")
}

func TestRunMangledELF(t *testing.T) {
	expectRule(t, "mangled-elf-magic", "invalid-format")
}

func TestRunWrongCWD(t *testing.T) {
	expectRule(t, "cwd-check", "wrong-cwd")
}

func TestRunMissingEnvVar(t *testing.T) {
	expectRule(t, "env-check", "missing-env-var")
}

// TestRunEnvVarSet is the negative case for missing-env-var.
func TestRunEnvVarSet(t *testing.T) {
	t.Setenv("WHY_TEST_VAR", "present")
	expectNoDiagnosis(t, "env-check")
}

func TestRunPortInUse(t *testing.T) {
	expectRule(t, "port-bind", "port-in-use", "45680")
}

// TestRunPermissionDenied copies a healthy ELF to a temp file with no
// execute bits; the exec must fail with EACCES and yield permission-denied.
func TestRunPermissionDenied(t *testing.T) {
	src := filepath.Join(fixtures, "hello-linux-x86_64")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dst := filepath.Join(dir, "noexec")
	if err := os.WriteFile(dst, data, 0o000); err != nil {
		t.Fatal(err)
	}
	// The why binary must be able to stat/read it for inspection, but exec
	// fails with EACCES. Run from a directory where the relative path is
	// absolute.
	out, code := why(t, "run", "--json", dst)
	if code != 2 {
		t.Fatalf("run noexec: exit code = %d, want 2; output: %s", code, out)
	}
	if !strings.Contains(out, "permission-denied") {
		t.Errorf("run noexec: missing permission-denied diagnosis: %s", out)
	}
}

func TestRunMissingTargetFile(t *testing.T) {
	_, code := why(t, "run", "does-not-exist")
	if code != 1 {
		t.Errorf("run missing target: exit code = %d, want 1 (tool failure)", code)
	}
}

func TestInspectHealthyHello(t *testing.T) {
	out, code := why(t, "inspect", "hello-linux-x86_64")
	if code != 0 {
		t.Errorf("inspect exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "kind: elf") {
		t.Errorf("inspect output missing elf kind: %s", out)
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
