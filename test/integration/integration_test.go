// Package integration builds the `why` CLI and runs it end-to-end against
// the golden fixtures, asserting exit codes and the JSON diagnosis rules.
// It is the cross-platform acceptance suite: the Windows cases run on
// windows-latest, the Linux cases on ubuntu-latest (see CI).
package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// whyBin is the built CLI path, produced by TestMain.
var whyBin string

// fixtures is test/fixtures/bin relative to this package.
var fixtures string

// TestMain builds the CLI once for all integration tests.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "why-integration-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	whyBin = filepath.Join(dir, "why")
	if os.PathSeparator == '\\' {
		whyBin += ".exe"
	}

	repo := filepath.Join("..", "..")
	cmd := exec.Command("go", "build", "-o", whyBin, "./cmd/why")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		panic("build why: " + err.Error() + ": " + string(out))
	}
	fixtures, _ = filepath.Abs(filepath.Join("..", "fixtures", "bin"))
	os.Exit(m.Run())
}

// why runs the CLI with the given arguments and returns stdout and the exit
// code. The why binary is run from the fixtures directory so relative-target
// behavior (cwd-check) is deterministic.
func why(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(whyBin, args...)
	cmd.Dir = fixtures
	out, err := cmd.Output()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if isExit(err, &ee) {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run why %v: %v", args, err)
		}
	}
	return string(out), code
}

func isExit(err error, ee **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*ee = e
	}
	return ok
}

// diagnosis is the minimal JSON shape we assert on.
type diagnosis struct {
	Rule string `json:"rule"`
}

// jsonDiag is the --json report shape.
type jsonDiag struct {
	Diagnoses []diagnosis `json:"diagnoses"`
	Unknown   bool        `json:"unknown"`
}

// runJSON runs `why run --json <target> <args...>` and returns the parsed
// report plus the exit code.
func runJSON(t *testing.T, target string, args ...string) (jsonDiag, int) {
	t.Helper()
	all := append([]string{"run", "--json", target}, args...)
	out, code := why(t, all...)
	var d jsonDiag
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("run --json %s: invalid JSON: %v\n%s", target, err, out)
	}
	return d, code
}

// expectRule asserts that the run exited 2 and produced a diagnosis for rule.
func expectRule(t *testing.T, target string, rule string, args ...string) {
	t.Helper()
	d, code := runJSON(t, target, args...)
	if code != 2 {
		t.Errorf("run %s: exit code = %d, want 2 (diagnosis emitted)", target, code)
	}
	for _, dg := range d.Diagnoses {
		if dg.Rule == rule {
			return
		}
	}
	t.Errorf("run %s: no diagnosis %q; got %+v", target, rule, d.Diagnoses)
}

// expectNoDiagnosis asserts that the run exited 0 with CAUSE UNKNOWN.
func expectNoDiagnosis(t *testing.T, target string) {
	t.Helper()
	d, code := runJSON(t, target)
	if code != 0 {
		t.Errorf("run %s: exit code = %d, want 0 (no diagnosis)", target, code)
	}
	if !d.Unknown {
		t.Errorf("run %s: unknown = false, want true (no diagnosis)", target)
	}
}
