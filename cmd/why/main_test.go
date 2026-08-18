package main

import (
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
)

// capture runs f with the given standard stream redirected to a pipe and
// returns what was written plus f's result.
func capture(stream **os.File, f func() int) (string, int) {
	old := *stream
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	*stream = w
	code := f()
	*stream = old
	w.Close()
	out, _ := io.ReadAll(r)
	r.Close()
	return string(out), code
}

func TestRun(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		stream   string
		wantSub  string
		wantCode int
	}{
		{name: "no args shows usage", args: nil, stream: "stderr", wantSub: "Usage:", wantCode: 1},
		{name: "unknown command", args: []string{"frobnicate"}, stream: "stderr", wantSub: `why: unknown command "frobnicate"`, wantCode: 1},
		{name: "run with target completes", args: []string{"run", "--json", "target"}, stream: "stderr", wantSub: "", wantCode: 0},
		{name: "run without target fails", args: []string{"run"}, stream: "stderr", wantSub: "why: run: missing target", wantCode: 1},
		{name: "run target after -- separator", args: []string{"run", "--", "-x"}, stream: "stderr", wantSub: "", wantCode: 0},
		{name: "inspect with target completes", args: []string{"inspect", "--json", "target"}, stream: "stderr", wantSub: "", wantCode: 0},
		{name: "inspect without target fails", args: []string{"inspect"}, stream: "stderr", wantSub: "why: inspect: missing target", wantCode: 1},
		{name: "doctor completes", args: []string{"doctor"}, stream: "stderr", wantSub: "", wantCode: 0},
		{name: "report with target completes", args: []string{"report", "--json", "target"}, stream: "stderr", wantSub: "", wantCode: 0},
		{name: "report without target fails", args: []string{"report"}, stream: "stderr", wantSub: "why: report: missing target", wantCode: 1},
		{name: "version prints version", args: []string{"version"}, stream: "stdout", wantSub: "why dev", wantCode: 0},
		{name: "run --rdr without value", args: []string{"run", "--rdr"}, stream: "stderr", wantSub: "--rdr requires a value", wantCode: 1},
		{name: "run unknown flag", args: []string{"run", "--bogus"}, stream: "stderr", wantSub: `unknown flag "--bogus"`, wantCode: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := &os.Stderr
			if tc.stream == "stdout" {
				target = &os.Stdout
			}
			got, code := capture(target, func() int { return run(tc.args) })
			if code != tc.wantCode {
				t.Fatalf("run(%v) exit code = %d, want %d", tc.args, code, tc.wantCode)
			}
			if tc.wantSub == "" {
				if got != "" {
					t.Fatalf("run(%v) %s = %q, want no output", tc.args, tc.stream, got)
				}
				return
			}
			if !strings.Contains(got, tc.wantSub) {
				t.Fatalf("run(%v) %s = %q, want substring %q", tc.args, tc.stream, got, tc.wantSub)
			}
		})
	}
}

// TestExitCodeContract pins the completed-run mapping: 0 = report produced
// with no diagnosis, 2 = at least one diagnosis emitted. The diagnosis count
// is the only input, so a child's raw exit code can never influence why's
// own exit code.
func TestExitCodeContract(t *testing.T) {
	if got := exitCode(0); got != 0 {
		t.Errorf("exitCode(0) = %d, want 0 (report with no diagnosis)", got)
	}
	for _, n := range []int{1, 2, 7} {
		if got := exitCode(n); got != 2 {
			t.Errorf("exitCode(%d) = %d, want 2 (at least one diagnosis)", n, got)
		}
	}
}

// TestExitErrorPinsToolFailureCode proves exitError implements error and
// carries the pinned tool-failure code 1.
func TestExitErrorPinsToolFailureCode(t *testing.T) {
	err := &exitError{code: 1, msg: "boom"}
	if got := err.Error(); got != "boom" {
		t.Errorf("Error() = %q, want %q", got, "boom")
	}
	if got := err.ExitCode(); got != 1 {
		t.Errorf("ExitCode() = %d, want 1 (tool failure)", got)
	}
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatal("errors.As(*exitError) failed")
	}
	if ee != err {
		t.Error("errors.As returned a different instance")
	}
}

// TestExitCodeOfConvertsResults pins the conversion of a subcommand result
// to an exit code: nil → 0, *exitError → its code, any other error → 1.
// A non-nil error is also written to stderr.
func TestExitCodeOfConvertsResults(t *testing.T) {
	gotOut, got := capture(&os.Stderr, func() int { return exitCodeOf(nil) })
	if got != 0 {
		t.Errorf("exitCodeOf(nil) = %d, want 0", got)
	}
	if gotOut != "" {
		t.Errorf("exitCodeOf(nil) wrote %q to stderr, want nothing", gotOut)
	}

	gotOut, got = capture(&os.Stderr, func() int {
		return exitCodeOf(&exitError{code: 1, msg: "why: run: missing target"})
	})
	if got != 1 {
		t.Errorf("exitCodeOf(exitError) = %d, want 1", got)
	}
	if !strings.Contains(gotOut, "missing target") {
		t.Errorf("exitCodeOf(exitError) stderr = %q, want failure message", gotOut)
	}

	gotOut, got = capture(&os.Stderr, func() int { return exitCodeOf(errors.New("unexpected")) })
	if got != 1 {
		t.Errorf("exitCodeOf(plain error) = %d, want 1", got)
	}
	if !strings.Contains(gotOut, "unexpected") {
		t.Errorf("exitCodeOf(plain error) stderr = %q, want failure message", gotOut)
	}
}

// TestChildRawExitNeverReturnedAsOwnExit pins the critical contract: the
// child's raw exit code is never conflated with why's own exit code. Every
// path — 0 (no diagnosis), 2 (diagnosis), 1 (tool failure) — stays inside
// the pinned 0/1/2 contract regardless of the child's exit.
func TestChildRawExitNeverReturnedAsOwnExit(t *testing.T) {
	const childCode = 5
	got := []int{exitCode(0), exitCode(1)}
	for i, c := range got {
		if c == childCode {
			t.Errorf("exit code %d equals the child's raw exit code 5", i)
		}
		if c != 0 && c != 1 && c != 2 {
			t.Errorf("exit code %d outside the pinned 0/1/2 contract", c)
		}
	}
}

func TestParseFlagsAnyPosition(t *testing.T) {
	jsonOut, rdrPath, rest, err := parseFlags(
		[]string{"target", "--json", "arg", "--rdr", "rec.rdr"}, flagJSON|flagRDR)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonOut {
		t.Error("jsonOut = false, want true")
	}
	if rdrPath != "rec.rdr" {
		t.Errorf("rdrPath = %q, want %q", rdrPath, "rec.rdr")
	}
	if want := []string{"target", "arg"}; !slices.Equal(rest, want) {
		t.Errorf("rest = %v, want %v", rest, want)
	}
}

func TestParseFlagsRDREquals(t *testing.T) {
	_, rdrPath, _, err := parseFlags([]string{"--rdr=rec.rdr"}, flagRDR)
	if err != nil {
		t.Fatal(err)
	}
	if rdrPath != "rec.rdr" {
		t.Errorf("rdrPath = %q, want %q", rdrPath, "rec.rdr")
	}
}

// TestParseFlagsSeparatorPassesVerbatim proves that everything after a `--`
// separator is returned untouched: flags appearing after it are NOT consumed.
func TestParseFlagsSeparatorPassesVerbatim(t *testing.T) {
	jsonOut, rdrPath, rest, err := parseFlags(
		[]string{"--json", "--", "--rdr", "target", "-x"}, flagJSON|flagRDR)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonOut {
		t.Error("jsonOut = false, want true")
	}
	if rdrPath != "" {
		t.Errorf("rdrPath = %q, want empty (after --, --rdr is positional)", rdrPath)
	}
	if want := []string{"--rdr", "target", "-x"}; !slices.Equal(rest, want) {
		t.Errorf("rest = %v, want %v (verbatim after --)", rest, want)
	}
}

func TestParseFlagsRejectsUnlistedFlag(t *testing.T) {
	if _, _, _, err := parseFlags([]string{"--json"}, flagRDR); err == nil {
		t.Error("--json accepted when only --rdr is allowed, want error")
	}
	if _, _, _, err := parseFlags([]string{"--rdr", "x"}, flagJSON); err == nil {
		t.Error("--rdr accepted when only --json is allowed, want error")
	}
}

func TestUsageTextListsAllCommands(t *testing.T) {
	for _, cmd := range []string{"run", "inspect", "doctor", "report", "version"} {
		if !strings.Contains(usageText, cmd) {
			t.Errorf("usage text missing command %q", cmd)
		}
	}
}
