package main

import (
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
		{name: "run dispatches", args: []string{"run", "--json", "target"}, stream: "stderr", wantSub: "why: run: not implemented", wantCode: 0},
		{name: "inspect dispatches", args: []string{"inspect", "--json", "target"}, stream: "stderr", wantSub: "why: inspect: not implemented", wantCode: 0},
		{name: "doctor dispatches", args: []string{"doctor"}, stream: "stderr", wantSub: "why: doctor: not implemented", wantCode: 0},
		{name: "report dispatches", args: []string{"report", "--json", "target"}, stream: "stderr", wantSub: "why: report: not implemented", wantCode: 0},
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
			if !strings.Contains(got, tc.wantSub) {
				t.Fatalf("run(%v) %s = %q, want substring %q", tc.args, tc.stream, got, tc.wantSub)
			}
		})
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
