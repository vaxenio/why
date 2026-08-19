// Command why diagnoses why a binary, process, or system is misbehaving.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"why/internal/evidence"
)

const usageText = `why - diagnose why a binary, process, or system is misbehaving

Usage:
  why run [--json] [--rdr <path>] [--] <target> [args...]
  why inspect [--json] [--] <target>
  why doctor
  why report [--json] [--] <target-or-.rdr>
  why version

Commands:
  run       Run diagnostics on a target
  inspect   Inspect a target in detail
  doctor    Check the environment for prerequisites
  report    Produce a report on a target (or from a recorded .rdr log)
  version   Print version information
`

func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches to the named subcommand and returns the process exit code.
func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usageText)
		return 1
	}
	switch args[0] {
	case "run":
		return runRun(args[1:])
	case "inspect":
		return runInspect(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "report":
		return runReport(args[1:])
	case "version":
		fmt.Println("why " + evidence.Version)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "why: unknown command %q\n\n%s", args[0], usageText)
		return 1
	}
}

// flagBits selects which flags parseFlags accepts for a subcommand.
type flagBits uint8

const (
	flagJSON flagBits = 1 << iota
	flagRDR
)

// parseFlags scans args for the flags in bits, recognizing them in any
// position: the stdlib flag package stops at the first positional argument,
// silently dropping a trailing --json/--rdr. Everything after a `--` separator
// is returned verbatim in rest. Positional arguments are collected in order; an
// unrecognized flag is an error.
func parseFlags(args []string, bits flagBits) (jsonOut bool, rdrPath string, rest []string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			rest = append(rest, args[i+1:]...)
			return
		case a == "--json":
			if bits&flagJSON == 0 {
				return false, "", nil, fmt.Errorf("unknown flag %q", a)
			}
			jsonOut = true
		case a == "--rdr":
			if bits&flagRDR == 0 {
				return false, "", nil, fmt.Errorf("unknown flag %q", a)
			}
			if i+1 >= len(args) {
				return false, "", nil, fmt.Errorf("--rdr requires a value")
			}
			i++
			rdrPath = args[i]
		case strings.HasPrefix(a, "--rdr="):
			if bits&flagRDR == 0 {
				return false, "", nil, fmt.Errorf("unknown flag %q", a)
			}
			rdrPath = strings.TrimPrefix(a, "--rdr=")
		case strings.HasPrefix(a, "-"):
			return false, "", nil, fmt.Errorf("unknown flag %q", a)
		default:
			rest = append(rest, a)
		}
	}
	return jsonOut, rdrPath, rest, nil
}

// runRun parses the `run` subcommand's flags and dispatches to the run
// pipeline. A completed run maps the diagnosis count to exit 0 or 2; a why
// tool failure exits 1.
func runRun(args []string) int {
	jsonOut, rdrPath, rest, err := parseFlags(args, flagJSON|flagRDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why: run: %v\n", err)
		return 1
	}
	n, err := runPipeline(rest, jsonOut, rdrPath)
	if err != nil {
		return exitCodeOf(err)
	}
	return exitCode(n)
}

// runInspect parses the `inspect` subcommand's flags and dispatches to the
// inspect pipeline.
func runInspect(args []string) int {
	jsonOut, _, rest, err := parseFlags(args, flagJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why: inspect: %v\n", err)
		return 1
	}
	_, err = inspectPipeline(rest, jsonOut)
	return exitCodeOf(err)
}

// runDoctor parses the `doctor` subcommand's flags (none accepted) and
// dispatches to the doctor pipeline.
func runDoctor(args []string) int {
	_, _, rest, err := parseFlags(args, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why: doctor: %v\n", err)
		return 1
	}
	_, err = doctorPipeline(rest)
	return exitCodeOf(err)
}

// runReport parses the `report` subcommand's flags and dispatches to the
// report pipeline.
func runReport(args []string) int {
	jsonOut, _, rest, err := parseFlags(args, flagJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why: report: %v\n", err)
		return 1
	}
	n, err := reportPipeline(rest, jsonOut)
	if err != nil {
		return exitCodeOf(err)
	}
	return exitCode(n)
}

// exitError is a why tool failure: it implements error and carries the
// pinned process exit code. Tool failures — usage errors, a missing target,
// tracer failure, or a .rdr write failure — carry code 1. It is never used
// to carry a diagnosis count or the target child's raw exit code: completed
// runs map through exitCode (0/2), so why's own exit code is always 0/1/2.
type exitError struct {
	code int
	msg  string
}

// Error implements error.
func (e *exitError) Error() string { return e.msg }

// ExitCode returns the pinned exit code this failure maps to: 1 for why
// tool failures.
func (e *exitError) ExitCode() int { return e.code }

// exitCode maps a completed run's diagnosis count to the pinned CLI exit
// code: 0 = report produced with no diagnosis, 2 = at least one diagnosis
// emitted. Why tool failures exit 1 through exitError and never reach this
// function. The target child's raw exit code is never mapped here either: it
// appears only inside the report, keeping why's own exit code 0/1/2.
func exitCode(numDiagnoses int) int {
	if numDiagnoses > 0 {
		return 2
	}
	return 0
}

// exitCodeOf converts a subcommand result into why's pinned exit code: nil
// is 0 (completed run with no diagnosis), *exitError yields its code (1 for
// tool failures), and any other error is also 1. A non-nil error is written
// to stderr so every failure path reports uniformly.
func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	fmt.Fprintln(os.Stderr, err)
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 1
}
