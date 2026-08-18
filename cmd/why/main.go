// Command why diagnoses why a binary, process, or system is misbehaving.
package main

import (
	"fmt"
	"os"
	"strings"
)

// version is the CLI version, defaulting to "dev" and overridden at build time
// via -ldflags "-X main.version=<tag>".
var version = "dev"

const usageText = `why - diagnose why a binary, process, or system is misbehaving

Usage:
  why run [--json] [--rdr <path>] [--] <target> [args...]
  why inspect [--json] [--] <target>
  why doctor [--] <target>
  why report [--json] [--] <target>
  why version

Commands:
  run       Run diagnostics on a target
  inspect   Inspect a target in detail
  doctor    Check the environment for prerequisites
  report    Produce a report on a target
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
		fmt.Println("why " + version)
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

// runRun parses the `run` subcommand's flags and dispatches to the run pipeline.
func runRun(args []string) int {
	jsonOut, rdrPath, rest, err := parseFlags(args, flagJSON|flagRDR)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why: run: %v\n", err)
		return 1
	}
	return runStub(rest, jsonOut, rdrPath)
}

// runInspect parses the `inspect` subcommand's flags and dispatches to the
// inspect pipeline.
func runInspect(args []string) int {
	jsonOut, _, rest, err := parseFlags(args, flagJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why: inspect: %v\n", err)
		return 1
	}
	return inspectStub(rest, jsonOut)
}

// runDoctor parses the `doctor` subcommand's flags (none accepted) and
// dispatches to the doctor pipeline.
func runDoctor(args []string) int {
	_, _, rest, err := parseFlags(args, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why: doctor: %v\n", err)
		return 1
	}
	return doctorStub(rest)
}

// runReport parses the `report` subcommand's flags and dispatches to the
// report pipeline.
func runReport(args []string) int {
	jsonOut, _, rest, err := parseFlags(args, flagJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "why: report: %v\n", err)
		return 1
	}
	return reportStub(rest, jsonOut)
}

// runStub is the placeholder run pipeline: it reports that the subcommand is
// not yet implemented and returns a placeholder exit code. The real pipeline
// and the exit-code contract land in later changes.
func runStub(rest []string, jsonOut bool, rdrPath string) int {
	fmt.Fprintln(os.Stderr, "why: run: not implemented")
	return 0
}

// inspectStub is the placeholder inspect pipeline.
func inspectStub(rest []string, jsonOut bool) int {
	fmt.Fprintln(os.Stderr, "why: inspect: not implemented")
	return 0
}

// doctorStub is the placeholder doctor pipeline.
func doctorStub(rest []string) int {
	fmt.Fprintln(os.Stderr, "why: doctor: not implemented")
	return 0
}

// reportStub is the placeholder report pipeline.
func reportStub(rest []string, jsonOut bool) int {
	fmt.Fprintln(os.Stderr, "why: report: not implemented")
	return 0
}
