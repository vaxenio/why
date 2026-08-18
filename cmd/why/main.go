// Command why diagnoses why a binary, process, or system is misbehaving.
//
// This is the entry-point stub: it prints usage and exits 1. Subcommand
// dispatch and flag parsing land in a later change.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "why: usage: why <command> [flags] [args]")
	os.Exit(1)
}
