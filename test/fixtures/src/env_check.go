//go:build ignore

// Command env_check is the source of bin/env-check.exe (Windows) and
// bin/env-check (Linux): it reads the WHY_TEST_VAR environment variable,
// exercising the environment-dependent path:
//
//   - exit 1 with "environment variable WHY_TEST_VAR is not set" on stderr
//     if the variable is unset or empty,
//   - exit 0 with "WHY_TEST_VAR is set to <value>" on stdout otherwise.
//
// Rebuild (pinned toolchain + flags, see README.md):
//
//	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/env-check.exe test/fixtures/src/env_check.go
//	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/env-check test/fixtures/src/env_check.go
//
// Committed binaries built 2026-08-19 with go1.26.5 windows/amd64,
// CGO_ENABLED=0; sha256 of each output in test/fixtures/README.md.
package main

import (
	"fmt"
	"os"
)

func main() {
	v := os.Getenv("WHY_TEST_VAR")
	if v == "" {
		fmt.Fprintln(os.Stderr, "environment variable WHY_TEST_VAR is not set")
		os.Exit(1)
	}
	fmt.Printf("WHY_TEST_VAR is set to %s\n", v)
}
