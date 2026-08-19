//go:build ignore

// Command cwd_check is the source of bin/cwd-check.exe (Windows) and
// bin/cwd-check (Linux): it opens the RELATIVE path why_config.json,
// exercising the working-directory-dependence path:
//
//   - exit 1 with "open why_config.json: <err>" on stderr if the file
//     cannot be opened (the normal case: fixtures run from a directory
//     that has no why_config.json),
//   - exit 0 with "ok" on stdout if the file exists and is readable.
//
// The error text is os.Open's own "open why_config.json: ..." message, so
// the exact stderr line is part of the fixture contract.
//
// Rebuild (pinned toolchain + flags, see README.md):
//
//	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/cwd-check.exe test/fixtures/src/cwd_check.go
//	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/cwd-check test/fixtures/src/cwd_check.go
//
// Committed binaries built 2026-08-19 with go1.26.5 windows/amd64,
// CGO_ENABLED=0; sha256 of each output in test/fixtures/README.md.
package main

import (
	"fmt"
	"os"
)

func main() {
	f, err := os.Open("why_config.json")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	f.Close()
	fmt.Println("ok")
}
