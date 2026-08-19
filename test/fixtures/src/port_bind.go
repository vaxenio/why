//go:build ignore

// Command port_bind is the source of bin/port-bind.exe (Windows) and
// bin/port-bind (Linux): it binds TCP 127.0.0.1:<port> twice with
// net.Listen, exercising the "address already in use" path:
//
//   - exit 3 if no port argument is given,
//   - exit 2 if the FIRST bind fails (port not bindable),
//   - exit 1 if the second bind of the same port does NOT fail with
//     EADDRINUSE (the error text "address already in use" is printed to
//     stderr and the process exits 1),
//   - exit 0 if the second bind correctly fails and the first listener is
//     closed.
//
// The observable contract is the same on both OSes (EADDRINUSE -> the bind
// error is printed to stderr and the process exits 1); the OS-specific
// error text is printed verbatim.
//
// Rebuild (pinned toolchain + flags, see README.md):
//
//	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/port-bind.exe test/fixtures/src/port_bind.go
//	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/port-bind test/fixtures/src/port_bind.go
//
// Committed binaries built 2026-08-19 with go1.26.5 windows/amd64,
// CGO_ENABLED=0; sha256 of each output in test/fixtures/README.md.
package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "port_bind: no port argument")
		os.Exit(3)
	}
	addr := "127.0.0.1:" + os.Args[1]

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "first bind %s: %v\n", addr, err)
		os.Exit(2)
	}
	defer ln.Close()

	second, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	second.Close()
	fmt.Fprintln(os.Stderr, "second bind unexpectedly succeeded")
	os.Exit(1)
}
