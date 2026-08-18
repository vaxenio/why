//go:build ignore

// Command hello is the source of every "healthy" fixture binary in
// test/fixtures/bin. It is built once per target with the pinned Go
// toolchain and determinism flags (see test/fixtures/README.md):
//
//	# PE (Windows host)
//	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/hello-x64.exe test/fixtures/src/hello.go
//	GOOS=windows GOARCH=386 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/hello-x86.exe test/fixtures/src/hello.go
//	GOOS=windows GOARCH=386 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/wrong-arch.exe test/fixtures/src/hello.go
//
//	# ELF (any host; Go cross-compiles deterministically with CGO_ENABLED=0)
//	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/hello-linux-x86_64 test/fixtures/src/hello.go
//	GOOS=linux GOARCH=386 go build -trimpath -ldflags=-buildid= -buildvcs=false \
//	    -o test/fixtures/bin/wrong-arch-linux test/fixtures/src/hello.go
//
// The committed binaries were built 2026-08-18 with go1.26.5 windows/amd64,
// CGO_ENABLED=0. sha256 of each output is recorded in test/fixtures/README.md.
package main

import "fmt"

func main() {
	fmt.Println("hello from why fixture")
}
