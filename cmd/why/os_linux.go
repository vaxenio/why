//go:build linux

package main

// Import the Unix platform package so `go mod tidy` keeps
// golang.org/x/sys in go.mod. Consumers land in later changes.
import _ "golang.org/x/sys/unix"
