//go:build windows

package main

// Import the Windows platform package so `go mod tidy` keeps
// golang.org/x/sys in go.mod. Consumers land in later changes.
import _ "golang.org/x/sys/windows"
