# why test fixtures

Golden PE/ELF binaries used as versioned test inputs by the why test suite
(PE inspector, ELF inspector, `inspect` cmd, Windows/Linux tracers, and the
integration tests). The binaries in `bin/` are **committed on purpose** (the
`.gitignore` un-ignores `test/fixtures/bin/`): they are deterministic,
reproducible fixtures whose exact bytes are part of the test contract.

`test/fixtures/determinism_test.go` guards the contract: it re-builds the
fixtures the **current host** can build and byte-compares them against the
committed goldens, and parse-asserts (magic + header + fixture-specific
shape) the cross-OS fixtures it skips.

## Layout

```
test/fixtures/
├── bin/                     committed fixture binaries (golden, byte-pinned)
├── src/
│   ├── hello.go             source of every "healthy" fixture (PE + ELF)
│   ├── missing_dll.go       source of missing-dll-x64.exe (PE import-table trick)
│   └── generate_elfs.go     synthetic ELF byte-builder (missing-so, bad-interp, musl-hello)
└── determinism_test.go      host-aware rebuild + byte-compare + parse asserts
```

## Fixture inventory

All sha256 hashes are for the committed bytes (2026-08-18).

| Fixture | Format | Size | sha256 | Purpose |
| --- | --- | --- | --- | --- |
| `bin/hello-x64.exe` | PE32+ amd64 | 2457088 | `985289d6…44baf` | healthy x64 PE; imports kernel32.dll only |
| `bin/hello-x86.exe` | PE32 i386 | 2309120 | `52055f6e…410cf` | healthy 32-bit PE (same source, GOARCH=386) |
| `bin/wrong-arch.exe` | PE32 i386 | 2309120 | `52055f6e…410cf` | x86 binary inspected/traced from an x64 context (byte-identical to hello-x86.exe) |
| `bin/missing-dll-x64.exe` | PE32+ amd64 | 2472448 | `666b1492…84e2b` | import table names the absent `DefinitelyMissing.dll` -> loader fails at start (STATUS_DLL_NOT_FOUND) |
| `bin/hello-linux-x86_64` | ELF64 x86-64 | 2392466 | `ad577528…bf26e` | healthy static ELF (no PT_INTERP, no DT_NEEDED) |
| `bin/wrong-arch-linux` | ELF32 i386 | 2231624 | `78b8fdfd…8d63` | 32-bit ELF inspected on an amd64 host |
| `bin/missing-so` | ELF64 x86-64 | 635 | `d1627e6a…42f69` | dynamic ELF: PT_INTERP present, DT_NEEDED `libdefinitelymissing.so.1` (absent) |
| `bin/bad-interp` | ELF64 x86-64 | 620 | `c40d6695…89b04` | PT_INTERP `/nonexistent/ld-linux-why.so` (never present), DT_NEEDED `libc.so.6` |
| `bin/musl-hello` | ELF64 x86-64 | 628 | `8d6574ba…c65a5` | musl-shaped: PT_INTERP `/lib/ld-musl-x86_64.so.1` + DT_NEEDED `libc.musl-x86_64.so.1` |
| `bin/truncated-hello-x64.exe` | PE (broken) | 64 | `7be6712b…cb614` | first 64 bytes of hello-x64.exe (DOS header only, no PE signature) |
| `bin/mangled-elf-magic` | ELF (broken) | 2392466 | `2c4967fa…d2c4a` | hello-linux-x86_64 with byte 0 flipped to 0x00 (magic corrupted) |

The synthetic ELF sonames use the unique `why` suffix so resolution results
are identical on every host (no real lib or `ld.so.cache` can contain them).
`wrong-arch.exe` shares hello-x86.exe's bytes by construction (same source,
same flags) — the two files are intentionally identical; the second name
exists so tracers/inspectors have a distinctly named wrong-arch target.

## Pinned toolchain

Determinism requires the exact toolchain the fixtures were built with
(2026-08-18): **Go 1.26.5** (`go version go1.26.5 windows/amd64`).

## Determinism flags

- **Go**: `-trimpath` (strip host paths), `-ldflags=-buildid=` (zero the
  build ID), `-buildvcs=false` (no VCS stamping), `CGO_ENABLED=0` (static,
  no host libs).
- **Synthetic ELFs**: pure byte-builder (`generate_elfs.go`) — no
  timestamps, build IDs, or paths at all.
- **Malformed fixtures**: committed as static bytes (truncation / magic
  flip are documented in the test).

Go builds are deterministic for the same toolchain + flags regardless of the
building host (CGO_ENABLED=0), so the ELF fixtures cross-compiled on this
Windows host are byte-identical to a rebuild on a Linux host with the same
Go version. The determinism test still only rebuilds ELF on Linux hosts by
design (see below).

## Rebuilding

Exact commands (from the repo root; every build is byte-deterministic):

```sh
export CGO_ENABLED=0
FLAGS="-trimpath -ldflags=-buildid= -buildvcs=false"

# PE fixtures (any host; GOOS=windows)
GOOS=windows GOARCH=amd64 go build $FLAGS -o test/fixtures/bin/hello-x64.exe test/fixtures/src/hello.go
GOOS=windows GOARCH=386  go build $FLAGS -o test/fixtures/bin/hello-x86.exe test/fixtures/src/hello.go
GOOS=windows GOARCH=386  go build $FLAGS -o test/fixtures/bin/wrong-arch.exe test/fixtures/src/hello.go
GOOS=windows GOARCH=amd64 go build $FLAGS -o test/fixtures/bin/missing-dll-x64.exe test/fixtures/src/missing_dll.go

# ELF fixtures (any host; GOOS=linux)
GOOS=linux GOARCH=amd64 go build $FLAGS -o test/fixtures/bin/hello-linux-x86_64 test/fixtures/src/hello.go
GOOS=linux GOARCH=386  go build $FLAGS -o test/fixtures/bin/wrong-arch-linux test/fixtures/src/hello.go

# Synthetic ELFs (any host; byte-builder)
go run ./test/fixtures/src/generate_elfs.go test/fixtures/bin

# Malformed fixtures (from the freshly built goldens)
head -c 64 test/fixtures/bin/hello-x64.exe > test/fixtures/bin/truncated-hello-x64.exe
cp test/fixtures/bin/hello-linux-x86_64 test/fixtures/bin/mangled-elf-magic && printf '\x00' | dd of=test/fixtures/bin/mangled-elf-magic bs=1 seek=0 count=1 conv=notrunc
```

The host-aware gate is `test/fixtures/determinism_test.go`:

- **Windows host**: rebuilds the 4 PE fixtures and byte-compares; skips ELF
  rebuilds with an explicit `t.Log` and parse-asserts the 5 ELF fixtures.
- **Linux host**: rebuilds the 5 ELF fixtures (2 via `go build`, 3 via the
  byte-builder) and byte-compares; skips PE rebuilds with an explicit
  `t.Log` and parse-asserts the PE fixtures.
- **Any host**: malformed fixtures are asserted as static bytes (truncated
  PE must lack the PE signature; mangled ELF must be rejected by
  `debug/elf`).

## Notes

- The PE fixtures import real system DLLs (kernel32) plus fixture-specific
  imports; the inspector resolves them against the host's real search path,
  so results differ slightly between Windows hosts (expected — assertions
  target the fixture's own imports).
- `missing-dll-x64.exe` cannot start (the loader fails on the absent DLL).
  That is the point: the tracer exercises the loader-error path and the
  static inspector sees the missing dependency in the import table. The
  `syscall.NewLazyDLL` call in the source documents the runtime-load
  intent but is never reached in practice.
- `musl-hello` is the synthetic byte-builder shape (musl interpreter path +
  `libc.musl` DT_NEEDED). A real musl-toolchain build is deferred to CI;
  the committed bytes are the deterministic synthetic output, and the
  parse-asserts lock the shape the inspector consumes (PT_INTERP /
  DT_NEEDED).
- Go 1.26's `debug/pe.ImportedLibraries` is a stub returning nil, so the
  determinism test walks the import directory itself
  (`hasPEImport` in determinism_test.go); the why PE inspector likewise
  parses `.idata` directly.
