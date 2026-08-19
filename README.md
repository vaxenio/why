# WHY — It doesn't run. Find out why.

WHY is a command-line tool that diagnoses **why a program or binary won't
start on your machine**. You point it at a broken executable, it runs it under
a debugger or tracer, collects hard evidence, and tells you the cause — or
says it doesn't know.

**Facts first. AI second.** WHY works locally and offline. It never guesses:
when the evidence isn't enough, it prints `CAUSE UNKNOWN` instead of making
something up.

## Ten seconds with WHY

```text
$ why run broken.exe
Diagnosis 1: missing DLL
  WHY: the program imports a DLL that does not exist anywhere the Windows loader searches.
  EVIDENCE:
    - the import table references DefinitelyMissing.dll, which was not found in the application directory, System32, CWD or PATH
    - process exited with 0xC0000135 (STATUS_DLL_NOT_FOUND)
  LIKELY FIX: install the DLL alongside the executable, or install the package that provides it.
  CONFIDENCE: high
```

Why — the name says it all. Not *what failed*, not *where to look*. **Why.**

## Why WHY

Running software that doesn't run is a daily ritual: a missing DLL, a 32-bit
binary on a 64-bit machine, a wrong interpreter, a port already in use. The
symptoms are everywhere, and the cause is usually a few concrete facts away —
but finding those facts is tedious. WHY automates it:

- **Deterministic rules over real evidence.** Every diagnosis is grounded in
  something observed: a loader error code, a missing module in the dependency
  graph, a line the program itself printed. No heuristics, no guessing.
- **`CAUSE UNKNOWN` is a feature.** If the evidence isn't sufficient, WHY says
  so. A wrong guess is worse than no answer.
- **Local and offline.** No cloud, no telemetry, no AI. The `.rdr` log is
  written only when you ask for it.

See [How WHY thinks — trust](./docs/TRUST.md) for the full reasoning model.

## Install

No Go toolchain required. Download the release binary for your platform from
the [Releases](https://github.com/vaxenio/why/releases) page, put it on your
`PATH`, and verify:

```sh
# Windows
why version        # -> why v0.1.0
why doctor         # are this machine's prerequisites OK?

# Linux
./why-linux-amd64 version
./why-linux-amd64 doctor
```

| Platform | Artifact |
| --- | --- |
| Windows x64 | `why-v0.1.0-windows-amd64.exe` |
| Linux x64 | `why-v0.1.0-linux-amd64` |
| Checksums | `why-v0.1.0-SHA256SUMS` |

Verify the checksum: `sha256sum -c why-v0.1.0-SHA256SUMS`.

## Four commands

| Command | What it does |
| --- | --- |
| `why run <binary> [args...]` | Runs the target under WHY's tracer and diagnoses why it didn't work. `--json` for machine output, `--rdr <path>` to record the run. |
| `why inspect <binary>` | Static analysis: headers, imports / `DT_NEEDED`, and the resolved dependency graph. Never runs the target. |
| `why doctor` | Checks this machine's prerequisites (OS, working dir, PATH, runtime libraries). |
| `why report <binary | run.rdr>` | Produces a report from a binary (static, no trace) or offline from a recorded `.rdr` log. |

Exit codes: `0` = report produced, no diagnosis; `2` = at least one diagnosis;
`1` = why itself failed (missing target, tracer failure).

## See WHY find the cause

Clone the repo and try it on the bundled broken fixtures (built from
`test/fixtures/src`). No setup beyond a `why` binary.

**Missing DLL** (Windows):

```sh
why run test/fixtures/bin/missing-dll-x64.exe
```

**Architecture mismatch** (Windows; an arm64 binary on an amd64 host):

```sh
why run test/fixtures/bin/wrong-arch-arm64.exe
# -> Diagnosis 1: architecture mismatch  (the binary is arm64; this host runs amd64)  CONFIDENCE: high
```

**Missing shared library** (Linux):

```sh
why run test/fixtures/bin/missing-so
# -> Diagnosis 1: missing shared library  CONFIDENCE: high
```

**Occupied port** (Windows or Linux):

```sh
why run test/fixtures/bin/port-bind.exe 8080   # Windows
why run test/fixtures/bin/port-bind 8080       # Linux
# -> Diagnosis 1: occupied port  CONFIDENCE: low
```

Record a run and re-analyze it later, offline:

```sh
why run --rdr run.rdr test/fixtures/bin/missing-dll-x64.exe
why report run.rdr
```

## How WHY thinks

WHY's whole value is that you can trust a negative answer as much as a
positive one. `docs/TRUST.md` explains:

- **Facts first, AI second** — evidence before interpretation; AI is not part
  of v0.1 at all.
- **`CAUSE UNKNOWN` instead of a guess** — when required evidence is missing,
  WHY says so and lists the facts it did collect.
- **Confidence levels** — every diagnosis carries `low` / `medium` / `high`,
  and the level never exceeds what the evidence supports.
- **`.rdr` contents and privacy** — exactly what a recording contains, that
  it is local, and that environment-variable *values* are never printed in
  reports.

## Platforms

- **Windows x64** — debugger-mode tracer (`DEBUG_PROCESS`, no DLL injection,
  no loader hooking in v0.1).
- **Linux x64** — `exec` + `LD_DEBUG=libs`, no `strace`/eBPF/root.

## Diagnostics (v0.1, 16 rules)

missing-dll · missing-so · missing-vc-runtime · missing-runtime ·
missing-interp · wrong-arch · invalid-format · permission-denied ·
elevation-required · entry-point-failure · dll-init-failure · path-conflict ·
missing-env-var · port-in-use · wrong-cwd · crash

## What v0.1 is not

No GUI. No daemon. No administrator requirement. No kernel driver. No DLL
injection. No auto-fix. No AI dependency. No cloud backend. It only *tells you
why* — fixing is up to you.

## Roadmap

v0.2 is **not** scheduled yet. It will be shaped by real `CAUSE UNKNOWN`
reports from people actually running WHY — not by our guesses about what else
a diagnostic tool needs. If a cause keeps showing up as `UNKNOWN`, that is
exactly what we add next.

- **v0.2** — snapshot/compare + deeper Windows loader tracing.
- **v0.3** — child processes, filesystem and port correlation.
- **v0.4** — community rules/plugins.
- **v0.5** — optional AI hypotheses (still facts-first).
- **v1.0** — a polished Windows/Linux root-cause platform.

## Development

Requires Go 1.26+.

```sh
go build ./... && go vet ./... && go test ./...
./scripts/build.sh v0.1.0    # cross-compile Windows + Linux into dist/
./scripts/release.sh v0.1.0  # build + verify (version, doctor)
```

Releases are cut from a `v*` tag (see `.github/workflows/release.yml`).
See [CHANGELOG.md](./CHANGELOG.md) for the release history.

## License

MIT — see [LICENSE](./LICENSE).
