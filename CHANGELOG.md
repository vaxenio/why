# Changelog

All notable changes to WHY are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/); this project adheres to
[Semantic Versioning](https://semver.org/).

## [v0.1.0] — 2026-08-19

First public release: WHY RunDoctor.

### Added

- `why run <binary> [args...]` — traces the target and diagnoses why it
  won't start. Human `CAUSE / WHY / EVIDENCE / LIKELY FIX / CONFIDENCE`
  output by default, `--json` for machines, `--rdr <path>` to record a run.
- `why inspect <binary>` — static analysis of a PE/ELF: headers, imports /
  DT_NEEDED, and the resolved dependency graph.
- `why doctor` — checks the host prerequisites WHY needs.
- `why report <binary | run.rdr>` — produces a report from a binary
  (static, no trace) or offline from a recorded `.rdr` log.
- `why version` — prints the stamped version.

### Diagnostics (16 rules, v0.1)

missing-dll, missing-so, missing-vc-runtime, missing-runtime,
missing-interp, wrong-arch, invalid-format, permission-denied,
elevation-required, entry-point-failure, dll-init-failure, path-conflict,
missing-env-var, port-in-use, wrong-cwd, crash.

### Platforms

- Windows x64 (debugger-mode tracer: DEBUG_PROCESS, no injection/hooking).
- Linux x64 (exec + LD_DEBUG=libs, no strace/eBPF/root).

### Trust

- Facts-first engine: rules fire only on collected evidence; CAUSE UNKNOWN
  when evidence is insufficient. No guessing.
- Local and offline: no cloud, no telemetry, no AI. `.rdr` logs are written
  only when `--rdr` is passed; report output never prints environment
  variable values.

### Notes

- Single source of truth for the version: `why/internal/evidence.Version`,
  stamped at build time (`-X why/internal/evidence.Version=v0.1.0`).
- Release artifacts are static binaries (CGO_ENABLED=0); no Go toolchain is
  required to run them.
