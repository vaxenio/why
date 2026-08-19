# How WHY thinks — trust

WHY is useful only if you can trust both a positive *and* a negative answer.
This document is the contract behind that trust: the reasoning model, the
confidence levels, and exactly what a recorded run contains.

## Facts first. AI second.

WHY's engine is a set of **deterministic rules** that match **observed
evidence**. Nothing is guessed, interpolated, or "AI-inferred".

For every diagnosis, the evidence chain is explicit and printed:

```
CAUSE:    what is wrong
WHY:      how the evidence leads to the cause
EVIDENCE: the observed facts, one per line
LIKELY FIX: an advisory remedy (never an auto-fix)
CONFIDENCE: how strongly the evidence supports the cause
```

The evidence is concrete: a loader error code (`0xC0000135` = missing DLL), a
module missing from the dependency graph, a line the program itself printed.
A rule **cannot** fire without its required evidence.

AI is not part of v0.1 at all. The roadmap's v0.5 is "optional AI
hypotheses" — and even then, hypotheses are layered *on top of* the facts,
never a replacement for them.

## `CAUSE UNKNOWN` instead of a guess

When the collected evidence is insufficient to name a cause, WHY prints:

```
CAUSE UNKNOWN
  WHY: the run completed but no known cause matched the collected evidence.
  FACTS:
    - process exited with code 1
```

This is a **deliberate feature**, not a failure:

- A wrong guess sends you down the wrong path and erodes trust.
- `CAUSE UNKNOWN` is honest: it tells you WHAT was observed so you have a
  starting point.
- It is the single most important signal for WHY's own development: a cause
  that repeatedly shows up as `UNKNOWN` is exactly what gets diagnosed next.

**False positives are worse than `CAUSE UNKNOWN`.** The rules are written so
that if the evidence is ambiguous, WHY stays silent rather than guess.

## Confidence levels

Every diagnosis carries a confidence band, and the band **never exceeds what
the evidence supports**:

| Level | Meaning | Example |
| --- | --- | --- |
| `high` | The evidence is a direct fact. | a loader error code, a missing module in the dependency graph, a start-failure errno |
| `medium` | The evidence is concrete, but the cause attribution involves a documented inference. | an environment variable named as missing by the program's own output |
| `low` | The evidence is the target's own text; the cause is attributed with explicit uncertainty. | "address already in use" (occupied port), a relative file-open failure (wrong working directory) |

Low-confidence diagnoses are still grounded in a real, quoted line of output
— they are never invented. They simply acknowledge that the program's own
message is the primary evidence, and the *cause* is our reading of it.

## What a recorded run (.rdr) contains

`.rdr` is a local JSON-lines log written **only** when you pass `--rdr <path>`
to `why run`. A normal `why run` writes nothing.

A `.rdr` file contains, in order:

1. **Header** — schema version, tool version, host OS, timestamp.
2. **`graph.snapshot`** — the static dependency graph of the target (module
   names, present/missing status, where each dependency resolved from).
3. **`env.snapshot`** — the host environment snapshot: OS/arch/Go version,
   working directory, PATH entries, open listening ports, and runtime-library
   presence. It also contains the **full environment-variable map** (see
   Privacy below).
4. **Trace events** — the ordered runtime events: process start, modules the
   loader resolved, start-failure or exit (with the exit code / signal), and
   the captured tail of the target's stdout/stderr.

The point of a `.rdr` is **offline re-analysis**: `why report run.rdr` rebuilds
the evidence and re-runs the rule engine without the binary or the original
machine. You can keep a recording and re-check it after installing a fix.

### Privacy and offline behavior

- **Fully offline.** WHY never contacts a network. No cloud, no telemetry, no
  "phone home". There is no backend.
- **Nothing written unless you ask.** No `.rdr` is created without `--rdr`.
  Reports go to stdout only.
- **Environment values are never printed.** Reports cite variable *names*
  (e.g. "the program reported `WHY_TEST_VAR` is not set") but never values —
  so secrets in the environment stay out of your screen and your terminal
  history.
- **The full environment map is in `.rdr`** if you choose to record one.
  Treat a `.rdr` like a session recording: keep it local, and don't share it
  casually — it can contain environment secrets alongside the diagnostic
  facts. If you must share a run, prefer `why report <binary>` (static, no
  environment) or redact the `.rdr`.
- **No admin required.** WHY runs as your normal user.

## Principles, in one line each

- Evidence before interpretation.
- `CAUSE UNKNOWN` over a guess.
- Confidence never exceeds evidence.
- Local, offline, and nothing recorded unless you ask.
