// report.go implements the `why report` command: it re-runs the rule engine
// over a binary (static report) or over a recorded .rdr log (offline report).
package main

import (
	"fmt"
	"os"
	"strings"

	"why/internal/collect"
	"why/internal/diagnose"
	"why/internal/evidence"
	"why/internal/report"
	"why/internal/rules"
)

// reportPipeline produces a report for rest[0]. If rest[0] is a .rdr log the
// report is rebuilt offline from the recorded events; otherwise the target is
// inspected statically (no trace) and analyzed. Returns the diagnosis count
// and a why tool failure for a missing/invalid input.
func reportPipeline(rest []string, jsonOut bool) (int, error) {
	if len(rest) == 0 {
		return 0, &exitError{code: 1, msg: "why: report: missing target"}
	}
	input := rest[0]
	if _, err := os.Stat(input); err != nil {
		return 0, &exitError{code: 1, msg: fmt.Sprintf("why: report: input not found: %s", input)}
	}

	var ev evidence.Evidence
	if events, err := loadRDR(input); err == nil {
		ev = evidence.EvidenceFromEvents(events)
	} else {
		ev = staticReport(input)
	}

	diags := diagnose.NewEngine(rules.All()).Evaluate(&ev)

	if jsonOut {
		if err := report.RenderJSON(os.Stdout, &ev, diags); err != nil {
			return 0, &exitError{code: 1, msg: fmt.Sprintf("why: report: %v", err)}
		}
		return len(diags), nil
	}
	report.RenderHuman(os.Stdout, &ev, diags)
	return len(diags), nil
}

// loadRDR parses input as a .rdr document, returning the events.
func loadRDR(input string) ([]evidence.Event, error) {
	data, err := os.ReadFile(input)
	if err != nil {
		return nil, err
	}
	_, events, err := evidence.UnmarshalEvents(data)
	if err != nil {
		return nil, err
	}
	return events, nil
}

// staticReport builds Evidence for a binary without tracing it: static
// inspection plus the environment snapshot.
func staticReport(target string) evidence.Evidence {
	ev := evidence.Evidence{SourcePath: target, TargetPath: target}
	kind, recognized := sniffKind(target)
	if recognized {
		ev.Kind = kind
		fillGraph(&ev, inspectGraph(target, kind))
	} else if isLikelyRDR(target) {
		ev.Events = append(ev.Events, evidence.LoaderError{
			Common:  evidence.Common{Kind: evidence.EventLoaderError, Time: now(), Src: evidence.SourceInspect},
			Path:    target,
			Message: "input is neither a PE/ELF image nor a valid .rdr log",
		})
	} else {
		ev.Events = append(ev.Events, evidence.LoaderError{
			Common:  evidence.Common{Kind: evidence.EventLoaderError, Time: now(), Src: evidence.SourceInspect},
			Path:    target,
			Message: "not a recognized PE or ELF image",
		})
	}
	ev.Env = collect.CollectEnv()
	return ev
}

// isLikelyRDR reports whether a file begins with a .rdr header line, so a
// broken .rdr is reported as a malformed log rather than an unknown binary.
func isLikelyRDR(target string) bool {
	data, err := os.ReadFile(target)
	if err != nil {
		return false
	}
	head := string(data)
	if len(head) > 256 {
		head = head[:256]
	}
	return strings.Contains(head, `"event_type":"rdr.header"`)
}
