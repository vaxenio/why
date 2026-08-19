// Package report renders the why report for a run: a human-readable
// multi-line format for terminals and an indented JSON format for
// machines. The human format is byte-stable (LF, no trailing blank line)
// so it is safe to diff and golden-test.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"why/internal/diagnose"
	"why/internal/evidence"
)

// targetPath returns the path of the inspected target: the path that was
// actually run when known, otherwise the source binary that was inspected.
func targetPath(ev *evidence.Evidence) string {
	if ev.TargetPath != "" {
		return ev.TargetPath
	}
	return ev.SourcePath
}

// RenderHuman writes the human-readable report to w: a three-line header,
// then one block per diagnosis, or a CAUSE UNKNOWN block carrying the facts
// that were collected when no rule matched. The output ends with a single
// newline and no trailing blank line.
func RenderHuman(w io.Writer, ev *evidence.Evidence, diags []*diagnose.Diagnosis) {
	fmt.Fprintf(w, "why report -- %s\n", targetPath(ev))
	fmt.Fprintf(w, "host: %s/%s (Go %s)  cwd: %s\n", ev.Env.OS, ev.Env.Arch, ev.Env.GoVersion, ev.Env.CWD)
	fmt.Fprintf(w, "kind: %s  machine: %s\n", ev.Kind, ev.TargetArch)

	if len(diags) == 0 {
		renderUnknown(w, ev)
		return
	}
	for i, d := range diags {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "Diagnosis %d: %s\n", i+1, d.Cause)
		fmt.Fprintf(w, "  WHY: %s\n", d.Why)
		fmt.Fprintf(w, "  EVIDENCE:\n")
		for _, e := range d.Evidence {
			fmt.Fprintf(w, "    - %s\n", e)
		}
		fmt.Fprintf(w, "  LIKELY FIX: %s\n", d.Fix)
		fmt.Fprintf(w, "  CONFIDENCE: %s\n", d.Confidence)
	}
}

// renderUnknown writes the CAUSE UNKNOWN block with the observable facts
// collected for the run.
func renderUnknown(w io.Writer, ev *evidence.Evidence) {
	fmt.Fprintln(w, "CAUSE UNKNOWN")
	fmt.Fprintln(w, "  WHY: the run completed but no known cause matched the collected evidence.")
	fmt.Fprintln(w, "  FACTS:")
	for _, f := range facts(ev) {
		fmt.Fprintf(w, "    - %s\n", f)
	}
}

// facts lists the observable facts in precedence order: a start failure is
// the most direct fact, then a process exit, then the absence of either.
func facts(ev *evidence.Evidence) []string {
	if sf, ok := ev.StartFailed(); ok {
		return []string{"process could not start: " + sf.Message}
	}
	if ex, ok := ev.Exit(); ok {
		f := fmt.Sprintf("process exited with code %d", ex.ExitCode)
		if ex.Signal != 0 {
			f += fmt.Sprintf("; signal %d", ex.Signal)
		}
		return []string{f}
	}
	return []string{"no process start or exit was observed"}
}

// jsonReport is the wire shape of the JSON report; field order is pinned by
// the contract.
type jsonReport struct {
	Tool      string          `json:"tool"`
	Version   string          `json:"version"`
	Target    jsonTarget      `json:"target"`
	Host      jsonHost        `json:"host"`
	Diagnoses []jsonDiagnosis `json:"diagnoses"`
	Unknown   bool            `json:"unknown"`
}

type jsonTarget struct {
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	Machine string `json:"machine,omitempty"`
	Class   string `json:"class,omitempty"`
}

type jsonHost struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
	CWD       string `json:"cwd"`
}

type jsonDiagnosis struct {
	Rule       string   `json:"rule"`
	Cause      string   `json:"cause"`
	Why        string   `json:"why"`
	Evidence   []string `json:"evidence"`
	Fix        string   `json:"fix"`
	Confidence string   `json:"confidence"`
}

// RenderJSON writes the report to w as JSON indented with two spaces,
// followed by a trailing newline.
func RenderJSON(w io.Writer, ev *evidence.Evidence, diags []*diagnose.Diagnosis) error {
	rep := jsonReport{
		Tool:    "why",
		Version: evidence.Version,
		Target: jsonTarget{
			Path:    targetPath(ev),
			Kind:    string(ev.Kind),
			Machine: ev.TargetArch,
			Class:   ev.TargetClass,
		},
		Host: jsonHost{
			OS:        ev.Env.OS,
			Arch:      ev.Env.Arch,
			GoVersion: ev.Env.GoVersion,
			CWD:       ev.Env.CWD,
		},
		Diagnoses: make([]jsonDiagnosis, 0, len(diags)),
		Unknown:   len(diags) == 0,
	}
	for _, d := range diags {
		rep.Diagnoses = append(rep.Diagnoses, jsonDiagnosis{
			Rule:       d.RuleID,
			Cause:      d.Cause,
			Why:        d.Why,
			Evidence:   d.Evidence,
			Fix:        d.Fix,
			Confidence: d.Confidence.String(),
		})
	}
	b, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.Write(b)
	return err
}
