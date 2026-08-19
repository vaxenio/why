// run.go implements the `why run` pipeline: inspect the target statically,
// collect the environment, trace it, apply the rule engine and render the
// report. It is the end-to-end diagnostic path behind the CLI.
package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"why/internal/collect"
	"why/internal/diagnose"
	"why/internal/evidence"
	"why/internal/inspect/elf"
	"why/internal/inspect/pe"
	"why/internal/report"
	"why/internal/rules"
)

// runPipeline runs diagnostics on rest[0] (the target) with rest[1:] as the
// target's arguments. It returns the number of diagnoses (0..n) and an error
// only for why tool failures. A completed run — including one where the
// target failed to start — returns nil; the diagnosis count maps to exit 0
// or 2 via exitCode.
func runPipeline(rest []string, jsonOut bool, rdrPath string) (int, error) {
	if len(rest) == 0 {
		return 0, &exitError{code: 1, msg: "why: run: missing target"}
	}
	target := rest[0]
	targetArgs := rest[1:]

	if _, err := os.Stat(target); err != nil {
		return 0, &exitError{code: 1, msg: fmt.Sprintf("why: run: target not found: %s", target)}
	}

	ev := evidence.Evidence{SourcePath: target, TargetPath: target}
	// Static inspection (works cross-OS: the PE/ELF parsers are pure).
	kind, recognized := sniffKind(target)
	if recognized {
		ev.Kind = kind
		fillGraph(&ev, inspectGraph(target, kind))
	} else {
		ev.Events = append(ev.Events, evidence.LoaderError{
			Common:  evidence.Common{Kind: evidence.EventLoaderError, Time: now(), Src: evidence.SourceInspect},
			Path:    target,
			Message: "not a recognized PE or ELF image",
		})
	}
	ev.Env = collect.CollectEnv()

	// Trace the target.
	tr, err := newTracer(target, targetArgs...)
	if err != nil {
		return 0, &exitError{code: 1, msg: fmt.Sprintf("why: run: %v", err)}
	}
	if err := tr.Run(); err != nil {
		// A tracer failure already recorded a LoaderError event.
		return 0, &exitError{code: 1, msg: fmt.Sprintf("why: run: %v", err)}
	}
	ev.Events = append(ev.Events, tr.Events()...)

	diags := diagnose.NewEngine(rules.All()).Evaluate(&ev)

	if rdrPath != "" {
		if err := writeRDR(rdrPath, &ev); err != nil {
			return 0, &exitError{code: 1, msg: fmt.Sprintf("why: run: %v", err)}
		}
	}
	if jsonOut {
		if err := report.RenderJSON(os.Stdout, &ev, diags); err != nil {
			return 0, &exitError{code: 1, msg: fmt.Sprintf("why: run: %v", err)}
		}
	} else {
		report.RenderHuman(os.Stdout, &ev, diags)
	}
	return len(diags), nil
}

// sniffKind detects the binary format of path from its magic bytes. The
// second result reports whether it is a recognized PE or ELF image.
func sniffKind(path string) (evidence.Kind, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := f.Read(magic[:]); err != nil {
		return "", false
	}
	switch {
	case magic[0] == 'M' && magic[1] == 'Z':
		return evidence.KindPE, true
	case magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F':
		return evidence.KindELF, true
	}
	return "", false
}

// inspectGraph inspects target with the inspector for kind and returns the
// concrete graph. On a parse failure it records a LoaderError event on ev and
// returns nil.
func inspectGraph(target string, kind evidence.Kind) any {
	switch kind {
	case evidence.KindPE:
		g, err := pe.Inspect(target, pe.Options{})
		if err != nil {
			return err
		}
		return g
	case evidence.KindELF:
		g, err := elf.Inspect(target, elf.Options{})
		if err != nil {
			return err
		}
		return g
	}
	return errors.New("unknown binary kind")
}

// fillGraph copies the concrete inspector graph's normalized fields into ev.
// g may be an error from a failed inspection, in which case a LoaderError
// event is recorded and ev.Graph stays nil.
func fillGraph(ev *evidence.Evidence, g any) {
	switch v := g.(type) {
	case *pe.Graph:
		ev.Graph = v
		ev.TargetArch = v.Machine
		ev.DepNodes = make([]evidence.Node, 0, len(v.Nodes))
		for _, n := range v.Nodes {
			ev.DepNodes = append(ev.DepNodes, evidence.Node{
				Module: n.Module, Status: string(n.Status), Source: n.Source, Arch: n.Arch,
			})
		}
	case *elf.Graph:
		ev.Graph = v
		ev.TargetArch = v.TargetArch
		ev.TargetClass = v.TargetClass
		ev.DepNodes = make([]evidence.Node, 0, len(v.Nodes))
		for _, n := range v.Nodes {
			ev.DepNodes = append(ev.DepNodes, evidence.Node{
				Module: n.Module, Status: string(n.Status), Source: n.Source, Arch: n.Arch,
			})
		}
	case error:
		ev.Events = append(ev.Events, evidence.LoaderError{
			Common:  evidence.Common{Kind: evidence.EventLoaderError, Time: now(), Src: evidence.SourceInspect},
			Path:    ev.SourcePath,
			Message: v.Error(),
		})
	}
}

// writeRDR serializes the run's evidence to a .rdr file so `why report` can
// re-run the rule engine offline.
func writeRDR(path string, ev *evidence.Evidence) error {
	var events []evidence.Event
	if ev.Graph != nil {
		events = append(events, evidence.GraphSnapshot{
			Common:  evidence.Common{Kind: evidence.EventGraphSnapshot, Time: now(), Src: evidence.SourceInspect},
			Kind:    string(ev.Kind),
			Machine: ev.TargetArch,
			Class:   ev.TargetClass,
			Nodes:   append([]evidence.Node(nil), ev.DepNodes...),
		})
	}
	events = append(events, evidence.EnvSnapshot{
		Common: evidence.Common{Kind: evidence.EventEnvSnapshot, Time: now(), Src: evidence.SourceEnv},
		Env:    ev.Env,
	})
	events = append(events, ev.Events...)

	data, err := evidence.MarshalEvents(evidence.NewHeader(), events)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// now returns the current UTC instant for event timestamps.
func now() time.Time { return time.Now().UTC() }
