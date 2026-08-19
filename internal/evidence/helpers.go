// helpers.go adds the event-scanning helpers rules use and the offline
// Evidence rebuild from recorded events (.rdr).
package evidence

import "strings"

// StartFailed returns the StartFailed event and whether one occurred. The
// target's failure to start is the most direct signal rules can use.
func (ev *Evidence) StartFailed() (StartFailed, bool) {
	for _, e := range ev.Events {
		if sf, ok := e.(StartFailed); ok {
			return sf, true
		}
	}
	return StartFailed{}, false
}

// Exit returns the Exit event and whether the process exited (i.e. tracing
// observed a clean process teardown rather than a start failure).
func (ev *Evidence) Exit() (Exit, bool) {
	for _, e := range ev.Events {
		if ex, ok := e.(Exit); ok {
			return ex, true
		}
	}
	return Exit{}, false
}

// LoaderErrors returns every LoaderError event (binary-parse failures and
// tracer-reported loader problems), in order.
func (ev *Evidence) LoaderErrors() []LoaderError {
	var out []LoaderError
	for _, e := range ev.Events {
		if le, ok := e.(LoaderError); ok {
			out = append(out, le)
		}
	}
	return out
}

// ModuleLoaded returns every ModuleLoaded event (DLLs/SOs the loader
// resolved), in order.
func (ev *Evidence) ModuleLoaded() []ModuleLoaded {
	var out []ModuleLoaded
	for _, e := range ev.Events {
		if ml, ok := e.(ModuleLoaded); ok {
			out = append(out, ml)
		}
	}
	return out
}

// Output returns the captured tail of a target stream ("stdout" or
// "stderr") as a joined text and whether it was truncated. Multiple Output
// events for one stream (unusual) are concatenated in order.
func (ev *Evidence) Output(stream string) (string, bool) {
	var sb strings.Builder
	truncated := false
	for _, e := range ev.Events {
		o, ok := e.(Output)
		if !ok || o.Stream != stream {
			continue
		}
		for _, line := range o.Lines {
			sb.WriteString(line)
			sb.WriteByte('\n')
		}
		truncated = truncated || o.Truncated
	}
	return sb.String(), truncated
}

// OutputContains reports whether the captured stdout or stderr contains
// substr anywhere (joined lines). It is the cheap predicate rules use
// before quoting the matching line as evidence.
func (ev *Evidence) OutputContains(substr string) bool {
	for _, stream := range []string{"stdout", "stderr"} {
		if text, _ := ev.Output(stream); strings.Contains(text, substr) {
			return true
		}
	}
	return false
}

// EvidenceFromEvents rebuilds an Evidence from recorded events, recovering
// the graph (GraphSnapshot), environment (EnvSnapshot) and target identity
// so the offline report command can re-run the rule engine without the
// binary or host. Fields without a recorded source (Graph detail) are left
// zero; normalized fields rules need are recovered.
func EvidenceFromEvents(events []Event) Evidence {
	ev := Evidence{Events: events}
	for _, e := range events {
		switch v := e.(type) {
		case GraphSnapshot:
			ev.Kind = Kind(v.Kind)
			ev.TargetArch = v.Machine
			ev.TargetClass = v.Class
			ev.DepNodes = append([]Node(nil), v.Nodes...)
			if len(v.Nodes) > 0 {
				ev.SourcePath = v.Nodes[0].Module
			}
		case EnvSnapshot:
			ev.Env = v.Env
		}
	}
	return ev
}
