// envrules.go implements the rules grounded in the environment and in the
// target's own output: PATH/runtime conflict, missing environment variable,
// occupied port, and wrong working directory. The three output-based rules
// are lower confidence because they attribute a cause from the target's
// text; they never fire without a matching observed line.
package rules

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"why/internal/diagnose"
	"why/internal/evidence"
)

// portRe extracts a port from a bind error line ("127.0.0.1:8080"). It avoids
// matching the error-code digit ("Only one usage ... 10048"): only the first
// colon-digit run in an address form is taken, which is the bound port.
var portRe = regexp.MustCompile(`(?:127\.0\.0\.1|0\.0\.0\.0|\[::|::|\d+\.\d+\.\d+\.\d+|localhost):(\d+)`)

// pathConflict fires when a PE dependency resolves from PATH rather than the
// application directory or system directory. The loaded copy may differ from
// the intended one — a runtime/path conflict hazard.
type pathConflict struct{}

func (*pathConflict) ID() string           { return "path-conflict" }
func (*pathConflict) Suppresses() []string { return nil }

func (*pathConflict) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	if ev.Kind != evidence.KindPE {
		return nil, false
	}
	for _, n := range ev.DepNodes {
		if n.Status != "present" || n.Source != "path" {
			continue
		}
		return diag(
			"path-conflict",
			"PATH / runtime conflict",
			"a DLL the program imports was found in PATH, not in the program's own directory or the system directory, so the loaded copy may be an unexpected version.",
			"place the expected DLL next to the executable (the loader prefers the application directory over PATH), or fix PATH.",
			diagnose.ConfMedium,
			n.Module+" resolved from a PATH entry instead of the application or system directory",
		), true
	}
	return nil, false
}

// missingEnvVar fires when the target's output names an environment variable
// as missing and that variable is indeed absent from the collected
// environment. It does not fire when the variable is set (negative
// condition).
type missingEnvVar struct{}

func (*missingEnvVar) ID() string           { return "missing-env-var" }
func (*missingEnvVar) Suppresses() []string { return nil }

func (*missingEnvVar) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	line := findMatchingOutputLine(ev, "environment variable", "env var", "not set", "not defined")
	if line == "" {
		return nil, false
	}
	var name string
	if m := envVarRe.FindStringSubmatch(line); m != nil {
		name = m[1]
	} else if m := envSetRe.FindStringSubmatch(line); m != nil {
		name = m[1]
	}
	if name == "" {
		return nil, false
	}
	// Negative condition: if the variable is actually set in the collected
	// environment, the output's claim is not the whole story.
	if envHas(ev.Env.Vars, name) {
		return nil, false
	}
	return diag(
		"missing-env-var",
		"missing environment variable",
		"the program reported that an environment variable it needs is not set, and it is not present in the environment.",
		"set the variable before running the program (set "+name+"=... on Windows, export "+name+" on Linux).",
		diagnose.ConfMedium,
		"the program output: "+line,
	), true
}

// envHas reports whether vars contains a key equal to name case-insensitively
// (Windows environment variable names are case-insensitive).
func envHas(vars map[string]string, name string) bool {
	for k, v := range vars {
		if strings.EqualFold(k, name) {
			_ = v
			return true
		}
	}
	return false
}

// portInUse fires when the target's output reports a bind address already in
// use. Env.Ports enriches the evidence with the current listeners.
type portInUse struct{}

func (*portInUse) ID() string           { return "port-in-use" }
func (*portInUse) Suppresses() []string { return nil }

func (*portInUse) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	line := findMatchingOutputLine(ev, "address already in use", "EADDRINUSE", "WSAEADDRINUSE",
		"Address already in use", "Only one usage of each socket address")
	if line == "" {
		return nil, false
	}
	evidence := []string{"the program output: " + line}

	// Prefer citing listeners on the port the error message names, so the
	// report points at the actual conflict instead of every listener. The
	// port snapshot is taken before the target runs, so the target's own
	// just-bound port may be absent — that is fine, the program's error line
	// is the authoritative evidence.
	port := portFromLine(line)
	var listeners []string
	switch {
	case port != 0:
		for _, p := range ev.Env.Ports {
			if p.Port == port {
				owner := p.Owner
				if owner == "" {
					owner = "unknown process"
				}
				listeners = append(listeners, fmt.Sprintf("port %d (owned by %s)", p.Port, owner))
			}
		}
	case len(ev.Env.Ports) > 0:
		// No port in the message; bound the context to avoid noise.
		for i, p := range ev.Env.Ports {
			if i >= 5 {
				listeners = append(listeners, "...")
				break
			}
			owner := p.Owner
			if owner == "" {
				owner = "unknown process"
			}
			listeners = append(listeners, fmt.Sprintf("port %d (owned by %s)", p.Port, owner))
		}
	}
	if len(listeners) > 0 {
		evidence = append(evidence, "currently listening: "+strings.Join(listeners, ", "))
	}
	return diag(
		"port-in-use",
		"occupied port",
		"the program tried to bind a network port that another process already holds, so it failed to start.",
		"stop the process holding the port, or configure the program to use a different port.",
		diagnose.ConfLow, evidence...,
	), true
}

// portFromLine extracts a port number from a bind error line like
// "listen tcp 127.0.0.1:8080: bind: ...". Returns 0 when none is present.
func portFromLine(line string) uint16 {
	m := portRe.FindStringSubmatch(line)
	if m == nil {
		return 0
	}
	n, err := strconv.ParseUint(m[1], 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// wrongCWD fires when the target exited and its output reports it could not
// open a relative path (a file it expected next to the working directory).
// It keys on the error-message *shape* (an open/read/load verb followed by a
// relative path) rather than on a specific error phrase, so it works across
// Windows ("The system cannot find the file specified.") and Linux ("no such
// file or directory").
type wrongCWD struct{}

func (*wrongCWD) ID() string           { return "wrong-cwd" }
func (*wrongCWD) Suppresses() []string { return nil }

func (*wrongCWD) Evaluate(ev *evidence.Evidence) (*diagnose.Diagnosis, bool) {
	ex, ok := ev.Exit()
	if !ok || ex.ExitCode == 0 {
		return nil, false
	}
	for _, stream := range []string{"stdout", "stderr"} {
		text, _ := ev.Output(stream)
		for _, line := range strings.Split(text, "\n") {
			m := cwdFileRe.FindStringSubmatch(line)
			if m == nil || len(m) < 2 {
				continue
			}
			token := strings.TrimSpace(m[1])
			// A single letter is a Windows drive root ("C:..."), not a
			// relative path.
			if len(token) < 2 || (len(token) == 1 && token[0] >= 'A' && token[0] <= 'Z') {
				continue
			}
			return diag(
				"wrong-cwd",
				"wrong working directory",
				"the program exited and reported it could not open a relative path, which is often because it is being run from the wrong directory.",
				"run the program from the directory that contains its data/configuration files (its intended working directory).",
				diagnose.ConfLow,
				"the program output: "+strings.TrimSpace(line),
			), true
		}
	}
	return nil, false
}
