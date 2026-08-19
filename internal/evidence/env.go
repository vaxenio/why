// env.go defines the environment snapshot model and the Evidence aggregate:
// the neutral bundle the run pipeline assembles and the rule engine consumes.
// EnvSnapshot is the schema-v1.0 event that carries a serialized Env in the
// .rdr log so the offline report command can rebuild Evidence.Env without
// re-collecting the environment.
package evidence

import (
	"errors"
	"strings"
)

// Kind identifies the binary format of the inspected target.
type Kind string

const (
	// KindPE marks a Windows PE image (inspected by internal/inspect/pe).
	KindPE Kind = "pe"
	// KindELF marks a Linux ELF image (inspected by internal/inspect/elf).
	KindELF Kind = "elf"
)

// Valid reports whether k is a known binary format.
func (k Kind) Valid() bool {
	switch k {
	case KindPE, KindELF:
		return true
	}
	return false
}

// PortInfo describes one open port and the process owning it, used by the
// occupied-port diagnosis (rule "port-in-use").
type PortInfo struct {
	Port  uint16 `json:"port"`
	Owner string `json:"owner"`
}

// Env is a snapshot of the target host environment: OS/arch/build info,
// working directory, PATH entries, environment variables, open ports, and
// platform-specific library presence (VC runtime on Windows, shared
// libraries on Linux). The JSON tags are the field names pinned by the
// env.snapshot schema-v1.0 contract; a nil map or slice is a valid "absent"
// value, so collectors may report empty state gracefully.
type Env struct {
	OS         string            `json:"os"`
	Arch       string            `json:"arch"`
	GoVersion  string            `json:"go_version"`
	CWD        string            `json:"cwd"`
	Paths      []string          `json:"paths"`
	Vars       map[string]string `json:"vars"`
	Ports      []PortInfo        `json:"ports"`
	VCRuntime  map[string]bool   `json:"vc_runtime"`
	SharedLibs map[string]bool   `json:"shared_libs"`
	Display    string            `json:"display"`
}

// EnvSnapshot records a serialized Env so the offline report command can
// rebuild Evidence.Env from the .rdr log. The payload field is named Env
// (not Kind), deliberately avoiding the field-shadowing hazard that
// GraphSnapshot.Kind has with Common.Kind; the event discriminant is always
// read as Common.Kind.
type EnvSnapshot struct {
	Common
	Env Env `json:"env"`
}

// validate enforces schema-v1.0 invariants for EnvSnapshot. OS and Arch are
// required because a real host always has them and the offline report needs
// at least those two fields to rebuild usable evidence; every other Env
// field may legitimately be empty (e.g. no open ports, no VC runtime).
func (e EnvSnapshot) validate() error {
	if err := e.Common.validate(); err != nil {
		return err
	}
	if err := kindIs(e.Common.Kind, EventEnvSnapshot, "EnvSnapshot"); err != nil {
		return err
	}
	if strings.TrimSpace(e.Env.OS) == "" {
		return errors.New("event: EnvSnapshot has empty os")
	}
	if strings.TrimSpace(e.Env.Arch) == "" {
		return errors.New("event: EnvSnapshot has empty arch")
	}
	return nil
}

// Evidence aggregates everything collected for one run of one target: the
// static dependency graph, the runtime trace events, the environment
// snapshot, and the target paths. It is the input to the rule engine.
//
// Graph is the static dependency graph produced by the matching inspector:
// *inspect/pe.Graph for KindPE, *inspect/elf.Graph for KindELF. It is typed
// as any because the two inspectors return distinct graph types; rules never
// inspect it — they read the normalized DepNodes/TargetArch/TargetClass
// fields, which the pipeline (or EvidenceFromEvents for offline reports)
// populates so rules stay decoupled from the concrete graph types.
type Evidence struct {
	// Kind is the binary format of the target ("pe" or "elf").
	Kind Kind
	// SourcePath is the path of the inspected target binary.
	SourcePath string
	// Graph is the static dependency graph (*pe.Graph or *elf.Graph), kept
	// for the report/inspect renderers.
	Graph any
	// TargetArch is the target's machine/arch name ("amd64", "x86", ...).
	// For ELF this is e_machine; for PE the IMAGE_FILE_MACHINE name.
	TargetArch string
	// TargetClass is the ELF EI_CLASS ("32"/"64"); empty for PE.
	TargetClass string
	// DepNodes is the dependency graph as a neutral node view, in the same
	// order as the concrete graph's Nodes.
	DepNodes []Node
	// Events are the runtime trace events in chronological order
	// (ProcessStart, ModuleLoaded*, Exit or StartFailed).
	Events []Event
	// Env is the environment snapshot collected for the run.
	Env Env
	// TargetPath is the path of the target binary that was run.
	TargetPath string
}

// Node looks up the dependency node for module, returning the node and
// whether it was found.
func (ev *Evidence) Node(module string) (Node, bool) {
	for _, n := range ev.DepNodes {
		if n.Module == module {
			return n, true
		}
	}
	return Node{}, false
}

// MissingNodes returns every dependency node that could not be resolved.
func (ev *Evidence) MissingNodes() []Node {
	var out []Node
	for _, n := range ev.DepNodes {
		if n.Status == "missing" || n.Status == "missing-interp" {
			out = append(out, n)
		}
	}
	return out
}
