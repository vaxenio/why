// Package evidence defines the normalized event model recorded in .rdr logs:
// the event-type and source discriminants, the shared Common envelope, the
// concrete events of schema v1.0, and per-event validation.
package evidence

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// EventType identifies the kind of an event in the .rdr schema.
type EventType string

// Event types in schema version 1.0. Every value appears on its own
// JSON-lines line after the rdr.header line (see rdr.go).
const (
	EventProcessStart  EventType = "process.start"
	EventModuleLoaded  EventType = "module.loaded"
	EventSearchFailed  EventType = "search.failed"
	EventLoaderError   EventType = "loader.error"
	EventStartFailed   EventType = "start.failed"
	EventExit          EventType = "exit"
	EventGraphSnapshot EventType = "graph.snapshot"
)

// Valid reports whether et is a known event type in schema version 1.0.
func (et EventType) Valid() bool {
	switch et {
	case EventProcessStart, EventModuleLoaded, EventSearchFailed,
		EventLoaderError, EventStartFailed, EventExit, EventGraphSnapshot:
		return true
	}
	return false
}

// Source identifies the component that produced an event.
type Source string

// Allowed source values in schema version 1.0.
const (
	SourceTrace   Source = "trace"
	SourceInspect Source = "inspect"
	SourceEnv     Source = "env"
	SourceCLI     Source = "cli"
)

// Valid reports whether s is a known source in schema version 1.0.
func (s Source) Valid() bool {
	switch s {
	case SourceTrace, SourceInspect, SourceEnv, SourceCLI:
		return true
	}
	return false
}

// Version is the why release version, stamped into .rdr headers as
// tool_version. It defaults to "dev" and is overridden at build time, e.g.
// -ldflags "-X why/internal/evidence.Version=v0.1.0".
var Version = "dev"

// SchemaVersion is the .rdr schema version pinned by this release. It is a
// breaking-change pin: readers must reject any file whose header version
// differs, and a schema-conformance test locks it to "1.0".
const SchemaVersion = "1.0"

// Event is the common interface implemented by every .rdr event.
type Event interface {
	EventType() EventType
	Timestamp() time.Time
	Source() Source
}

// Common carries the fields shared by every event. It is embedded in all
// concrete events and flattened into the same JSON object; the JSON names are
// event_type/timestamp/source. The Go field names (Kind/Time/Src) avoid
// clashing with the Event interface accessors of the same intent.
type Common struct {
	Kind EventType `json:"event_type"`
	Time time.Time `json:"timestamp"`
	Src  Source    `json:"source"`
}

// EventType returns the event's discriminant.
func (c Common) EventType() EventType { return c.Kind }

// Timestamp returns when the event occurred (RFC3339Nano on the wire).
func (c Common) Timestamp() time.Time { return c.Time }

// Source returns the component that produced the event.
func (c Common) Source() Source { return c.Src }

// validate enforces the schema-v1.0 invariants shared by every event.
func (c Common) validate() error {
	if !c.Kind.Valid() {
		return fmt.Errorf("event: unknown event_type %q", c.Kind)
	}
	if !c.Src.Valid() {
		return fmt.Errorf("event: invalid source %q", c.Src)
	}
	if c.Time.IsZero() {
		return errors.New("event: zero timestamp")
	}
	return nil
}

// kindIs reports an error when kind does not match the concrete event type.
func kindIs(kind EventType, want EventType, concrete string) error {
	if kind != want {
		return fmt.Errorf("event: %s has event_type %q, want %q", concrete, kind, want)
	}
	return nil
}

// ProcessStart records that the target process was spawned.
type ProcessStart struct {
	Common
}

// validate enforces schema-v1.0 invariants for ProcessStart.
func (e ProcessStart) validate() error {
	if err := e.Common.validate(); err != nil {
		return err
	}
	return kindIs(e.Kind, EventProcessStart, "ProcessStart")
}

// ModuleLoaded records a module (DLL/SO) resolved by the loader.
// Found is false when the module was found via search-path fallback.
type ModuleLoaded struct {
	Common
	Path  string `json:"path"`
	Found bool   `json:"found"`
}

// validate enforces schema-v1.0 invariants for ModuleLoaded.
func (e ModuleLoaded) validate() error {
	if err := e.Common.validate(); err != nil {
		return err
	}
	if err := kindIs(e.Kind, EventModuleLoaded, "ModuleLoaded"); err != nil {
		return err
	}
	if strings.TrimSpace(e.Path) == "" {
		return errors.New("event: ModuleLoaded has empty path")
	}
	return nil
}

// SearchFailed records a loader search for a library that failed.
type SearchFailed struct {
	Common
	Library     string   `json:"library"`
	SearchPaths []string `json:"search_paths"`
}

// validate enforces schema-v1.0 invariants for SearchFailed.
func (e SearchFailed) validate() error {
	if err := e.Common.validate(); err != nil {
		return err
	}
	if err := kindIs(e.Kind, EventSearchFailed, "SearchFailed"); err != nil {
		return err
	}
	if strings.TrimSpace(e.Library) == "" {
		return errors.New("event: SearchFailed has empty library")
	}
	return nil
}

// LoaderError records a loader or binary-parse failure.
type LoaderError struct {
	Common
	Path    string `json:"path"`
	Message string `json:"message"`
}

// validate enforces schema-v1.0 invariants for LoaderError.
func (e LoaderError) validate() error {
	if err := e.Common.validate(); err != nil {
		return err
	}
	if err := kindIs(e.Kind, EventLoaderError, "LoaderError"); err != nil {
		return err
	}
	if strings.TrimSpace(e.Path) == "" {
		return errors.New("event: LoaderError has empty path")
	}
	if strings.TrimSpace(e.Message) == "" {
		return errors.New("event: LoaderError has empty message")
	}
	return nil
}

// StartFailed records that the target process could not be started.
// ErrorCode carries the Windows NTSTATUS/win32 code (0 on Linux).
type StartFailed struct {
	Common
	ErrorCode uint32 `json:"error_code"`
	Message   string `json:"message"`
}

// validate enforces schema-v1.0 invariants for StartFailed.
func (e StartFailed) validate() error {
	if err := e.Common.validate(); err != nil {
		return err
	}
	if err := kindIs(e.Kind, EventStartFailed, "StartFailed"); err != nil {
		return err
	}
	if strings.TrimSpace(e.Message) == "" {
		return errors.New("event: StartFailed has empty message")
	}
	return nil
}

// Exit records the target process exit. Signal is 0 on a normal exit.
type Exit struct {
	Common
	ExitCode uint32 `json:"exit_code"`
	Signal   int    `json:"signal"`
}

// validate enforces schema-v1.0 invariants for Exit.
func (e Exit) validate() error {
	if err := e.Common.validate(); err != nil {
		return err
	}
	return kindIs(e.Kind, EventExit, "Exit")
}

// Node is one node of the static dependency graph carried by GraphSnapshot.
type Node struct {
	Module string `json:"module"`
	Status string `json:"status"`
}

// GraphSnapshot records the static dependency graph of the target so the
// offline report command can rebuild Evidence.Graph without re-inspecting the
// binary. Kind is the graph kind ("pe" or "elf"); the event's discriminant is
// carried separately by Common.Kind under the JSON name event_type. The outer
// Kind field shadows Common.Kind for selector access, so the discriminant is
// always read as Common.Kind.
type GraphSnapshot struct {
	Common
	Kind  string `json:"kind"`
	Nodes []Node `json:"nodes"`
}

// validate enforces schema-v1.0 invariants for GraphSnapshot.
func (e GraphSnapshot) validate() error {
	if err := e.Common.validate(); err != nil {
		return err
	}
	if err := kindIs(e.Common.Kind, EventGraphSnapshot, "GraphSnapshot"); err != nil {
		return err
	}
	if strings.TrimSpace(e.Kind) == "" {
		return errors.New("event: GraphSnapshot has empty kind")
	}
	for i, n := range e.Nodes {
		if strings.TrimSpace(n.Module) == "" {
			return fmt.Errorf("event: GraphSnapshot node %d has empty module", i)
		}
		if strings.TrimSpace(n.Status) == "" {
			return fmt.Errorf("event: GraphSnapshot node %d has empty status", i)
		}
	}
	return nil
}

// Validate reports whether e conforms to the schema-v1.0 invariants of its
// concrete event type. It is the entry point used by the .rdr marshaler.
func Validate(e Event) error {
	switch v := e.(type) {
	case ProcessStart:
		return v.validate()
	case ModuleLoaded:
		return v.validate()
	case SearchFailed:
		return v.validate()
	case LoaderError:
		return v.validate()
	case StartFailed:
		return v.validate()
	case Exit:
		return v.validate()
	case GraphSnapshot:
		return v.validate()
	case nil:
		return errors.New("event: nil event")
	default:
		return fmt.Errorf("event: unknown concrete event type %T", e)
	}
}
