// rdr.go implements the .rdr JSON-lines writer/reader: a schema-v1.0
// document is a header line followed by one JSON event per line, LF
// separated. Marshaling validates every line first, so a non-nil result is
// always a conformant document; unmarshaling is strict in the other
// direction (unknown event types, empty lines, and contract violations are
// all rejected) while tolerating CRLF line endings for hand-edited files.
package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
)

// EventHeader identifies the schema-metadata line that opens every .rdr
// file. It is not an Event; the header is validated separately from events.
const EventHeader EventType = "rdr.header"

// Header is the first line of a .rdr file. It carries schema metadata for
// the whole document: the pinned schema version, the tool identity, and
// when the file was written.
type Header struct {
	EventType   EventType `json:"event_type"`   // always EventHeader ("rdr.header")
	Version     string    `json:"version"`      // always SchemaVersion ("1.0")
	Tool        string    `json:"tool"`         // always "why"
	ToolVersion string    `json:"tool_version"` // evidence.Version
	OS          string    `json:"os"`           // runtime.GOOS
	CreatedAt   time.Time `json:"created_at"`   // RFC3339Nano
}

// validate enforces schema-v1.0 header invariants.
func (h Header) validate() error {
	if h.EventType != EventHeader {
		return fmt.Errorf("rdr: header event_type %q, want %q", h.EventType, EventHeader)
	}
	if h.Version != SchemaVersion {
		return fmt.Errorf("rdr: unsupported schema version %q (want %q)", h.Version, SchemaVersion)
	}
	if h.Tool != "why" {
		return fmt.Errorf("rdr: header tool %q, want %q", h.Tool, "why")
	}
	if h.ToolVersion == "" {
		return errors.New("rdr: header tool_version must not be empty")
	}
	if h.OS == "" {
		return errors.New("rdr: header os must not be empty")
	}
	if h.CreatedAt.IsZero() {
		return errors.New("rdr: header created_at must not be zero")
	}
	return nil
}

// NewHeader returns a header stamped with the current schema version,
// evidence.Version as the tool_version, and the runtime OS.
func NewHeader() Header {
	return Header{
		EventType:   EventHeader,
		Version:     SchemaVersion,
		Tool:        "why",
		ToolVersion: Version,
		OS:          runtime.GOOS,
		CreatedAt:   time.Now().UTC(),
	}
}

// MarshalEvents serializes h and events as a .rdr JSON-lines document: one
// header line, then one JSON event per line, LF-separated. Both the header
// and every event are validated before writing, so a non-nil result is
// always a schema-conformant version-1.0 document.
func MarshalEvents(h Header, events []Event) ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	hb, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("rdr: marshal header: %w", err)
	}
	var buf bytes.Buffer
	buf.Write(hb)
	buf.WriteByte('\n')
	for i, e := range events {
		eb, err := MarshalEvent(e)
		if err != nil {
			return nil, fmt.Errorf("rdr: event %d: %w", i, err)
		}
		buf.Write(eb)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), nil
}

// UnmarshalEvents parses a .rdr document. It strictly validates the header
// (event_type, schema version, tool) and rejects unknown event types,
// invalid sources, and empty lines. CRLF line endings are tolerated.
func UnmarshalEvents(data []byte) (Header, []Event, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Header{}, nil, errors.New("rdr: empty input")
	}
	// Accept a single trailing newline; \r\n endings are stripped per line
	// below via TrimSpace.
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")

	var h Header
	if err := json.Unmarshal([]byte(strings.TrimSpace(lines[0])), &h); err != nil {
		return Header{}, nil, fmt.Errorf("rdr: header line 1: %w", err)
	}
	if err := h.validate(); err != nil {
		return Header{}, nil, err
	}

	events := make([]Event, 0, len(lines)-1)
	for i, line := range lines[1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			return Header{}, nil, fmt.Errorf("rdr: line %d: empty line", i+2)
		}
		e, err := UnmarshalEvent([]byte(trimmed))
		if err != nil {
			return Header{}, nil, fmt.Errorf("rdr: line %d: %w", i+2, err)
		}
		events = append(events, e)
	}
	return h, events, nil
}

// MarshalEvent serializes a single event as one JSON-lines line. The event
// must satisfy the schema-v1.0 invariants of its concrete type (checked via
// the package Validate entry point), including a Kind matching its type.
func MarshalEvent(e Event) ([]byte, error) {
	if e == nil {
		return nil, errors.New("event: cannot marshal nil event")
	}
	if err := Validate(e); err != nil {
		return nil, err
	}
	switch v := e.(type) {
	case ProcessStart:
		return json.Marshal(v)
	case ModuleLoaded:
		return json.Marshal(v)
	case SearchFailed:
		return json.Marshal(v)
	case LoaderError:
		return json.Marshal(v)
	case StartFailed:
		return json.Marshal(v)
	case Exit:
		return json.Marshal(v)
	case GraphSnapshot:
		return json.Marshal(v)
	default:
		return nil, fmt.Errorf("event: cannot marshal event of type %T", e)
	}
}

// eventTypeProbe extracts the event_type discriminant from a JSON line.
type eventTypeProbe struct {
	EventType EventType `json:"event_type"`
}

// UnmarshalEvent parses a single event line, dispatching on event_type and
// rejecting unknown types and contract violations.
func UnmarshalEvent(line []byte) (Event, error) {
	var probe eventTypeProbe
	if err := json.Unmarshal(line, &probe); err != nil {
		return nil, fmt.Errorf("event: decode event_type: %w", err)
	}
	switch probe.EventType {
	case EventProcessStart:
		return unmarshalTyped[ProcessStart](line)
	case EventModuleLoaded:
		return unmarshalTyped[ModuleLoaded](line)
	case EventSearchFailed:
		return unmarshalTyped[SearchFailed](line)
	case EventLoaderError:
		return unmarshalTyped[LoaderError](line)
	case EventStartFailed:
		return unmarshalTyped[StartFailed](line)
	case EventExit:
		return unmarshalTyped[Exit](line)
	case EventGraphSnapshot:
		return unmarshalTyped[GraphSnapshot](line)
	default:
		return nil, fmt.Errorf("event: unknown event_type %q", probe.EventType)
	}
}

// unmarshalTyped decodes line into a concrete event type and enforces the
// shared invariants via the package Validate entry point. Dispatch has
// already guaranteed Kind is known, so Validate's Kind.Valid() check also
// covers it; the per-type kindIs check confirms Kind matches the concrete
// type.
func unmarshalTyped[T Event](line []byte) (Event, error) {
	var v T
	if err := json.Unmarshal(line, &v); err != nil {
		return nil, fmt.Errorf("event: decode %T: %w", v, err)
	}
	if err := Validate(v); err != nil {
		return nil, err
	}
	return v, nil
}
