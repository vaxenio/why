package evidence

import (
	"bytes"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

// sec returns a fixed UTC instant i seconds past 12:30. time.Date carries no
// monotonic clock, so events round-trip through RFC3339Nano byte-exactly.
func sec(i int) time.Time { return time.Date(2026, 8, 18, 12, 30, i, 0, time.UTC) }

// validHeaderLine is the byte-exact header line of the golden document.
const validHeaderLine = `{"event_type":"rdr.header","version":"1.0","tool":"why","tool_version":"test-1.0","os":"linux","created_at":"2026-08-18T12:30:00Z"}`

// goldenDoc is a known schema-v1.0 .rdr document covering every concrete
// event type. MarshalEvents(header, events) must produce exactly these bytes,
// and the document must round-trip (unmarshal → remarshal) unchanged.
const goldenDoc = `{"event_type":"rdr.header","version":"1.0","tool":"why","tool_version":"test-1.0","os":"linux","created_at":"2026-08-18T12:30:00Z"}
{"event_type":"process.start","timestamp":"2026-08-18T12:30:01Z","source":"trace"}
{"event_type":"module.loaded","timestamp":"2026-08-18T12:30:02Z","source":"trace","path":"kernel32.dll","found":true}
{"event_type":"search.failed","timestamp":"2026-08-18T12:30:03Z","source":"trace","library":"msvcp140.dll","search_paths":["System32","AppDir"]}
{"event_type":"loader.error","timestamp":"2026-08-18T12:30:04Z","source":"trace","path":"missing.so","message":"not found"}
{"event_type":"start.failed","timestamp":"2026-08-18T12:30:05Z","source":"trace","error_code":740,"message":"requires elevation"}
{"event_type":"exit","timestamp":"2026-08-18T12:30:06Z","source":"trace","exit_code":1,"signal":0}
{"event_type":"graph.snapshot","timestamp":"2026-08-18T12:30:07Z","source":"trace","kind":"pe","nodes":[{"module":"kernel32.dll","status":"ok"}]}
`

// goldenHeader returns the header stamped into the golden document.
func goldenHeader() Header {
	return Header{
		EventType:   EventHeader,
		Version:     SchemaVersion,
		Tool:        "why",
		ToolVersion: "test-1.0",
		OS:          "linux",
		CreatedAt:   sec(0),
	}
}

// goldenEvents returns the events carried by the golden document.
func goldenEvents() []Event {
	return []Event{
		ProcessStart{Common{EventProcessStart, sec(1), SourceTrace}},
		ModuleLoaded{Common{EventModuleLoaded, sec(2), SourceTrace}, "kernel32.dll", true},
		SearchFailed{Common{EventSearchFailed, sec(3), SourceTrace}, "msvcp140.dll", []string{"System32", "AppDir"}},
		LoaderError{Common{EventLoaderError, sec(4), SourceTrace}, "missing.so", "not found"},
		StartFailed{Common{EventStartFailed, sec(5), SourceTrace}, 740, "requires elevation"},
		Exit{Common{EventExit, sec(6), SourceTrace}, 1, 0},
		GraphSnapshot{Common: Common{EventGraphSnapshot, sec(7), SourceTrace}, Kind: "pe", Nodes: []Node{{Module: "kernel32.dll", Status: "ok"}}},
	}
}

// TestGoldenDoc pins the exact bytes a known .rdr document marshals to and
// verifies it round-trips identically (unmarshal → remarshal).
func TestGoldenDoc(t *testing.T) {
	got, err := MarshalEvents(goldenHeader(), goldenEvents())
	if err != nil {
		t.Fatalf("MarshalEvents: %v", err)
	}
	if string(got) != goldenDoc {
		t.Errorf("MarshalEvents bytes mismatch\n got: %s\nwant: %s", got, goldenDoc)
	}

	h, events, err := UnmarshalEvents(got)
	if err != nil {
		t.Fatalf("UnmarshalEvents: %v", err)
	}
	if !reflect.DeepEqual(h, goldenHeader()) {
		t.Errorf("header after round-trip = %+v, want %+v", h, goldenHeader())
	}
	if !reflect.DeepEqual(events, goldenEvents()) {
		t.Errorf("events after round-trip = %+v, want %+v", events, goldenEvents())
	}

	again, err := MarshalEvents(h, events)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if !bytes.Equal(again, got) {
		t.Errorf("remarshal not byte-identical:\n got: %s\nwant: %s", again, got)
	}
}

// TestCRLFTolerated verifies \r\n line endings parse identically to LF and
// remarshal to the canonical LF document.
func TestCRLFTolerated(t *testing.T) {
	crlf := strings.ReplaceAll(goldenDoc, "\n", "\r\n")
	h, events, err := UnmarshalEvents([]byte(crlf))
	if err != nil {
		t.Fatalf("UnmarshalEvents with CRLF: %v", err)
	}
	if !reflect.DeepEqual(h, goldenHeader()) {
		t.Errorf("header = %+v, want %+v", h, goldenHeader())
	}
	if !reflect.DeepEqual(events, goldenEvents()) {
		t.Errorf("events = %+v, want %+v", events, goldenEvents())
	}
	again, err := MarshalEvents(h, events)
	if err != nil {
		t.Fatalf("remarshal: %v", err)
	}
	if string(again) != goldenDoc {
		t.Errorf("remarshal of CRLF input = %s, want canonical LF document", again)
	}
}

// TestNewHeader verifies the constructor stamps every required header field.
func TestNewHeader(t *testing.T) {
	h := NewHeader()
	if h.EventType != EventHeader {
		t.Errorf("EventType = %q, want %q", h.EventType, EventHeader)
	}
	if h.Version != SchemaVersion {
		t.Errorf("Version = %q, want %q", h.Version, SchemaVersion)
	}
	if h.Tool != "why" {
		t.Errorf("Tool = %q, want %q", h.Tool, "why")
	}
	if h.ToolVersion != Version {
		t.Errorf("ToolVersion = %q, want %q", h.ToolVersion, Version)
	}
	if h.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", h.OS, runtime.GOOS)
	}
	if h.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero")
	}
	// A NewHeader-stamped document must also pass strict validation.
	if _, err := MarshalEvents(h, nil); err != nil {
		t.Errorf("MarshalEvents(NewHeader(), nil): %v", err)
	}
}

// TestUnmarshalEventsRejects is the schema-conformance table: every malformed
// or non-conformant document must fail with a descriptive error.
func TestUnmarshalEventsRejects(t *testing.T) {
	ev := `{"event_type":"exit","timestamp":"2026-08-18T12:30:06Z","source":"trace","exit_code":1,"signal":0}`
	cases := []struct {
		name, doc, wantErr string
	}{
		{"empty input", "", "empty input"},
		{"whitespace only", "  \n\t ", "empty input"},
		{"wrong schema version",
			`{"event_type":"rdr.header","version":"2.0","tool":"why","tool_version":"test-1.0","os":"linux","created_at":"2026-08-18T12:30:00Z"}` + "\n",
			`unsupported schema version "2.0"`},
		{"wrong header event_type",
			`{"event_type":"rdr.events","version":"1.0","tool":"why","tool_version":"test-1.0","os":"linux","created_at":"2026-08-18T12:30:00Z"}` + "\n",
			`header event_type "rdr.events"`},
		{"wrong tool",
			`{"event_type":"rdr.header","version":"1.0","tool":"rundoctor","tool_version":"test-1.0","os":"linux","created_at":"2026-08-18T12:30:00Z"}` + "\n",
			`header tool "rundoctor"`},
		{"missing tool_version",
			`{"event_type":"rdr.header","version":"1.0","tool":"why","os":"linux","created_at":"2026-08-18T12:30:00Z"}` + "\n",
			"tool_version"},
		{"missing os",
			`{"event_type":"rdr.header","version":"1.0","tool":"why","tool_version":"test-1.0","created_at":"2026-08-18T12:30:00Z"}` + "\n",
			"header os"},
		{"zero created_at",
			`{"event_type":"rdr.header","version":"1.0","tool":"why","tool_version":"test-1.0","os":"linux"}` + "\n",
			"created_at"},
		{"unknown event type",
			validHeaderLine + "\n" + `{"event_type":"bogus","timestamp":"2026-08-18T12:30:01Z","source":"trace"}` + "\n",
			`unknown event_type "bogus"`},
		{"event missing timestamp",
			validHeaderLine + "\n" + `{"event_type":"exit","source":"trace","exit_code":1,"signal":0}` + "\n",
			"zero timestamp"},
		{"event missing source",
			validHeaderLine + "\n" + `{"event_type":"exit","timestamp":"2026-08-18T12:30:06Z","exit_code":1,"signal":0}` + "\n",
			"invalid source"},
		{"event missing required field",
			validHeaderLine + "\n" + `{"event_type":"module.loaded","timestamp":"2026-08-18T12:30:02Z","source":"trace","found":true}` + "\n",
			"empty path"},
		{"header only", validHeaderLine + "\n", ""}, // valid: zero events is legal
		{"empty line after header",
			validHeaderLine + "\n\n",
			"empty line"},
		{"empty line between events",
			validHeaderLine + "\n" + ev + "\n\n" + ev + "\n",
			"empty line"},
		{"malformed json line",
			validHeaderLine + "\n" + `{"event_type":"exit",` + "\n",
			"decode"},
		{"json garbage",
			validHeaderLine + "\n" + `not json` + "\n",
			"decode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := UnmarshalEvents([]byte(tc.doc))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("UnmarshalEvents returned %v, want success", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("UnmarshalEvents succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestMarshalEventsRejects verifies the writer refuses non-conformant input:
// invalid header, invalid event, and nil events.
func TestMarshalEventsRejects(t *testing.T) {
	cases := []struct {
		name    string
		h       Header
		events  []Event
		wantErr string
	}{
		{"wrong version", Header{EventHeader, "2.0", "why", "test", "linux", sec(0)}, nil, `unsupported schema version "2.0"`},
		{"wrong tool", Header{EventHeader, SchemaVersion, "rundoctor", "test", "linux", sec(0)}, nil, `header tool "rundoctor"`},
		{"empty tool_version", Header{EventHeader, SchemaVersion, "why", "", "linux", sec(0)}, nil, "tool_version"},
		{"zero created_at", Header{EventHeader, SchemaVersion, "why", "test", "linux", time.Time{}}, nil, "created_at"},
		{"nil event", goldenHeader(), []Event{nil}, "nil event"},
		{"zero timestamp event", goldenHeader(), []Event{ProcessStart{Common{EventProcessStart, time.Time{}, SourceTrace}}}, "zero timestamp"},
		{"unknown concrete type", goldenHeader(), []Event{fakeEvent{Common{EventProcessStart, sec(1), SourceTrace}}}, "unknown concrete event type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := MarshalEvents(tc.h, tc.events)
			if err == nil {
				t.Fatalf("MarshalEvents succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestEventRoundTrip verifies each concrete event marshals to one line and
// unmarshals back losslessly, including GraphSnapshot's shadowed Kind field.
func TestEventRoundTrip(t *testing.T) {
	events := goldenEvents()
	for _, e := range events {
		b, err := MarshalEvent(e)
		if err != nil {
			t.Fatalf("MarshalEvent(%T): %v", e, err)
		}
		if strings.ContainsRune(string(b), '\n') {
			t.Errorf("MarshalEvent(%T) contains a newline", e)
		}
		got, err := UnmarshalEvent(b)
		if err != nil {
			t.Fatalf("UnmarshalEvent(%T): %v", e, err)
		}
		if !reflect.DeepEqual(got, e) {
			t.Errorf("round-trip %T = %+v, want %+v", e, got, e)
		}
	}
	// GraphSnapshot: the event discriminant lives in Common.Kind, the graph
	// kind in the shadowing field Kind — both must survive the round-trip.
	gs := events[len(events)-1].(GraphSnapshot)
	if gs.Common.Kind != EventGraphSnapshot || gs.Kind != "pe" {
		t.Errorf("GraphSnapshot discriminant corrupted: Common.Kind=%q Kind=%q", gs.Common.Kind, gs.Kind)
	}
}

// TestUnmarshalEventRejects verifies per-line dispatch refuses unknown types,
// non-conformant events, and malformed JSON.
func TestUnmarshalEventRejects(t *testing.T) {
	cases := []struct {
		name, line, wantErr string
	}{
		{"unknown type", `{"event_type":"bogus","timestamp":"2026-08-18T12:30:01Z","source":"trace"}`, `unknown event_type "bogus"`},
		{"header line is not an event", validHeaderLine, `unknown event_type "rdr.header"`},
		{"missing timestamp", `{"event_type":"exit","source":"trace","exit_code":1,"signal":0}`, "zero timestamp"},
		{"missing source", `{"event_type":"exit","timestamp":"2026-08-18T12:30:06Z","exit_code":1,"signal":0}`, "invalid source"},
		{"missing path", `{"event_type":"module.loaded","timestamp":"2026-08-18T12:30:02Z","source":"trace","found":true}`, "empty path"},
		{"malformed json", `{"event_type":"exit"`, "decode"},
		{"empty line", "", "decode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnmarshalEvent([]byte(tc.line))
			if err == nil {
				t.Fatalf("UnmarshalEvent succeeded, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestMarshalEventRejects verifies the per-line writer refuses nil and
// non-conformant events.
func TestMarshalEventRejects(t *testing.T) {
	if _, err := MarshalEvent(nil); err == nil {
		t.Error("MarshalEvent(nil) succeeded, want error")
	}
	if _, err := MarshalEvent(fakeEvent{Common{EventProcessStart, sec(1), SourceTrace}}); err == nil {
		t.Error("MarshalEvent(unknown concrete type) succeeded, want error")
	}
}
