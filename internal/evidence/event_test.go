package evidence

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// at returns a fixed UTC instant for event construction. time.Date carries no
// monotonic clock reading, so events built with at() round-trip through JSON
// (RFC3339Nano) byte-exactly and compare equal with reflect.DeepEqual.
func at() time.Time { return time.Date(2026, 8, 18, 12, 30, 0, 0, time.UTC) }

// fakeEvent satisfies Event without being one of the concrete event types, so
// Validate's default branch is reachable in tests.
type fakeEvent struct{ Common }

func TestSchemaVersion(t *testing.T) {
	if SchemaVersion != "1.0" {
		t.Errorf("SchemaVersion = %q, want %q", SchemaVersion, "1.0")
	}
}

func TestVersionDefaultsToDev(t *testing.T) {
	if Version != "dev" {
		t.Errorf("Version = %q, want %q", Version, "dev")
	}
}

func TestEventTypeValid(t *testing.T) {
	all := []EventType{
		EventProcessStart, EventModuleLoaded, EventSearchFailed,
		EventLoaderError, EventStartFailed, EventExit, EventGraphSnapshot,
		EventEnvSnapshot, EventOutput,
	}
	for _, et := range all {
		if !et.Valid() {
			t.Errorf("EventType %q: Valid() = false, want true", et)
		}
	}
	if EventType("bogus").Valid() {
		t.Error(`EventType("bogus").Valid() = true, want false`)
	}
}

// TestEnvSnapshotAndOutputEventTypes pins the schema-v1.0 event set added by
// the v0.1 evidence model: env.snapshot (serialized Env for offline report
// rebuild) and target.output (captured stdout/stderr tail).
func TestEnvSnapshotAndOutputEventTypes(t *testing.T) {
	for _, et := range []EventType{EventEnvSnapshot, EventOutput} {
		if !et.Valid() {
			t.Errorf("EventType %q: Valid() = false, want true", et)
		}
	}
	if got := EventEnvSnapshot; got != "env.snapshot" {
		t.Errorf("EventEnvSnapshot = %q, want %q", got, "env.snapshot")
	}
	if got := EventOutput; got != "target.output" {
		t.Errorf("EventOutput = %q, want %q", got, "target.output")
	}
}

func TestSourceValid(t *testing.T) {
	all := []Source{SourceTrace, SourceInspect, SourceEnv, SourceCLI}
	for _, s := range all {
		if !s.Valid() {
			t.Errorf("Source %q: Valid() = false, want true", s)
		}
	}
	if Source("bogus").Valid() {
		t.Error(`Source("bogus").Valid() = true, want false`)
	}
}

func TestCommonAccessors(t *testing.T) {
	now := at()
	ev := ProcessStart{Common{EventProcessStart, now, SourceTrace}}
	if got := ev.EventType(); got != EventProcessStart {
		t.Errorf("EventType() = %q, want %q", got, EventProcessStart)
	}
	if got := ev.Timestamp(); !got.Equal(now) {
		t.Errorf("Timestamp() = %v, want %v", got, now)
	}
	if got := ev.Source(); got != SourceTrace {
		t.Errorf("Source() = %q, want %q", got, SourceTrace)
	}
}

// TestRoundTrip marshals every concrete event, asserts the wire event_type
// discriminant, unmarshals into a fresh value of the same type, and requires
// a lossless round-trip.
func TestRoundTrip(t *testing.T) {
	now := at()
	tests := []struct {
		name string
		ev   Event
	}{
		{"process.start", ProcessStart{Common{EventProcessStart, now, SourceTrace}}},
		{"module.loaded", ModuleLoaded{Common{EventModuleLoaded, now, SourceTrace}, `C:\Windows\System32\kernel32.dll`, true}},
		{"search.failed", SearchFailed{Common{EventSearchFailed, now, SourceTrace}, "msvcp140.dll", []string{`C:\app`, `C:\Windows\System32`}}},
		{"loader.error", LoaderError{Common{EventLoaderError, now, SourceTrace}, `C:\app\foo.dll`, "parse failed"}},
		{"start.failed", StartFailed{Common{EventStartFailed, now, SourceCLI}, 740, "The requested operation requires elevation."}},
		{"exit", Exit{Common{EventExit, now, SourceTrace}, 0, 0}},
		{"graph.snapshot", GraphSnapshot{Common: Common{EventGraphSnapshot, now, SourceInspect}, Kind: "pe", Machine: "amd64", Class: "64", Nodes: []Node{{Module: "kernel32.dll", Status: "present"}, {Module: "user32.dll", Status: "missing"}}}},
		{"env.snapshot", EnvSnapshot{Common: Common{EventEnvSnapshot, now, SourceEnv}, Env: Env{OS: "windows", Arch: "amd64"}}},
		{"target.output", Output{Common: Common{EventOutput, now, SourceTrace}, Stream: "stderr", Lines: []string{"listen tcp :8080: bind: address already in use"}, Truncated: false}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.ev)
			if err != nil {
				t.Fatalf("Marshal(%T): %v", tt.ev, err)
			}

			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatalf("Unmarshal into map: %v", err)
			}
			if got := m["event_type"]; got != tt.name {
				t.Errorf("event_type = %v, want %q", got, tt.name)
			}

			decoded := decodeJSON(t, tt.ev, b)
			if !reflect.DeepEqual(decoded, tt.ev) {
				t.Errorf("round-trip mismatch:\n got %#v\nwant %#v", decoded, tt.ev)
			}
		})
	}
}

// decodeJSON unmarshals b into a fresh zero value of the same concrete type
// as ev and returns it as an Event.
func decodeJSON(t *testing.T, ev Event, b []byte) Event {
	t.Helper()
	v := reflect.New(reflect.TypeOf(ev))
	if err := json.Unmarshal(b, v.Interface()); err != nil {
		t.Fatalf("Unmarshal(%T): %v", ev, err)
	}
	return v.Elem().Interface().(Event)
}

// TestGraphSnapshotJSONFields pins the field-shadowing hazard: the graph's
// own "kind" and the event discriminant "event_type" must both marshal.
func TestGraphSnapshotJSONFields(t *testing.T) {
	ev := GraphSnapshot{Common: Common{EventGraphSnapshot, at(), SourceInspect}, Kind: "pe", Nodes: []Node{{Module: "a.dll", Status: "present"}}}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if got := m["event_type"]; got != "graph.snapshot" {
		t.Errorf("event_type = %v, want graph.snapshot", got)
	}
	if got := m["kind"]; got != "pe" {
		t.Errorf("kind = %v, want pe", got)
	}
	if _, ok := m["nodes"]; !ok {
		t.Error("nodes field missing from graph.snapshot JSON")
	}
}

func TestValidateAccepts(t *testing.T) {
	now := at()
	valid := []Event{
		ProcessStart{Common{EventProcessStart, now, SourceTrace}},
		ModuleLoaded{Common{EventModuleLoaded, now, SourceTrace}, "kernel32.dll", true},
		SearchFailed{Common{EventSearchFailed, now, SourceTrace}, "msvcp140.dll", []string{`C:\app`}},
		LoaderError{Common{EventLoaderError, now, SourceTrace}, "foo.dll", "parse failed"},
		StartFailed{Common{EventStartFailed, now, SourceCLI}, 740, "elevation required"},
		Exit{Common{EventExit, now, SourceTrace}, 1, 0},
		GraphSnapshot{Common: Common{EventGraphSnapshot, now, SourceInspect}, Kind: "pe", Nodes: []Node{{Module: "kernel32.dll", Status: "present"}}},
		EnvSnapshot{Common: Common{EventEnvSnapshot, now, SourceEnv}, Env: Env{OS: "linux", Arch: "amd64"}},
		Output{Common: Common{EventOutput, now, SourceTrace}, Stream: "stdout", Lines: []string{"hi"}, Truncated: true},
	}
	for _, ev := range valid {
		if err := Validate(ev); err != nil {
			t.Errorf("Validate(%T) = %v, want nil", ev, err)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	now := at()
	tests := []struct {
		name string
		ev   Event
	}{
		{"zero timestamp", ProcessStart{Common{EventProcessStart, time.Time{}, SourceTrace}}},
		{"invalid source", ProcessStart{Common{EventProcessStart, now, Source("bogus")}}},
		{"unknown event type", ProcessStart{Common{EventType("bogus"), now, SourceTrace}}},
		{"kind mismatches concrete type", ModuleLoaded{Common{EventExit, now, SourceTrace}, "kernel32.dll", true}},
		{"empty module path", ModuleLoaded{Common{EventModuleLoaded, now, SourceTrace}, "", true}},
		{"empty library", SearchFailed{Common{EventSearchFailed, now, SourceTrace}, "", []string{`C:\app`}}},
		{"empty loader path", LoaderError{Common{EventLoaderError, now, SourceTrace}, "", "boom"}},
		{"empty loader message", LoaderError{Common{EventLoaderError, now, SourceTrace}, "foo.dll", ""}},
		{"empty start message", StartFailed{Common{EventStartFailed, now, SourceCLI}, 740, ""}},
		{"empty graph kind", GraphSnapshot{Common: Common{EventGraphSnapshot, now, SourceInspect}, Kind: ""}},
		{"empty node module", GraphSnapshot{Common: Common{EventGraphSnapshot, now, SourceInspect}, Kind: "pe", Nodes: []Node{{Module: "", Status: "present"}}}},
		{"empty node status", GraphSnapshot{Common: Common{EventGraphSnapshot, now, SourceInspect}, Kind: "pe", Nodes: []Node{{Module: "kernel32.dll", Status: ""}}}},
		{"env snapshot empty os", EnvSnapshot{Common: Common{EventEnvSnapshot, now, SourceEnv}, Env: Env{Arch: "amd64"}}},
		{"env snapshot empty arch", EnvSnapshot{Common: Common{EventEnvSnapshot, now, SourceEnv}, Env: Env{OS: "windows"}}},
		{"output invalid stream", Output{Common: Common{EventOutput, now, SourceTrace}, Stream: "journald", Lines: nil}},
		{"nil event", nil},
		{"unknown concrete type", fakeEvent{Common{EventProcessStart, now, SourceTrace}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Validate(tt.ev); err == nil {
				t.Errorf("Validate(%T) = nil, want error", tt.ev)
			}
		})
	}
}
