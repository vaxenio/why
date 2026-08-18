package trace

import (
	"errors"
	"testing"
	"time"

	"why/internal/evidence"
)

// at returns a fixed UTC instant for event construction (same convention as
// internal/evidence/event_test.go: time.Date carries no monotonic clock, so
// events built with at() compare equal with reflect.DeepEqual).
func at() time.Time { return time.Date(2026, 8, 18, 12, 30, 0, 0, time.UTC) }

// stubTracer implements Tracer so the interface contract can be exercised
// without a real platform tracer.
type stubTracer struct {
	events []evidence.Event
}

func (s *stubTracer) Run() error { return nil }
func (s *stubTracer) Stop()      {}

// Events returns a snapshot copy of the collected events.
func (s *stubTracer) Events() []evidence.Event {
	return append([]evidence.Event(nil), s.events...)
}

// Compile-time assertion: stubTracer satisfies Tracer, pinning the exact
// method set (Run/Stop/Events) the platform tracers must implement.
var _ Tracer = (*stubTracer)(nil)

// TestNewReturnsTypedError covers the nil-tracer path: until the platform
// tracers land, New must return a typed error and must not panic.
func TestNewReturnsTypedError(t *testing.T) {
	tr, err := New()
	if tr != nil {
		t.Errorf("New() tracer = %v, want nil (no platform tracer yet)", tr)
	}
	if err == nil {
		t.Fatal("New() error = nil, want ErrUnsupportedPlatform")
	}
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Errorf("New() error = %v, want errors.Is(err, ErrUnsupportedPlatform)", err)
	}
}

// TestEventsReturnsSnapshot verifies the snapshot contract: mutating the
// returned slice must not change the tracer's collected events.
func TestEventsReturnsSnapshot(t *testing.T) {
	ev := evidence.ProcessStart{Common: evidence.Common{
		Kind: evidence.EventProcessStart,
		Time: at(),
		Src:  evidence.SourceTrace,
	}}
	tr := &stubTracer{events: []evidence.Event{ev}}

	got := tr.Events()
	if len(got) != 1 {
		t.Fatalf("Events() len = %d, want 1", len(got))
	}
	got[0] = nil // caller mutates the snapshot
	if got := tr.Events(); len(got) != 1 || got[0] == nil {
		t.Error("Events() returned a live slice: mutating it changed the tracer's state")
	}
}
