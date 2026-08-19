// Package diagnose defines the diagnosis model and the deterministic rule
// engine that turns Evidence into Diagnoses. A diagnosis is only ever
// emitted when its rule's required evidence is present; the engine never
// guesses. When no rule matches, the caller reports CAUSE UNKNOWN with the
// facts that were collected.
package diagnose

import (
	"fmt"
)

// Confidence is how strongly the evidence supports a diagnosis, on a 0-100
// scale. v0.1 uses three bands; a rule never emits below ConfLow, and the
// bands are chosen so a claim is never stronger than its evidence:
//
//	ConfHigh   (100): the evidence is a direct fact (a loader error code,
//	                  a missing module in the dependency graph, ...).
//	ConfMedium (75):  the evidence is concrete but the cause attribution
//	                  involves a documented inference.
//	ConfLow    (50):  the evidence is the target's own output; the cause is
//	                  attributed with explicit uncertainty.
type Confidence int

const (
	ConfLow    Confidence = 50
	ConfMedium Confidence = 75
	ConfHigh   Confidence = 100
)

// Valid reports whether c is a known confidence band.
func (c Confidence) Valid() bool {
	switch c {
	case ConfLow, ConfMedium, ConfHigh:
		return true
	}
	return false
}

// String returns the human band name used in reports: "low", "medium",
// "high".
func (c Confidence) String() string {
	switch c {
	case ConfLow:
		return "low"
	case ConfMedium:
		return "medium"
	case ConfHigh:
		return "high"
	}
	return fmt.Sprintf("confidence(%d)", c)
}

// Diagnosis is one rule verdict. Every field is human-facing and printed by
// the report layer as CAUSE / WHY / EVIDENCE / LIKELY FIX / CONFIDENCE.
//
// Evidence must contain only facts that were actually observed: event lines,
// error codes, graph nodes. A diagnosis with no evidence is a bug.
type Diagnosis struct {
	// RuleID is the stable rule identifier, e.g. "missing-dll".
	RuleID string
	// Cause is the one-line human cause (the CAUSE section).
	Cause string
	// Why is the explanation of how the evidence leads to the cause.
	Why string
	// Evidence lists the concrete observed facts, one per line.
	Evidence []string
	// Fix is the likely remedy (never an auto-fix; always advisory).
	Fix string
	// Confidence is the evidence strength band.
	Confidence Confidence
}

// Validate checks that a Diagnosis is well-formed enough to render: a stable
// rule id, non-empty cause/why/fix, at least one evidence line, and a known
// confidence band. The rule engine and the report layer both rely on this.
func (d *Diagnosis) Validate() error {
	if d.RuleID == "" {
		return fmt.Errorf("diagnose: diagnosis has empty rule id")
	}
	if d.Cause == "" {
		return fmt.Errorf("diagnose: diagnosis %q has empty cause", d.RuleID)
	}
	if d.Why == "" {
		return fmt.Errorf("diagnose: diagnosis %q has empty why", d.RuleID)
	}
	if len(d.Evidence) == 0 {
		return fmt.Errorf("diagnose: diagnosis %q has no evidence", d.RuleID)
	}
	if d.Fix == "" {
		return fmt.Errorf("diagnose: diagnosis %q has empty fix", d.RuleID)
	}
	if !d.Confidence.Valid() {
		return fmt.Errorf("diagnose: diagnosis %q has invalid confidence %d", d.RuleID, d.Confidence)
	}
	return nil
}
