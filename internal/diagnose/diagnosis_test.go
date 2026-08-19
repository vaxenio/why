package diagnose

import (
	"testing"

	"why/internal/evidence"
)

// staticRule is a scripted rule for engine tests: it fires with a fixed
// diagnosis and suppresses the given rules.
type staticRule struct {
	id         string
	suppresses []string
	diag       *Diagnosis
	fire       bool
}

func (r *staticRule) ID() string           { return r.id }
func (r *staticRule) Suppresses() []string { return r.suppresses }
func (r *staticRule) Evaluate(ev *evidence.Evidence) (*Diagnosis, bool) {
	return r.diag, r.fire
}

func validDiag(id string) *Diagnosis {
	return &Diagnosis{
		RuleID:     id,
		Cause:      "cause " + id,
		Why:        "why " + id,
		Evidence:   []string{"evidence for " + id},
		Fix:        "fix " + id,
		Confidence: ConfHigh,
	}
}

func TestConfidenceBands(t *testing.T) {
	for _, c := range []Confidence{ConfLow, ConfMedium, ConfHigh} {
		if !c.Valid() {
			t.Errorf("Confidence(%d).Valid() = false, want true", c)
		}
	}
	if Confidence(0).Valid() || Confidence(99).Valid() {
		t.Error("out-of-band confidence reported valid")
	}
	if got, want := ConfHigh.String(), "high"; got != want {
		t.Errorf("ConfHigh.String() = %q, want %q", got, want)
	}
	if got, want := ConfMedium.String(), "medium"; got != want {
		t.Errorf("ConfMedium.String() = %q, want %q", got, want)
	}
	if got, want := ConfLow.String(), "low"; got != want {
		t.Errorf("ConfLow.String() = %q, want %q", got, want)
	}
}

func TestDiagnosisValidate(t *testing.T) {
	base := validDiag("r")
	if err := base.Validate(); err != nil {
		t.Fatalf("valid diagnosis rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Diagnosis)
	}{
		{"empty rule id", func(d *Diagnosis) { d.RuleID = "" }},
		{"empty cause", func(d *Diagnosis) { d.Cause = "" }},
		{"empty why", func(d *Diagnosis) { d.Why = "" }},
		{"no evidence", func(d *Diagnosis) { d.Evidence = nil }},
		{"empty fix", func(d *Diagnosis) { d.Fix = "" }},
		{"invalid confidence", func(d *Diagnosis) { d.Confidence = 60 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := validDiag("r")
			tt.mutate(d)
			if err := d.Validate(); err == nil {
				t.Error("Validate() = nil, want error")
			}
		})
	}
}

func TestEngineNoRulesNoDiagnosis(t *testing.T) {
	got := NewEngine(nil).Evaluate(&evidence.Evidence{})
	if got == nil {
		t.Fatal("Evaluate returned nil, want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("Evaluate len = %d, want 0", len(got))
	}
}

func TestEngineFiresInOrderAndSortsByConfidence(t *testing.T) {
	low := validDiag("low")
	low.Confidence = ConfLow
	high := validDiag("high")
	high.Confidence = ConfHigh
	med := validDiag("med")
	med.Confidence = ConfMedium

	rules := []Rule{
		&staticRule{id: "low", diag: low, fire: true},
		&staticRule{id: "high", diag: high, fire: true},
		&staticRule{id: "med", diag: med, fire: true},
	}
	got := NewEngine(rules).Evaluate(&evidence.Evidence{})
	if len(got) != 3 {
		t.Fatalf("Evaluate len = %d, want 3", len(got))
	}
	// Sorted by confidence descending regardless of registration order.
	wantOrder := []string{"high", "med", "low"}
	for i, id := range wantOrder {
		if got[i].RuleID != id {
			t.Errorf("diagnosis[%d] = %q, want %q", i, got[i].RuleID, id)
		}
	}
}

// TestEngineSuppression pins the core overlap contract: when a specific rule
// fires, diagnoses of the rules it suppresses are dropped, and the
// suppression is applied to ALL such diagnoses even when they fired first.
func TestEngineSuppression(t *testing.T) {
	generic := validDiag("generic")
	specific := validDiag("specific")
	rules := []Rule{
		&staticRule{id: "generic", diag: generic, fire: true},
		&staticRule{id: "specific", suppresses: []string{"generic"}, diag: specific, fire: true},
	}
	got := NewEngine(rules).Evaluate(&evidence.Evidence{})
	if len(got) != 1 {
		t.Fatalf("Evaluate len = %d, want 1 (generic suppressed)", len(got))
	}
	if got[0].RuleID != "specific" {
		t.Errorf("surviving diagnosis = %q, want %q", got[0].RuleID, "specific")
	}
}

// TestEngineSuppressionTransitive pins that suppression is transitive: when
// a (which suppresses b) fires and b suppresses c, then c is dropped too —
// the surviving verdict claims the whole subtree, so a single root cause
// cannot emit a stack of increasingly-generic diagnoses.
func TestEngineSuppressionTransitive(t *testing.T) {
	rules := []Rule{
		&staticRule{id: "a", suppresses: []string{"b"}, diag: validDiag("a"), fire: true},
		&staticRule{id: "b", suppresses: []string{"c"}, diag: validDiag("b"), fire: true},
		&staticRule{id: "c", diag: validDiag("c"), fire: true},
	}
	got := NewEngine(rules).Evaluate(&evidence.Evidence{})
	if len(got) != 1 {
		t.Fatalf("Evaluate len = %d, want 1 (b and c suppressed transitively)", len(got))
	}
	if got[0].RuleID != "a" {
		t.Errorf("surviving diagnosis = %q, want %q", got[0].RuleID, "a")
	}
}

// TestEngineNonFiringRuleSuppressesNothing pins that a rule's Suppresses
// list only matters when the rule actually fires.
func TestEngineNonFiringRuleSuppressesNothing(t *testing.T) {
	rules := []Rule{
		&staticRule{id: "generic", diag: validDiag("generic"), fire: true},
		&staticRule{id: "specific", suppresses: []string{"generic"}, fire: false},
	}
	got := NewEngine(rules).Evaluate(&evidence.Evidence{})
	if len(got) != 1 || got[0].RuleID != "generic" {
		t.Errorf("survivors = %v, want generic (specific did not fire)", got)
	}
}
