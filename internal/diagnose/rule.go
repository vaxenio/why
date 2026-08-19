// rule.go defines the Rule interface and the deterministic engine that
// applies rules to Evidence.
//
// Determinism is a hard contract: a rule must be a pure function of its
// Evidence input (no clocks, no filesystem, no randomness), and the engine
// evaluates rules in a fixed registration order so two runs over the same
// evidence produce the same diagnoses.
package diagnose

import (
	"fmt"
	"sort"

	"why/internal/evidence"
)

// Rule is one deterministic diagnosis rule. Rules are pure functions of the
// Evidence: they never probe the system themselves (inspectors, collectors
// and tracers already did that and recorded the facts in Evidence).
type Rule interface {
	// ID returns the stable rule identifier ("missing-dll", "wrong-arch",
	// ...). It is unique within the rule set.
	ID() string

	// Suppresses lists rule IDs this rule subsumes when it fires: a
	// diagnosis for "missing VC runtime" replaces the generic "missing
	// DLL" diagnosis for the same evidence. Suppression is transitive in
	// the engine: when this rule (or a rule that suppresses it) fires, the
	// entire subtree is dropped, so a root cause yields one diagnosis, not
	// a stack of increasingly-generic ones.
	Suppresses() []string

	// Evaluate inspects ev and returns a diagnosis when the rule's
	// required evidence is present and its negative conditions are not.
	// The second result reports whether the rule fired.
	Evaluate(ev *evidence.Evidence) (*Diagnosis, bool)
}

// Engine applies a fixed rule set to Evidence and yields the final
// diagnosis list. Rules fire independently; overlapping diagnoses are
// resolved by suppression (a fired rule drops diagnoses of the rules it
// suppresses) and the survivors are sorted by confidence descending, stable
// in registration order within a band.
type Engine struct {
	rules    []Rule
	suppress map[string][]string // fired rule ID -> rule IDs it suppresses
}

// NewEngine returns an Engine over rules, evaluated in the given order.
// Registration order is the tie-break for equal confidence, so callers pass
// the canonical order (specific rules before the generic ones they
// suppress).
func NewEngine(rules []Rule) *Engine {
	suppress := make(map[string][]string, len(rules))
	for _, r := range rules {
		suppress[r.ID()] = r.Suppresses()
	}
	return &Engine{rules: append([]Rule(nil), rules...), suppress: suppress}
}

// Evaluate applies every rule to ev and returns the final diagnoses,
// suppression applied and sorted by confidence descending. The result is
// never nil; it is empty exactly when no rule matched (CAUSE UNKNOWN).
// A rule that produces an ill-formed diagnosis is a programming error and
// panics, so defects surface in tests, never as silently skipped verdicts.
func (e *Engine) Evaluate(ev *evidence.Evidence) []*Diagnosis {
	fired := map[string]bool{}
	diags := make([]*Diagnosis, 0, len(e.rules))
	for _, r := range e.rules {
		d, ok := r.Evaluate(ev)
		if !ok {
			continue
		}
		if err := d.Validate(); err != nil {
			panic(fmt.Sprintf("rule %q produced an invalid diagnosis: %v", r.ID(), err))
		}
		fired[r.ID()] = true
		diags = append(diags, d)
	}

	// Suppression: compute the transitive closure of "suppresses" starting
	// from the rules that actually fired. A fired rule f subsumes the whole
	// subtree it suppresses: if f suppresses s, and s suppresses c, then c
	// is redundant too and is dropped. This keeps a single root cause from
	// producing a stack of increasingly-generic diagnoses.
	subsumed := map[string]bool{} // rule IDs dropped as suppressors
	queue := make([]string, 0, len(fired))
	for id := range fired {
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, s := range e.suppress[id] {
			if subsumed[s] {
				continue
			}
			subsumed[s] = true
			queue = append(queue, s) // propagate s's own suppressions
		}
	}

	out := diags[:0]
	for _, d := range diags {
		if subsumed[d.RuleID] {
			continue
		}
		out = append(out, d)
	}

	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Confidence > out[j].Confidence
	})
	return out
}
