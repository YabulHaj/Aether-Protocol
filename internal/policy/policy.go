package policy

import (
	"time"

	"aether-protocol/internal/envelope"
)

// Rule is ONE explicit permission. All four fields must match the
// incoming envelope exactly for the rule to apply. There are no
// wildcards, no prefixes, and no pattern matching anywhere in this
// file — see "security decisions" below for why that is deliberate.
type Rule struct {
	ID             string `json:"id"`               // human-readable label, e.g. "R-001"
	IdentityRef    string `json:"identity_ref"`     // WHO is permitted
	Intent         string `json:"intent,omitempty"` // WHY permitted (optional exact match)
	Capability     string `json:"capability"`       // WHAT permission class
	TargetResource string `json:"target_resource"`  // WHAT resource
	Operation      string `json:"operation"`        // WHAT verb
}

// Policy is a versioned, human-readable list of explicitly allowed
// rules. Anything not listed here is denied. There is no "deny rule"
// concept because there is nothing to deny FROM — deny is the default.
type Policy struct {
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

// Reason codes explain WHY a decision came out the way it did.
const (
	ReasonAllowedByRule   = "allow_matched_rule"
	ReasonNoMatchingRule  = "deny_no_matching_rule"
	ReasonEnvelopeInvalid = "deny_envelope_invalid"
	ReasonNoPolicyLoaded  = "deny_no_policy_loaded"
	ReasonMalformedRule   = "deny_no_matching_rule" // malformed rules are skipped, not matched
)

// Decision is the structured result of an evaluation. Every field is
// meant to end up in the evidence log later.
type Decision struct {
	Allow         bool      `json:"allow"`
	MatchedRuleID string    `json:"matched_rule_id"` // empty string when nothing matched
	ReasonCode    string    `json:"reason_code"`
	PolicyVersion string    `json:"policy_version"`
	Timestamp     time.Time `json:"timestamp"`
}

// PolicyEngine is the contract. Note it returns a Decision and NO error:
// a denial is a perfectly normal, successful outcome, not a failure.
// Mixing "denied" and "something broke" into one error channel is how
// systems accidentally fail open.
type PolicyEngine interface {
	Evaluate(env *envelope.ActionEnvelope, now time.Time) Decision
}

// RuleBasedEngine is the real (no longer stubbed) implementation.
type RuleBasedEngine struct {
	policy Policy
}

func NewRuleBasedEngine(p Policy) *RuleBasedEngine {
	return &RuleBasedEngine{policy: p}
}

// PolicyVersion exposes which policy version this engine is running.
func (e *RuleBasedEngine) PolicyVersion() string {
	return e.policy.Version
}

// deny builds a denial decision. Every exit path that isn't an explicit
// match goes through here, so it is impossible to accidentally return
// an allow.
func (e *RuleBasedEngine) deny(reason string, now time.Time) Decision {
	return Decision{
		Allow:         false,
		MatchedRuleID: "",
		ReasonCode:    reason,
		PolicyVersion: e.policy.Version,
		Timestamp:     now,
	}
}

// Evaluate decides whether an envelope is permitted.
//
// The structure is deliberately boring: deny, deny, deny, and only at
// the very end, on an exact four-field match, allow.
func (e *RuleBasedEngine) Evaluate(env *envelope.ActionEnvelope, now time.Time) Decision {
	// A missing envelope is not a reason to guess. Deny.
	if env == nil {
		return e.deny(ReasonEnvelopeInvalid, now)
	}

	// Re-validate the envelope here even though the HTTP layer already
	// did. The engine must never trust that someone else checked.
	if err := env.Validate(now); err != nil {
		return e.deny(ReasonEnvelopeInvalid, now)
	}

	// An empty policy means nothing is permitted — NOT that everything is.
	if len(e.policy.Rules) == 0 {
		return e.deny(ReasonNoPolicyLoaded, now)
	}

	for _, r := range e.policy.Rules {
		// A rule with any blank field is treated as malformed and skipped,
		// so a half-filled rule can never accidentally match something.
		if r.IdentityRef == "" || r.Capability == "" ||
			r.TargetResource == "" || r.Operation == "" {
			continue
		}

		// Exact match on required fields and optional intent. Any single mismatch = no match.
		if r.IdentityRef == env.IdentityRef &&
			(r.Intent == "" || r.Intent == env.Intent) &&
			r.Capability == env.Capability &&
			r.TargetResource == env.TargetResource &&
			r.Operation == env.Operation {
			return Decision{
				Allow:         true,
				MatchedRuleID: r.ID,
				ReasonCode:    ReasonAllowedByRule,
				PolicyVersion: e.policy.Version,
				Timestamp:     now,
			}
		}
	}

	// Fell through every rule without an exact match. This is the
	// implicit deny.
	return e.deny(ReasonNoMatchingRule, now)
}
