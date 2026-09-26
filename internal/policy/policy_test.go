package policy

import (
	"testing"
	"time"

	"aether-protocol/internal/envelope"
)

// testPolicy is a small, deliberately narrow policy: the finance bot may
// READ invoice/12345 and nothing else. Every test below probes the edges
// of that single permission.
func testPolicy() Policy {
	return Policy{
		Version: "v0.1.0",
		Rules: []Rule{
			{
				ID:             "R-001",
				IdentityRef:    "agent://finance-bot-01",
				Capability:     "read:invoices",
				TargetResource: "invoice/12345",
				Operation:      "GET",
			},
		},
	}
}

// validEnvelope returns an envelope that exactly matches R-001 and is fresh.
// Each test starts here and changes exactly one thing.
func validEnvelope(now time.Time) envelope.ActionEnvelope {
	return envelope.ActionEnvelope{
		IdentityRef:    "agent://finance-bot-01",
		Intent:         "summarize_invoice",
		Capability:     "read:invoices",
		TargetResource: "invoice/12345",
		Operation:      "GET",
		Audience:       "aether-gateway",
		IssuedAt:       now.Add(-1 * time.Minute),
		Expiry:         now.Add(5 * time.Minute),
		NonceID:        "nonce-abc-123",
		PayloadHash:    "sha256:deadbeef",
	}
}

func TestEvaluate_AllowExactMatch(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	engine := NewRuleBasedEngine(testPolicy())
	env := validEnvelope(now)

	d := engine.Evaluate(&env, now)

	if !d.Allow {
		t.Fatalf("expected allow, got deny with reason %q", d.ReasonCode)
	}
	if d.MatchedRuleID != "R-001" {
		t.Fatalf("expected matched rule R-001, got %q", d.MatchedRuleID)
	}
	if d.ReasonCode != ReasonAllowedByRule {
		t.Fatalf("expected reason %q, got %q", ReasonAllowedByRule, d.ReasonCode)
	}
	if d.PolicyVersion != "v0.1.0" {
		t.Fatalf("expected policy version v0.1.0, got %q", d.PolicyVersion)
	}
	if !d.Timestamp.Equal(now) {
		t.Fatalf("expected timestamp %v, got %v", now, d.Timestamp)
	}
}

func TestEvaluate_DenyCases(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		policy     Policy
		mutate     func(e *envelope.ActionEnvelope)
		wantReason string
	}{
		// --- Implicit deny: nothing in policy covers this at all ---
		{
			name:       "implicit deny - completely unknown identity",
			policy:     testPolicy(),
			mutate:     func(e *envelope.ActionEnvelope) { e.IdentityRef = "agent://unknown-bot-99" },
			wantReason: ReasonNoMatchingRule,
		},
		{
			name:       "implicit deny - empty policy allows nothing",
			policy:     Policy{Version: "v0.1.0", Rules: []Rule{}},
			mutate:     func(e *envelope.ActionEnvelope) {},
			wantReason: ReasonNoPolicyLoaded,
		},

		// --- Boundary failures: one field off, everything else correct ---
		{
			name:       "boundary - wrong target resource",
			policy:     testPolicy(),
			mutate:     func(e *envelope.ActionEnvelope) { e.TargetResource = "invoice/99999" },
			wantReason: ReasonNoMatchingRule,
		},
		{
			name:   "boundary - target is a near-miss (trailing character)",
			policy: testPolicy(),
			mutate: func(e *envelope.ActionEnvelope) { e.TargetResource = "invoice/123456" },
			// Proves matching is exact, not prefix-based.
			wantReason: ReasonNoMatchingRule,
		},
		{
			name:       "boundary - wrong capability",
			policy:     testPolicy(),
			mutate:     func(e *envelope.ActionEnvelope) { e.Capability = "read:payroll" },
			wantReason: ReasonNoMatchingRule,
		},
		{
			name:       "boundary - wrong operation",
			policy:     testPolicy(),
			mutate:     func(e *envelope.ActionEnvelope) { e.Operation = "DELETE" },
			wantReason: ReasonNoMatchingRule,
		},
		{
			name:   "boundary - operation case mismatch",
			policy: testPolicy(),
			mutate: func(e *envelope.ActionEnvelope) { e.Operation = "get" },
			// Proves matching is case-sensitive, not normalized.
			wantReason: ReasonNoMatchingRule,
		},

		// --- Privilege escalation attempts ---
		{
			name:   "escalation - allowed identity claims admin capability",
			policy: testPolicy(),
			mutate: func(e *envelope.ActionEnvelope) {
				e.Capability = "admin:*"
			},
			wantReason: ReasonNoMatchingRule,
		},
		{
			name:   "escalation - allowed identity upgrades read to write on same target",
			policy: testPolicy(),
			mutate: func(e *envelope.ActionEnvelope) {
				e.Capability = "write:invoices"
				e.Operation = "PUT"
			},
			wantReason: ReasonNoMatchingRule,
		},
		{
			name:   "escalation - wildcard target does not match anything",
			policy: testPolicy(),
			mutate: func(e *envelope.ActionEnvelope) {
				e.TargetResource = "invoice/*"
			},
			wantReason: ReasonNoMatchingRule,
		},
		{
			name:   "escalation - benign intent does not override capability mismatch",
			policy: testPolicy(),
			mutate: func(e *envelope.ActionEnvelope) {
				e.Intent = "summarize_invoice" // looks legitimate
				e.Capability = "delete:invoices"
				e.Operation = "DELETE"
			},
			wantReason: ReasonNoMatchingRule,
		},

		// --- Invalid envelopes are denied before rule matching ---
		{
			name:   "invalid envelope - expired",
			policy: testPolicy(),
			mutate: func(e *envelope.ActionEnvelope) {
				e.IssuedAt = now.Add(-10 * time.Minute)
				e.Expiry = now.Add(-1 * time.Minute)
			},
			wantReason: ReasonEnvelopeInvalid,
		},
		{
			name:       "invalid envelope - missing nonce",
			policy:     testPolicy(),
			mutate:     func(e *envelope.ActionEnvelope) { e.NonceID = "" },
			wantReason: ReasonEnvelopeInvalid,
		},
		{
			name:       "invalid envelope - missing payload hash",
			policy:     testPolicy(),
			mutate:     func(e *envelope.ActionEnvelope) { e.PayloadHash = "" },
			wantReason: ReasonEnvelopeInvalid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			engine := NewRuleBasedEngine(tc.policy)
			env := validEnvelope(now)
			tc.mutate(&env)

			d := engine.Evaluate(&env, now)

			if d.Allow {
				t.Fatalf("FAIL OPEN: expected deny, got allow (matched rule %q)", d.MatchedRuleID)
			}
			if d.ReasonCode != tc.wantReason {
				t.Fatalf("expected reason %q, got %q", tc.wantReason, d.ReasonCode)
			}
			if d.MatchedRuleID != "" {
				t.Fatalf("a denial must not report a matched rule, got %q", d.MatchedRuleID)
			}
			if d.PolicyVersion != tc.policy.Version {
				t.Fatalf("expected policy version %q, got %q", tc.policy.Version, d.PolicyVersion)
			}
		})
	}
}

func TestEvaluate_NilEnvelopeIsDenied(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	engine := NewRuleBasedEngine(testPolicy())

	d := engine.Evaluate(nil, now)

	if d.Allow {
		t.Fatal("FAIL OPEN: a nil envelope must never be allowed")
	}
	if d.ReasonCode != ReasonEnvelopeInvalid {
		t.Fatalf("expected reason %q, got %q", ReasonEnvelopeInvalid, d.ReasonCode)
	}
}

func TestEvaluate_MalformedRuleNeverMatches(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	// A rule with blank fields must be skipped, never treated as a match.
	badPolicy := Policy{
		Version: "v0.1.0",
		Rules: []Rule{
			{ID: "R-BAD", IdentityRef: "agent://finance-bot-01", Capability: "", TargetResource: "", Operation: ""},
		},
	}
	engine := NewRuleBasedEngine(badPolicy)
	env := validEnvelope(now)

	d := engine.Evaluate(&env, now)

	if d.Allow {
		t.Fatal("FAIL OPEN: a malformed rule must never produce an allow")
	}
}

func TestEvaluate_IsDeterministic(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	engine := NewRuleBasedEngine(testPolicy())
	env := validEnvelope(now)

	first := engine.Evaluate(&env, now)
	second := engine.Evaluate(&env, now)

	if first != second {
		t.Fatalf("same input produced different decisions: %+v vs %+v", first, second)
	}
}
