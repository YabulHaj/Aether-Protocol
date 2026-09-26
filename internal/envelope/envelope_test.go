package envelope

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// validEnvelope returns a fully-filled-in, currently-valid envelope for
// a given "now". Every negative test below starts from this known-good
// envelope and breaks exactly one thing, so we know precisely which
// error should come back.
func validEnvelope(now time.Time) ActionEnvelope {
	return ActionEnvelope{
		IdentityRef:    "agent://finance-bot-01",
		Intent:         "summarize_invoice",
		Capability:     "read:invoices",
		TargetResource: "invoice/12345",
		Operation:      "GET",
		Constraints:    map[string]string{"max_rows": "100"},
		Audience:       "aether-gateway",
		IssuedAt:       now.Add(-1 * time.Minute),
		Expiry:         now.Add(5 * time.Minute),
		NonceID:        "nonce-abc-123",
		PayloadHash:    "sha256:deadbeef",
	}
}

func TestValidate_ValidEnvelope(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	env := validEnvelope(now)

	if err := env.Validate(now); err != nil {
		t.Fatalf("expected a valid envelope to pass, got error: %v", err)
	}
}

func TestValidate_NegativeCases(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		mutate  func(e *ActionEnvelope) // how to break the valid envelope
		wantErr error                   // exact error we expect back
	}{
		{"missing identity ref", func(e *ActionEnvelope) { e.IdentityRef = "" }, ErrMissingIdentityRef},
		{"missing intent", func(e *ActionEnvelope) { e.Intent = "" }, ErrMissingIntent},
		{"missing capability", func(e *ActionEnvelope) { e.Capability = "" }, ErrMissingCapability},
		{"missing target resource", func(e *ActionEnvelope) { e.TargetResource = "" }, ErrMissingTargetResource},
		{"missing operation", func(e *ActionEnvelope) { e.Operation = "" }, ErrMissingOperation},
		{"missing audience", func(e *ActionEnvelope) { e.Audience = "" }, ErrMissingAudience},
		{"missing nonce id", func(e *ActionEnvelope) { e.NonceID = "" }, ErrMissingNonceID},
		{"missing payload hash", func(e *ActionEnvelope) { e.PayloadHash = "" }, ErrMissingPayloadHash},
		{"missing issued at", func(e *ActionEnvelope) { e.IssuedAt = time.Time{} }, ErrMissingIssuedAt},
		{"missing expiry", func(e *ActionEnvelope) { e.Expiry = time.Time{} }, ErrMissingExpiry},
		{
			// "mismatched data": the envelope claims to expire before it
			// was even issued — internally inconsistent, not just missing.
			name: "expiry before issued at (mismatched timing)",
			mutate: func(e *ActionEnvelope) {
				e.IssuedAt = now
				e.Expiry = now.Add(-1 * time.Minute)
			},
			wantErr: ErrExpiryBeforeIssuedAt,
		},
		{
			// "malformed input": a timestamp that claims to be from the
			// future relative to "now" — structurally present but
			// logically broken.
			name: "issued in the future (malformed timestamp)",
			mutate: func(e *ActionEnvelope) {
				e.IssuedAt = now.Add(10 * time.Minute)
				e.Expiry = now.Add(20 * time.Minute)
			},
			wantErr: ErrIssuedInFuture,
		},
		{
			name: "expired envelope",
			mutate: func(e *ActionEnvelope) {
				e.IssuedAt = now.Add(-10 * time.Minute)
				e.Expiry = now.Add(-1 * time.Minute)
			},
			wantErr: ErrExpired,
		},
		{
			name: "payload hash mismatch (tampered payload)",
			mutate: func(e *ActionEnvelope) {
				e.Payload = "legitimate data"
				e.PayloadHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
			},
			wantErr: ErrPayloadHashMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := validEnvelope(now) // start from known-good each time
			tc.mutate(&env)           // break exactly one thing

			err := env.Validate(now)
			if err == nil {
				t.Fatalf("expected error %v, got nil", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected error %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidate_ValidPayloadHash(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	payload := `{"action":"transfer","amount":100}`
	hash := ComputePayloadHash([]byte(payload))

	env := validEnvelope(now)
	env.Payload = payload
	env.PayloadHash = hash

	if err := env.Validate(now); err != nil {
		t.Fatalf("expected matching payload hash to validate, got: %v", err)
	}

	// Also verify without sha256: prefix (raw hex)
	env.PayloadHash = strings.TrimPrefix(hash, "sha256:")
	if err := env.Validate(now); err != nil {
		t.Fatalf("expected raw hex payload hash to validate, got: %v", err)
	}
}
