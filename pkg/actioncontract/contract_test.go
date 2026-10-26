package actioncontract

import (
	"errors"
	"testing"
)

func TestValidatePayloadAcceptsMatchingAction(t *testing.T) {
	raw := `{"target_resource":"invoice/12345","operation":"GET","arguments":{"invoice_id":"12345"}}`

	got, err := ValidatePayload(
		AuthorizedAction{
			TargetResource: "invoice/12345",
			Operation:      "GET",
		},
		raw,
	)
	if err != nil {
		t.Fatalf("expected matching payload to validate, got: %v", err)
	}

	if got.TargetResource != "invoice/12345" || got.Operation != "GET" {
		t.Fatalf("unexpected validated action: %+v", got)
	}

	if string(got.Arguments) != `{"invoice_id":"12345"}` {
		t.Fatalf("unexpected arguments: %s", got.Arguments)
	}
}

func TestValidatePayloadRejectsActionMismatch(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "target mismatch",
			raw:  `{"target_resource":"invoice/99999","operation":"GET"}`,
		},
		{
			name: "operation mismatch",
			raw:  `{"target_resource":"invoice/12345","operation":"DELETE"}`,
		},
	}

	authorized := AuthorizedAction{
		TargetResource: "invoice/12345",
		Operation:      "GET",
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidatePayload(authorized, tc.raw)
			if !errors.Is(err, ErrActionMismatch) {
				t.Fatalf("expected ErrActionMismatch, got: %v", err)
			}
		})
	}
}

func TestValidatePayloadRejectsMalformedOrAmbiguousJSON(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "duplicate target key",
			raw:  `{"target_resource":"invoice/12345","target_resource":"invoice/99999","operation":"GET"}`,
		},
		{
			name: "case-variant operation key",
			raw:  `{"target_resource":"invoice/12345","operation":"GET","Operation":"DELETE"}`,
		},
		{
			name: "case-variant target key",
			raw:  `{"target_resource":"invoice/12345","Target_Resource":"invoice/99999","operation":"GET"}`,
		},
		{
			name: "non-canonical top-level key",
			raw:  `{"Target_Resource":"invoice/12345","operation":"GET"}`,
		},
		{
			name: "duplicate nested argument key",
			raw:  `{"target_resource":"invoice/12345","operation":"GET","arguments":{"invoice_id":"12345","invoice_id":"99999"}}`,
		},
		{
			name: "unknown top-level key",
			raw:  `{"target_resource":"invoice/12345","operation":"GET","execute_anyway":true}`,
		},
		{
			name: "multiple JSON values",
			raw:  `{"target_resource":"invoice/12345","operation":"GET"} {"operation":"DELETE"}`,
		},
		{
			name: "malformed JSON",
			raw:  `{"target_resource":`,
		},
		{
			name: "missing target",
			raw:  `{"operation":"GET"}`,
		},
	}

	authorized := AuthorizedAction{
		TargetResource: "invoice/12345",
		Operation:      "GET",
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidatePayload(authorized, tc.raw)
			if !errors.Is(err, ErrMalformedPayload) {
				t.Fatalf("expected ErrMalformedPayload, got: %v", err)
			}
		})
	}
}
func TestValidatePayloadRejectsMissingPayloadOrAuthority(t *testing.T) {
	authorized := AuthorizedAction{
		TargetResource: "invoice/12345",
		Operation:      "GET",
	}

	if _, err := ValidatePayload(authorized, " "); !errors.Is(err, ErrMissingPayload) {
		t.Fatalf("expected ErrMissingPayload, got: %v", err)
	}

	if _, err := ValidatePayload(AuthorizedAction{}, `{"target_resource":"invoice/12345","operation":"GET"}`); !errors.Is(err, ErrInvalidAuthorizedAction) {
		t.Fatalf("expected ErrInvalidAuthorizedAction, got: %v", err)
	}
}
