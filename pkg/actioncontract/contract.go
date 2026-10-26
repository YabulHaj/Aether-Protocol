package actioncontract

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	ErrInvalidAuthorizedAction = errors.New("action contract: authorized target and operation are required")
	ErrMissingPayload          = errors.New("action contract: payload is required")
	ErrMalformedPayload        = errors.New("action contract: malformed or ambiguous payload")
	ErrActionMismatch          = errors.New("action contract: payload action differs from authorized action")
)

// AuthorizedAction is the action approved by the outer authorization boundary.
type AuthorizedAction struct {
	TargetResource string
	Operation      string
}

// Payload is the strict reference JSON action format.
// Application-specific input belongs inside Arguments.
type Payload struct {
	TargetResource string          `json:"target_resource"`
	Operation      string          `json:"operation"`
	Arguments      json.RawMessage `json:"arguments,omitempty"`
}

// ValidatePayload validates the reference payload and ensures its action-defining
// fields exactly match the authorized outer action. It does not make an
// authorization decision and must not be treated as proof of caller identity.
func ValidatePayload(authorized AuthorizedAction, rawPayload string) (Payload, error) {
	if strings.TrimSpace(authorized.TargetResource) == "" ||
		strings.TrimSpace(authorized.Operation) == "" {
		return Payload{}, ErrInvalidAuthorizedAction
	}

	if strings.TrimSpace(rawPayload) == "" {
		return Payload{}, ErrMissingPayload
	}

	// Reject duplicate keys at any depth. Different JSON parsers can otherwise
	// interpret a repeated action or argument key differently.
	if err := rejectDuplicateJSONKeys(rawPayload); err != nil {
		return Payload{}, fmt.Errorf("%w: %v", ErrMalformedPayload, err)
	}

	if err := validateTopLevelPayloadKeys(rawPayload); err != nil {
		return Payload{}, fmt.Errorf("%w: %v", ErrMalformedPayload, err)
	}
	decoder := json.NewDecoder(strings.NewReader(rawPayload))
	decoder.DisallowUnknownFields()

	var payload Payload
	if err := decoder.Decode(&payload); err != nil {
		return Payload{}, fmt.Errorf("%w: %v", ErrMalformedPayload, err)
	}

	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return Payload{}, fmt.Errorf("%w: multiple JSON values", ErrMalformedPayload)
		}
		return Payload{}, fmt.Errorf("%w: %v", ErrMalformedPayload, err)
	}

	if strings.TrimSpace(payload.TargetResource) == "" ||
		strings.TrimSpace(payload.Operation) == "" {
		return Payload{}, fmt.Errorf(
			"%w: target_resource and operation are required",
			ErrMalformedPayload,
		)
	}

	if payload.TargetResource != authorized.TargetResource ||
		payload.Operation != authorized.Operation {
		return Payload{}, ErrActionMismatch
	}

	return payload, nil
}

func validateTopLevelPayloadKeys(rawPayload string) error {
	var fields map[string]json.RawMessage

	if err := json.Unmarshal([]byte(rawPayload), &fields); err != nil {
		return err
	}
	if fields == nil {
		return errors.New("payload must be a JSON object")
	}

	for key := range fields {
		switch key {
		case "target_resource", "operation", "arguments":
			// Only canonical top-level field names are allowed.
		default:
			return fmt.Errorf("unknown or non-canonical top-level field %q", key)
		}
	}

	return nil
}
func rejectDuplicateJSONKeys(raw string) error {
	decoder := json.NewDecoder(strings.NewReader(raw))

	if err := consumeJSONValue(decoder); err != nil {
		return err
	}

	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}

	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})

		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}

			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}

			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}

			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}

		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("object is not closed")
		}

	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}

		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("array is not closed")
		}

	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}

	return nil
}
