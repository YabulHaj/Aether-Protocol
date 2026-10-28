package actioncontract

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"aether-protocol/internal/envelope"
)

const maxEnvelopeBytes int64 = 1 << 20

// SimulatedEffect records an in-memory effect made only after action binding
// has been validated. It is not evidence of a real external-world action.
type SimulatedEffect struct {
	TargetResource string          `json:"target_resource"`
	Operation      string          `json:"operation"`
	Arguments      json.RawMessage `json:"arguments,omitempty"`
}

// ReferenceHandler is a demonstration downstream consumer for the strict
// action contract. It validates payload-to-envelope consistency and records
// simulated effects. It does not authenticate the caller or independently
// authorize the action; do not expose it as a production authorization service.
type ReferenceHandler struct {
	mu       sync.Mutex
	requests int
	effects  []SimulatedEffect
}

// NewReferenceHandler creates a reference consumer with an empty effect ledger.
func NewReferenceHandler() *ReferenceHandler {
	return &ReferenceHandler{}
}

// RequestCount returns the number of HTTP requests received by this handler.
func (h *ReferenceHandler) RequestCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.requests
}

// EffectCount returns the number of simulated effects recorded after validation.
func (h *ReferenceHandler) EffectCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.effects)
}

// Effects returns a snapshot of the simulated effect ledger.
func (h *ReferenceHandler) Effects() []SimulatedEffect {
	h.mu.Lock()
	defer h.mu.Unlock()

	out := make([]SimulatedEffect, len(h.effects))
	copy(out, h.effects)
	for i := range out {
		out[i].Arguments = append(json.RawMessage(nil), out[i].Arguments...)
	}
	return out
}

func (h *ReferenceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.requests++
	h.mu.Unlock()

	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{
			"error": "method_not_allowed",
		})
		return
	}

	if r.URL.Path != "/v1/action" {
		http.NotFound(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxEnvelopeBytes+1))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body_read_failed"})
		return
	}
	if int64(len(body)) > maxEnvelopeBytes {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body_too_large"})
		return
	}

	env, err := decodeEnvelopeJSON(string(body))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_envelope_json"})
		return
	}

	// This validates envelope completeness, freshness, and the supplied
	// payload digest. It does not authenticate the HTTP caller.
	if err := env.Validate(time.Now().UTC()); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_envelope"})
		return
	}

	payload, err := ValidatePayload(
		AuthorizedAction{
			TargetResource: env.TargetResource,
			Operation:      env.Operation,
		},
		env.Payload,
	)
	if err != nil {
		if errors.Is(err, ErrActionMismatch) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "action_mismatch"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_action_payload"})
		return
	}

	effect := SimulatedEffect{
		TargetResource: payload.TargetResource,
		Operation:      payload.Operation,
		Arguments:      append(json.RawMessage(nil), payload.Arguments...),
	}

	h.mu.Lock()
	h.effects = append(h.effects, effect)
	count := len(h.effects)
	h.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":          "simulated_effect_recorded",
		"target_resource": effect.TargetResource,
		"operation":       effect.Operation,
		"effect_count":    count,
	})
}

func decodeEnvelopeJSON(raw string) (envelope.ActionEnvelope, error) {
	var env envelope.ActionEnvelope

	// Reject duplicate keys before decoding, including duplicates in nested
	// objects such as constraints. Payload is a string and is validated
	// separately using the strict action-payload contract.
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return env, err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &fields); err != nil {
		return env, err
	}
	if fields == nil {
		return env, errors.New("envelope must be a JSON object")
	}

	allowed := map[string]struct{}{
		"identity_ref":    {},
		"intent":          {},
		"capability":      {},
		"target_resource": {},
		"operation":       {},
		"constraints":     {},
		"audience":        {},
		"issued_at":       {},
		"expiry":          {},
		"nonce_id":        {},
		"payload_hash":    {},
		"payload":         {},
	}
	for key := range fields {
		if _, ok := allowed[key]; !ok {
			return env, errors.New("unknown or non-canonical envelope field")
		}
	}

	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&env); err != nil {
		return env, err
	}

	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return env, errors.New("multiple JSON values")
		}
		return env, err
	}

	return env, nil
}

// DecodeEnvelopeJSON parses an action envelope using the strict JSON checks
// shared with the reference handler. It rejects duplicate keys, unknown or
// non-canonical fields, malformed JSON, and trailing JSON values.
func DecodeEnvelopeJSON(raw string) (envelope.ActionEnvelope, error) {
	return decodeEnvelopeJSON(raw)
}
func writeJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
