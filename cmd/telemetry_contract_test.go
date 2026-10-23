package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"aether-protocol/internal/enforcement"
	"aether-protocol/internal/evidence"
	"aether-protocol/internal/identity"
	"aether-protocol/internal/policy"
	"aether-protocol/internal/revocation"
	"aether-protocol/internal/telemetry"
)

func TestTelemetryDecisionStatusIsNotUpstreamResponseStatus(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"upstream conflict"}`))
		},
	))
	defer upstream.Close()

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	enforcer, err := enforcement.NewReverseProxyEnforcer(target)
	if err != nil {
		t.Fatalf("create enforcement proxy: %v", err)
	}

	var evidenceBuffer bytes.Buffer
	evidenceLogger := evidence.NewStructuredEvidenceLogger(&evidenceBuffer)

	srv := NewServer(
		identity.NewMockIdentityProvider(),
		policy.NewRuleBasedEngine(defaultPolicy()),
		enforcer,
		evidenceLogger,
		revocation.NewInMemoryRevocationRegistry(),
		target,
	)

	events := srv.Telemetry.Subscribe()
	defer srv.Telemetry.Unsubscribe(events)

	response := postWithAuth(
		t,
		srv,
		freshEnvelopeJSON(t, nil),
		validAuthHeader,
	)

	if response.Code != http.StatusConflict {
		t.Fatalf(
			"expected upstream HTTP 409 to reach client; got %d: %s",
			response.Code,
			response.Body.String(),
		)
	}

	select {
	case event := <-events:
		if !event.Allowed {
			t.Fatal("expected authorization decision to be allowed")
		}
		if event.DecisionStatus != http.StatusOK {
			t.Fatalf(
				"expected decision_status 200, got %d",
				event.DecisionStatus,
			)
		}
		if event.Status != http.StatusOK {
			t.Fatalf(
				"expected legacy status alias 200, got %d",
				event.Status,
			)
		}

		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal telemetry event: %v", err)
		}

		var wire map[string]interface{}
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatalf("decode telemetry event: %v", err)
		}

		if wire["decision_status"] != float64(http.StatusOK) {
			t.Fatalf(
				"expected JSON decision_status 200, got %v",
				wire["decision_status"],
			)
		}
		if wire["status"] != float64(http.StatusOK) {
			t.Fatalf(
				"expected backwards-compatible JSON status 200, got %v",
				wire["status"],
			)
		}

		t.Logf(
			"CONFIRMED: client_http_status=%d decision_status=%d legacy_status=%d allowed=%t",
			response.Code,
			event.DecisionStatus,
			event.Status,
			event.Allowed,
		)

	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for telemetry event")
	}
}
func TestTelemetryDecisionStatusOmittedWhenUnset(t *testing.T) {
	event := telemetry.Event{
		Status:  http.StatusForbidden,
		Allowed: false,
	}

	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("marshal legacy telemetry event: %v", err)
	}

	var wire map[string]interface{}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatalf("decode legacy telemetry event: %v", err)
	}

	if _, exists := wire["decision_status"]; exists {
		t.Fatalf(
			"expected unset decision_status to be omitted, got %v",
			wire["decision_status"],
		)
	}

	if wire["status"] != float64(http.StatusForbidden) {
		t.Fatalf(
			"expected legacy status 403 to be preserved, got %v",
			wire["status"],
		)
	}
}
