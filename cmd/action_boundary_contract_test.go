package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"aether-protocol/internal/enforcement"
	"aether-protocol/internal/envelope"
	"aether-protocol/internal/evidence"
	"aether-protocol/internal/identity"
	"aether-protocol/internal/policy"
	"aether-protocol/internal/revocation"
	"aether-protocol/pkg/actioncontract"
)

func newActionBoundaryContractTestServer(
	t *testing.T,
) (*Server, *actioncontract.ReferenceHandler) {
	t.Helper()

	backend := actioncontract.NewReferenceHandler()
	upstream := httptest.NewServer(backend)
	t.Cleanup(upstream.Close)

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse reference backend URL: %v", err)
	}

	enforcer, err := enforcement.NewReverseProxyEnforcer(target)
	if err != nil {
		t.Fatalf("create reverse proxy enforcer: %v", err)
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

	return srv, backend
}

func makeContractPayload(t *testing.T, target, operation string) string {
	t.Helper()

	raw, err := json.Marshal(actioncontract.Payload{
		TargetResource: target,
		Operation:      operation,
		Arguments:      json.RawMessage(`{"invoice_id":"12345"}`),
	})
	if err != nil {
		t.Fatalf("marshal reference action payload: %v", err)
	}

	return string(raw)
}

func makeContractEnvelope(
	t *testing.T,
	payload string,
	mutate func(*envelope.ActionEnvelope),
) []byte {
	t.Helper()

	return freshEnvelopeJSON(t, func(env *envelope.ActionEnvelope) {
		env.Payload = payload
		env.PayloadHash = envelope.ComputePayloadHash([]byte(payload))
		if mutate != nil {
			mutate(env)
		}
	})
}

func TestActionBoundaryContract_MatchingPayloadRecordsSimulatedEffect(t *testing.T) {
	srv, backend := newActionBoundaryContractTestServer(t)

	payload := makeContractPayload(t, "invoice/12345", "GET")
	body := makeContractEnvelope(t, payload, nil)

	response := postWithAuth(t, srv, body, validAuthHeader)
	if response.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200 for matching action, got %d: %s", response.Code, response.Body.String())
	}

	if got := backend.RequestCount(); got != 1 {
		t.Fatalf("expected one downstream request, got %d", got)
	}
	if got := backend.EffectCount(); got != 1 {
		t.Fatalf("expected one simulated effect, got %d", got)
	}

	effects := backend.Effects()
	if len(effects) != 1 ||
		effects[0].TargetResource != "invoice/12345" ||
		effects[0].Operation != "GET" {
		t.Fatalf("unexpected simulated effects: %+v", effects)
	}
}

func TestActionBoundaryContract_ConflictingPayloadRejectedBeforeEffect(t *testing.T) {
	srv, backend := newActionBoundaryContractTestServer(t)

	events := srv.Telemetry.Subscribe()
	defer srv.Telemetry.Unsubscribe(events)

	payload := makeContractPayload(t, "invoice/99999", "DELETE")
	body := makeContractEnvelope(t, payload, nil)

	response := postWithAuth(t, srv, body, validAuthHeader)

	// The outer action matches Aether's policy, so the gateway authorizes and
	// forwards it. The downstream reference contract must reject the conflict.
	if response.Code != http.StatusConflict {
		t.Fatalf("expected downstream HTTP 409 for action mismatch, got %d: %s", response.Code, response.Body.String())
	}

	if got := backend.RequestCount(); got != 1 {
		t.Fatalf("expected one downstream request, got %d", got)
	}
	if got := backend.EffectCount(); got != 0 {
		t.Fatalf("SECURITY REGRESSION: conflicting action caused %d simulated effects", got)
	}

	select {
	case event := <-events:
		if !event.Allowed {
			t.Fatal("expected Aether's outer authorization decision to remain ALLOW")
		}
		if event.DecisionStatus != http.StatusOK || event.Status != http.StatusOK {
			t.Fatalf("expected authorization decision status 200, got decision_status=%d status=%d",
				event.DecisionStatus, event.Status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Aether authorization telemetry")
	}
}

func TestActionBoundaryContract_NonCanonicalOuterKeyRejectedBeforeEffect(t *testing.T) {
	srv, backend := newActionBoundaryContractTestServer(t)

	payload := makeContractPayload(t, "invoice/12345", "GET")
	body := makeContractEnvelope(t, payload, nil)

	raw := string(body)
	needle := `"target_resource":"invoice/12345"`
	if strings.Count(raw, needle) != 1 {
		t.Fatalf("expected one canonical outer target field, got %d", strings.Count(raw, needle))
	}

	// The canonical field remains present and authorizes the outer action.
	// The reference consumer must reject the additional case-variant field.
	raw = strings.Replace(
		raw,
		needle,
		`"Target_Resource":"invoice/99999",`+needle,
		1,
	)

	response := postWithAuth(t, srv, []byte(raw), validAuthHeader)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected strict downstream envelope rejection (400), got %d: %s",
			response.Code, response.Body.String())
	}

	if got := backend.RequestCount(); got != 1 {
		t.Fatalf("expected gateway to contact the reference adapter once, got %d", got)
	}
	if got := backend.EffectCount(); got != 0 {
		t.Fatalf("SECURITY REGRESSION: ambiguous outer envelope produced %d effects", got)
	}
}
func TestActionBoundaryContract_OuterPolicyDenialNeverReachesAdapter(t *testing.T) {
	srv, backend := newActionBoundaryContractTestServer(t)

	payload := makeContractPayload(t, "invoice/12345", "DELETE")
	body := makeContractEnvelope(t, payload, func(env *envelope.ActionEnvelope) {
		env.Operation = "DELETE"
	})

	response := postWithAuth(t, srv, body, validAuthHeader)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 for policy-denied outer action, got %d", response.Code)
	}

	if got := backend.RequestCount(); got != 0 {
		t.Fatalf("SECURITY REGRESSION: denied request reached reference adapter %d times", got)
	}
	if got := backend.EffectCount(); got != 0 {
		t.Fatalf("SECURITY REGRESSION: denied request produced %d simulated effects", got)
	}
}
