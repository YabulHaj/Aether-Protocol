package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aether-protocol/internal/enforcement"
	"aether-protocol/internal/envelope"
	"aether-protocol/internal/evidence"
	"aether-protocol/internal/identity"
	"aether-protocol/internal/policy"
	"aether-protocol/internal/revocation"
)

const validAuthHeader = "Bearer mock-token-finance-bot"

type testBackend struct {
	hits     int32
	lastBody []byte
}

func (b *testBackend) hitCount() int32 { return atomic.LoadInt32(&b.hits) }

func newTestServer(t *testing.T) (*Server, *testBackend, *revocation.InMemoryRevocationRegistry, *bytes.Buffer) {
	t.Helper()

	backendState := &testBackend{}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&backendState.hits, 1)
		body, _ := io.ReadAll(r.Body)
		backendState.lastBody = body
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend-reached"))
	}))
	t.Cleanup(backend.Close)

	target, _ := url.Parse(backend.URL)
	enforcer, _ := enforcement.NewReverseProxyEnforcer(target)

	registry := revocation.NewInMemoryRevocationRegistry()
	var evBuf bytes.Buffer
	evLogger := evidence.NewStructuredEvidenceLogger(&evBuf)

	srv := NewServer(identity.NewMockIdentityProvider(), policy.NewRuleBasedEngine(defaultPolicy()), enforcer, evLogger, registry, target)
	return srv, backendState, registry, &evBuf
}

func freshEnvelopeJSON(t *testing.T, mutate func(e *envelope.ActionEnvelope)) []byte {
	t.Helper()
	now := time.Now().UTC()
	env := envelope.ActionEnvelope{
		IdentityRef:    "agent://finance-bot-01",
		Intent:         "summarize",
		Capability:     "read:invoices",
		TargetResource: "invoice/12345",
		Operation:      "GET",
		Audience:       "aether-gateway",
		IssuedAt:       now.Add(-1 * time.Minute),
		Expiry:         now.Add(5 * time.Minute),
		NonceID:        "nonce-abc-123",
		PayloadHash:    "sha256:deadbeef",
	}
	if mutate != nil {
		mutate(&env)
	}
	b, _ := json.Marshal(env)
	return b
}

func postWithAuth(t *testing.T, srv *Server, body []byte, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/action", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	return w
}

// === DAY 5/6 EXISTING TESTS PRESERVED ===

func TestHealthEndpoint(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestActionEndpoint_AllowedRequestIsProxied(t *testing.T) {
	srv, backend, _, _ := newTestServer(t)
	w := postWithAuth(t, srv, freshEnvelopeJSON(t, nil), validAuthHeader)
	if w.Code != http.StatusOK || backend.hitCount() != 1 {
		t.Fatalf("expected 200 and 1 hit, got %d and %d hits", w.Code, backend.hitCount())
	}
}

func TestActionEndpoint_DeniedRequestNeverReachesBackend(t *testing.T) {
	srv, backend, _, _ := newTestServer(t)
	w := postWithAuth(t, srv, freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.Operation = "DELETE" }), validAuthHeader)
	if backend.hitCount() != 0 || w.Code != http.StatusForbidden {
		t.Fatalf("FAIL OPEN: expected 403 and 0 hits, got %d code and %d hits", w.Code, backend.hitCount())
	}
}

// === DAY 7 REVOCATION & EVIDENCE TESTS ===

func TestRevocation_IdentityRevokedReturns403AndZeroHits(t *testing.T) {
	srv, backend, registry, evBuf := newTestServer(t)

	registry.RevokeIdentity("agent://finance-bot-01")

	w := postWithAuth(t, srv, freshEnvelopeJSON(t, nil), validAuthHeader)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if backend.hitCount() != 0 {
		t.Fatalf("SECURITY REGRESSION: revoked identity reached backend")
	}

	if !strings.Contains(evBuf.String(), evidence.ReasonRevoked) {
		t.Fatalf("expected REVOKED reason in evidence log, got: %s", evBuf.String())
	}
}

func TestRevocation_NonceRevokedReturns403AndZeroHits(t *testing.T) {
	srv, backend, registry, _ := newTestServer(t)
	registry.RevokeNonce("nonce-abc-123")

	w := postWithAuth(t, srv, freshEnvelopeJSON(t, nil), validAuthHeader)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	if backend.hitCount() != 0 {
		t.Fatalf("SECURITY REGRESSION: revoked nonce reached backend")
	}
}

func TestEvidence_HashVerifiesForAllowedRequest(t *testing.T) {
	srv, _, _, evBuf := newTestServer(t)
	postWithAuth(t, srv, freshEnvelopeJSON(t, nil), validAuthHeader)

	lines := strings.Split(strings.TrimSpace(evBuf.String()), "\n")
	lastLine := lines[len(lines)-1]

	var rec evidence.EvidenceRecord
	if err := json.Unmarshal([]byte(lastLine), &rec); err != nil {
		t.Fatalf("evidence is not valid JSON: %v", err)
	}

	// FIX: The actual policy engine returns "allow_matched_rule", not "ALLOW"
	if rec.ReasonCode != "allow_matched_rule" {
		t.Fatalf("expected allow_matched_rule, got %s", rec.ReasonCode)
	}
	if !evidence.VerifyRecordHash(rec) {
		t.Fatalf("SECURITY REGRESSION: Evidence tamper hash failed verification")
	}
}

func TestAntiReplay_DuplicateNonceRejectedAndZeroHits(t *testing.T) {
	srv, backend, _, evBuf := newTestServer(t)
	body := freshEnvelopeJSON(t, nil)

	// First request: fresh nonce, must succeed and reach backend
	w1 := postWithAuth(t, srv, body, validAuthHeader)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 for initial request, got %d", w1.Code)
	}
	if backend.hitCount() != 1 {
		t.Fatalf("expected 1 backend hit, got %d", backend.hitCount())
	}

	// Second request: replayed identical nonce, MUST be blocked by anti-replay
	w2 := postWithAuth(t, srv, body, validAuthHeader)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("SECURITY REGRESSION: expected 403 Forbidden for replayed nonce, got %d", w2.Code)
	}
	if backend.hitCount() != 1 {
		t.Fatalf("SECURITY REGRESSION: replayed request reached backend! hits=%d", backend.hitCount())
	}

	if !strings.Contains(evBuf.String(), evidence.ReasonReplay) {
		t.Fatalf("expected REPLAY_DETECTED in evidence log, got: %s", evBuf.String())
	}
}

func TestAntiReplay_ConcurrentSameNonceAllowsExactlyOne(t *testing.T) {
	srv, backend, _, evBuf := newTestServer(t)

	body := freshEnvelopeJSON(t, nil)

	const concurrentRequests = 32

	start := make(chan struct{})
	results := make(chan int, concurrentRequests)

	var wg sync.WaitGroup
	wg.Add(concurrentRequests)

	for i := 0; i < concurrentRequests; i++ {
		go func() {
			defer wg.Done()

			<-start

			w := postWithAuth(t, srv, body, validAuthHeader)
			results <- w.Code
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	var allowed int
	var forbidden int

	for status := range results {
		switch status {
		case http.StatusOK:
			allowed++
		case http.StatusForbidden:
			forbidden++
		default:
			t.Fatalf("unexpected HTTP status under concurrent replay: %d", status)
		}
	}

	if allowed != 1 {
		t.Fatalf("SECURITY REGRESSION: expected exactly 1 allowed request, got %d", allowed)
	}

	if forbidden != concurrentRequests-1 {
		t.Fatalf(
			"SECURITY REGRESSION: expected %d replay rejections, got %d",
			concurrentRequests-1,
			forbidden,
		)
	}

	if backend.hitCount() != 1 {
		t.Fatalf(
			"SECURITY REGRESSION: expected exactly 1 backend hit, got %d",
			backend.hitCount(),
		)
	}

	if !strings.Contains(evBuf.String(), evidence.ReasonReplay) {
		t.Fatalf(
			"expected REPLAY_DETECTED evidence under concurrent replay, got: %s",
			evBuf.String(),
		)
	}
}

func TestAudienceBoundary_MismatchRejected(t *testing.T) {
	srv, backend, _, evBuf := newTestServer(t)
	body := freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) {
		e.Audience = "untrusted-foreign-gateway"
	})

	w := postWithAuth(t, srv, body, validAuthHeader)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for audience mismatch, got %d", w.Code)
	}
	if backend.hitCount() != 0 {
		t.Fatalf("SECURITY REGRESSION: request with audience mismatch reached backend")
	}
	if !strings.Contains(evBuf.String(), evidence.ReasonMalformed) {
		t.Fatalf("expected MALFORMED reason in evidence log, got: %s", evBuf.String())
	}
}

func TestAction_MethodNotAllowedProducesEvidence(t *testing.T) {
	srv, backend, _, evBuf := newTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/v1/action", nil)
	w := httptest.NewRecorder()

	srv.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed, got %d", w.Code)
	}

	if backend.hitCount() != 0 {
		t.Fatalf("SECURITY REGRESSION: 405 request reached backend, hits=%d", backend.hitCount())
	}

	if !strings.Contains(evBuf.String(), evidence.ReasonMethodNotAllowed) {
		t.Fatalf("expected METHOD_NOT_ALLOWED evidence, got: %s", evBuf.String())
	}
}

func TestAction_RequestTooLargeProducesEvidence(t *testing.T) {
	srv, backend, _, evBuf := newTestServer(t)

	oversizedBody := bytes.Repeat([]byte("A"), maxRequestBodyBytes+1)

	req := httptest.NewRequest(http.MethodPost, "/v1/action", bytes.NewReader(oversizedBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", validAuthHeader)

	w := httptest.NewRecorder()

	srv.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Request Entity Too Large, got %d", w.Code)
	}

	if backend.hitCount() != 0 {
		t.Fatalf("SECURITY REGRESSION: oversized request reached backend, hits=%d", backend.hitCount())
	}

	if !strings.Contains(evBuf.String(), evidence.ReasonRequestTooLarge) {
		t.Fatalf("expected REQUEST_TOO_LARGE evidence, got: %s", evBuf.String())
	}
}

func TestHealthEndpoint_MethodNotAllowed(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 Method Not Allowed for POST /health, got %d", w.Code)
	}
}

func TestBuildIdentityProvider_ZeroSilentFallback(t *testing.T) {
	// 1. When unset, must fail closed
	orig := os.Getenv(identityModeEnvVar)
	defer os.Setenv(identityModeEnvVar, orig)

	_ = os.Unsetenv(identityModeEnvVar)
	provider, err := buildIdentityProvider()
	if err == nil {
		t.Fatal("SECURITY REGRESSION: buildIdentityProvider must fail closed when AETHER_IDENTITY_MODE is unset")
	}
	if provider != nil {
		t.Fatal("expected nil provider on failure")
	}

	// 2. When set to invalid, must fail closed
	_ = os.Setenv(identityModeEnvVar, "insecure-bypass")
	provider, err = buildIdentityProvider()
	if err == nil {
		t.Fatal("SECURITY REGRESSION: buildIdentityProvider must fail closed on invalid mode")
	}

	// 3. When explicitly set to mock, succeeds with warning
	_ = os.Setenv(identityModeEnvVar, "mock")
	provider, err = buildIdentityProvider()
	if err != nil {
		t.Fatalf("expected success with explicit mock mode, got: %v", err)
	}
	if provider == nil {
		t.Fatal("expected non-nil provider for explicit mock mode")
	}
}

func TestUIRoute_ServesDashboard(t *testing.T) {
	srv, _, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /ui/, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "AETHER LIVE") {
		t.Fatalf("expected UI HTML body to contain 'Aether Protocol', got: %s", w.Body.String())
	}
}
