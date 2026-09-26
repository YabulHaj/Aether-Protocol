package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"aether-protocol/internal/enforcement"
	"aether-protocol/internal/envelope"
	"aether-protocol/internal/evidence"
	"aether-protocol/internal/identity"
	"aether-protocol/internal/policy"
	"aether-protocol/internal/revocation"
	"aether-protocol/internal/telemetry"
)

const (
	maxRequestBodyBytes  = 1 << 20 // 1 MB
	upstreamURL          = "http://localhost:9090"
	identityModeEnvVar   = "AETHER_IDENTITY_MODE"
	identityModeMock     = "mock"
	identityModeSpiffe   = "spiffe"
	spiffeTrustDomain    = "aether.example.org"
	spiffeConnectTimeout = 3 * time.Second
	GatewayAudience      = "aether-gateway"
)

var spiffeAudience = []string{"aether-gateway"}

type Server struct {
	Identity   identity.IdentityProvider
	Policy     policy.PolicyEngine
	Enforcer   enforcement.EnforcementPoint
	Evidence   evidence.EvidenceLogger
	Revocation revocation.RevocationRegistry
	Target     *url.URL
	Telemetry  *telemetry.Broker
}

func NewServer(
	id identity.IdentityProvider,
	p policy.PolicyEngine,
	e enforcement.EnforcementPoint,
	ev evidence.EvidenceLogger,
	rev revocation.RevocationRegistry,
	target *url.URL,
) *Server {
	return &Server{
		Identity:   id,
		Policy:     p,
		Enforcer:   e,
		Evidence:   ev,
		Revocation: rev,
		Target:     target,
		Telemetry:  telemetry.NewBroker(),
	}
}

func logEvidence(logger evidence.EvidenceLogger, rec evidence.EvidenceRecord) (evidence.EvidenceRecord, error) {
	if detailed, ok := logger.(evidence.DetailedEvidenceLogger); ok {
		return detailed.LogAndReturn(rec)
	}
	err := logger.Log(rec)
	return rec, err
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) actionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.logEvidenceAndWriteError(w, evidence.EvidenceRecord{
			Allowed:    false,
			ReasonCode: evidence.ReasonMethodNotAllowed,
		}, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// 1. Identity Verification
	verifiedIdentity, err := s.Identity.Verify(r)
	if err != nil {
		s.logEvidenceAndWriteError(w, evidence.EvidenceRecord{
			ReasonCode: evidence.ReasonIdentityInvalid,
		}, http.StatusUnauthorized, "unauthorized")
		return
	}

	// 2. Read Body safely to extract Envelope
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.logEvidenceAndWriteError(w, evidence.EvidenceRecord{
			IdentityRef: verifiedIdentity,
			Allowed:     false,
			ReasonCode:  evidence.ReasonRequestTooLarge,
		}, http.StatusRequestEntityTooLarge, "request body too large or unreadable")
		return
	}

	var env envelope.ActionEnvelope
	if err := json.Unmarshal(bodyBytes, &env); err != nil {
		s.logEvidenceAndWriteError(w, evidence.EvidenceRecord{
			IdentityRef: verifiedIdentity,
			ReasonCode:  evidence.ReasonMalformed,
		}, http.StatusBadRequest, "invalid json")
		return
	}

	// 3. Revocation Check
	if s.Revocation.IsRevoked(verifiedIdentity, env.NonceID) {
		s.logEvidenceAndWriteError(w, evidence.EvidenceRecord{
			IdentityRef:    verifiedIdentity,
			NonceID:        env.NonceID,
			Capability:     env.Capability,
			TargetResource: env.TargetResource,
			Operation:      env.Operation,
			Allowed:        false,
			ReasonCode:     evidence.ReasonRevoked,
		}, http.StatusForbidden, "forbidden: identity or request revoked")
		return
	}

	// 4. Envelope Validation
	now := time.Now().UTC()
	if err := env.Validate(now); err != nil {
		s.logEvidenceAndWriteError(w, evidence.EvidenceRecord{
			IdentityRef:    verifiedIdentity,
			NonceID:        env.NonceID,
			Intent:         env.Intent,
			Capability:     env.Capability,
			TargetResource: env.TargetResource,
			Operation:      env.Operation,
			PayloadHash:    env.PayloadHash,
			ReasonCode:     evidence.ReasonMalformed,
		}, http.StatusBadRequest, "invalid envelope")
		return
	}

	// 5. Audience Boundary Check
	if env.Audience != GatewayAudience {
		s.logEvidenceAndWriteError(w, evidence.EvidenceRecord{
			IdentityRef:    verifiedIdentity,
			NonceID:        env.NonceID,
			Intent:         env.Intent,
			Capability:     env.Capability,
			TargetResource: env.TargetResource,
			Operation:      env.Operation,
			PayloadHash:    env.PayloadHash,
			ReasonCode:     evidence.ReasonMalformed,
		}, http.StatusBadRequest, "audience mismatch")
		return
	}

	// 6. Identity Mismatch Check
	if verifiedIdentity != env.IdentityRef {
		s.logEvidenceAndWriteError(w, evidence.EvidenceRecord{
			IdentityRef:    verifiedIdentity,
			NonceID:        env.NonceID,
			Intent:         env.Intent,
			Capability:     env.Capability,
			TargetResource: env.TargetResource,
			Operation:      env.Operation,
			PayloadHash:    env.PayloadHash,
			ReasonCode:     evidence.ReasonIdentityMismatch,
		}, http.StatusUnauthorized, "unauthorized")
		return
	}

	// 7. Anti-Replay Nonce Check & Consume
	if !s.Revocation.CheckAndConsumeNonce(env.NonceID) {
		s.logEvidenceAndWriteError(w, evidence.EvidenceRecord{
			IdentityRef:    verifiedIdentity,
			NonceID:        env.NonceID,
			Intent:         env.Intent,
			Capability:     env.Capability,
			TargetResource: env.TargetResource,
			Operation:      env.Operation,
			PayloadHash:    env.PayloadHash,
			ReasonCode:     evidence.ReasonReplay,
		}, http.StatusForbidden, "replay detected: nonce already consumed")
		return
	}

	// 8. Policy Evaluation
	decision := s.Policy.Evaluate(&env, now)

	// 9. Write Structured Evidence
	rec := evidence.EvidenceRecord{
		IdentityRef:    env.IdentityRef,
		NonceID:        env.NonceID,
		Intent:         env.Intent,
		Capability:     env.Capability,
		TargetResource: env.TargetResource,
		Operation:      env.Operation,
		PayloadHash:    env.PayloadHash,
		Allowed:        decision.Allow,
		RuleID:         decision.MatchedRuleID,
		ReasonCode:     decision.ReasonCode,
		PolicyVersion:  decision.PolicyVersion,
	}

	loggedRec, err := logEvidence(s.Evidence, rec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	// Telemetry observes the decision without blocking
	if s.Telemetry != nil {
		s.Telemetry.Broadcast(telemetry.Event{
			Identity:   loggedRec.IdentityRef,
			Intent:     env.Intent,
			Capability: loggedRec.Capability,
			Target:     loggedRec.TargetResource,
			Operation:  loggedRec.Operation,
			Reason:     loggedRec.ReasonCode,
			Status: func() int {
				if loggedRec.Allowed {
					return http.StatusOK
				}
				return http.StatusForbidden
			}(),
			Hash:    loggedRec.TamperHash,
			Allowed: loggedRec.Allowed,
		})
	}

	if !decision.Allow {
		writeError(w, http.StatusForbidden, "forbidden by policy")
		return
	}

	// 8. Enforcement Proxying
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	r.ContentLength = int64(len(bodyBytes))

	if err := s.Enforcer.Enforce(w, r, decision.Allow, s.Target); err != nil {
		log.Printf("enforcement_outcome=%v", err)
	}
}

func (s *Server) logEvidenceAndWriteError(w http.ResponseWriter, rec evidence.EvidenceRecord, status int, msg string) {
	loggedRec, err := logEvidence(s.Evidence, rec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	if s.Telemetry != nil {
		s.Telemetry.Broadcast(telemetry.Event{
			Identity:   loggedRec.IdentityRef,
			Capability: loggedRec.Capability,
			Target:     loggedRec.TargetResource,
			Operation:  loggedRec.Operation,
			Reason:     loggedRec.ReasonCode,
			Status:     status,
			Hash:       loggedRec.TamperHash,
			Allowed:    false,
		})
	}

	writeError(w, status, msg)
}

func uiFileSystem() http.FileSystem {
	if _, err := os.Stat("ui/index.html"); err == nil {
		return http.Dir("ui")
	}
	if _, err := os.Stat("../ui/index.html"); err == nil {
		return http.Dir("../ui")
	}
	return http.Dir("ui")
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.healthHandler)
	mux.HandleFunc("/v1/action", s.actionHandler)
	mux.HandleFunc("/v1/events", s.eventsHandler)
	mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(uiFileSystem())))
	mux.HandleFunc("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusPermanentRedirect)
	})
	return mux
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func defaultPolicy() policy.Policy {
	return policy.Policy{
		Version: "v0.1.0",
		Rules: []policy.Rule{
			{
				ID:             "R-001",
				IdentityRef:    "agent://finance-bot-01",
				Intent:         "summarize",
				Capability:     "read:invoices",
				TargetResource: "invoice/12345",
				Operation:      "GET",
			},
		},
	}
}

func buildIdentityProvider() (identity.IdentityProvider, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv(identityModeEnvVar)))

	switch mode {
	case identityModeMock:
		log.Println("[SECURITY WARNING] Running in INSECURE LOCAL DEV MODE with MockIdentityProvider")
		return identity.NewMockIdentityProvider(), nil

	case identityModeSpiffe:
		log.Println("identity mode: SPIFFE -- connecting to local Workload API...")
		ctx, cancel := context.WithTimeout(context.Background(), spiffeConnectTimeout)
		defer cancel()

		provider, err := identity.NewSpiffeIdentityProvider(ctx, spiffeTrustDomain, spiffeAudience, nil)
		if err != nil {
			return nil, err
		}
		return provider, nil

	case "":
		return nil, fmt.Errorf("%s is not set: must be explicitly configured to %q or %q (fail-closed, zero silent fallback)", identityModeEnvVar, identityModeMock, identityModeSpiffe)

	default:
		return nil, fmt.Errorf("invalid %s value %q: must be %q or %q", identityModeEnvVar, mode, identityModeMock, identityModeSpiffe)
	}
}

func main() {
	target, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatalf("invalid upstream url: %v", err)
	}

	enforcer, err := enforcement.NewReverseProxyEnforcer(target)
	if err != nil {
		log.Fatalf("could not build enforcement point: %v", err)
	}

	idProvider, err := buildIdentityProvider()
	if err != nil {
		log.Fatal("SPIFFE provider initialization failed: ", err)
	}
	if closer, ok := idProvider.(interface{ Close() error }); ok {
		defer closer.Close()
	}

	registry := revocation.NewInMemoryRevocationRegistry()
	evidenceLogger := evidence.NewStructuredEvidenceLogger(os.Stdout)

	srv := NewServer(idProvider, policy.NewRuleBasedEngine(defaultPolicy()), enforcer, evidenceLogger, registry, target)

	httpServer := &http.Server{
		Addr:        "localhost:8080",
		Handler:     srv.Routes(),
		ReadTimeout: 5 * time.Second,
		IdleTimeout: 120 * time.Second, // WriteTimeout omitted: SSE requires long-lived connections
	}

	log.Printf("Aether gateway listening on localhost:8080")
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func (s *Server) eventsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	if s.Telemetry == nil {
		http.Error(w, "Telemetry not enabled", http.StatusServiceUnavailable)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	clientChan := s.Telemetry.Subscribe()
	defer s.Telemetry.Unsubscribe(clientChan)

	// Immediately establish the SSE connection.
	// The comment is a valid SSE frame and forces the HTTP
	// headers/body to be sent before the first telemetry event.
	_, _ = fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return

		case ev, ok := <-clientChan:
			if !ok {
				return
			}

			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}

			_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}
