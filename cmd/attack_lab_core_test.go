package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aether-protocol/internal/envelope"
	"aether-protocol/internal/evidence"
	"aether-protocol/internal/policy"
	"aether-protocol/internal/revocation"
)

// ============================================================
// Aether Attack Lab — Core Corpus
//
// Exercises the REAL gateway end-to-end over HTTP:
//
//   http.Client -> httptest.NewServer(srv.Routes())
//              -> real *Server -> real actionHandler pipeline
//              -> real ReverseProxyEnforcer -> counting backend
//
// No part of the authorization pipeline is reimplemented here.
// Every scenario runs against a FRESH server with a fresh
// counting backend and a fresh evidence buffer.
// ============================================================

// Outcome taxonomy (exact strings).
const (
	outcomeAllowedBaseline     = "ALLOWED_BASELINE"
	outcomeBlocked             = "BLOCKED"
	outcomeBypassed            = "BYPASSED"
	outcomeInconclusive        = "INCONCLUSIVE"
	outcomeInfrastructureError = "INFRASTRUCTURE_ERROR"
)

// Scenario categories.
const (
	catBaseline   = "baseline"
	catMethod     = "method"
	catAuth       = "auth"
	catEnvelope   = "envelope"
	catRevocation = "revocation"
	catPolicy     = "policy"
)

// scenario describes one attack case. Body construction is deferred
// so it can use the subtest's *testing.T.
type scenario struct {
	ID             string
	Name           string
	Category       string
	Method         string
	Path           string
	AuthHeader     string
	BuildBody      func(t *testing.T) []byte
	Revoke         func(reg *revocation.InMemoryRevocationRegistry)
	ExpectedStatus int
	ExpectedReason string // evidence reason code; "" means no evidence expected
	ExpectedDelta  int
}

// outcome is one machine-readable record, written to the corpus files.
type outcome struct {
	ScenarioID     string                    `json:"scenario_id"`
	Name           string                    `json:"name"`
	Category       string                    `json:"category"`
	Method         string                    `json:"method"`
	Path           string                    `json:"path"`
	AuthHeader     string                    `json:"auth_header"`
	RequestBody    string                    `json:"request_body"`
	ExpectedStatus int                       `json:"expected_status"`
	ActualStatus   int                       `json:"actual_status"`
	ExpectedReason string                    `json:"expected_reason"`
	ActualReasons  []string                  `json:"actual_reasons"`
	ActualRecords  []evidence.EvidenceRecord `json:"actual_records"`
	ExpectedDelta  int                       `json:"expected_backend_delta"`
	ActualDelta    int                       `json:"actual_backend_delta"`
	Outcome        string                    `json:"outcome"`
	Notes          string                    `json:"notes,omitempty"`
}

func TestAttackLabCore(t *testing.T) {
	// Fixed path: go test runs from within the cmd/ directory, so we need ../..
	corpusDir := filepath.Join("..", "..", "Aether-Evidence", "08_attack_lab")
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		t.Fatalf("could not create corpus dir %q: %v", corpusDir, err)
	}

	scenarios := buildCoreScenarios()
	results := make([]outcome, 0, len(scenarios))

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.ID, func(t *testing.T) {
			srv, backend, registry, evBuf := newTestServer(t)
			gateway := httptest.NewServer(srv.Routes())
			defer gateway.Close()

			if sc.Revoke != nil {
				sc.Revoke(registry)
			}

			body := sc.BuildBody(t)

			beforeHits := backend.hitCount()
			beforeEv := evBuf.String()

			req, err := http.NewRequest(sc.Method, gateway.URL+sc.Path, bytes.NewReader(body))
			if err != nil {
				t.Fatalf("%s: could not build request: %v", sc.ID, err)
			}
			if sc.AuthHeader != "" {
				req.Header.Set("Authorization", sc.AuthHeader)
			}
			if sc.Method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
			}

			client := &http.Client{Timeout: 10 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				rec := outcome{
					ScenarioID:     sc.ID,
					Name:           sc.Name,
					Category:       sc.Category,
					Method:         sc.Method,
					Path:           sc.Path,
					AuthHeader:     sc.AuthHeader,
					RequestBody:    string(body),
					ExpectedStatus: sc.ExpectedStatus,
					ActualStatus:   0,
					ExpectedReason: sc.ExpectedReason,
					ActualReasons:  nil,
					ActualRecords:  nil,
					ExpectedDelta:  sc.ExpectedDelta,
					ActualDelta:    0,
					Outcome:        outcomeInfrastructureError,
					Notes:          fmt.Sprintf("HTTP request failed: %v", err),
				}
				results = append(results, rec)
				t.Fatalf("%s: %s", sc.ID, rec.Notes)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			afterHits := backend.hitCount()
			delta := int(afterHits - beforeHits)

			newEv := strings.TrimPrefix(evBuf.String(), beforeEv)
			reasons, records, hashOK, parseErr := parseAndVerifyEvidence(newEv)

			rec := outcome{
				ScenarioID:     sc.ID,
				Name:           sc.Name,
				Category:       sc.Category,
				Method:         sc.Method,
				Path:           sc.Path,
				AuthHeader:     sc.AuthHeader,
				RequestBody:    string(body),
				ExpectedStatus: sc.ExpectedStatus,
				ActualStatus:   resp.StatusCode,
				ExpectedReason: sc.ExpectedReason,
				ActualReasons:  reasons,
				ActualRecords:  records,
				ExpectedDelta:  sc.ExpectedDelta,
				ActualDelta:    delta,
			}

			switch {
			case !hashOK || parseErr != nil:
				rec.Outcome = outcomeBypassed
				rec.Notes = fmt.Sprintf("evidence integrity failure: %v (hashOK=%v)", parseErr, hashOK)
			case resp.StatusCode != sc.ExpectedStatus:
				rec.Outcome = outcomeInconclusive
				rec.Notes = fmt.Sprintf("status mismatch: want %d got %d", sc.ExpectedStatus, resp.StatusCode)
			case sc.Category == catBaseline && delta != sc.ExpectedDelta:
				rec.Outcome = outcomeBypassed
				rec.Notes = fmt.Sprintf("baseline expected %d backend hit(s), got %d", sc.ExpectedDelta, delta)
			case sc.Category != catBaseline && delta != 0:
				rec.Outcome = outcomeBypassed
				rec.Notes = fmt.Sprintf("SECURITY FAILURE: blocked scenario reached backend %d time(s)", delta)
			case sc.ExpectedReason != "" && (len(reasons) != 1 || reasons[0] != sc.ExpectedReason):
				rec.Outcome = outcomeInconclusive
				rec.Notes = fmt.Sprintf("expected exact evidence reason %q, got %v", sc.ExpectedReason, reasons)
			default:
				if sc.Category == catBaseline {
					rec.Outcome = outcomeAllowedBaseline
				} else {
					rec.Outcome = outcomeBlocked
				}
			}

			results = append(results, rec)

			if rec.Outcome == outcomeBypassed ||
				rec.Outcome == outcomeInconclusive ||
				rec.Outcome == outcomeInfrastructureError {
				t.Fatalf("%s (%s) outcome=%s notes=%s", sc.ID, sc.Name, rec.Outcome, rec.Notes)
			}
		})
	}

	writeCoreCorpus(t, corpusDir, results)
}

// parseAndVerifyEvidence walks the newly appended NDJSON records,
// asserts each parses into evidence.EvidenceRecord and hashes
// correctly, and returns the observed reason codes and full records.
func parseAndVerifyEvidence(raw string) (reasons []string, records []evidence.EvidenceRecord, hashOK bool, err error) {
	hashOK = true
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil, true, nil
	}
	for _, line := range strings.Split(trimmed, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec evidence.EvidenceRecord
		if e := json.Unmarshal([]byte(line), &rec); e != nil {
			return reasons, records, false, fmt.Errorf("evidence record is not valid JSON: %w", e)
		}
		if !evidence.VerifyRecordHash(rec) {
			hashOK = false
		}
		reasons = append(reasons, rec.ReasonCode)
		records = append(records, rec)
	}
	return reasons, records, hashOK, nil
}

// ============================================================
// Corpus writers
// ============================================================

func writeCoreCorpus(t *testing.T, dir string, results []outcome) {
	t.Helper()

	// --- day8-attack-lab.txt (human readable) ---
	var txt strings.Builder
	txt.WriteString("Aether Attack Lab — Core Corpus — Actual Local Execution\n")
	txt.WriteString("=========================================\n\n")
	txt.WriteString(fmt.Sprintf("Generated at: %s\n", time.Now().UTC().Format(time.RFC3339Nano)))
	txt.WriteString(fmt.Sprintf("Total scenarios: %d\n\n", len(results)))

	for _, r := range results {
		txt.WriteString(fmt.Sprintf("[%s] %s\n", r.ScenarioID, r.Name))
		txt.WriteString(fmt.Sprintf("  Category            : %s\n", r.Category))
		txt.WriteString(fmt.Sprintf("  Request             : %s %s\n", r.Method, r.Path))
		txt.WriteString(fmt.Sprintf("  Auth header         : %q\n", r.AuthHeader))
		txt.WriteString(fmt.Sprintf("  Request body        : %s\n", r.RequestBody))
		txt.WriteString(fmt.Sprintf("  Expected status     : %d\n", r.ExpectedStatus))
		txt.WriteString(fmt.Sprintf("  Actual status       : %d\n", r.ActualStatus))
		txt.WriteString(fmt.Sprintf("  Expected reason     : %q\n", r.ExpectedReason))
		txt.WriteString(fmt.Sprintf("  Actual reasons      : %v\n", r.ActualReasons))
		txt.WriteString(fmt.Sprintf("  Expected backend Δ  : %d\n", r.ExpectedDelta))
		txt.WriteString(fmt.Sprintf("  Actual backend Δ    : %d\n", r.ActualDelta))
		txt.WriteString(fmt.Sprintf("  Outcome             : %s\n", r.Outcome))
		if r.Notes != "" {
			txt.WriteString(fmt.Sprintf("  Notes               : %s\n", r.Notes))
		}
		txt.WriteString("\n")
	}

	if err := os.WriteFile(filepath.Join(dir, "day8-attack-lab.txt"), []byte(txt.String()), 0o644); err != nil {
		t.Fatalf("could not write day8-attack-lab.txt: %v", err)
	}

	// --- day8-scenario-corpus.json (structured) ---
	corpus := struct {
		GeneratedAt    string    `json:"generated_at"`
		TotalScenarios int       `json:"total_scenarios"`
		Allowed        int       `json:"allowed"`
		Blocked        int       `json:"blocked"`
		Bypassed       int       `json:"bypassed"`
		Inconclusive   int       `json:"inconclusive"`
		InfraErrors    int       `json:"infrastructure_errors"`
		Scenarios      []outcome `json:"scenarios"`
	}{
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339Nano),
		TotalScenarios: len(results),
		Scenarios:      results,
	}
	for _, r := range results {
		switch r.Outcome {
		case outcomeAllowedBaseline:
			corpus.Allowed++
		case outcomeBlocked:
			corpus.Blocked++
		case outcomeBypassed:
			corpus.Bypassed++
		case outcomeInconclusive:
			corpus.Inconclusive++
		case outcomeInfrastructureError:
			corpus.InfraErrors++
		}
	}

	corpusJSON, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		t.Fatalf("could not marshal corpus: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "day8-scenario-corpus.json"), corpusJSON, 0o644); err != nil {
		t.Fatalf("could not write day8-scenario-corpus.json: %v", err)
	}

	// --- day8-attack-lab.jsonl (one JSON object per line) ---
	var jsonl strings.Builder
	for _, r := range results {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("could not marshal jsonl outcome: %v", err)
		}
		jsonl.Write(line)
		jsonl.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "day8-attack-lab.jsonl"), []byte(jsonl.String()), 0o644); err != nil {
		t.Fatalf("could not write day8-attack-lab.jsonl: %v", err)
	}
}

// ============================================================
// Scenario table — DAY8-001 .. DAY8-020
// ============================================================

func buildCoreScenarios() []scenario {
	validAuth := validAuthHeader
	validPath := "/v1/action"

	return []scenario{
		// --- 001 valid baseline ---
		{
			ID:             "DAY8-001",
			Name:           "valid baseline",
			Category:       catBaseline,
			Method:         http.MethodPost,
			Path:           validPath,
			AuthHeader:     validAuth,
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusOK,
			ExpectedReason: policy.ReasonAllowedByRule, // "allow_matched_rule"
			ExpectedDelta:  1,
		},

		// --- 002 wrong HTTP method ---
		{
			ID:             "DAY8-002",
			Name:           "wrong HTTP method",
			Category:       catMethod,
			Method:         http.MethodGet,
			Path:           validPath,
			AuthHeader:     validAuth,
			BuildBody:      func(t *testing.T) []byte { return []byte{} },
			ExpectedStatus: http.StatusMethodNotAllowed,
			ExpectedReason: "",
			ExpectedDelta:  0,
		},

		// --- 003 missing Authorization ---
		{
			ID:             "DAY8-003",
			Name:           "missing Authorization",
			Category:       catAuth,
			Method:         http.MethodPost,
			Path:           validPath,
			AuthHeader:     "",
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedReason: evidence.ReasonIdentityInvalid, // "IDENTITY_INVALID"
			ExpectedDelta:  0,
		},

		// --- 004 unknown token ---
		{
			ID:             "DAY8-004",
			Name:           "unknown token",
			Category:       catAuth,
			Method:         http.MethodPost,
			Path:           validPath,
			AuthHeader:     "Bearer mock-token-does-not-exist",
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedReason: evidence.ReasonIdentityInvalid,
			ExpectedDelta:  0,
		},

		// --- 005 malformed JSON ---
		{
			ID:             "DAY8-005",
			Name:           "malformed JSON",
			Category:       catEnvelope,
			Method:         http.MethodPost,
			Path:           validPath,
			AuthHeader:     validAuth,
			BuildBody:      func(t *testing.T) []byte { return []byte(`{"identity_ref":"agent://finance-bot-01"`) },
			ExpectedStatus: http.StatusBadRequest,
			ExpectedReason: evidence.ReasonMalformed, // "MALFORMED"
			ExpectedDelta:  0,
		},

		// --- 006 missing IdentityRef ---
		{
			ID:         "DAY8-006",
			Name:       "missing IdentityRef",
			Category:   catEnvelope,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.IdentityRef = "" })
			},
			ExpectedStatus: http.StatusBadRequest,
			ExpectedReason: evidence.ReasonMalformed,
			ExpectedDelta:  0,
		},

		// --- 007 identity mismatch (VERIFIED: 401 + IDENTITY_MISMATCH) ---
		{
			ID:         "DAY8-007",
			Name:       "identity mismatch",
			Category:   catEnvelope,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) {
					// Token proves finance-bot-01; envelope claims hr-bot-01.
					e.IdentityRef = "agent://hr-bot-01"
				})
			},
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedReason: evidence.ReasonIdentityMismatch,
			ExpectedDelta:  0,
		},

		// --- 008 missing NonceID ---
		{
			ID:         "DAY8-008",
			Name:       "missing NonceID",
			Category:   catEnvelope,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.NonceID = "" })
			},
			ExpectedStatus: http.StatusBadRequest,
			ExpectedReason: evidence.ReasonMalformed,
			ExpectedDelta:  0,
		},

		// --- 009 missing Capability ---
		{
			ID:         "DAY8-009",
			Name:       "missing Capability",
			Category:   catEnvelope,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.Capability = "" })
			},
			ExpectedStatus: http.StatusBadRequest,
			ExpectedReason: evidence.ReasonMalformed,
			ExpectedDelta:  0,
		},

		// --- 010 missing TargetResource ---
		{
			ID:         "DAY8-010",
			Name:       "missing TargetResource",
			Category:   catEnvelope,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.TargetResource = "" })
			},
			ExpectedStatus: http.StatusBadRequest,
			ExpectedReason: evidence.ReasonMalformed,
			ExpectedDelta:  0,
		},

		// --- 011 missing Operation ---
		{
			ID:         "DAY8-011",
			Name:       "missing Operation",
			Category:   catEnvelope,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.Operation = "" })
			},
			ExpectedStatus: http.StatusBadRequest,
			ExpectedReason: evidence.ReasonMalformed,
			ExpectedDelta:  0,
		},

		// --- 012 expired envelope ---
		{
			ID:         "DAY8-012",
			Name:       "expired envelope",
			Category:   catEnvelope,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) {
					now := time.Now().UTC()
					e.IssuedAt = now.Add(-10 * time.Minute)
					e.Expiry = now.Add(-1 * time.Minute)
				})
			},
			ExpectedStatus: http.StatusBadRequest,
			ExpectedReason: evidence.ReasonMalformed,
			ExpectedDelta:  0,
		},

		// --- 013 future IssuedAt ---
		{
			ID:         "DAY8-013",
			Name:       "future IssuedAt",
			Category:   catEnvelope,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) {
					now := time.Now().UTC()
					e.IssuedAt = now.Add(10 * time.Minute)
					e.Expiry = now.Add(20 * time.Minute)
				})
			},
			ExpectedStatus: http.StatusBadRequest,
			ExpectedReason: evidence.ReasonMalformed,
			ExpectedDelta:  0,
		},

		// --- 014 revoked identity ---
		{
			ID:         "DAY8-014",
			Name:       "revoked identity",
			Category:   catRevocation,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody:  func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			Revoke: func(reg *revocation.InMemoryRevocationRegistry) {
				reg.RevokeIdentity("agent://finance-bot-01")
			},
			ExpectedStatus: http.StatusForbidden,
			ExpectedReason: evidence.ReasonRevoked, // "REVOKED"
			ExpectedDelta:  0,
		},

		// --- 015 revoked nonce ---
		{
			ID:         "DAY8-015",
			Name:       "revoked nonce",
			Category:   catRevocation,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody:  func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			Revoke: func(reg *revocation.InMemoryRevocationRegistry) {
				reg.RevokeNonce("nonce-abc-123")
			},
			ExpectedStatus: http.StatusForbidden,
			ExpectedReason: evidence.ReasonRevoked,
			ExpectedDelta:  0,
		},

		// --- 016 wrong target ---
		{
			ID:         "DAY8-016",
			Name:       "wrong target",
			Category:   catPolicy,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) {
					e.TargetResource = "invoice/99999"
				})
			},
			ExpectedStatus: http.StatusForbidden,
			ExpectedReason: policy.ReasonNoMatchingRule, // "deny_no_matching_rule"
			ExpectedDelta:  0,
		},

		// --- 017 wrong operation ---
		{
			ID:         "DAY8-017",
			Name:       "wrong operation",
			Category:   catPolicy,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) {
					e.Operation = "DELETE"
				})
			},
			ExpectedStatus: http.StatusForbidden,
			ExpectedReason: policy.ReasonNoMatchingRule,
			ExpectedDelta:  0,
		},

		// --- 018 capability escalation ---
		{
			ID:         "DAY8-018",
			Name:       "capability escalation",
			Category:   catPolicy,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) {
					e.Capability = "admin:*"
				})
			},
			ExpectedStatus: http.StatusForbidden,
			ExpectedReason: policy.ReasonNoMatchingRule,
			ExpectedDelta:  0,
		},

		// --- 019 near-miss target ---
		{
			ID:         "DAY8-019",
			Name:       "near-miss target",
			Category:   catPolicy,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) {
					// Exact-match policy must reject prefix/suffix tricks.
					e.TargetResource = "invoice/123456"
				})
			},
			ExpectedStatus: http.StatusForbidden,
			ExpectedReason: policy.ReasonNoMatchingRule,
			ExpectedDelta:  0,
		},

		// --- 020 missing PayloadHash ---
		{
			ID:         "DAY8-020",
			Name:       "missing PayloadHash",
			Category:   catEnvelope,
			Method:     http.MethodPost,
			Path:       validPath,
			AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) {
					e.PayloadHash = ""
				})
			},
			ExpectedStatus: http.StatusBadRequest,
			ExpectedReason: evidence.ReasonMalformed,
			ExpectedDelta:  0,
		},
	}
}
