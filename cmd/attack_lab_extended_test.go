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
	"aether-protocol/internal/revocation"
)

// freshEnvelopeJSONAt constructs an ActionEnvelope using native time.Time fields and standard json.Marshal.
func freshEnvelopeJSONAt(t *testing.T, fixedNow time.Time, mutate func(e *envelope.ActionEnvelope)) []byte {
	t.Helper()
	env := envelope.ActionEnvelope{
		IdentityRef:    "agent://finance-bot-01",
		Intent:         "summarize",
		Capability:     "read:invoices",
		TargetResource: "invoice/12345",
		Operation:      "GET",
		Audience:       "aether-gateway",
		NonceID:        "nonce-attack-lab",
		PayloadHash:    "sha256:0000000000000000",
		IssuedAt:       fixedNow.Add(-1 * time.Minute),
		Expiry:         fixedNow.Add(5 * time.Minute),
	}

	if mutate != nil {
		mutate(&env)
	}

	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}
	return b
}

func buildExtendedScenarios() []scenario {
	validAuth := validAuthHeader
	validPath := "/v1/action"

	// Deterministic reference anchors for freshness testing
	expiredAnchor := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	futureAnchor := time.Date(2099, 1, 1, 12, 0, 0, 0, time.UTC)

	return []scenario{
		// --- CATEGORY: ENVELOPE STRUCTURAL INTEGRITY (Expected Status: 400 Bad Request) ---
		{
			ID: "AET-ATT-0021", Name: "Missing IdentityRef Field", Category: "envelope", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.IdentityRef = "" })
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0022", Name: "Missing Intent Field", Category: "envelope", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.Intent = "" })
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0023", Name: "Missing TargetResource Field", Category: "envelope", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.TargetResource = "" })
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0024", Name: "Missing Operation Field", Category: "envelope", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.Operation = "" })
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0025", Name: "Missing NonceID Field", Category: "envelope", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.NonceID = "" })
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0026", Name: "Empty PayloadHash Field", Category: "envelope", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.PayloadHash = "" })
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0027", Name: "Audience Boundary Mismatch", Category: "envelope", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.Audience = "untrusted-gateway" })
			},
			ExpectedStatus: http.StatusBadRequest, ExpectedDelta: 0,
		},

		// --- CATEGORY: DETERMINISTIC FRESHNESS ---
		{
			ID: "AET-ATT-0028", Name: "Expired Envelope Timestamp", Category: "freshness", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSONAt(t, expiredAnchor, nil) },
			ExpectedStatus: http.StatusBadRequest, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0029", Name: "Future IssuedAt Timestamp", Category: "freshness", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSONAt(t, futureAnchor, nil) },
			ExpectedStatus: http.StatusBadRequest, ExpectedDelta: 0,
		},

		// --- CATEGORY: IDENTITY & BOUNDARY (Expected Status: 401 Unauthorized) ---
		{
			ID: "AET-ATT-0030", Name: "Identity Mismatch (Header vs Envelope)", Category: "auth", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.IdentityRef = "agent://unauthorized-bot" })
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0031", Name: "Empty Bearer Authorization Token", Category: "auth", Method: http.MethodPost, Path: validPath, AuthHeader: "Bearer ",
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusUnauthorized, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0032", Name: "Malformed Authorization Header Format", Category: "auth", Method: http.MethodPost, Path: validPath, AuthHeader: "mock-token-finance-bot",
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusUnauthorized, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0033", Name: "Identity Reference Case Inconsistency", Category: "auth", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.IdentityRef = "AGENT://FINANCE-BOT-01" })
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0034", Name: "Truncated Token Credential", Category: "auth", Method: http.MethodPost, Path: validPath, AuthHeader: "Bearer mock-token",
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusUnauthorized, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0035", Name: "Special Characters in Identity Boundary", Category: "auth", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.IdentityRef = "agent://finance-bot-01' OR '1'='1" })
			},
			ExpectedStatus: http.StatusUnauthorized, ExpectedDelta: 0,
		},

		// --- CATEGORY: METHOD & ROUTING CONFUSION ---
		{
			ID: "AET-ATT-0036", Name: "Disallowed HTTP Method PUT", Category: "method", Method: http.MethodPut, Path: validPath, AuthHeader: validAuth,
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusMethodNotAllowed, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0037", Name: "Disallowed HTTP Method PATCH", Category: "method", Method: http.MethodPatch, Path: validPath, AuthHeader: validAuth,
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusMethodNotAllowed, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0038", Name: "Disallowed HTTP Method OPTIONS", Category: "method", Method: http.MethodOptions, Path: validPath, AuthHeader: validAuth,
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusMethodNotAllowed, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0039", Name: "Unknown Action Subpath", Category: "method", Method: http.MethodPost, Path: "/v1/action/execute", AuthHeader: validAuth,
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusNotFound, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0040", Name: "Path Traversal Sequence in Request URL", Category: "method", Method: http.MethodPost, Path: "/v1/action/../health", AuthHeader: validAuth,
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusNotFound, ExpectedDelta: 0,
		},

		// --- CATEGORY: POLICY ABUSE (Expected Status: 403 Forbidden) ---
		{
			ID: "AET-ATT-0041", Name: "Unsupported Grant Operation", Category: "policy", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.Operation = "GRANT" })
			},
			ExpectedStatus: http.StatusForbidden, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0042", Name: "Unsupported Revoke Operation", Category: "policy", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.Operation = "REVOKE" })
			},
			ExpectedStatus: http.StatusForbidden, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0043", Name: "Escalated Target Resource (system/root)", Category: "policy", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.TargetResource = "system/root" })
			},
			ExpectedStatus: http.StatusForbidden, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0044", Name: "Escalated Intent Definition", Category: "policy", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.Intent = "escalate_privileges" })
			},
			ExpectedStatus: http.StatusForbidden, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0045", Name: "Escalated Capability Wildcard", Category: "policy", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.Capability = "admin:*" })
			},
			ExpectedStatus: http.StatusForbidden, ExpectedDelta: 0,
		},

		// --- CATEGORY: INPUT BOUNDARY & REVOCATION ---
		{
			ID: "AET-ATT-0046", Name: "Unsanitized Markup in Intent String", Category: "policy", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.Intent = "<script>alert(1)</script>" })
			},
			ExpectedStatus: http.StatusForbidden, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0047", Name: "Null Byte Injection in Target Field", Category: "policy", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.TargetResource = "invoice/123\x00" })
			},
			ExpectedStatus: http.StatusForbidden, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0048", Name: "Revoked Identity Principal", Category: "revocation", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			Revoke:         func(r *revocation.InMemoryRevocationRegistry) { r.RevokeIdentity("agent://finance-bot-01") },
			BuildBody:      func(t *testing.T) []byte { return freshEnvelopeJSON(t, nil) },
			ExpectedStatus: http.StatusForbidden, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0049", Name: "Revoked Nonce Identifier", Category: "revocation", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			Revoke: func(r *revocation.InMemoryRevocationRegistry) { r.RevokeNonce("nonce-day9-049") },
			BuildBody: func(t *testing.T) []byte {
				return freshEnvelopeJSON(t, func(e *envelope.ActionEnvelope) { e.NonceID = "nonce-day9-049" })
			},
			ExpectedStatus: http.StatusForbidden, ExpectedDelta: 0,
		},
		{
			ID: "AET-ATT-0050", Name: "Resource Limit Exceeded (2MB Payload)", Category: "envelope", Method: http.MethodPost, Path: validPath, AuthHeader: validAuth,
			BuildBody:      func(t *testing.T) []byte { return bytes.Repeat([]byte("A"), 2*1024*1024) },
			ExpectedStatus: http.StatusRequestEntityTooLarge, ExpectedDelta: 0,
		},
	}
}

// TestAttackLabExtended runs the complete 50-scenario Attack Lab corpus
// (DAY8-001 through DAY8-020 plus AET-ATT-0021 through AET-ATT-0050).
func TestAttackLabExtended(t *testing.T) {
	corpusDir := filepath.Join("..", "..", "Aether-Evidence", "09_attack_lab")
	if err := os.MkdirAll(corpusDir, 0o755); err != nil {
		t.Fatalf("could not create corpus dir %q: %v", corpusDir, err)
	}

	scenarios := append(buildCoreScenarios(), buildExtendedScenarios()...)
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

	writeExtendedCorpus(t, corpusDir, results)
}

func writeExtendedCorpus(t *testing.T, dir string, results []outcome) {
	t.Helper()

	// --- day9-attack-lab.txt (human readable) ---
	var txt strings.Builder
	txt.WriteString("Day 9 Attack Lab — 50-Scenario Expansion Execution\n")
	txt.WriteString("==================================================\n\n")
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

	if err := os.WriteFile(filepath.Join(dir, "day9-attack-lab.txt"), []byte(txt.String()), 0o644); err != nil {
		t.Fatalf("could not write day9-attack-lab.txt: %v", err)
	}

	// --- day9-scenario-corpus.json (structured) ---
	corpus := struct {
		CorpusVersion  string    `json:"corpus_version"`
		GeneratedAt    string    `json:"generated_at"`
		TotalScenarios int       `json:"total_scenarios"`
		Allowed        int       `json:"allowed"`
		Blocked        int       `json:"blocked"`
		Bypassed       int       `json:"bypassed"`
		Inconclusive   int       `json:"inconclusive"`
		InfraErrors    int       `json:"infrastructure_errors"`
		Scenarios      []outcome `json:"scenarios"`
	}{
		CorpusVersion:  "v0.2.0-day9",
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
		t.Fatalf("could not marshal day 9 corpus: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "day9-scenario-corpus.json"), corpusJSON, 0o644); err != nil {
		t.Fatalf("could not write day9-scenario-corpus.json: %v", err)
	}

	// --- day9-attack-lab.jsonl (one JSON object per line) ---
	var jsonl strings.Builder
	for _, r := range results {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("could not marshal jsonl outcome: %v", err)
		}
		jsonl.Write(line)
		jsonl.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "day9-attack-lab.jsonl"), []byte(jsonl.String()), 0o644); err != nil {
		t.Fatalf("could not write day9-attack-lab.jsonl: %v", err)
	}
}
