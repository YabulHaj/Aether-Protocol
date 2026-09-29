package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	benchmarkIterations = 100
	benchmarkWarmups    = 5
)

// --- Result Schema Definitions ---

type BenchmarkReport struct {
	BenchmarkVersion    string           `json:"benchmark_version"`
	GeneratedAt         string           `json:"generated_at"`
	Environment         EnvironmentInfo  `json:"environment"`
	ExecutionParameters ExecutionParams  `json:"execution_parameters"`
	Summary             BenchmarkSummary `json:"summary"`
	Scenarios           []ScenarioResult `json:"scenarios"`
}

type EnvironmentInfo struct {
	OS                     string `json:"os"`
	Architecture           string `json:"architecture"`
	GoVersion              string `json:"go_version"`
	ExecutionType          string `json:"execution_type"`
	UncertaintyLimitations string `json:"uncertainty_limitations"`
}

type ExecutionParams struct {
	IterationsPerScenario int `json:"iterations_per_scenario"`
	WarmupCycles          int `json:"warmup_cycles"`
}

type BenchmarkSummary struct {
	TotalScenarios int            `json:"total_scenarios"`
	AetherOutcomes map[string]int `json:"aether_outcomes"`
}

type ScenarioResult struct {
	ScenarioID     string                    `json:"scenario_id"`
	Category       string                    `json:"category"`
	ExpectedStatus int                       `json:"expected_status"`
	ExpectedDelta  int                       `json:"expected_backend_delta"`
	Baselines      map[string]BaselineResult `json:"baselines"`
}

type BaselineResult struct {
	State                    string         `json:"state"`
	Description              string         `json:"description"`
	IterationsRequested      int            `json:"iterations_requested,omitempty"`
	IterationsCompleted      int            `json:"iterations_completed,omitempty"`
	StatusCounts             map[int]int    `json:"status_counts,omitempty"`
	BackendDeltaCounts       map[int]int    `json:"backend_delta_counts,omitempty"`
	OutcomeCounts            map[string]int `json:"outcome_counts,omitempty"`
	EvidenceRecordCounts     map[int]int    `json:"evidence_record_counts,omitempty"`
	EvidenceHashValidCounts  map[string]int `json:"evidence_hash_valid_counts,omitempty"`
	EvidenceParseErrorCounts map[string]int `json:"evidence_parse_error_counts,omitempty"`
	IsStable                 *bool          `json:"is_stable,omitempty"`
	FinalClassification      string         `json:"final_classification,omitempty"`
	LatencySampleCount       int            `json:"latency_sample_count,omitempty"`
	LatencyP50Ms             float64        `json:"latency_p50_ms,omitempty"`
	LatencyP95Ms             float64        `json:"latency_p95_ms,omitempty"`
	LatencyP99Ms             *float64       `json:"latency_p99_ms"`
	StandardDeviation        float64        `json:"standard_deviation_ms,omitempty"`
}

// --- Baseline Abstraction ---

type BaselineState string

const (
	StateMeasured       BaselineState = "MEASURED"
	StateNotImplemented BaselineState = "NOT_IMPLEMENTED"
	StateNotApplicable  BaselineState = "NOT_APPLICABLE"
)

type BaselineAdapter interface {
	Name() string
	Description() string
	Supports(sc scenario) BaselineState
	RunIteration(t *testing.T, sc scenario) (latency time.Duration, actualStatus int, actualDelta int, outcome string, evCount int, evHashValid bool, parseErrStr string)
}

// -- 1. Aether Enforced Baseline --
type AetherBaseline struct{}

func (a *AetherBaseline) Name() string { return "aether_zero_trust" }
func (a *AetherBaseline) Description() string {
	return "The Aether zero-trust enforcement pipeline executing full identity, policy, and evidence validation."
}
func (a *AetherBaseline) Supports(sc scenario) BaselineState { return StateMeasured }

func (a *AetherBaseline) RunIteration(t *testing.T, sc scenario) (latency time.Duration, actualStatus int, actualDelta int, outcome string, evCount int, evHashValid bool, parseErrStr string) {
	ok := t.Run("", func(it *testing.T) {
		srv, backend, registry, evBuf := newTestServer(it)
		if sc.Revoke != nil {
			sc.Revoke(registry)
		}
		ts := httptest.NewServer(srv.Routes())
		it.Cleanup(func() { ts.Close() })
		client := ts.Client()

		// Warm-up
		for i := 0; i < benchmarkWarmups; i++ {
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
			resp, _ := client.Do(req)
			if resp != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}

		body := sc.BuildBody(it)
		req, err := http.NewRequest(sc.Method, ts.URL+sc.Path, bytes.NewReader(body))
		if err != nil {
			it.Fatalf("failed to create request: %v", err)
		}
		if sc.AuthHeader != "" {
			req.Header.Set("Authorization", sc.AuthHeader)
		}

		beforeHits := backend.hitCount()
		beforeEv := evBuf.Len()

		// Measured Execution
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			it.Fatalf("request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		latency = time.Since(start)

		actualStatus = resp.StatusCode
		actualDelta = int(backend.hitCount() - beforeHits)

		newEv := evBuf.String()[beforeEv:]
		reasons, records, hashOK, parseErr := parseAndVerifyEvidence(newEv)

		evCount = len(records)
		evHashValid = hashOK
		if parseErr != nil {
			parseErrStr = parseErr.Error()
		}

		evidenceValid := true
		if parseErr != nil {
			evidenceValid = false
		} else if evCount > 0 && !hashOK {
			evidenceValid = false
		}

		if sc.ExpectedReason != "" {
			if evCount != 1 || !hashOK {
				evidenceValid = false
			} else {
				reasonMatch := false
				for _, r := range reasons {
					if r == sc.ExpectedReason {
						reasonMatch = true
						break
					}
				}
				if !reasonMatch {
					evidenceValid = false
				}
			}
		}

		outcome = outcomeInconclusive
		if actualStatus == sc.ExpectedStatus && actualDelta == sc.ExpectedDelta && evidenceValid {
			if sc.Category == catBaseline {
				outcome = outcomeAllowedBaseline
			} else {
				outcome = outcomeBlocked
			}
		} else if actualStatus >= 200 && actualStatus < 300 && sc.ExpectedStatus >= 400 {
			outcome = outcomeBypassed
		} else if actualStatus >= 500 {
			outcome = outcomeInfrastructureError
		}
	})

	if !ok {
		t.Fatalf("benchmark iteration failed fatally for scenario %s in baseline %s", sc.ID, a.Name())
	}
	return
}

// -- 2. Weak Passthrough Baseline --
type WeakPassthroughBaseline struct{}

func (w *WeakPassthroughBaseline) Name() string { return "weak_passthrough" }
func (w *WeakPassthroughBaseline) Description() string {
	return "An intentionally weak no-enforcement HTTP control. Request counter represents requests reaching the weak handler, not Aether backend hits."
}
func (w *WeakPassthroughBaseline) Supports(sc scenario) BaselineState { return StateMeasured }

func (w *WeakPassthroughBaseline) RunIteration(t *testing.T, sc scenario) (latency time.Duration, actualStatus int, actualDelta int, outcome string, evCount int, evHashValid bool, parseErrStr string) {
	ok := t.Run("", func(it *testing.T) {
		var hits int
		handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" {
				rw.WriteHeader(http.StatusOK)
				return
			}
			hits++
			io.Copy(io.Discard, r.Body)
			rw.WriteHeader(http.StatusOK)
		})
		ts := httptest.NewServer(handler)
		it.Cleanup(func() { ts.Close() })
		client := ts.Client()

		for i := 0; i < benchmarkWarmups; i++ {
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
			resp, _ := client.Do(req)
			if resp != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}

		body := sc.BuildBody(it)
		req, err := http.NewRequest(sc.Method, ts.URL+sc.Path, bytes.NewReader(body))
		if err != nil {
			it.Fatalf("failed to create request: %v", err)
		}
		if sc.AuthHeader != "" {
			req.Header.Set("Authorization", sc.AuthHeader)
		}

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			it.Fatalf("request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		latency = time.Since(start)

		actualStatus = resp.StatusCode
		actualDelta = hits
		evCount = 0
		evHashValid = true
		parseErrStr = ""

		outcome = outcomeInconclusive
		if actualStatus == sc.ExpectedStatus && actualDelta == sc.ExpectedDelta {
			if sc.Category == catBaseline {
				outcome = outcomeAllowedBaseline
			} else {
				outcome = outcomeBlocked
			}
		} else if actualStatus >= 200 && actualStatus < 300 && sc.ExpectedStatus >= 400 {
			outcome = outcomeBypassed
		}
	})

	if !ok {
		t.Fatalf("benchmark iteration failed fatally for scenario %s in baseline %s", sc.ID, w.Name())
	}
	return
}

// -- 3. Conventional OIDC Baseline --
type ConventionalOIDCTokenBaseline struct{}

func (c *ConventionalOIDCTokenBaseline) Name() string { return "conventional_oidc" }
func (c *ConventionalOIDCTokenBaseline) Description() string {
	return "A conventional token-based authorization baseline (e.g., OAuth/OIDC/IAM)."
}
func (c *ConventionalOIDCTokenBaseline) Supports(sc scenario) BaselineState {
	return StateNotImplemented
}
func (c *ConventionalOIDCTokenBaseline) RunIteration(t *testing.T, sc scenario) (time.Duration, int, int, string, int, bool, string) {
	return 0, 0, 0, "", 0, false, ""
}

// --- Execution and Stats Logic ---

func calculateSampleStats(latencies []time.Duration) (p50, p95, sampleStdDev float64) {
	if len(latencies) == 0 {
		return 0, 0, 0
	}

	var ms []float64
	var sum float64
	for _, l := range latencies {
		val := float64(l.Microseconds()) / 1000.0
		ms = append(ms, val)
		sum += val
	}

	sort.Float64s(ms)
	p50Idx := int(math.Floor(float64(len(ms)-1) * 0.50))
	p95Idx := int(math.Floor(float64(len(ms)-1) * 0.95))

	p50 = ms[p50Idx]
	p95 = ms[p95Idx]

	if len(ms) > 1 {
		mean := sum / float64(len(ms))
		var sqDiffSum float64
		for _, val := range ms {
			diff := val - mean
			sqDiffSum += diff * diff
		}
		sampleStdDev = math.Sqrt(sqDiffSum / float64(len(ms)-1))
	}

	return p50, p95, sampleStdDev
}

// --- Day 10 Main Benchmark Harness ---

func TestDay10Benchmark(t *testing.T) {
	scenarios := append(buildCoreScenarios(), buildExtendedScenarios()...)
	baselines := []BaselineAdapter{
		&AetherBaseline{},
		&WeakPassthroughBaseline{},
		&ConventionalOIDCTokenBaseline{},
	}

	report := BenchmarkReport{
		BenchmarkVersion: "v0.2.0-day10",
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		Environment: EnvironmentInfo{
			OS:                     runtime.GOOS,
			Architecture:           runtime.GOARCH,
			GoVersion:              runtime.Version(),
			ExecutionType:          "local_loopback",
			UncertaintyLimitations: "Local loopback execution using httptest. Results are local loopback measurements and do not represent production network or remote identity-provider latency.",
		},
		ExecutionParameters: ExecutionParams{
			IterationsPerScenario: benchmarkIterations,
			WarmupCycles:          benchmarkWarmups,
		},
		Summary: BenchmarkSummary{
			TotalScenarios: len(scenarios),
			AetherOutcomes: make(map[string]int),
		},
		Scenarios: make([]ScenarioResult, 0, len(scenarios)),
	}

	for _, sc := range scenarios {
		res := ScenarioResult{
			ScenarioID:     sc.ID,
			Category:       sc.Category,
			ExpectedStatus: sc.ExpectedStatus,
			ExpectedDelta:  sc.ExpectedDelta,
			Baselines:      make(map[string]BaselineResult),
		}

		for _, adapter := range baselines {
			state := adapter.Supports(sc)
			baseRes := BaselineResult{
				State:       string(state),
				Description: adapter.Description(),
			}

			if state == StateMeasured {
				baseRes.IterationsRequested = benchmarkIterations
				baseRes.StatusCounts = make(map[int]int)
				baseRes.BackendDeltaCounts = make(map[int]int)
				baseRes.OutcomeCounts = make(map[string]int)
				baseRes.EvidenceRecordCounts = make(map[int]int)
				baseRes.EvidenceHashValidCounts = make(map[string]int)
				baseRes.EvidenceParseErrorCounts = make(map[string]int)

				var latencies []time.Duration
				var firstStatus, firstDelta int
				var firstOutcome string
				isStable := true

				for i := 0; i < benchmarkIterations; i++ {
					latency, actualStatus, actualDelta, outcome, evCount, evHashValid, parseErrStr := adapter.RunIteration(t, sc)
					latencies = append(latencies, latency)

					baseRes.StatusCounts[actualStatus]++
					baseRes.BackendDeltaCounts[actualDelta]++
					baseRes.OutcomeCounts[outcome]++
					baseRes.EvidenceRecordCounts[evCount]++

					hashKey := "true"
					if !evHashValid {
						hashKey = "false"
					}
					baseRes.EvidenceHashValidCounts[hashKey]++

					if parseErrStr != "" {
						baseRes.EvidenceParseErrorCounts[parseErrStr]++
					}

					baseRes.IterationsCompleted++

					if i == 0 {
						firstStatus = actualStatus
						firstDelta = actualDelta
						firstOutcome = outcome
					} else {
						if actualStatus != firstStatus || actualDelta != firstDelta || outcome != firstOutcome {
							isStable = false
						}
					}
				}

				if baseRes.IterationsCompleted != baseRes.IterationsRequested {
					t.Fatalf("benchmark failure: iterations completed (%d) != requested (%d) for scenario %s, baseline %s",
						baseRes.IterationsCompleted, baseRes.IterationsRequested, sc.ID, adapter.Name())
				}

				p50, p95, stdDev := calculateSampleStats(latencies)
				baseRes.LatencySampleCount = len(latencies)
				baseRes.LatencyP50Ms = p50
				baseRes.LatencyP95Ms = p95
				baseRes.StandardDeviation = stdDev
				baseRes.LatencyP99Ms = nil
				baseRes.IsStable = &isStable

				if isStable {
					baseRes.FinalClassification = firstOutcome
				} else {
					baseRes.FinalClassification = "INCONCLUSIVE_UNSTABLE"
				}

				if adapter.Name() == "aether_zero_trust" {
					expectedOutcome := outcomeBlocked
					if sc.Category == catBaseline {
						expectedOutcome = outcomeAllowedBaseline
					}

					if !isStable || baseRes.FinalClassification != expectedOutcome {
						t.Fatalf("Day 10 Aether benchmark gate failed for scenario %s: got final classification %q, expected %q (stable: %v)",
							sc.ID, baseRes.FinalClassification, expectedOutcome, isStable)
					}

					report.Summary.AetherOutcomes[baseRes.FinalClassification]++
				}
			}
			res.Baselines[adapter.Name()] = baseRes
		}
		report.Scenarios = append(report.Scenarios, res)
	}

	writeBenchmarkReports(t, report)
}

func writeBenchmarkReports(t *testing.T, report BenchmarkReport) {
	t.Helper()
	benchDir := filepath.Join("..", "evidence", "10_benchmarks")
	if err := os.MkdirAll(benchDir, 0o755); err != nil {
		t.Fatalf("could not create benchmark dir: %v", err)
	}

	b, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("could not marshal JSON report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(benchDir, "benchmark-results.json"), b, 0o644); err != nil {
		t.Fatalf("could not write json report: %v", err)
	}

	var txt strings.Builder
	txt.WriteString("Aether Protocol Day 10 Benchmark Report\n")
	txt.WriteString("=======================================\n\n")
	txt.WriteString(fmt.Sprintf("Generated At : %s\n", report.GeneratedAt))
	txt.WriteString(fmt.Sprintf("Environment  : %s / %s / %s\n", report.Environment.OS, report.Environment.Architecture, report.Environment.GoVersion))
	txt.WriteString(fmt.Sprintf("Scenarios    : %d\n", report.Summary.TotalScenarios))
	txt.WriteString(fmt.Sprintf("Iterations   : %d per scenario (Warmup: %d)\n", report.ExecutionParameters.IterationsPerScenario, report.ExecutionParameters.WarmupCycles))
	txt.WriteString(fmt.Sprintf("Limitations  : %s\n\n", report.Environment.UncertaintyLimitations))

	txt.WriteString("--- Aether Security Outcomes (Aggregated) ---\n")
	for k, v := range report.Summary.AetherOutcomes {
		txt.WriteString(fmt.Sprintf("%s: %d\n", k, v))
	}
	txt.WriteString("\n--- Scenario Results ---\n")

	for _, sc := range report.Scenarios {
		txt.WriteString(fmt.Sprintf("[%s] %s (Expected: HTTP %d, Delta %d)\n", sc.ScenarioID, sc.Category, sc.ExpectedStatus, sc.ExpectedDelta))
		for baseName, baseRes := range sc.Baselines {
			if baseRes.State == string(StateMeasured) {
				stability := "STABLE"
				if baseRes.IsStable != nil && !*baseRes.IsStable {
					stability = "UNSTABLE"
				} else {
					stability = fmt.Sprintf("All %d observed iterations produced the same recorded outcome.", baseRes.IterationsCompleted)
				}
				txt.WriteString(fmt.Sprintf("  %-20s -> %-16s | P50: %6.2fms | P95: %6.2fms | StdDev: %5.2fms\n",
					baseName, baseRes.FinalClassification, baseRes.LatencyP50Ms, baseRes.LatencyP95Ms, baseRes.StandardDeviation))
				txt.WriteString(fmt.Sprintf("    Status: %v | Deltas: %v | EvCounts: %v | Stability: %s\n", baseRes.StatusCounts, baseRes.BackendDeltaCounts, baseRes.EvidenceRecordCounts, stability))
			} else {
				txt.WriteString(fmt.Sprintf("  %-20s -> %s\n", baseName, baseRes.State))
			}
		}
		txt.WriteString("\n")
	}

	if err := os.WriteFile(filepath.Join(benchDir, "benchmark-report.txt"), []byte(txt.String()), 0o644); err != nil {
		t.Fatalf("could not write text report: %v", err)
	}
}
