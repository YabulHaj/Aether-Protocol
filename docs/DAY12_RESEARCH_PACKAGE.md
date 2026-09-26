# Aether Day 12 — Research Package

**Date:** 2026-09-22
**Purpose:** Technical research and evidence documentation
**Evidence posture:** Creator-controlled evidence only unless explicitly stated otherwise

---

## 0. Scope and Source Basis

This research package is based on the Aether-Protocol repository artifacts reviewed for Day 12, including:

* `README.md`
* `docs/CHARTER.md`
* `docs/THREAT_MODEL.md`
* `DEFINITION_OF_DONE.md`
* `docs/DAY11_REPRODUCTION.md`
* `docs/KNOWN_LIMITATIONS.md`
* `docs/IP_BOUNDARY.md`
* `evidence/MASTER_INDEX.md`
* `evidence/AET-EV-2026-0011_Day11_Reproduction.md`
* `evidence/10_benchmarks/day10-benchmark-results.json`
* `evidence/10_benchmarks/day10-benchmark-report.txt`
* `evidence/reproduction_20260922_225514/`
* `evidence/reproduction_20260922_225859/`
* `evidence/reproduction_20260923_011320/`
* `cmd/main.go`
* `cmd/main_test.go`
* `cmd/attack_lab_test.go`
* `cmd/attack_lab_day9_test.go`
* `cmd/benchmark_test.go`
* `cmd/sse_test.go`
* `cmd/telemetry_test.go`
* `internal/identity/`
* `internal/policy/`
* `internal/envelope/`
* `internal/revocation/`
* `internal/evidence/`
* `internal/enforcement/`
* `internal/telemetry/`
* `scripts/reproduce.ps1`

Where a repository file was not available for direct inspection during this analysis, its assertions are not inferred and are explicitly identified as unaudited.

The status vocabulary used throughout this document is:

* `IMPLEMENTED`
* `TESTED`
* `OBSERVED`
* `NOT TESTED`
* `NOT VERIFIED`
* `OUT OF SCOPE`
* `DOCUMENTED`

### Day 11 evidence boundary

The formal Day 11 evidence record remains:

**Evidence ID:** `AET-EV-2026-0011`
**Classification:** `Creator-controlled clean reproduction`

Recorded successful runs:

* `reproduction_20260922_225514`
* `reproduction_20260922_225859`
* `reproduction_20260923_011320`

Independent reproduction: **NOT VERIFIED**
Independent security review: **NOT VERIFIED**
Independent organizational evaluation: **NOT VERIFIED**

This document does not upgrade that classification.

---

# 1. Threat Model

**Status: `DOCUMENTED`, with individual controls partially `TESTED` / `OBSERVED` where supported.**

Source: `docs/THREAT_MODEL.md`, corroborated by the inspected implementation.

The threat model is a documented research artifact. It describes intended protections and boundaries. It is not itself a runtime component and is therefore not classified as an implemented security control.

## 1.1 Protected threats documented by the repository

The repository threat model identifies the following threat classes:

* Unauthorized tool use — an agent invoking a capability it was not granted.
* Privilege escalation — obtaining or using more access than authorized.
* Replay of stale authorization — reuse of old or already-used authorization material.
* Unauthorized target/resource access — acting outside authorized resource scope.
* Unauthorized methods or operations — performing operations not authorized by policy.
* Failure to revoke compromised identities or sessions.
* Inadequate auditability of autonomous actions.

## 1.2 Explicitly out of scope

The documented threat model excludes:

* General AI alignment.
* Machine consciousness or philosophical questions.
* All forms of prompt injection as a detection/prevention problem.
* Zero-day vulnerabilities in underlying software or infrastructure.
* Every possible future attack technique.
* Universal AI safety.
* Absolute or guaranteed security.

Aether may reduce the consequences of some upstream failures, but the repository does not establish that it detects or prevents every upstream attack class.

## 1.3 Implementation anchors

### Envelope validation and freshness

`internal/envelope/envelope.go`

Relevant mechanisms include:

* required-field validation
* expiration checks
* future-issuance checks
* expiry ordering checks
* audience validation
* payload-hash validation

Status: **IMPLEMENTED / TESTED / OBSERVED** for the exercised request classes.

### Revocation and anti-replay

`internal/revocation/revocation.go`

Relevant mechanisms include:

* identity revocation
* nonce revocation
* combined revocation checks
* one-time nonce consumption

Status: **IMPLEMENTED / TESTED / OBSERVED** for the exercised request classes.

### Policy evaluation

`internal/policy/policy.go`

The implementation uses default-deny evaluation and exact-match authorization.

The policy match uses four required exact dimensions:

* `IdentityRef`
* `Capability`
* `TargetResource`
* `Operation`

and an exact `Intent` match when the rule specifies `Intent`.

Status: **IMPLEMENTED / TESTED / OBSERVED** for the exercised policy cases.

### Record-level evidence integrity

`internal/evidence/evidence.go`

The implementation generates structured NDJSON evidence records and computes a record-level hash over defined fields. Verification uses constant-time comparison.

Status: **IMPLEMENTED / TESTED / OBSERVED** for request classes that generate records; **PARTIALLY OBSERVED** for early-exit request classes.

### Gateway orchestration

`cmd/main.go`

The inspected request path performs, in order:

`identity → body parsing → revocation → envelope validation → audience → identity binding → anti-replay → policy → evidence/telemetry → enforcement`

Status: **IMPLEMENTED / OBSERVED**; individual stages are tested to varying degrees.

## 1.4 Threat-model gaps not directly established

The supplied evidence does not establish:

* a directly named test for the broader "No Self-Authorization" invariant;
* a measured revocation time-to-enforce bound;
* end-to-end behavior against a live external identity provider;
* distributed or multi-instance enforcement behavior;
* production infrastructure resilience.

---

# 2. System Architecture

**Status: `IMPLEMENTED` for the inspected source components; `TESTED` at the cmd-level integration layer where corresponding tests were available.**

The implemented architecture can be traced as:

**IDENTITY → INTENT → AUTHORITY → ACTION → ENFORCEMENT → EVIDENCE**

with revocation operating as a cross-cutting control before authorization.

| Stage       | Implementation                                                 | Role                                                       |
| ----------- | -------------------------------------------------------------- | ---------------------------------------------------------- |
| IDENTITY    | `internal/identity/identity.go`, `internal/identity/spiffe.go` | Derives/verifies requester identity                        |
| INTENT      | `internal/envelope/envelope.go`                                | Carries stated purpose of the requested action             |
| AUTHORITY   | `internal/policy/policy.go`                                    | Decides whether the request matches an authorization rule  |
| REVOCATION  | `internal/revocation/revocation.go`                            | Rejects revoked identities/nonces and consumes nonces once |
| ACTION      | `internal/envelope/envelope.go`                                | Carries target resource and operation                      |
| ENFORCEMENT | `internal/enforcement/enforcement.go`                          | Proxies only allowed actions to the configured backend     |
| EVIDENCE    | `internal/evidence/evidence.go`                                | Records structured authorization/security decisions        |
| TELEMETRY   | `internal/telemetry/telemetry.go`                              | Provides bounded, non-blocking event distribution          |

## 2.1 Handler order

The inspected `actionHandler` in `cmd/main.go` performs the following sequence:

1. Method check — non-POST requests return `405`.
2. Identity verification — invalid identity returns `401`.
3. Body read with a `1 MB` `MaxBytesReader` boundary.
4. JSON parsing — malformed JSON returns `400`.
5. Revocation check — revoked identity/nonce returns `403`.
6. Envelope validation — invalid envelope returns `400`.
7. Audience validation — invalid audience returns `400`.
8. Verified-identity versus envelope-identity comparison — mismatch returns `401`.
9. One-time nonce consumption — replay returns `403`.
10. Policy evaluation.
11. Telemetry broadcast.
12. Denial returns `403`; allowed actions proceed to enforcement.

The precise evidence behavior of early-exit request classes is addressed separately in §3.6.

## 2.2 Identity-provider mode selection

`cmd/main.go` reads `AETHER_IDENTITY_MODE`.

The inspected implementation supports:

* `mock` → `MockIdentityProvider`, accompanied by an explicit security warning.
* `spiffe` → `SpiffeIdentityProvider`.
* empty value → startup error.
* unsupported value → startup error.

This is consistent with a fail-closed configuration choice: the gateway does not silently select a fallback identity mode.

The supplied `cmd/main_test.go` contains `TestBuildIdentityProvider_ZeroSilentFallback`.

## 2.3 Identity implementation

`internal/identity/identity.go` defines the identity-provider contract and separates credential-derived identity from the caller-supplied `identity_ref` field in the action envelope.

The implementation therefore treats:

* the verified identity derived from the request credential, and
* the identity declared inside the JSON envelope

as separate values that must subsequently agree.

This is an implementation observation, not a claim that all possible credential systems are secure.

## 2.4 SPIFFE implementation

`internal/identity/spiffe.go` contains SPIFFE-related provider logic, including JWT-SVID validation and X.509-SVID identity extraction.

The supplied evidence does not establish successful end-to-end operation against a live SPIRE deployment.

The repository itself notes that the gateway does not currently terminate TLS, limiting the directly exercised mTLS path.

## 2.5 Enforcement path

`internal/enforcement/enforcement.go` implements reverse-proxy enforcement.

The inspected source:

* requires a configured HTTP/HTTPS upstream;
* strips `X-Forwarded-*` headers;
* strips `X-Aether-*` headers;
* sets the decision header for an allowed request; and
* re-validates the requested target against the configured upstream before proxying.

The supplied evidence supports the existence and local testing of this enforcement path. It does not establish production reverse-proxy resilience.

---

# 3. Security Invariants

Each invariant below distinguishes implementation, test evidence, observed result, and limitation.

## 3.1 Default Deny — `TESTED / OBSERVED`

**Implementation:**
`internal/policy/policy.go`

The policy engine returns denial when no matching rule authorizes the request.

Policy matching uses four required exact dimensions:

* `IdentityRef`
* `Capability`
* `TargetResource`
* `Operation`

plus an exact `Intent` match when the rule specifies `Intent`.

**Tests/evidence:**

* `DAY8-016`
* `DAY8-017`
* `DAY8-018`
* `DAY8-019`
* `AET-ATT-0041` through `AET-ATT-0047`
* Day 10 benchmark artifacts

**Observed result:**
The supplied artifacts report blocked outcomes for the tested non-matching policy cases.

**Limitation:**
The observed default-deny property is exercised against the loaded policy. It does not establish that every possible future policy configuration is correct or complete.

---

## 3.2 Freshness and Anti-Replay — `TESTED / OBSERVED`

**Implementation:**

* `internal/envelope/envelope.go`
* `internal/revocation/revocation.go`

Relevant controls include:

* expiration validation;
* future `IssuedAt` rejection;
* expiry ordering;
* one-time nonce consumption.

**Tests/evidence:**

* `DAY8-012`
* `DAY8-013`
* `DAY8-015`
* `AET-ATT-0028`
* `AET-ATT-0029`
* `AET-ATT-0049`
* `TestAntiReplay_DuplicateNonceRejectedAndZeroHits`

**Observed result:**
The supplied artifacts report blocked stale/replayed/revoked requests. The duplicate-nonce test preserves the backend hit count at one after the replay attempt.

**Limitation:**
The nonce store is process-local memory. The inspected implementation does not establish persistence, eviction, or cross-instance synchronization.

---

## 3.3 Target and Action Scope Binding — `TESTED / OBSERVED`

**Implementation:**
`internal/policy/policy.go`

The authorization decision uses exact matching across the four required dimensions, with optional exact `Intent`.

**Tests/evidence:**

* `DAY8-016`
* `DAY8-017`
* `DAY8-019`
* `AET-ATT-0043`
* `AET-ATT-0044`
* `AET-ATT-0045`

**Observed result:**
The supplied artifacts report `deny_no_matching_rule` for the tested wrong-target, wrong-operation, and near-miss resource cases.

**Limitation:**
The implementation does not establish wildcard, prefix, hierarchical, or case-folded resource semantics.

---

## 3.4 No Self-Authorization — `NOT DIRECTLY TESTED`

**Implementation observation:**
The inspected source loads policy from `defaultPolicy()` during process construction. The inspected request path does not expose a caller-controlled runtime policy mutation interface.

**Evidence status:**
No supplied test directly establishes the broader "No Self-Authorization" invariant as a passing security gate.

**Bounded interpretation:**
The inspected implementation does not expose an observed runtime caller-controlled policy mutation path. This is an architectural observation, not proof of a universal no-self-authorization property.

---

## 3.5 Fail Closed on Invalid Security Data — `TESTED / OBSERVED`

**Implementation:**

* `internal/envelope/envelope.go`
* `cmd/main.go`

Envelope validation returns an error rather than silently accepting invalid data. Invalid identity-mode configuration also prevents silent fallback.

**Tests/evidence:**

* `TestBuildIdentityProvider_ZeroSilentFallback`
* `DAY8-005`
* `DAY8-006`
* `DAY8-008` through `DAY8-013`
* `DAY8-020`
* `AET-ATT-0021` through `AET-ATT-0027`

**Observed result:**
The supplied artifacts report blocked/malformed outcomes with zero backend impact for these tested conditions.

**Limitation:**
Envelope validation reports the first detected validation error rather than aggregating all errors.

---

## 3.6 Structured Evidence Generation — `PARTIALLY OBSERVED`

**Implementation:**
`internal/evidence/evidence.go`

The inspected implementation:

* creates structured evidence records;
* emits NDJSON;
* assigns record IDs and timestamps;
* computes a record-level tamper hash;
* verifies the hash using constant-time comparison.

**Tests/evidence:**

* `TestEvidence_HashVerifiesForAllowedRequest`
* attack-lab evidence parsing/verification
* Day 10 benchmark artifacts

**Observed result:**
For envelope/auth/policy/revocation request classes, the supplied benchmark shows one evidence record per tested request.

However, the supplied benchmark also reports zero evidence records for specific early-exit classes:

* method-not-allowed (`405`);
* route-not-found (`404`);
* payload-too-large (`413`).

### Documented requirement versus observed behavior

`DEFINITION_OF_DONE.md` gate 9 states that every processed request during testing should produce a corresponding structured evidence record.

The supplied benchmark artifacts show zero records for the early-exit classes above.

This discrepancy is:

**NOT RESOLVED IN PROVIDED EVIDENCE.**

The package does not assume whether the phrase "processed request" was intended to exclude those early exits. Resolving the discrepancy would require either documented clarification or an implementation/test change.

This invariant therefore must not be described as cleanly passing.

---

## 3.7 Revocation — `TESTED / OBSERVED`

**Implementation:**
`internal/revocation/revocation.go`

Relevant mechanisms include:

* identity revocation;
* nonce revocation;
* combined revocation checking;
* one-time nonce consumption.

**Tests/evidence:**

* `TestRevocation_IdentityRevokedReturns403AndZeroHits`
* `TestRevocation_NonceRevokedReturns403AndZeroHits`
* `DAY8-014`
* `DAY8-015`
* `AET-ATT-0048`
* `AET-ATT-0049`

**Observed result:**
The supplied artifacts report `403 REVOKED` responses with zero backend impact for the tested revocation cases.

**Limitation:**
No measured revocation time-to-enforce bound is established. The process-local storage model also does not establish distributed revocation semantics.

---

# 4. Attack Findings

The supplied evidence contains two principal Attack Lab generations:

* `cmd/attack_lab_test.go` — `DAY8-001` through `DAY8-020`
* `cmd/attack_lab_day9_test.go` — `AET-ATT-0021` through `AET-ATT-0050`

The Day 10 benchmark incorporates the scenario corpus into repeated execution.

The statements below are **observations of the supplied benchmark/test artifacts**, not independent verification.

## 4.1 Day 8 scenarios

| ID       | Condition                | Expected                      | Reported observed result | Control          | Backend Δ | Classification |
| -------- | ------------------------ | ----------------------------- | ------------------------ | ---------------- | --------: | -------------- |
| DAY8-001 | Valid baseline           | 200 / `allow_matched_rule`    | 200                      | Allow            |         1 | PASS           |
| DAY8-002 | GET on `/v1/action`      | 405                           | 405                      | Method gate      |         0 | PASS           |
| DAY8-003 | Missing `Authorization`  | 401 / `IDENTITY_INVALID`      | 401                      | Identity         |         0 | PASS           |
| DAY8-004 | Unknown bearer           | 401 / `IDENTITY_INVALID`      | 401                      | Identity         |         0 | PASS           |
| DAY8-005 | Malformed JSON           | 400 / `MALFORMED`             | 400                      | Envelope         |         0 | PASS           |
| DAY8-006 | Missing `IdentityRef`    | 400 / `MALFORMED`             | 400                      | Envelope         |         0 | PASS           |
| DAY8-007 | Identity mismatch        | 401 / `IDENTITY_MISMATCH`     | 401                      | Identity binding |         0 | PASS           |
| DAY8-008 | Missing `NonceID`        | 400 / `MALFORMED`             | 400                      | Envelope         |         0 | PASS           |
| DAY8-009 | Missing `Capability`     | 400 / `MALFORMED`             | 400                      | Envelope         |         0 | PASS           |
| DAY8-010 | Missing `TargetResource` | 400 / `MALFORMED`             | 400                      | Envelope         |         0 | PASS           |
| DAY8-011 | Missing `Operation`      | 400 / `MALFORMED`             | 400                      | Envelope         |         0 | PASS           |
| DAY8-012 | Expired                  | 400 / `MALFORMED`             | 400                      | Freshness        |         0 | PASS           |
| DAY8-013 | Future `IssuedAt`        | 400 / `MALFORMED`             | 400                      | Freshness        |         0 | PASS           |
| DAY8-014 | Revoked identity         | 403 / `REVOKED`               | 403                      | Revocation       |         0 | PASS           |
| DAY8-015 | Revoked nonce            | 403 / `REVOKED`               | 403                      | Revocation       |         0 | PASS           |
| DAY8-016 | Wrong target             | 403 / `deny_no_matching_rule` | 403                      | Policy           |         0 | PASS           |
| DAY8-017 | Wrong operation          | 403 / `deny_no_matching_rule` | 403                      | Policy           |         0 | PASS           |
| DAY8-018 | Capability escalation    | 403 / `deny_no_matching_rule` | 403                      | Policy           |         0 | PASS           |
| DAY8-019 | Near-miss target         | 403 / `deny_no_matching_rule` | 403                      | Policy           |         0 | PASS           |
| DAY8-020 | Missing `PayloadHash`    | 400 / `MALFORMED`             | 400                      | Envelope         |         0 | PASS           |

## 4.2 Day 9 scenario categories

The supplied Day 9 test file covers:

* Envelope structural integrity: `AET-ATT-0021` through `AET-ATT-0027`
* Freshness: `AET-ATT-0028`, `AET-ATT-0029`
* Identity/boundary cases: `AET-ATT-0030` through `AET-ATT-0035`
* Method/routing cases: `AET-ATT-0036` through `AET-ATT-0040`
* Policy abuse: `AET-ATT-0041` through `AET-ATT-0047`
* Revocation: `AET-ATT-0048`, `AET-ATT-0049`
* Input boundary: `AET-ATT-0050`

The supplied benchmark artifacts report blocked outcomes for these tested attack conditions.

## 4.3 Overall attack-result statement

**The supplied benchmark/test artifacts report 50/50 scenarios meeting their expected outcomes.**

This statement is an observation of creator-controlled test artifacts.

It does not establish:

* independent verification;
* universal attack coverage;
* absence of undiscovered vulnerabilities;
* security against attack classes not represented by the test corpus.

## 4.4 Control comparison observations

The supplied benchmark contains a `weak_passthrough` comparison.

The artifact reports `BYPASSED` behavior for the non-baseline scenarios under that control, demonstrating that the scenario corpus can distinguish an enforcing local pipeline from a deliberately permissive control condition.

The benchmark also reports:

`conventional_oidc: NOT_IMPLEMENTED`

Therefore no functional empirical comparison against a conventional OIDC deployment is established.

---

# 5. Reproduction Method

**Status: `OBSERVED` for three creator-controlled runs; `NOT VERIFIED` for independent reproduction.**

The reproduction harness is:

`scripts/reproduce.ps1`

The documented method includes:

1. execution from a repository containing `go.mod`;
2. use of Go and Git;
3. `go test -count=1 ./...`;
4. execution of the Day 10 benchmark test;
5. generation of timestamped reproduction artifacts.

The primary formal evidence record is:

`evidence/AET-EV-2026-0011_Day11_Reproduction.md`

## 5.1 Formal Day 11 evidence record

**Evidence ID:** `AET-EV-2026-0011`

**Classification:** `Creator-controlled clean reproduction`

**Successful recorded runs:**

* `reproduction_20260922_225514`
* `reproduction_20260922_225859`
* `reproduction_20260923_011320`

**Independent reproduction:** `NOT VERIFIED`

**Independent security review:** `NOT VERIFIED`

**Independent organizational evaluation:** `NOT VERIFIED`

The formal evidence record is intentionally left unchanged.

## 5.2 Recorded outcomes

The supplied artifacts report:

* `reproduction_20260922_225514` — core test suite PASS; benchmark PASS.
* `reproduction_20260922_225859` — core test suite PASS; benchmark PASS.
* `reproduction_20260923_011320` — core test suite PASS; benchmark PASS.

These are creator-controlled observations.

## 5.3 Historical / unindexed reproduction artifact

A separate artifact directory exists:

`reproduction_20260922_224844`

Its recorded core-test output contains:

`FAIL aether-protocol/cmd [setup failed]`

This historical/unindexed artifact:

* is not part of `AET-EV-2026-0011`;
* is not counted as a successful reproduction;
* is not used as evidence supporting successful reproduction;
* does not alter the formal Day 11 evidence record.

Its existence is preserved here for chronology and transparency.

---

# 6. Known Limitations

Sources include `docs/KNOWN_LIMITATIONS.md` and the inspected source/evidence.

## 6.1 Record-level evidence integrity

The repository implements record-level hashing using SHA-256 over defined canonical fields and constant-time comparison for verification.

For this research package, this is described as a **record-level tamper-detection mechanism**, not as a universal integrity guarantee for an entire log system.

The evidence does not establish:

* whole-log integrity;
* ordering guarantees;
* protection against an actor capable of rewriting every log entry;
* external log retention integrity.

## 6.2 Payload integrity

The envelope includes payload-hash verification logic.

The supplied evidence supports detection of payload mutation under the tested mechanism.

It does not establish protection against all forms of application-layer semantic manipulation.

## 6.3 In-memory revocation and replay state

The inspected implementation maintains revocation and consumed-nonce state in process-local memory.

The evidence does not establish:

* persistent replay state;
* distributed replay state;
* cross-instance synchronization;
* bounded memory growth;
* recovery semantics after process restart.

## 6.4 Mock identity provider

`MockIdentityProvider` is a test-oriented identity mechanism.

The repository explicitly requires an explicit `AETHER_IDENTITY_MODE=mock` selection rather than silently falling back.

Mock identity is not evidence of production credential security.

## 6.5 SPIFFE integration scope

`internal/identity/spiffe.go` contains SPIFFE provider code, but the supplied evidence does not establish end-to-end operation against a live SPIFFE/SPIRE environment.

The gateway does not currently terminate TLS in the inspected implementation, limiting direct exercise of the mTLS path.

## 6.6 Dynamic policy management

The inspected policy is statically constructed through `defaultPolicy()`.

The repository does not establish:

* multi-tenant dynamic policy management;
* persistent policy storage;
* runtime policy administration;
* distributed policy synchronization.

## 6.7 Telemetry delivery

The telemetry broker uses bounded queues and is designed to avoid blocking the gateway.

The corresponding tests support non-blocking behavior under saturation.

This does not establish guaranteed delivery; events may be dropped under backpressure by design.

## 6.8 Benchmark scope

The benchmark is local loopback execution using `httptest`.

It does not establish:

* production network latency;
* production throughput;
* production resilience;
* remote identity-provider latency;
* multi-instance behavior;
* distributed storage performance.

## 6.9 Evidence coverage on early exits

The benchmark evidence indicates zero evidence records for certain:

* `405` method rejection;
* `404` route-not-found;
* `413` payload-too-large

requests.

This conflicts with the broad wording of the Day 11 Definition of Done gate concerning evidence coverage.

The discrepancy remains unresolved in the supplied evidence.

## 6.10 Revocation timing

No documented and measured revocation time-to-enforce bound was established in the reviewed material.

## 6.11 Independent validation

The following remain open:

* independent reproduction;
* independent security review;
* independent organizational evaluation.

---

# 7. Bounded Claims

| Claim                                   | Supporting Evidence                                                                                       | What the Evidence Supports                                                                           | What It Does NOT Establish                                                                        |
| --------------------------------------- | --------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Default-deny policy engine              | `internal/policy/policy.go`; Day 8/Day 9 attack scenarios; benchmark artifacts                            | Requests that do not match the loaded authorization rule set are denied in the tested implementation | That every possible policy configuration is correct, complete, or production-suitable             |
| Single-use nonce anti-replay            | `internal/revocation/revocation.go`; `TestAntiReplay_DuplicateNonceRejectedAndZeroHits`; attack scenarios | Duplicate nonces are rejected within the tested process-local mechanism                              | Persistent, distributed, or long-duration replay protection                                       |
| Record-level tamper-detection mechanism | `internal/evidence/evidence.go`; evidence verification test                                               | Mutation of covered fields can be detected for a record under the implemented verification mechanism | Whole-log integrity, ordering integrity, or protection against complete log rewriting             |
| Exact target/operation binding          | `internal/policy/policy.go`; tested wrong-target/wrong-operation cases                                    | The policy engine uses exact matching of the required dimensions                                     | Wildcard, prefix, hierarchical, or case-folded authorization semantics                            |
| Fail-closed identity-mode selection     | `cmd/main.go`; `TestBuildIdentityProvider_ZeroSilentFallback`                                             | Missing or unsupported identity-mode configuration does not silently choose a fallback               | Production identity correctness, key management, rotation, or external identity-provider security |
| Non-blocking telemetry behavior         | `internal/telemetry/telemetry.go`; telemetry tests                                                        | Broadcast can remain non-blocking when a subscriber is saturated                                     | Guaranteed event delivery                                                                         |
| SPIFFE provider code exists             | `internal/identity/spiffe.go`                                                                             | SPIFFE-related provider logic exists in the implementation                                           | End-to-end operation against a live SPIRE deployment                                              |
| Creator-controlled reproduction         | `AET-EV-2026-0011`; three recorded runs                                                                   | The documented reproduction workflow was successfully executed three times by the creator            | Independent reproduction or external validation                                                   |
| Day 10 benchmark observation            | Benchmark source and recorded benchmark artifacts                                                         | The supplied artifacts report 50 scenarios with 100 iterations and the recorded local outcomes       | Production scalability, remote latency, or resilience                                             |
| Attack Lab artifact result              | Attack Lab tests and benchmark evidence                                                                   | The supplied artifacts report 50/50 scenarios meeting their expected outcomes                        | Universal attack coverage or independent security verification                                    |

---

# 8. Claim Audit

| #  | Claim                                                                                   | Supporting Source                                   | Evidence Type         | Observed                                                     | Limitation                                       |
| -- | --------------------------------------------------------------------------------------- | --------------------------------------------------- | --------------------- | ------------------------------------------------------------ | ------------------------------------------------ |
| 1  | Identity is derived from the request credential and compared with the envelope identity | `internal/identity/identity.go`, `cmd/main.go`      | Source + cmd tests    | Identity failure/mismatch scenarios are reported as rejected | Mock identity dominates the tested path          |
| 2  | Envelope validation is fail-fast                                                        | `internal/envelope/envelope.go`                     | Source + attack tests | Malformed-envelope cases are rejected                        | First error only                                 |
| 3  | Audience is constrained to `aether-gateway`                                             | `cmd/main.go`, envelope validation, audience test   | Source + test         | Mismatch rejected                                            | Hard-coded audience                              |
| 4  | Identity mismatch between verified credential and envelope is rejected                  | `cmd/main.go`                                       | Source + test         | `401 IDENTITY_MISMATCH` in the tested case                   | Mock provider scope                              |
| 5  | Revoked identities/nonces are denied                                                    | `internal/revocation/revocation.go`                 | Source + attack tests | `403 REVOKED`, backend impact zero in tested cases           | In-memory state                                  |
| 6  | Duplicate nonces are rejected                                                           | `CheckAndConsumeNonce`, replay test                 | Source + test         | Replay does not produce an additional backend hit            | No persistence/distribution                      |
| 7  | Unmatched policy requests are denied                                                    | `internal/policy/policy.go`                         | Source + attack tests | `deny_no_matching_rule` in tested scenarios                  | Exact-match model                                |
| 8  | Evidence records are generated for tested envelope/auth/policy/revocation paths         | `internal/evidence/evidence.go`, benchmark evidence | Source + artifact     | One record per tested request in those classes               | Early-exit 405/404/413 classes show zero records |
| 9  | Record hashes are verifiable                                                            | `internal/evidence/evidence.go`, evidence test      | Source + test         | Verification succeeds for tested record                      | Coverage limited to implemented hash fields      |
| 10 | Telemetry can remain non-blocking under saturation                                      | `internal/telemetry/telemetry.go`, telemetry tests  | Source + test         | Saturated subscriber test returns without blocking           | Events may be dropped                            |
| 11 | SPIFFE provider implementation exists                                                   | `internal/identity/spiffe.go`                       | Source                | Code exists                                                  | Live SPIFFE/SPIRE behavior not established       |
| 12 | The recorded benchmark exercises 50 scenarios × 100 iterations                          | Benchmark source + recorded results                 | Source + artifact     | Reported by supplied benchmark artifacts                     | Local loopback only                              |
| 13 | Three creator-controlled reproductions succeeded                                        | `scripts/reproduce.ps1`, `AET-EV-2026-0011`         | Script + artifact     | Three formal runs PASS                                       | Independent reproduction not verified            |
| 14 | A functional conventional OIDC comparison exists                                        | `cmd/benchmark_test.go`, benchmark result           | Source + artifact     | `NOT_IMPLEMENTED`                                            | No real OIDC comparison is established           |
| 15 | A measured revocation time bound exists                                                 | `DEFINITION_OF_DONE.md`                        | Requirement only      | Not established                                              | No measured bound found in supplied material     |

---

# 9. Claims Explicitly Excluded

The following claims are excluded because the supplied evidence does not establish them:

* Production-ready
* Enterprise-ready
* Independently validated
* Externally validated
* Adopted
* Universally secure
* Guaranteed security
* Production-scale performance
* Production resilience
* Formal verification of the complete system
* Comparative superiority over conventional OIDC/OAuth/IAM systems
* Secure behavior under concurrent multi-instance deployment
* Distributed or persistent replay/revocation guarantees
* Gateway-native TLS termination
* End-to-end production SPIFFE/SPIRE validation
* Independent organizational adoption or deployment
* General immunity to prompt injection
* General AI safety

The repository's own `PROVEN` taxonomy for selected cryptographic mechanisms is not interpreted here as a system-level proof.

---

# 10. Research Findings and Open Issues

## 10.1 Primary finding: evidence-coverage discrepancy

The most significant Day 12 research finding is a specific documentation-versus-behavior discrepancy:

* the Definition of Done requires structured evidence for processed requests;
* the supplied benchmark artifacts show zero evidence records on selected early-exit request classes.

This issue is concrete, reproducible from the supplied artifacts, and remains unresolved.

## 10.2 Primary limitation: local/process scope

The strongest empirical results are bounded by:

* local loopback execution;
* process-local state;
* mock identity in exercised paths where applicable;
* absence of independent reproduction;
* absence of distributed deployment testing.

## 10.3 Independent validation remains open

Creator-controlled reproduction demonstrates repeatability in the creator environment.

It does not establish independent reproduction, external security review, or organizational validation.

## 10.4 Historical reproduction failure retained transparently

A separate historical artifact contains a setup failure.

It is not part of the formal Day 11 evidence record and is not used to support a successful-reproduction claim.

Its existence is retained in this package for chronology and transparency.

---

# 11. Definition-of-Research Status

### Completed for Day 12

* Threat model documented and bounded.
* Implemented architecture traced to inspected source.
* Security invariants derived from implementation and available tests/evidence.
* Attack findings documented from supplied artifacts.
* Day 11 reproduction method documented.
* Known limitations documented.
* Bounded claims documented.
* Unsupported claims explicitly excluded.
* Evidence classification preserved.
* Documented-versus-observed discrepancy identified rather than suppressed.

### Open

* Direct audit of internal package unit-test files whose contents were not included in the analysis material.
* Direct test of the broader "No Self-Authorization" invariant.
* Measured revocation time-to-enforce bound.
* Resolution of the early-exit evidence-coverage discrepancy.
* Independent reproduction.
* Independent security review.
* Independent organizational evaluation.
* External identity-provider integration testing.
* Distributed/multi-instance testing.
* Production-scale performance characterization.

---

# 12. Final Bounded Statement

Based on the reviewed repository implementation and creator-controlled evidence, Aether demonstrates a locally exercised authorization gateway architecture combining identity verification, structured action envelopes, exact policy evaluation, revocation/anti-replay controls, reverse-proxy enforcement, structured evidence recording, and bounded telemetry.

The supplied artifacts report successful execution of the defined attack corpus and three successful creator-controlled reproduction runs.

Those observations do **not** establish independent validation, production readiness, production-scale performance, distributed-state guarantees, or universal security.

The research package therefore treats the demonstrated behaviors as bounded technical observations and explicitly preserves the unresolved evidence-coverage issue and other limitations rather than converting them into broader security claims.
