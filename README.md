# Aether

### Open-Source Authorization Boundary for AI Agents

**Identity is not authority.**

**IDENTITY → INTENT → AUTHORITY → ACTION → EVIDENCE**

Aether is an open-source authorization boundary for autonomous software agents.

It evaluates whether a **specific action**, by a **specific workload**, under a **specific context**, is authorized, enforceable, auditable, observable, and revocable.

> **Authentication answers:** “Who are you?”
>
> **Aether asks:** “What are you allowed to do, here, now, and can that decision be enforced and evidenced?”

---

## See the Proof

Aether is designed to be **run, inspected, and challenged**.

**Creator-controlled launch-candidate verification includes:**

* `go test ./...` — PASS
* `go test -race ./...` — PASS
* `go vet ./...` — PASS
* `go build ./...` — PASS
* 50 documented attack/misuse scenarios
* clean-clone reproduction
* live authorized action → HTTP 200 → protected backend reached
* live unauthorized action → HTTP 403 → protected backend not reached

These are creator-controlled observations, not independent external validation.

### Try to Break Aether

**[Break Aether](./docs/BREAK_AETHER.md)**

Try to:

* replay authorization material;
* change the target;
* change the identity;
* change the intent or capability;
* modify protected payload context;
* race authorization reuse;
* submit malformed security material;
* test revoked authority.

**If you find a bypass, report it.**

A failed security test is more valuable than an untested claim.

---

## The Authorization Boundary

```text
┌──────────────────────┐
│      AI AGENT        │
│  plan → request      │
└──────────┬───────────┘
           │
           ▼
┌────────────────────────────────────┐
│             AETHER                 │
│                                    │
│  IDENTITY                          │
│      ↓                             │
│  INTENT                            │
│      ↓                             │
│  AUTHORITY                         │
│      ↓                             │
│  ACTION                            │
│      ↓                             │
│  EVIDENCE                          │
└──────────────┬─────────────────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
      ALLOW          DENY
        │             │
        ▼             ▼
     TOOL/API       NOTHING
        │
        ▼
     EVIDENCE
```

Aether sits above workload identity and evaluates the requested action at the enforcement boundary.

It does **not** attempt to determine whether an AI model is intelligent, correct, or trustworthy.

---

## Run It

Start with the documented reproduction path:

**[Clean Reproduction Guide](./docs/DAY11_REPRODUCTION.md)**

**[Threat Model](./docs/THREAT_MODEL.md)** · **[Attack Lab](./docs/BREAK_AETHER.md)** · **[Security Policy](./SECURITY.md)**

The public repository is the canonical source:

**https://github.com/YabulHaj/Aether-Protocol**

---

## Core Security Model

Aether is built around a narrow authorization chain:

```text
IDENTITY
   ↓
INTENT
   ↓
AUTHORITY
   ↓
ACTION
   ↓
EVIDENCE
```

The implementation currently includes boundaries for:

* workload identity
* deterministic policy evaluation
* action-envelope validation
* freshness checks
* anti-replay controls
* revocation
* reverse-proxy enforcement
* structured decision evidence
* adversarial testing

Established identity mechanisms are treated as an input to authorization rather than reinvented by Aether.

---

## What Aether Currently Demonstrates

The current repository contains a deterministic HTTP enforcement path, authorization policy engine, identity abstraction, revocation controls, evidence generation, and an Attack Lab / benchmark corpus.

Creator-controlled benchmark artifacts currently report:

**50/50 tested scenarios meeting their defined expected outcomes.**

This is a statement about the supplied test artifacts.

It does **not** mean:

* Aether is universally secure.
* All possible attack classes have been tested.
* No undiscovered vulnerability exists.
* The benchmark constitutes independent validation.
* The benchmark represents production security performance.

Independent validation is an explicit future objective.

---

## Attack Lab

### A reproducible challenge against the authorization boundary

Aether includes an adversarial test corpus designed to challenge the same enforcement path used for ordinary requests.

The purpose is not to produce a visually impressive security demonstration.

The purpose is to answer a narrower question:

> **When a request violates a defined authorization invariant, does Aether prevent that request from reaching the target?**

### Current tested corpus

The current benchmark artifacts cover **50 defined scenarios** across several security categories:

```text
┌─────────────────────────────────────────────┐
│              AETHER ATTACK LAB              │
├─────────────────────────────────────────────┤
│  Envelope Integrity                         │
│  Freshness                                  │
│  Identity Boundaries                        │
│  Method / Routing                           │
│  Policy Abuse                               │
│  Revocation                                 │
│  Input Boundaries                           │
└─────────────────────────────────────────────┘
```

Examples include:

```text
Missing identity
Missing intent
Missing capability
Missing target
Missing operation
Expired authorization
Future-issued authorization
Revoked identity
Revoked nonce
Wrong target
Wrong operation
Capability escalation
Near-miss target
Missing payload hash
```

### The important invariant

A denial response by itself is not enough.

For an unauthorized request, the expected enforcement property is:

```text
ATTACK
  │
  ▼
┌───────────────┐
│    AETHER     │
│               │
│  evaluate     │
│  authorize    │
│  enforce      │
└───────┬───────┘
        │
        ✕
        │
        ▼
     TARGET

Expected backend hits:
        0
```

For an authorized baseline request:

```text
REQUEST
   │
   ▼
 AETHER
   │
   ▼
 TARGET

Expected backend hits:
        1
```

This distinction lets the benchmark test whether the security boundary is actually enforcing the decision rather than merely reporting it.

### Current benchmark observation

The supplied creator-controlled benchmark artifacts report:

```text
50 / 50
tested scenarios
meeting their defined expected outcomes
```

The benchmark artifacts report blocked outcomes for the tested adversarial conditions and preserve the expected backend-enforcement behavior for the tested scenarios.

This observation is limited to the documented corpus and test environment.

It does **not** establish:

* universal attack coverage
* absence of undiscovered vulnerabilities
* production security
* independent validation
* security against attack classes outside the corpus

### How to reproduce it

Run:

```powershell
go test -count=1 -v ./cmd -run TestDay10Benchmark
```

Then inspect the resulting benchmark and evidence artifacts.

The project is designed so that another technical evaluator can inspect the methodology, scenario definitions, expected outcomes, observed results, and supporting artifacts rather than relying on a headline number.

### Break the assumption

Aether is intentionally built to be challenged.

A useful security finding is not treated as a failure of the research process.

A confirmed bypass should become:

```text
finding
   ↓
reproduction
   ↓
regression test
   ↓
fix
   ↓
new benchmark
   ↓
documented correction
```

That feedback loop is part of the project's research model.

### Evidence boundary

Current Attack Lab results are **creator-controlled test evidence**.

Independent reproduction, independent security review, external contributors, and organizational evaluation are separate evidence categories and are not implied by the benchmark result.

---

## Evidence

Aether treats evidence as part of the security design rather than an afterthought.

Decision records can capture structured information about:

* identity
* requested intent
* capability
* target
* operation
* policy rule
* decision
* reason
* request information
* timestamps
* request identifiers
* integrity hashes
* revocation state

The evidence layer is intended to make authorization decisions inspectable and reproducible.

The UI is not the source of security truth.

The underlying server-side decision and evidence records remain authoritative.

---

## Architecture

```mermaid
flowchart LR

    A[AI Agent] --> B[Identity]
    B --> C[Action Envelope]
    C --> D[Policy Engine]
    D --> E[Enforcement]

    E -->|ALLOW| F[Target API]
    E -->|DENY| G[Request Stopped]

    D --> H[Evidence]
    E --> H
    H --> I[Audit / Research Artifacts]

    J[Revocation Registry] --> D
    J --> E
```

### Major components

| Component   | Purpose                                           |
| ----------- | ------------------------------------------------- |
| Identity    | Establish workload identity                       |
| Envelope    | Validate the requested action                     |
| Policy      | Produce deterministic authorization decisions     |
| Revocation  | Remove authority when required                    |
| Enforcement | Prevent unauthorized requests reaching the target |
| Evidence    | Preserve structured decision records              |
| Attack Lab  | Challenge defined security invariants             |
| Benchmark   | Produce reproducible machine-readable results     |

---

## Quickstart

### Requirements

You need:

* Git
* Go 1.27.1 or newer
* Windows PowerShell, or an equivalent terminal

Aether is currently designed for local development and security research.

### 1. Clone the repository

```bash
git clone https://github.com/YabulHaj/Aether-Protocol.git
cd Aether-Protocol
```

### 2. Verify the repository builds and tests pass

Run:

```bash
go test ./...
go build ./...
```

Both commands should complete without errors.

### 3. Start the protected demo backend

Open **Terminal 1** in the Aether repository and run:

```powershell
go run ./tools/dummy-backend
```

You should see:

```text
Dummy backend listening on localhost:9090
```

Keep this terminal open. The dummy backend represents the protected upstream target and prints a `[BACKEND]` line whenever it receives a request.

### 4. Start the Aether gateway

Open **Terminal 2** in the Aether repository and run:

```powershell
$env:AETHER_IDENTITY_MODE="mock"
go run ./cmd
```

You should see the gateway listening on:

```text
localhost:8080
```

The mock identity provider is intended for local development and testing. It is **not a production identity configuration**.

### 5. Open the Live River UI

Open this in a browser:

```text
http://localhost:8080/ui/
```

The UI displays real server-sent telemetry from Aether. It does not generate synthetic security events.

When the gateway is unavailable, the UI reports **DISCONNECTED**. A successful connection reports **LIVE**.

### 6. Send an authorized action

Leave both terminals running and open a third PowerShell terminal in the repository.

Run:

```powershell
$now = [DateTime]::UtcNow
$body = @{
  identity_ref    = "agent://finance-bot-01"
  intent          = "summarize"
  capability      = "read:invoices"
  target_resource = "invoice/12345"
  operation       = "GET"
  audience        = "aether-gateway"
  issued_at       = $now.AddMinutes(-1).ToString("o")
  expiry          = $now.AddMinutes(5).ToString("o")
  nonce_id        = ("demo-" + [guid]::NewGuid().ToString())
  payload_hash    = "sha256:0000000000000000"
} | ConvertTo-Json -Compress

Invoke-WebRequest `
  -Uri "http://localhost:8080/v1/action" `
  -Method POST `
  -Headers @{ Authorization = "Bearer mock-token-finance-bot" } `
  -ContentType "application/json" `
  -Body $body `
  -UseBasicParsing
```

Expected behavior:

* HTTP `200`
* Aether returns the protected-data success response
* The Live River shows `ALLOWED`
* Terminal 1 records a `[BACKEND]` request

The configured policy for this demonstration is:

```text
Identity:   agent://finance-bot-01
Intent:     summarize
Capability: read:invoices
Target:     invoice/12345
Operation:  GET
Audience:   aether-gateway
```

### 7. Send a denied action and verify the enforcement boundary

For a clean backend verification, stop the dummy backend with `Ctrl+C`, start it again, and confirm that the terminal shows only:

```text
Dummy backend listening on localhost:9090
```

Then run this **fresh request** in the PowerShell terminal:

```powershell
$now = [DateTime]::UtcNow
$body = @{
  identity_ref    = "agent://finance-bot-01"
  intent          = "summarize"
  capability      = "read:invoices"
  target_resource = "invoice/99999"
  operation       = "GET"
  audience        = "aether-gateway"
  issued_at       = $now.AddMinutes(-1).ToString("o")
  expiry          = $now.AddMinutes(5).ToString("o")
  nonce_id        = ("clean-deny-" + [guid]::NewGuid().ToString())
  payload_hash    = "sha256:0000000000000000"
} | ConvertTo-Json -Compress

try {
  $r = Invoke-WebRequest `
    -Uri "http://localhost:8080/v1/action" `
    -Method POST `
    -Headers @{ Authorization = "Bearer mock-token-finance-bot" } `
    -ContentType "application/json" `
    -Body $body `
    -UseBasicParsing

  "HTTP $($r.StatusCode)"
  $r.Content
}
catch {
  if ($_.Exception.Response) {
    "HTTP $([int]$_.Exception.Response.StatusCode)"
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    $reader.ReadToEnd()
    $reader.Dispose()
  } else {
    throw
  }
}
```

Expected behavior:

* HTTP `403`
* Aether reports a policy denial
* The Live River shows `DENIED`
* **No new `[BACKEND]` line appears in Terminal 1**

This demonstrates the intended enforcement boundary: a request that violates the configured target policy is denied before it reaches the protected dummy backend.

### 8. Run the Attack Lab / benchmark

The benchmark is separate from the live demo and does **not** require the dummy backend or a running gateway. It uses local `httptest` execution.

Run:

```powershell
go test -count=1 -v ./cmd -run TestDay10Benchmark
```

The current benchmark configuration executes 50 scenarios, 100 measured iterations per scenario, and 5 warmup cycles.

The test writes:

```text
evidence/10_benchmarks/day10-benchmark-results.json
evidence/10_benchmarks/day10-benchmark-report.txt
```

The benchmark reports identify the environment as local loopback and state that the measurements do not represent production network or remote identity-provider latency.

### 9. Reproducibility and evidence

For research purposes, inspect both the implementation and the generated evidence.

The important enforcement question is not only:

```text
Did Aether return DENY?
```

It is also:

```text
Did the unauthorized request reach the target?
```

UI output is visualization. The server-side implementation, automated tests, benchmark artifacts, and structured evidence are the authoritative research record.

### 10. Security boundary

Aether is intentionally narrow.

It does not claim to:

* secure an AI model itself
* determine whether a model's reasoning is correct
* replace workload identity systems
* replace general-purpose IAM
* eliminate application vulnerabilities
* eliminate prompt injection
* guarantee agent safety
* guarantee production security

Aether instead focuses on the authorization and enforcement boundary surrounding autonomous software actions.

### 11. Current benchmark limitation

Benchmark results are **creator-controlled** and are not independent security validation.

They do not establish universal attack coverage or prove the absence of undiscovered vulnerabilities.

Independent reproduction and external technical review remain separate research objectives.

### 12. Research principle

```text
No action without authorization.
No authorization without context.
No security claim without evidence.
```

The goal is to make authorization behavior measurable, inspectable, and reproducible.

---
## Security Boundary

Aether is intentionally narrow.

It does not claim to:

* secure an AI model itself
* determine whether a model's reasoning is correct
* replace workload identity systems
* replace general-purpose IAM
* eliminate application vulnerabilities
* eliminate prompt injection
* guarantee agent safety
* guarantee production security

Aether instead focuses on the authorization and enforcement boundary surrounding autonomous software actions.

---

## Research Questions

The project investigates questions such as:

1. Can autonomous-agent actions be evaluated using deterministic authorization rules rather than identity alone?

2. Can unauthorized agent actions be prevented from reaching their target?

3. Can authorization decisions be recorded as structured, integrity-verifiable evidence?

4. Can stale, replayed, revoked, malformed, or out-of-policy actions be rejected consistently?

5. Can the resulting security experiments be independently reproduced?

6. Where are the limitations and bypasses of this model?

The project treats discovered weaknesses as research inputs.

A confirmed bypass should become a regression test whenever technically appropriate.

---

## Current Limitations

The current implementation remains a research / validation platform rather than a claim of production completeness.

Known limitations include areas such as:

* creator-controlled rather than independently reproduced benchmark results
* local development identity mode
* process-local revocation state
* incomplete production-scale deployment validation
* incomplete end-to-end SPIFFE/SPIRE validation
* evolving live telemetry / visualization infrastructure

These limitations are part of the research record.

---

## Reproducibility

The project is designed so that an unfamiliar technical evaluator can:

1. obtain the repository;
2. follow the Quickstart;
3. execute the test suite;
4. execute the benchmark;
5. inspect the policy decisions;
6. inspect evidence artifacts;
7. reproduce defined scenarios;
8. compare observed behavior with documented expectations.

The goal is not simply to demonstrate that Aether works.

The goal is to make it possible for another technical person to determine **what actually happened**.

---

## Contributing

Security findings, reproducibility reports, technical review, integrations, and improvements are welcome.

Aether is particularly interested in:

* bypass research
* authorization edge cases
* reproducibility
* security testing
* identity integration
* benchmark methodology
* evidence integrity
* independent evaluation

When reporting a security weakness, provide enough technical detail to reproduce the behavior safely.

---

## Security

Please do not disclose sensitive vulnerability details through ordinary public issues when responsible disclosure is more appropriate.

See the repository security policy for the current reporting process.

---

## Status

Aether is an active open-source security research project.

The project prioritizes:

**reproducibility over hype,**

**evidence over assertion,**

**independent validation over self-description,**

and

**measurable security behavior over visual demonstration.**

---

## License

See `LICENSE`.

---

## Research Principle

> **No action without authorization.
> No authorization without context.
> No security claim without evidence.**
