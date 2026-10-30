# Aether

### Open-source authorization boundary for AI agents

[![Aether CI](https://github.com/YabulHaj/Aether-Protocol/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/YabulHaj/Aether-Protocol/actions/workflows/ci.yml)

**Identity is not authority.**

**IDENTITY -> INTENT -> AUTHORITY -> ACTION -> EVIDENCE**

Aether is an open-source authorization boundary for autonomous software agents.

It evaluates whether a specific action, by a specific workload, under a specific context, is authorized, enforceable, auditable, observable, and revocable.

Authentication answers:

> **Who are you?**

Aether asks:

> **What are you allowed to do, here, now, and can that decision actually be enforced and evidenced?**

---

## See the proof

**[Watch the 25-second demo](./aether-25-second-demo.mp4)**

The central experiment is simple:

```text
AUTHORIZED

HTTP 200
Backend hits: 1
```

versus:

```text
UNAUTHORIZED

HTTP 403
Backend hits: 0
```

**Run it yourself:** [Quickstart](./QUICKSTART.md)

**[Action-boundary contract and reproducible tests](./docs/ACTION_BOUNDARY_CONTRACT.md)** — inspect strict gateway envelope parsing, payload-action binding, regression tests, and documented limitations.

### What the latest action-boundary tests demonstrate

The gateway now validates a supplied, non-empty structured JSON action payload against the authorized outer action before forwarding a policy-allowed request.

The payload's `target_resource` and `operation` must match the corresponding values in the outer action envelope.

The tested rejection behavior is:

| Condition | Gateway response | Downstream requests | Simulated effects |
|---|---:|---:|---:|
| Conflicting payload action | HTTP 409 | 0 | 0 |
| Malformed payload | HTTP 400 | 0 | 0 |
| Ambiguous or non-canonical outer envelope | HTTP 400 | 0 | 0 |

These regression tests verify gateway rejection and downstream request/effect counts for the tested cases. They do not establish that arbitrary application payloads are semantically safe or that all possible attack paths have been eliminated.

The important question is not only whether Aether returned `403`.

It is:

> **Did the unauthorized action actually reach the protected target?**

These are creator-controlled local demonstrations and tests, not independent security validation.

---

## What Aether is

Aether sits at the authorization and enforcement boundary around autonomous software actions.

It is designed around four cooperating planes:

| Plane | Purpose |
|---|---|
| Enforcement | Decide and enforce whether an action is authorized |
| Evidence | Preserve structured records of authorization decisions |
| Live Control Plane | Make real server-side security activity observable |
| Attack / Research | Challenge defined security invariants and produce reproducible results |

The security path remains authoritative.

The Live Control Plane is a read-only projection of what the server already decided.

---

## The security boundary

Aether evaluates an action using context such as:

```text
identity
intent
capability
target
operation
constraints
freshness
revocation
```

The simplified path is:

```text
AI Agent
   |
   v
Identity Verification
   |
   v
Strict Action Envelope Parsing
   |
   v
Revocation Check
   |
   v
Envelope / Context Validation
   |
   v
Policy Evaluation
   |
   +---- DENY --------------------> Record rejection and stop
   |
   v
Payload Action Binding
   |
   +---- MALFORMED / MISMATCH ---> Record rejection and stop
   |
   v
Structured Evidence
   |
   v
Enforcement
   |
   +---- ALLOW -------------------> Target
```

Payload action binding applies when a non-empty payload is supplied and the outer action passes policy.

It checks the supported structured JSON payload's action-defining fields against the authorized outer action.

The payload check does not interpret arbitrary application data or establish that the business meaning of every argument is safe.

Aether is deliberately narrow.

It does not attempt to:

- secure an AI model itself;
- determine whether model reasoning is correct;
- replace workload identity systems;
- replace general-purpose IAM;
- eliminate application vulnerabilities;
- eliminate prompt injection;
- guarantee agent safety;
- guarantee production security.

Established identity mechanisms remain an input to authorization rather than something Aether attempts to reinvent.

---

## Current proof

The current repository includes:

- deterministic HTTP authorization and enforcement;
- workload identity abstraction;
- strict JSON action-envelope decoding;
- rejection of duplicate, unknown, and non-canonical outer-envelope fields;
- freshness and anti-replay controls;
- revocation;
- pre-forwarding validation of supplied structured JSON payload actions;
- structured decision evidence;
- a reproducible Attack Lab;
- benchmark infrastructure;
- a real server telemetry path;
- a read-only Live Control Plane.

### Verified security patch

Commit [`8d54fcf`](https://github.com/YabulHaj/Aether-Protocol/commit/8d54fcfe713d26b7b878f795d389d759ac325fb0) adds gateway-side action binding and regression tests for conflicting payloads, malformed payloads, and ambiguous outer-envelope fields.

The tests check that the relevant rejected requests do not reach the downstream adapter and do not produce simulated effects.

### Verification results

[GitHub Actions run #8](https://github.com/YabulHaj/Aether-Protocol/actions/runs/40762028598) for commit `8d54fcf` completed successfully in 1 minute 33 seconds.

The successful workflow reported:

```text
Go test suite (authorization benchmark excluded): PASS
Authorization benchmark: PASS
go vet ./...: PASS
go build ./...: PASS
Live allow/deny enforcement smoke test: PASS
```

The authorization benchmark was also run separately during local verification and passed in 86.351 seconds.

Benchmark timing alone does not establish a performance improvement without a controlled comparison.

The race detector (`go test -race ./...`) was not part of this CI workflow.

These results are creator-controlled observations.

They do not establish:

- universal security;
- complete attack coverage;
- absence of undiscovered vulnerabilities;
- production security;
- independent validation.

Independent reproduction and external technical review remain explicit objectives.

---

## Break Aether

Aether is built to be challenged.

**[BREAK AETHER](./docs/BREAK_AETHER.md)**

Useful attacks include:

- replaying authorization material;
- changing the target after authorization;
- changing identity;
- changing intent or capability;
- modifying protected request context;
- reusing authorization concurrently;
- submitting malformed security material;
- testing revoked authority;
- introducing duplicate or non-canonical envelope fields;
- making the payload action conflict with the authorized outer action.

The most valuable result is not a flattering test.

It is a reproducible finding.

The intended research loop is:

```text
finding
   ->
reproduction
   ->
regression test
   ->
fix
   ->
new benchmark
   ->
documented correction
```

A confirmed weakness is therefore useful research input, not something to hide.

---

## Attack Lab

The Attack Lab challenges the same enforcement path used for ordinary requests.

The current Attack Lab contains **50 defined scenarios** with documented expected outcomes.

Current scenario classes include:

```text
Envelope integrity
Freshness
Identity boundaries
Method / routing
Policy abuse
Revocation
Input boundaries
```

The key invariant is:

```text
Unauthorized request
        |
        v
      Aether
        |
       DENY
        |
        X
        |
      Target

Expected backend hits: 0
```

For an authorized baseline:

```text
Request
   |
   v
 Aether
   |
   v
Target

Expected backend hits: 1
```

A denial response alone is therefore not the complete security observation.

The enforcement behavior at the protected target matters.

For the supported structured JSON action contract, an outer action that passes policy can still be rejected before forwarding if the supplied payload is malformed or its action-defining fields conflict with the authorized action.

---

## Evidence

Aether treats evidence as part of the security design.

Structured evidence can preserve information such as:

- identity;
- intent;
- capability;
- target;
- operation;
- policy rule;
- decision;
- reason;
- timestamps;
- request identifiers;
- integrity information;
- revocation state.

Evidence must distinguish an authorization decision from a downstream response and a verified effect.

The browser is not the source of security truth.

The server-side decision, tests, benchmark artifacts, and structured evidence remain authoritative.

A test that records zero downstream requests or zero simulated effects provides evidence about that tested execution path. It is not an independent attestation that no real-world side effect occurred.

---

## Live Control Plane

The Live Control Plane makes authorization activity visible without becoming an authorization mechanism.

Its rules are simple:

```text
Server decides.
Server emits.
Browser observes.
```

LIVE mode uses real Aether telemetry.

The UI does not:

- create identities;
- approve requests;
- alter policy;
- override enforcement;
- turn blocked events into allowed events.

The visualization exists to make real security behavior easier to inspect.

It does not replace the underlying evidence.

Telemetry's `decision_status` and legacy `status` describe Aether's gateway authorization/enforcement outcome, not the upstream HTTP response.

A request may pass policy evaluation but subsequently be rejected by gateway-side payload validation. An upstream HTTP error also does not, by itself, change the original authorization decision.

---

## Run it

### Requirements

- Git
- Go 1.27.1+
- Windows PowerShell or an equivalent terminal

Aether is currently intended for local development and security research.

### Clone

```bash
git clone https://github.com/YabulHaj/Aether-Protocol.git
cd Aether-Protocol
```

### Verify

```bash
go test ./...
go build ./...
```

The full test suite includes the authorization benchmark and may take longer than ordinary unit tests.

### Full reproduction path

**[QUICKSTART.md](./QUICKSTART.md)**

The full quickstart covers:

- the protected dummy backend;
- the Aether gateway;
- local development identity mode;
- the Live Control Plane;
- an authorized request;
- a denied request;
- backend-side verification;
- benchmark execution.

The local mock identity provider is for development and testing only. It is not a production identity configuration.

---

## Reproducibility

Aether is designed so that another technical evaluator can:

1. obtain the repository;
2. follow the reproduction path;
3. run the tests;
4. execute defined scenarios;
5. inspect authorization decisions;
6. inspect evidence artifacts;
7. compare observed behavior with expected behavior.

The goal is not simply to demonstrate that Aether works.

The goal is to make it possible for another technical person to determine **what actually happened**.

**[Clean Reproduction Guide](./docs/CLEAN_REPRODUCTION.md)**

Independent reproduction is different from running the creator's tests or seeing a green CI badge. External evaluators should be able to repeat the documented cases, inspect the results, and report differences or limitations.

---

## Research questions

The project investigates questions including:

1. Can agent actions be authorized using explicit action context rather than identity alone?
2. Can defined classes of unauthorized actions be prevented from reaching their targets?
3. Can authorization decisions be preserved as structured, inspectable evidence?
4. Can stale, replayed, revoked, malformed, or out-of-policy actions be rejected consistently?
5. Can the resulting experiments be independently reproduced?
6. Where are the limitations and bypasses of the model?
7. Can the authorization boundary integrate with established workload-identity infrastructure?
8. Can payload action conflicts be rejected before downstream forwarding within a defined, testable contract?

The project treats negative findings and unresolved cases as part of the research record.

---

## Current limitations

Aether is a research and validation platform, not a claim of production completeness.

Current limitations include:

- creator-controlled benchmark and test results;
- local development identity mode;
- process-local revocation state;
- incomplete production-scale deployment validation;
- incomplete end-to-end SPIFFE/SPIRE validation;
- evolving telemetry and visualization infrastructure;
- no independent security review yet;
- no independent organizational evaluation yet;
- payload action binding covers the documented structured JSON contract, not arbitrary payload formats or the business semantics of application-specific arguments.

The current gateway validates the supplied payload's action-defining fields against the authorized outer action when a non-empty payload is present and policy allows the outer action.

This does not mean Aether can infer the meaning of arbitrary application data, validate every business rule, or prove that all possible downstream effects are safe.

These limitations are intentionally documented rather than assumed away.

---

## Documentation

| Document | Purpose |
|---|---|
| [QUICKSTART](./QUICKSTART.md) | Run Aether locally |
| [ACTION-BOUNDARY CONTRACT](./docs/ACTION_BOUNDARY_CONTRACT.md) | Inspect action-binding behavior, regression tests, and limitations |
| [BREAK AETHER](./docs/BREAK_AETHER.md) | Challenge the authorization boundary |
| [CLEAN REPRODUCTION](./docs/CLEAN_REPRODUCTION.md) | Reproduce the documented experiments |
| [THREAT MODEL](./docs/THREAT_MODEL.md) | Security boundary and threats |
| [SECURITY](./SECURITY.md) | Security reporting |
| [RESEARCH PACKAGE](./docs/RESEARCH_PACKAGE.md) | Technical research record |
| [SECURITY HARDENING](./docs/SECURITY_HARDENING.md) | Security-hardening record |
| [RELEASE CANDIDATE](./docs/RELEASE_CANDIDATE.md) | Release verification record |
| [DEFINITION OF DONE](./DEFINITION_OF_DONE.md) | Technical completion criteria |

---

## Contributing

Useful contributions include:

- bypass research;
- authorization edge cases;
- reproducibility reports;
- security testing;
- identity integrations;
- benchmark methodology;
- evidence integrity;
- documentation improvements;
- independent evaluation.

Aether is particularly interested in contributions that can be reproduced, challenged, and turned into stronger tests or clearer evidence.

See:

**[CONTRIBUTING.md](./CONTRIBUTING.md)**

---

## Security

Please do not disclose sensitive vulnerability details through ordinary public issues when responsible disclosure is more appropriate.

See:

**[SECURITY.md](./SECURITY.md)**

---

## Status

Aether is an active open-source security research project.

The project prioritizes:

**reproducibility over hype**

**evidence over assertion**

**independent validation over self-description**

**measurable security behavior over visual demonstration**

---

## Research principle

> **No action without authorization.**
>
> **No authorization without context.**
>
> **No security claim without evidence.**