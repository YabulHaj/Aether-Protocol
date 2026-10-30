# Aether Action-Boundary Contract

**Status:** Partially implemented and creator-verified. This document distinguishes implemented behavior, tested behavior, remaining requirements, and trust assumptions. It is not an independent security assessment or a claim that every proposed requirement is fully implemented.

**Baseline reviewed:** `8d54fcfe713d26b7b878f795d389d759ac325fb0`

**Related commit:** [Enforce action binding before gateway forwarding](https://github.com/YabulHaj/Aether-Protocol/commit/8d54fcfe713d26b7b878f795d389d759ac325fb0)

**CI verification:** [GitHub Actions run #8](https://github.com/YabulHaj/Aether-Protocol/actions/runs/40762028598)

---

## 1. Purpose

Aether must distinguish three different questions:

1. **Authorization decision:** Did Aether permit or deny the requested action?
2. **Downstream HTTP outcome:** What HTTP status did the upstream service return, if a request was forwarded?
3. **Verified effect:** Is there trusted evidence that the intended action actually occurred, did not occur, or remains unknown?

These outcomes must not be conflated.

A successful authorization decision is not proof of successful execution.

An HTTP response is not, by itself, proof of a real-world effect.

A recorded simulated effect is not a durable external-world action.

The purpose of this contract is to define how an action authorized through Aether remains bound to the action that reaches its configured downstream enforcement path.

---

## 2. Current implementation behavior

The following describes the implementation reviewed at commit `8d54fcf`.

### 2.1 Gateway request sequence

The current gateway follows this relevant sequence:

1. Verify the caller using the configured identity provider.
2. Read the request body subject to the gateway's 1 MiB request-body limit.
3. Strictly decode the outer action envelope.
4. Check revocation.
5. Validate envelope completeness, freshness, and a supplied payload digest.
6. Check the gateway audience.
7. Compare the verified identity with the envelope identity.
8. Check and consume the request nonce.
9. Evaluate the outer action against policy.
10. If policy allows and a non-empty payload is supplied, validate the payload against the authorized outer action.
11. Record the gateway decision or rejection as structured evidence and telemetry.
12. Forward an allowed request through the configured enforcement proxy.

A failure at a pre-forwarding validation step returns an error instead of forwarding the request.

### 2.2 Strict outer-envelope JSON decoding

The gateway uses the shared exported `DecodeEnvelopeJSON` entry point in the action-contract package.

The decoder rejects:

- non-object JSON input;
- malformed JSON;
- duplicate JSON object keys, including keys at nested levels;
- unknown outer-envelope fields;
- non-canonical or case-variant outer-envelope field names;
- multiple JSON values in the same request body;
- trailing invalid JSON content.

The supported canonical outer-envelope fields are:

```text
identity_ref
intent
capability
target_resource
operation
constraints
audience
issued_at
expiry
nonce_id
payload_hash
payload
```

The `payload` field is a string containing the supplied payload content. It is validated separately under the structured JSON action-payload contract described below.

### 2.3 Supported structured JSON action payload

Aether currently supports the following reference payload structure:

```json
{
  "target_resource": "invoice/12345",
  "operation": "GET",
  "arguments": {
    "invoice_id": "12345"
  }
}
```

The action-defining fields are:

- `target_resource`
- `operation`

The `arguments` field carries application-specific input. The validator preserves it as JSON data but does not interpret its business meaning.

The validator rejects:

- malformed JSON;
- non-object payloads;
- duplicate object keys at any depth;
- unknown top-level fields;
- non-canonical or case-variant top-level field names;
- multiple JSON values;
- missing or blank action-defining fields;
- missing payload content;
- missing authorized target or operation.

The accepted canonical top-level payload fields are:

```text
target_resource
operation
arguments
```

The validator compares the payload target and operation with the authorized outer action using exact string equality.

It does not normalize different resource names or operation representations into equivalent values.

### 2.4 Gateway-side payload binding

When the outer policy decision is ALLOW and a non-empty payload is supplied, the gateway calls `ValidatePayload` before forwarding the request.

The gateway supplies the authorized `target_resource` and `operation` from the outer envelope.

The payload must match both values.

The rejection behavior is:

| Condition | Gateway HTTP response | Evidence reason |
|---|---:|---|
| Malformed or ambiguous payload | 400 Bad Request | `MALFORMED` |
| Payload target or operation differs from outer action | 409 Conflict | `ACTION_MISMATCH` |

In either rejection case:

- the request is not forwarded to the configured downstream adapter;
- the reference adapter receives zero requests;
- the reference adapter records zero simulated effects in the regression test.

A payload validation failure is a gateway rejection even when the outer policy evaluation initially returned ALLOW.

The payload check is skipped when the payload is empty. An omitted payload therefore does not receive the same payload-to-envelope binding validation.

### 2.5 Policy denial

When the outer action is denied by policy, the gateway returns HTTP 403 and does not forward the request.

A policy-denied request does not become allowed because its payload happens to match the outer action.

Payload binding is an additional enforcement check, not a replacement for policy authorization.

### 2.6 Reference downstream handler

The reference handler is a demonstration downstream consumer.

It validates envelope completeness and freshness, verifies a supplied payload digest when content is present, validates the structured action payload, and records an in-memory simulated effect after successful validation.

It does not:

- authenticate the HTTP caller;
- independently evaluate Aether policy;
- establish that the outer envelope was authorized;
- perform a durable external-world action.

The gateway now performs the supported payload binding before forwarding. The reference handler retains its own validation as a downstream demonstration consumer.

---

## 3. Proposed action-boundary contract

The following requirements define the intended boundary. Their implementation status is stated explicitly rather than inferred from the existence of this document.

### C1. Explicit authorization context

The authorized action is determined from the validated outer action context, including:

- identity;
- intent;
- capability;
- target resource;
- operation.

The decision is subject to configured policy and the other envelope-validation controls.

**Current status:** Implemented in the reviewed gateway path. Identity verification, envelope validation, audience checks, identity matching, nonce handling, and policy evaluation occur before forwarding.

The policy engine remains the authority for whether the outer action is allowed.

### C2. Payload cannot silently redefine authority

Payload content is application data unless a specific, trusted integration defines and validates its action semantics.

For the supported structured JSON reference payload, Aether now requires the payload's `target_resource` and `operation` to exactly match the authorized outer action before forwarding a policy-allowed request.

Malformed or ambiguous payloads are rejected with HTTP 400.

Action mismatches are rejected with HTTP 409.

A mismatch must not reach the configured downstream adapter through the tested gateway path.

**Current status:** Implemented for the documented structured JSON action-payload contract.

This does not make the gateway a generic interpreter of arbitrary JSON, text, binary data, or application-specific instructions.

The contents of `arguments` are not interpreted as an independent authorization request. An application that gives those arguments action-changing semantics must define and validate those semantics under its own schema before any consequential effect.

### C3. Denial before downstream effect

A denied request must not reach the protected action handler through the tested enforcement path.

A malformed or conflicting action payload must not reach the downstream adapter through the supported gateway integration.

Request count and simulated effect count must be measured separately where both measurements are available.

**Current status:** Regression tests cover:

- matching payload forwarded to the reference adapter;
- conflicting payload rejected before forwarding;
- malformed payload rejected before forwarding;
- non-canonical outer-envelope key rejected before forwarding;
- policy-denied outer action rejected before forwarding.

The tests distinguish receiving a downstream HTTP request from recording a simulated effect.

They do not constitute independent attestation of real-world side effects.

### C4. Separate decision, response, and effect records

Authorization telemetry must identify the gateway's authorization or enforcement outcome and its reason.

An upstream HTTP response must not be mistaken for the original authorization decision.

A downstream response status is not proof that a business operation completed successfully.

If a real downstream effect is not independently verified, evidence must not imply that it was.

**Current status:** The telemetry event distinguishes the gateway decision/outcome from an upstream HTTP response, which is not captured as the telemetry decision status.

The legacy `status` field is an alias for `decision_status`.

For a policy-allowed request that later receives HTTP 409 from the upstream service, the gateway's authorization telemetry remains ALLOW with decision status 200. The upstream HTTP response is delivered to the client but is not represented as an authorization denial.

For pre-forwarding payload-validation rejections, the gateway records the rejection with `Allowed=false`, the corresponding HTTP rejection status, and its reason code.

The conflicting-payload case uses `ACTION_MISMATCH`. The malformed-payload case uses `MALFORMED`.

The telemetry event does not independently attest to a durable downstream effect.

### C5. Correct interpretation of payload hashes

A content digest can establish consistency between supplied content and a supplied digest when the implementation verifies that comparison.

It does not establish:

- who authorized the action;
- whether the action is permitted;
- whether the caller is authenticated;
- whether the target performed the action;
- whether an external-world effect occurred.

When payload content is absent, the system must not describe its contents as digest-verified.

**Current status:** The envelope validator requires a payload-hash field and compares the supplied digest with the supplied payload content when the payload is non-empty.

Payload binding and digest verification are separate checks.

A valid digest does not authorize an action, and a matching payload action does not prove the business semantics of its arguments are safe.

### C6. Enforcement scope must be explicit

The guarantee applies only to actions routed through the tested gateway enforcement boundary and supported integrations.

It does not establish universal prevention if an agent, caller, or other process can reach the downstream service through an unguarded route.

**Current status:** The regression tests use Aether's configured reverse-proxy enforcement path and an in-memory reference handler.

Direct downstream access is outside the guarantee established by those tests.

---

## 4. Regression and conformance tests

The permanent tests distinguish payload validation from gateway enforcement.

### 4.1 Payload-contract unit tests

The action-contract package tests cover:

| Scenario | Expected result |
|---|---|
| Matching target and operation | Payload accepted |
| Different target | `ErrActionMismatch` |
| Different operation | `ErrActionMismatch` |
| Duplicate top-level key | `ErrMalformedPayload` |
| Case-variant operation key | `ErrMalformedPayload` |
| Case-variant target key | `ErrMalformedPayload` |
| Non-canonical top-level key | `ErrMalformedPayload` |
| Duplicate nested argument key | `ErrMalformedPayload` |
| Unknown top-level key | `ErrMalformedPayload` |
| Multiple JSON values | `ErrMalformedPayload` |
| Malformed JSON | `ErrMalformedPayload` |
| Missing target | `ErrMalformedPayload` |
| Missing payload | `ErrMissingPayload` |
| Missing authorized target or operation | `ErrInvalidAuthorizedAction` |

These tests establish behavior of the payload validator. They are not all independent end-to-end gateway tests.

### 4.2 Gateway action-boundary regression tests

The gateway regression tests cover:

| Scenario | Gateway response | Downstream requests | Simulated effects |
|---|---:|---:|---:|
| Matching payload action | 200 OK | 1 | 1 |
| Conflicting payload action | 409 Conflict | 0 | 0 |
| Malformed payload | 400 Bad Request | 0 | 0 |
| Non-canonical outer-envelope field | 400 Bad Request | 0 | 0 |
| Policy-denied outer action | 403 Forbidden | 0 | 0 |

The matching case verifies that the reference handler records one simulated effect for the matching target and operation.

The rejection cases verify that the reference handler receives no request and records no simulated effect.

The conflicting-payload and malformed-payload tests also inspect telemetry:

- `Allowed` is false;
- the rejection status is recorded;
- `DecisionStatus` matches the gateway rejection status;
- the expected reason code is present.

The non-canonical outer-envelope regression verifies rejection at the gateway, before forwarding.

### 4.3 Interpretation

These tests demonstrate the behavior of specific requests and code paths.

They do not prove that every possible malformed envelope, payload encoding, application schema, integration, or downstream route has been tested.

The contract must not be considered fully implemented merely because the focused tests pass.

Each additional claimed property must be linked to permanent tests and reproducible evidence.

---

## 5. Reproduce the reference contract locally

Run these commands from the repository root with Go installed.

### 5.1 Payload-contract tests

```powershell
go test -count=1 -v ./pkg/actioncontract -run '^TestValidatePayload'
```

### 5.2 Gateway action-boundary regression tests

```powershell
go test -count=1 -v ./cmd -run '^TestActionBoundaryContract_'
```

### 5.3 Full Go suite, excluding the separately measured benchmark

```powershell
go test -count=1 -skip '^TestAuthorizationEnforcementBenchmark$' ./...
```

### 5.4 Authorization benchmark

```powershell
go test -count=1 -v ./cmd -run '^TestAuthorizationEnforcementBenchmark$'
```

### 5.5 Static analysis and build

```powershell
go vet ./...
go build ./...
```

The full ordinary Go test suite includes the authorization benchmark unless it is explicitly excluded. The benchmark is therefore run separately in the verification sequence above.

### 5.6 CI verification

The published CI workflow runs:

```text
Go tests, excluding the authorization benchmark
Authorization benchmark
go vet
go build
Live allow/deny enforcement smoke test
```

The workflow is defined in:

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml)

For the reviewed security patch, [GitHub Actions run #8](https://github.com/YabulHaj/Aether-Protocol/actions/runs/40762028598) completed successfully for commit `8d54fcf`.

The run completed in 1 minute 33 seconds.

The race detector was not part of that workflow.

### 5.7 Expected observations

| Scenario | Gateway decision | Reference adapter outcome | Simulated effects |
|---|---|---|---:|
| Matching action | ALLOW | HTTP 200 | 1 |
| Conflicting nested action | Outer policy may ALLOW; gateway rejects with HTTP 409 before forwarding | Not reached | 0 |
| Malformed payload | Gateway rejects with HTTP 400 before forwarding | Not reached | 0 |
| Non-canonical outer field | Gateway rejects with HTTP 400 before forwarding | Not reached | 0 |
| Policy-denied outer action | DENY; HTTP 403 | Not reached | 0 |

These are creator-controlled test observations, not independent validation.

---

## 6. Explicit non-goals

Aether does not claim to:

- build a generic parser that guesses the meaning of arbitrary application payloads;
- determine whether arbitrary application arguments are safe;
- treat a hash as a signature or proof of approval;
- treat an ALLOW decision as proof of completed execution;
- treat HTTP 200 as universal proof of a completed real-world effect;
- prove the absence of all downstream effects from a local simulated-effect count;
- eliminate every possible route that bypasses the configured gateway;
- establish production readiness or universal bypass prevention;
- claim independent security certification without the corresponding external evidence;
- claim compatibility with an external standard merely because the architecture has related concepts.

---

## 7. Adoption and research direction

Aether should focus on a narrow, reusable authorization-boundary conformance capability.

Potential future research includes:

- independent reproduction by developers outside the project;
- review of the gateway's strict parsing behavior;
- challenge cases for payload and envelope ambiguity;
- downstream integration testing;
- direct-route and proxy-bypass analysis;
- application-specific argument-schema validation;
- independent review of evidence and telemetry semantics;
- controlled benchmark comparisons;
- compatibility evaluation with established workload-identity infrastructure.

Compatibility with the OWASP Agent Control Standard or existing security benchmarks is a research and integration option to evaluate.

It is not a claim of current compatibility and not a reason to create another standard prematurely.

---

## 8. Trust assumptions and evidence limits

### 8.1 Reference handler

The reference handler is an in-memory demonstration consumer, not a production authorization service.

It validates envelope structure and freshness, verifies a supplied payload digest when content is present, and checks that payload `target_resource` and `operation` match the outer action.

It does not independently authenticate the caller or evaluate Aether policy.

### 8.2 Trusted gateway path

The reference handler is designed to be reached through Aether's configured enforcement proxy on a trusted network path.

If an untrusted caller can reach the handler directly, the caller can bypass the gateway's policy decision.

The adapter's action-binding check is not proof that the envelope was authorized.

Authorization relies on the trusted gateway and deployment path.

### 8.3 Application-specific semantics

The adapter validates the structure and top-level action fields of its reference payload.

It does not interpret application-specific semantics inside `arguments`.

If a downstream application treats fields inside `arguments` as instructions that can alter the target, operation, authority, scope, or side effects, that application must define and validate those fields under its own schema and enforce authorization and binding checks before any effect.

Matching the outer target and operation does not prove that the business meaning of arguments is safe or authorized.

### 8.4 Simulated effects

Recorded effects are simulated in-memory entries.

They are not durable external actions or independent attestations.

A zero effect count means that the tested reference handler did not record a simulated effect during that test. It does not prove that every possible external system or alternate route was unaffected.

### 8.5 Independence

The current tests, benchmark results, evidence, and successful CI run are creator-controlled.

They have not, by themselves, established independent reproduction, external security review, production readiness, universal bypass prevention, or compatibility with an external standard.

Independent reproduction and review remain open research objectives.

---

## 9. Implementation references

The following source files at the reviewed baseline provide the implementation and test evidence for this contract:

| Source | Relevant behavior |
|---|---|
| [`cmd/main.go`](https://github.com/YabulHaj/Aether-Protocol/blob/8d54fcfe713d26b7b878f795d389d759ac325fb0/cmd/main.go) | Gateway request sequence, policy evaluation, payload validation, pre-forwarding rejection, and telemetry |
| [`pkg/actioncontract/contract.go`](https://github.com/YabulHaj/Aether-Protocol/blob/8d54fcfe713d26b7b878f795d389d759ac325fb0/pkg/actioncontract/contract.go) | Structured JSON payload schema, duplicate-key rejection, strict parsing, and action comparison |
| [`pkg/actioncontract/reference_handler.go`](https://github.com/YabulHaj/Aether-Protocol/blob/8d54fcfe713d26b7b878f795d389d759ac325fb0/pkg/actioncontract/reference_handler.go) | Strict envelope decoder and demonstration downstream reference handler |
| [`cmd/action_boundary_contract_test.go`](https://github.com/YabulHaj/Aether-Protocol/blob/8d54fcfe713d26b7b878f795d389d759ac325fb0/cmd/action_boundary_contract_test.go) | Gateway matching, mismatch, malformed, non-canonical, and policy-denial regression tests |
| [`pkg/actioncontract/contract_test.go`](https://github.com/YabulHaj/Aether-Protocol/blob/8d54fcfe713d26b7b878f795d389d759ac325fb0/pkg/actioncontract/contract_test.go) | Payload-contract unit tests |
| [`internal/envelope/envelope.go`](https://github.com/YabulHaj/Aether-Protocol/blob/8d54fcfe713d26b7b878f795d389d759ac325fb0/internal/envelope/envelope.go) | Envelope completeness, freshness, and supplied-payload digest validation |
| [`.github/workflows/ci.yml`](https://github.com/YabulHaj/Aether-Protocol/blob/8d54fcfe713d26b7b878f795d389d759ac325fb0/.github/workflows/ci.yml) | Published CI verification workflow |

---

## Contract principle

**The outer action defines the authority.**

**The supported payload must remain bound to that action.**

**A rejection must happen before forwarding through the tested boundary.**

**Evidence must describe what the implementation actually observed.**

**No security claim should exceed the evidence that supports it.**