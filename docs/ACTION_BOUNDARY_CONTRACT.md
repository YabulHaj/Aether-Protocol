# Aether Action-Boundary Contract

**Status:** Draft design contract. This document describes proposed requirements; it is not evidence that every requirement is currently enforced or independently validated.

**Baseline reviewed:** `75ef00d0cb1e866f8e9e017fba238041858d38ec`

## 1. Purpose

Aether must distinguish three different questions:

1. **Authorization decision:** Did Aether permit or deny the requested action?
2. **Downstream HTTP outcome:** What HTTP status did the upstream service return, if a request was forwarded?
3. **Verified effect:** Is there trusted evidence that the intended action actually occurred, did not occur, or remains unknown?

These outcomes must not be conflated. A successful authorization decision is not proof of successful execution.

## 2. Relevant current implementation behavior

The following points describe the reviewed implementation and its current limitations:

- The policy matcher uses identity, optional intent, capability, target resource, and operation. Payload and constraints are not currently policy-matching fields.
- When a request is allowed, the current proxy path forwards the original request body.
- The current generic gateway does not parse arbitrary nested payload formats and compare their meaning with the outer authorized action.
- The payload digest is compared with content only when payload content is supplied. A digest alone is not proof of the requester's authority or an approving party's identity.
- Telemetry `decision_status` describes the authorization decision. The legacy `status` field remains an alias for that decision; neither represents the upstream HTTP response.
- The current telemetry event does not independently attest to a durable downstream effect.

These facts limit what Aether can currently claim. In particular, a downstream application that interprets conflicting action fields inside a payload must not be assumed to reject them automatically.

## 3. Proposed action-boundary contract

### C1. Explicit authorization context

The authorized action is determined from the validated outer action context, including identity, intent, capability, target resource, and operation, subject to the configured policy and the other envelope-validation controls.

### C2. Payload cannot silently redefine authority

Payload content is application data unless a specific, trusted integration defines and validates its action semantics.

If the downstream service interprets payload fields as an action, a trusted enforcement adapter must parse them under a defined schema, normalize the action-defining fields, and compare them with the authorized action context before any side effect. A mismatch must be rejected before execution.

This contract does not require a generic gateway to guess the semantics of every possible JSON or binary payload.

### C3. Denial before downstream effect

A denied request must not reach the protected action handler through the tested enforcement path. A conflicting action must not cause a simulated or real downstream side effect through the supported integration.

Validation must count downstream requests and simulated effects separately where both measurements are available.

### C4. Separate decision, response, and effect records

Authorization telemetry must identify the authorization decision and reason. If upstream response status is collected, it must be represented separately from decision status. If downstream effects are not independently verified, the evidence must not imply that they were.

### C5. Correct interpretation of payload hashes

A content digest may establish consistency between supplied content and a supplied digest when the implementation verifies that comparison. It does not establish who authorized the action, whether the action is permitted, or whether a downstream effect occurred.

When payload content is absent, the system must not describe its contents as digest-verified.

### C6. Enforcement scope must be explicit

The guarantee applies only to actions routed through the tested enforcement boundary and supported integrations. It does not establish universal prevention if an agent or caller can reach the downstream service through an unguarded route.

## 4. Required regression and conformance tests

| Scenario | Required observation |
|---|---|
| Exact authorized action | Authorization allows; the reference downstream receives the intended action and records the expected simulated effect. |
| Explicitly denied action | Authorization denies; downstream request count and effect count do not increase. |
| Conflicting nested action | The trusted boundary rejects the mismatch before a simulated effect; a response code alone is insufficient evidence. |
| Wrong digest with supplied payload | Validation rejects the request before downstream access. |
| Allowed request with upstream HTTP 409 | The authorization decision remains ALLOW; the upstream response remains 409; execution success is not inferred. |
| Replayed, revoked, or identity-mismatched request | The tested enforcement path rejects it before downstream access. |
| Payload omitted | Evidence does not claim payload-content verification when no content was supplied. |

The contract is not considered implemented merely because this document exists. Each claimed property must be linked to permanent tests and reproducible evidence.

## 5. Explicit non-goals

- Do not build a generic parser that guesses the meaning of arbitrary application payloads.
- Do not treat a hash as a signature or proof of approval.
- Do not treat HTTP 200, an ALLOW decision, or a local demonstration as universal proof of a completed real-world effect.
- Do not claim production readiness, universal bypass prevention, or independent security certification without the corresponding evidence.

## 6. Adoption direction

Aether should focus on a narrow, reusable authorization-boundary conformance capability. Compatibility with the OWASP Agent Control Standard or existing security benchmarks is a research and integration option to evaluate, not a claim of current compatibility and not a reason to create another standard prematurely.


## 7. Reproduce the reference contract locally

Run these commands from the repository root with Go installed.

### Focused tests

```powershell
go test -count=1 -v ./pkg/actioncontract ./cmd -run 'TestValidatePayload|TestActionBoundaryContract'
```

### Full validation

```powershell
go test -count=1 ./...
go vet ./...
go build ./...
```

The full test suite includes the authorization benchmark. Timing varies and is not proof of a performance improvement without a controlled comparison.

### Expected observations

| Scenario | Gateway decision | Reference adapter outcome | Simulated effects |
|---|---|---|---:|
| Matching action | ALLOW | HTTP 200 | 1 |
| Conflicting nested action | ALLOW | HTTP 409 | 0 |
| Non-canonical outer field | May forward | HTTP 400 from adapter | 0 |
| Policy-denied outer action | DENY | HTTP 403; adapter not reached | 0 |

These are creator-controlled local test results, not independent validation. Not every scenario listed elsewhere has a dedicated end-to-end adapter test.

## 8. Trust assumptions and evidence limits

The reference handler is an in-memory demonstration consumer, not a production authorization service. It validates envelope structure and freshness, verifies a supplied payload digest when content is present, and checks that the payload target_resource and operation match the outer action. It does not independently authenticate the caller or evaluate Aether policy.

The reference handler is designed to be reached through Aether's configured enforcement proxy on a trusted network path. If an untrusted caller can reach the handler directly, the caller can bypass the gateway's policy decision. The adapter's action-binding check is not proof that the envelope was authorized; authorization relies on the trusted gateway and deployment path.

The adapter validates the structure and top-level action fields of its reference payload, but it does not interpret application-specific semantics inside arguments. If a downstream application treats fields inside arguments as instructions that can alter the target, operation, authority, scope, or side effects, that application must define and validate those fields under its own schema and enforce authorization and binding checks before any effect. Matching the outer target and operation does not prove that the business meaning of arguments is safe or authorized.

Recorded effects are simulated in-memory entries. They are not durable external actions or independent attestations. These tests do not establish production readiness, universal bypass prevention, or compatibility with an external standard. The current tests and results remain creator-controlled until reproduced or reviewed independently.
