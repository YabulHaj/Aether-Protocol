# Aether Day 13 — Security Hardening

**Date:** September 23, 2026
**Evidence ID:** `AET-EV-2026-0013`
**Classification:** Creator-controlled security hardening evidence

## 1. Purpose

Day 13 hardened two specific security properties identified during the Aether development and research cycle:

1. Structured evidence coverage for authorization-boundary early exits.
2. Concurrent anti-replay protection for reuse of the same authorization nonce.

This document records the implementation changes and tests actually executed.

This document is **not** an independent security review.

## 2. Authorization-Boundary Evidence

The `/v1/action` authorization boundary now produces structured evidence for:

* `405 METHOD_NOT_ALLOWED`
* `413 REQUEST_TOO_LARGE`

The expected HTTP responses were preserved.

Unmatched `404` routes remain outside the authorization evidence boundary because they are rejected by the outer router before entering Aether authorization processing.

### Verification

`TestAction_MethodNotAllowedProducesEvidence`

* Request: `GET /v1/action`
* HTTP result: `405`
* Backend hits: `0`
* Evidence reason: `METHOD_NOT_ALLOWED`
* Result: PASS

`TestAction_RequestTooLargeProducesEvidence`

* Request: oversized `POST /v1/action`
* HTTP result: `413`
* Backend hits: `0`
* Evidence reason: `REQUEST_TOO_LARGE`
* Result: PASS

## 3. Concurrent Anti-Replay Hardening

The in-memory nonce registry performs nonce check-and-consume as one mutex-protected operation.

A nonce is rejected when it is already consumed or revoked.

### Verification

`TestAntiReplay_ConcurrentSameNonceAllowsExactlyOne`

* Concurrent requests: `32`
* Shared nonce: same nonce for all requests
* Allowed requests: `1`
* Rejected requests: `31`
* Backend hits: `1`
* Replay evidence observed: `REPLAY_DETECTED`
* Result: PASS

The test was also executed with the Go race detector and completed without a reported data race.

## 4. Repository Verification

The following creator-controlled test suites passed:

```text
go test -count=1 ./cmd
go test -count=1 ./...
go test -race -count=1 ./cmd
go test -race -count=1 ./...
```

The Day 9 attack-lab test was also re-run successfully:

```text
TestDay9AttackLab: PASS
```

The existing Day 10 benchmark remains part of the repository test suite. Its longer execution time is expected because it intentionally performs repeated local benchmark iterations.

## 5. Security Boundary

The completed work establishes behavior only for the tested local implementation.

It does not establish:

* independent reproduction;
* independent security review;
* distributed or multi-instance replay guarantees;
* production-scale performance;
* production readiness;
* organizational adoption;
* end-to-end production SPIFFE/SPIRE validation.

## 6. Important Limitation

The `REQUEST_TOO_LARGE` evidence path was specifically verified using an oversized request.

The current implementation groups body-read failures under the `REQUEST_TOO_LARGE` handling path. A future hardening cycle may distinguish a true `MaxBytesError` from other body-read failures if that distinction becomes necessary.

## 7. Day 13 Result

The documented `405` / `413` evidence-coverage issue has been resolved for the defined Aether authorization boundary.

The `404` case remains outside that boundary.

Concurrent reuse of the same authorization nonce is now tested under contention, with exactly one successful request and the remaining concurrent requests rejected.

Day 13 remains classified as:

**CREATOR-CONTROLLED SECURITY HARDENING EVIDENCE**

Formal evidence record:

`evidence/AET-EV-2026-0013_Day13_Security_Hardening.md`
