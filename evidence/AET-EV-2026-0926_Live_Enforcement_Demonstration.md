# Aether Live Enforcement Demonstration

**Date:** 2026-09-27  
**Repository:** Aether Protocol  
**Test type:** Manual live end-to-end demonstration

## Purpose

Verify that Aether:

1. Allows an authorized action.
2. Proxies the authorized action to the protected backend.
3. Denies an unauthorized target.
4. Does not proxy the denied action to the protected backend.
5. Emits corresponding ALLOWED and DENIED live telemetry events.

## Authorized test

### Request

- Identity: `agent://finance-bot-01`
- Intent: `summarize`
- Capability: `read:invoices`
- Operation: `GET`
- Target: `invoice/12345`
- Audience: `aether-gateway`

### Observed result

HTTP response:

`200 OK`

Response:

`{"status":"success","message":"Protected data accessed"}`

The Aether Live River UI displayed:

**ALLOWED**

The protected dummy backend recorded:

`[BACKEND] Securely received request: /v1/action`

## Unauthorized test

### Request

The same authorization context was used except for the target:

- Target: `invoice/99999`

### Observed result

Aether returned:

`{"error":"forbidden by policy"}`

The Aether Live River UI displayed:

**DENIED**

For the clean verification run, the dummy backend was restarted before the test and showed only:

`Dummy backend listening on localhost:9090`

No subsequent:

`[BACKEND] Securely received request: /v1/action`

message appeared.

## Interpretation

This manual demonstration provides direct evidence that the configured Aether policy allowed the authorized target and denied the mismatched target, with the denied request not observed reaching the protected dummy backend during the clean verification run.

This is a manual creator-controlled demonstration. It is not independent security validation and does not establish universal security, production readiness, or complete attack coverage.

## Evidence boundary

The UI is a visualization of server-side decisions. The authoritative implementation and automated test artifacts remain the primary security evidence.

## Related benchmark

Aether's broader Attack Lab contains creator-controlled adversarial scenarios and should be evaluated separately from this manual live demonstration.

