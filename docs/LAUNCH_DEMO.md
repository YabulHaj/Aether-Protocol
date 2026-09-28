# Aether 60-Second Launch Demo

## Purpose

This document defines the canonical 60-second public demonstration of Aether.

The demo must show actual observed authorization behavior from the running implementation.

It must not use fabricated telemetry, simulated backend hits, prewritten fake security events, or claims that were not observed.

The objective is simple:

> Show an autonomous action arriving at an explicit authorization boundary, show the decision, and show whether the protected target was reached.

---

## Canonical Flow

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

The visual story should immediately communicate:

```text
Identity is not authority.
```

---

## 0–5 seconds — Identity

Display the live Aether UI.

Show:

```text
IDENTITY
agent://finance-bot-01
```

Keep the presentation visually clean.

Do not explain the architecture verbally yet.

---

## 5–12 seconds — Intent

Show:

```text
INTENT
summarize
```

The identity and intent should remain visible together if the UI permits it.

---

## 12–20 seconds — Authority

Show:

```text
AUTHORITY
read:invoices
```

Then show the complete authorized context:

```text
IDENTITY:   agent://finance-bot-01
INTENT:     summarize
AUTHORITY:  read:invoices
TARGET:     invoice/12345
OPERATION:  GET
```

The authorization rule used in the verified local demonstration is:

```text
R-001
```

---

## 20–30 seconds — Authorized action

Send the real authorized request through the running gateway.

Expected observed result:

```text
HTTP 200
{"status":"success","message":"Protected data accessed"}
```

The Live River should show:

```text
ALLOWED
```

The protected backend should show:

```text
[BACKEND] Securely received request: /v1/action
```

This is the key proof:

```text
AUTHORIZED
      ↓
ALLOWED
      ↓
BACKEND HIT
```

---

## 30–40 seconds — Replay attempt

Reuse the same authorization material or nonce in a controlled reproduction of the replay scenario.

Expected security decision:

```text
BLOCKED
```

Expected invariant:

```text
REPLAY_DETECTED
```

The protected backend must not receive the replayed action.

Only show an actual observed result.

Do not invent a replay message if the current UI does not expose that exact text.

---

## 40–48 seconds — Authorization boundary test

Change the target from the authorized resource:

```text
invoice/12345
```

to an unauthorized resource:

```text
invoice/99999
```

Expected observed result from the verified clean-clone demonstration:

```text
HTTP 403
```

Structured evidence:

```text
allowed: false
reason_code: deny_no_matching_rule
```

Live River:

```text
BLOCKED
```

Protected backend:

```text
NO NEW BACKEND REQUEST
```

The visual proof is:

```text
UNAUTHORIZED ACTION
        ↓
     BLOCKED
        ↓
 BACKEND HIT: 0
```

Only display the backend-hit metric if it is directly tied to the actual observed backend console/result.

---

## 48–55 seconds — Attack sequence

Rapidly show short labels for additional tested security boundaries.

Use only scenarios supported by the current implementation/tests.

Examples:

```text
WRONG IDENTITY
BLOCKED

WRONG TARGET
BLOCKED

REPLAY
BLOCKED

MALFORMED REQUEST
BLOCKED

REVOKED AUTHORITY
BLOCKED
```

Do not claim that these represent every possible AI-agent attack.

They are examples from the documented and tested authorization boundary.

---

## 55–60 seconds — Challenge

End on a simple screen:

```text
TRY TO BREAK AETHER
```

Then:

```text
Open source.
Reproducible.
Challengeable.

github.com/YabulHaj/Aether-Protocol
```

Do not end with:

```text
Star this repository.
```

The primary invitation is testing.

---

## Required visual language

The canonical visual sequence is:

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

Authorized state:

```text
ALLOWED
```

Unauthorized state:

```text
BLOCKED
```

The demo should make the security decision visually obvious without requiring the viewer to read the entire README.

---

## Evidence rules

Every frame showing a security result must correspond to a real observed result.

Do not fabricate:

* HTTP responses;
* backend hits;
* security decisions;
* benchmark results;
* attack outcomes;
* external-user results;
* independent validation;
* production claims.

The benchmark and clean-clone results are creator-controlled evidence.

Independent validation remains an open future objective.

---

## Canonical verified results used by this demo

### Authorized clean-clone result

```text
HTTP 200
{"status":"success","message":"Protected data accessed"}
```

Evidence included:

```text
allowed: true
rule_id: R-001
identity_ref: agent://finance-bot-01
target_resource: invoice/12345
reason_code: allow_matched_rule
```

Protected backend:

```text
[BACKEND] Securely received request: /v1/action
```

### Denied clean-clone result

```text
HTTP 403
```

Evidence included:

```text
allowed: false
reason_code: deny_no_matching_rule
target_resource: invoice/99999
```

Protected backend:

```text
No new [BACKEND] request
```

### Clean-clone engineering verification

```text
go test ./...        PASS
go test -race ./...  PASS
go vet ./...         PASS
go build ./...       PASS
```

Attack Lab / benchmark:

```text
50 scenarios
100 measured iterations per scenario
5 warmup iterations per scenario
PASS
```

---

## Recording rule

The strongest version of the demo is recorded directly from the running system.

Preferred capture order:

```text
1. Start dummy backend
2. Start Aether gateway
3. Open Live River
4. Capture authorized action
5. Capture backend confirmation
6. Capture denied action
7. Capture absence of backend request
8. Show Attack Lab output
9. End with TRY TO BREAK AETHER
```

The recording should preserve enough context for a technically knowledgeable viewer to understand that the security decisions came from the running implementation.

---

## What the demo does not prove

The 60-second demo does not prove:

* universal agent security;
* absence of undiscovered vulnerabilities;
* prevention of all prompt-injection attacks;
* production readiness;
* distributed security guarantees;
* independent security validation;
* organizational deployment.

The demo proves only what the observed implementation and displayed evidence actually demonstrate.

---

## Canonical message

The entire demo should leave the viewer with one idea:

> An authenticated agent should not automatically have authority to perform every action.

Aether places an explicit authorization boundary between agent identity and action execution.

Then:

> Try to break it.
