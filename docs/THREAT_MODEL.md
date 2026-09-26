# Aether — Threat Model

This document explains, in plain language, what Aether v0.1 is designed to protect against, what it explicitly does not try to protect against, and the specific security guarantees ("invariants") it must uphold.

## Protected Against

Aether v0.1 is designed to reduce risk from:

- **Unauthorized tool use** — an agent invoking a capability it was never granted.
- **Privilege escalation** — an agent obtaining or using more access than it was authorized for.
- **Replay of stale authorization** — reusing an old, expired, or already-used authorization to perform a new action.
- **Unauthorized target/resource access** — an agent acting on a resource outside its authorized scope (e.g., authorized for file A, but accessing file B).
- **Unauthorized methods or operations** — an agent performing an operation type it wasn't authorized for (e.g., authorized to "read," but performing "delete").
- **Failure to revoke compromised identities/sessions** — a compromised or retired identity continuing to act because revocation didn't work or wasn't checked.
- **Inadequate auditability of autonomous actions** — actions happening without a clear, structured record of what was requested, decided, and done.

## Explicitly Out of Scope

Aether v0.1 does **not** attempt to address:

- General AI alignment (making an AI system "want" the right things).
- Machine consciousness or related philosophical questions.
- All forms of prompt injection (Aether may reduce the *impact* of some prompt-injection-driven actions by enforcing authorization boundaries, but it does not detect or prevent prompt injection itself).
- All zero-day vulnerabilities in underlying software or infrastructure.
- Every possible future attack technique.
- Universal AI safety in any general sense.
- Absolute or guaranteed security of any kind.

## Aether v0.1 Security Invariants

An "invariant" is a rule that must always hold true, no matter what. If an invariant is ever violated, that is treated as a critical failure of the system.

### 1. Default Deny

**What it means:** If Aether cannot positively confirm that an action is authorized, the action is denied. There is no "allow by default" state.

**Why it matters:** Systems that fail open (allow by default) turn any gap in coverage — a missing policy rule, a misconfigured check — into an automatic authorization. Default deny makes gaps fail safely instead.

**What Aether will test:** That any request with missing, incomplete, ambiguous, or unrecognized policy input is denied, not allowed.

**Example failure:** A new action type is introduced that no policy rule covers yet, and the system allows it because no rule explicitly denied it.

**What should happen when violated:** The action must be blocked, and the gap must be logged as a policy coverage failure requiring immediate review.

### 2. Freshness / Anti-Replay

**What it means:** An authorization decision is valid only for a specific action, at a specific time, and cannot be reused later or replayed for a different action.

**Why it matters:** Without freshness guarantees, a captured or logged authorization could be reused by an attacker to perform the same (or a similar) action again without new approval.

**What Aether will test:** That a previously issued authorization token/decision cannot be successfully reused after its validity window, or reused for a different action than the one it was issued for.

**Example failure:** An authorization issued for "send this one payment" is intercepted and successfully reused to send a second payment.

**What should happen when violated:** The replayed request must be denied, and the replay attempt must be recorded as a security event.

### 3. Target/Action Scope Binding

**What it means:** An authorization is bound tightly to a specific target (resource) and a specific action (operation) — not to a broad category.

**Why it matters:** Without scope binding, an authorization for "access this one file" could be misused to justify "access any file," or "read" could be misused to justify "write" or "delete."

**What Aether will test:** That an authorization issued for target X and operation Y cannot be used to justify action on target X' or operation Y'.

**Example failure:** An agent authorized to *read* a specific record instead *deletes* it, and the system allows it because it only checked the target, not the operation.

**What should happen when violated:** The mismatched action must be denied, and the mismatch logged.

### 4. No Self-Authorization

**What it means:** An agent cannot grant, approve, or extend its own authorization. Authorization must come from a source independent of the agent requesting the action.

**Why it matters:** If an agent could approve its own actions, the entire authorization layer becomes meaningless — it would just be the agent's own decision, restated.

**What Aether will test:** That no code path allows the requesting identity to also serve as the approving authority for its own request.

**Example failure:** A misconfiguration allows the agent's own service identity to also sign off on its policy evaluation.

**What should happen when violated:** This must be treated as a critical architectural defect, not a normal denied request — it invalidates the authorization guarantee entirely and requires immediate remediation.

### 5. Fail Closed on Invalid Security Data

**What it means:** If any security-relevant input is malformed, unverifiable, expired, or otherwise invalid (a bad signature, a broken identity token, corrupted policy data), Aether must deny the action rather than guess or proceed.

**Why it matters:** Attempting to "handle gracefully" by proceeding anyway turns data corruption or tampering into an authorization bypass.

**What Aether will test:** That malformed, corrupted, expired, or unverifiable identity tokens, envelopes, or policy data always result in denial, never in proceeding with a best-effort guess.

**Example failure:** A cryptographic signature fails verification, but the system proceeds anyway because the rest of the request "looks fine."

**What should happen when violated:** The action is denied, and the invalid-data event is logged for investigation.

### 6. Structured Evidence Generation

**What it means:** Every authorization decision — allowed or denied — produces a structured, machine-readable record: who requested it, what was requested, what the decision was, why, and when.

**Why it matters:** Without structured evidence, no one can audit what an autonomous agent actually did, or verify that the authorization system is working correctly.

**What Aether will test:** That 100% of processed action envelopes produce a corresponding evidence record, with no silent/unlogged decisions.

**Example failure:** A denied request is correctly blocked, but no record of the denial is ever created, so the attempted violation is invisible to auditors.

**What should happen when violated:** Missing evidence for any processed request is treated as a Definition-of-Done failure (see DEFINITION_OF_DONE.md) — the system is not considered working correctly.

### 7. Revocation

**What it means:** It must be possible to invalidate an identity's or session's authorization such that all future actions from that identity/session are denied, within a defined and tested time bound.

**Why it matters:** If an identity is compromised, revocation is the mechanism that limits further damage. A system without reliable revocation cannot contain a compromise.

**What Aether will test:** That after revocation is issued, subsequent requests from the revoked identity/session are denied, and that the time between revocation and enforcement is measured and bounded.

**Example failure:** An identity is revoked, but cached authorization data allows it to keep acting for an unacceptably long time afterward.

**What should happen when violated:** This is treated as a critical failure requiring immediate fix — revocation delay must be measured against a defined maximum acceptable bound, and any excess is a release blocker.