# Aether — Project Charter

## The Problem Aether Addresses

Autonomous AI agents are increasingly given the ability to take real-world actions: calling APIs, moving money, modifying infrastructure, sending communications, and invoking tools on behalf of a user or organization. Most current systems can verify *what software* is making a request (workload identity), but very few systems can rigorously verify *whether the specific action being requested, right now, in this context, is actually authorized*.

This gap creates risk: an agent's credentials may be valid, but the action it is trying to take may be unauthorized, stale, out of scope, or the result of manipulation. Existing workload-identity systems solve "who is this?" They do not solve "should this specific action happen, right now, under this policy?"

## The Exact Purpose of Aether v0.1

Aether v0.1 is an action-authorization and evidence layer that sits between an already-identified autonomous agent and the action it wants to take. Its job is narrow and specific: given a known identity, a stated intent, a requested action, and a target, Aether determines whether that action is authorized under explicit, human-defined policy, enforces that decision, and produces structured evidence of what happened.

## What Aether Does

- Accepts an "action envelope" describing an intended action (who, why, what capability, what target).
- Evaluates that envelope against explicit policy.
- Enforces an allow/deny decision before the action is permitted to proceed.
- Produces structured, auditable evidence of the decision and the action.
- Supports revocation of authorization for a given identity or session.

## What Aether Does NOT Do

- Aether is **not** a general AI alignment system. It does not attempt to make an AI agent "want" the right things.
- Aether is **not** a universal AI-safety solution. It does not protect against every possible harm an AI system could cause.
- Aether does **not** claim 100% security. No authorization system can guarantee that.
- Aether is **not** a replacement for established workload-identity systems (such as SPIFFE/SPIRE). It assumes identity is already solved and builds on top of it.

## The Relationship Between Workload Identity and Aether

Workload identity answers: *"Which specific piece of software or agent is making this request, and can I cryptographically trust that claim?"*

Aether answers a different question that comes **after** identity is established: *"Given that I trust who this is, is the specific action they are requesting right now actually authorized?"*

Aether does not issue or verify identity credentials itself. It consumes identity as a trusted input from an established identity system.

## The Role of SPIFFE/SPIRE

SPIFFE/SPIRE is one intended workload-identity integration path for Aether. SPIFFE defines a standard format for workload identity; SPIRE is a common implementation that issues those identities. Aether v0.1 is designed to accept a verified SPIFFE identity (or an equivalent trusted identity input) as the starting point of its authorization flow. Aether does not require SPIFFE/SPIRE specifically — it requires *some* trustworthy identity source — but SPIFFE/SPIRE is the reference integration for v0.1.

## The Core Flow

identity → intent/purpose → capability → target/action → authorization → enforcement → evidence → revocation


- **identity** — a verified workload identity (e.g., from SPIRE) making the request.
- **intent/purpose** — a declared reason the action is being taken.
- **capability** — the specific class of action being requested (e.g., "read file," "send payment").
- **target/action** — the specific resource and operation (e.g., "read file X," "transfer $Y to account Z").
- **authorization** — a policy evaluation producing an explicit allow/deny decision.
- **enforcement** — the mechanism that actually blocks or permits the action based on the decision.
- **evidence** — a structured, tamper-evident record of what was requested, decided, and done.
- **revocation** — the ability to invalidate an identity's or session's authorization going forward.

## Intended Users

- Teams building autonomous AI agents that take real-world actions and need an authorization boundary between "agent decides" and "action happens."
- Security and platform engineers responsible for constraining what autonomous systems are allowed to do.
- Organizations that already use, or plan to use, workload-identity infrastructure and need an authorization layer on top of it.

## Intended Technical Outcome

A working reference implementation demonstrating that:
1. An action envelope can be constructed and cryptographically bound to a verified identity.
2. Policy evaluation can produce a correct allow/deny decision under defined conditions.
3. Enforcement reliably blocks unauthorized actions and permits authorized ones.
4. Every decision produces structured evidence sufficient for audit.
5. Revocation reliably and promptly removes authorization.

## The 14-Day MVP Objective

Within 14 days, produce a working, testable reference implementation of the full flow above — identity input, envelope construction, policy evaluation, enforcement, evidence generation, and revocation — for a small, clearly defined set of example actions, along with a reproducible test suite (the Attack Lab) demonstrating the security invariants defined in THREAT_MODEL.md.

## Measurable Success Criteria

- 100% of default-deny tests pass (see DEFINITION_OF_DONE.md).
- 100% of defined Attack Lab scenarios produce the expected allow/deny outcome.
- 100% of enforced actions produce structured evidence records.
- Revocation of an identity/session measurably prevents further authorized actions within a defined time bound.
- All success criteria are reproducible by a third party following the documented setup steps in a clean environment.