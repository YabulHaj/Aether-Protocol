# Aether

### Open-source authorization boundary for AI agents

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

The important question is not only whether Aether returned `403`.

It is:

> **Did the unauthorized action actually reach the protected target?**

These are creator-controlled local demonstrations, not independent security validation.

---

## What Aether is

Aether sits at the authorization and enforcement boundary around autonomous software actions.

It is designed around four cooperating planes:

| Plane              | Purpose                                                                |
| ------------------ | ---------------------------------------------------------------------- |
| Enforcement        | Decide and enforce whether an action is authorized                     |
| Evidence           | Preserve structured records of authorization decisions                 |
| Live Control Plane | Make real server-side security activity observable                     |
| Attack / Research  | Challenge defined security invariants and produce reproducible results |

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
Identity
   |
   v
Action Envelope
   |
   v
Policy
   |
   v
Enforcement
   |
   +---- ALLOW ----> Target
   |
   +---- DENY -----> Stop
   |
   v
Evidence
```

Aether is deliberately narrow.

It does not attempt to:

* secure an AI model itself;
* determine whether model reasoning is correct;
* replace workload identity systems;
* replace general-purpose IAM;
* eliminate application vulnerabilities;
* eliminate prompt injection;
* guarantee agent safety;
* guarantee production security.

Established identity mechanisms remain an input to authorization rather than something Aether attempts to reinvent.

---

## Current proof

The current repository includes:

* deterministic HTTP authorization and enforcement;
* workload identity abstraction;
* action-envelope validation;
* freshness and anti-replay controls;
* revocation;
* structured decision evidence;
* a reproducible Attack Lab;
* benchmark infrastructure;
* a real server telemetry path;
* a read-only Live Control Plane.

Current creator-controlled verification includes:

```text
go test ./...        PASS
go test -race ./...  PASS
go vet ./...         PASS
go build ./...       PASS
```

The current Attack Lab contains **50 defined scenarios** with documented expected outcomes.

Those results are creator-controlled observations.

They do not establish:

* universal security;
* complete attack coverage;
* absence of undiscovered vulnerabilities;
* production security;
* independent validation.

Independent reproduction and external technical review remain explicit objectives.

---

## Break Aether

Aether is built to be challenged.

**[BREAK AETHER](./docs/BREAK_AETHER.md)**

Useful attacks include:

* replaying authorization material;
* changing the target after authorization;
* changing identity;
* changing intent or capability;
* modifying protected request context;
* reusing authorization concurrently;
* submitting malformed security material;
* testing revoked authority.

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

---

## Evidence

Aether treats evidence as part of the security design.

Structured evidence can preserve information such as:

* identity;
* intent;
* capability;
* target;
* operation;
* policy rule;
* decision;
* reason;
* timestamps;
* request identifiers;
* integrity information;
* revocation state.

The browser is not the source of security truth.

The server-side decision, tests, benchmark artifacts, and structured evidence remain authoritative.

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

* create identities;
* approve requests;
* alter policy;
* override enforcement;
* turn blocked events into allowed events.

The visualization exists to make real security behavior easier to inspect.

It does not replace the underlying evidence.

---

## Run it

### Requirements

* Git
* Go 1.27.1+
* Windows PowerShell or an equivalent terminal

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

### Full reproduction path

**[QUICKSTART.md](./QUICKSTART.md)**

The full quickstart covers:

* the protected dummy backend;
* the Aether gateway;
* local development identity mode;
* the Live Control Plane;
* an authorized request;
* a denied request;
* backend-side verification;
* benchmark execution.

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

The project treats negative findings and unresolved cases as part of the research record.

---

## Current limitations

Aether is a research and validation platform, not a claim of production completeness.

Current limitations include:

* creator-controlled benchmark results;
* local development identity mode;
* process-local revocation state;
* incomplete production-scale deployment validation;
* incomplete end-to-end SPIFFE/SPIRE validation;
* evolving telemetry and visualization infrastructure;
* no independent security review yet;
* no independent organizational evaluation yet.

These limitations are intentionally documented rather than assumed away.

---

## Documentation

| Document                                           | Purpose                              |
| -------------------------------------------------- | ------------------------------------ |
| [QUICKSTART](./QUICKSTART.md)                      | Run Aether locally                   |
| [BREAK AETHER](./docs/BREAK_AETHER.md)             | Challenge the authorization boundary |
| [CLEAN REPRODUCTION](./docs/CLEAN_REPRODUCTION.md) | Reproduce the documented experiments |
| [THREAT MODEL](./docs/THREAT_MODEL.md)             | Security boundary and threats        |
| [SECURITY](./SECURITY.md)                          | Security reporting                   |
| [RESEARCH PACKAGE](./docs/RESEARCH_PACKAGE.md)     | Technical research record            |
| [SECURITY HARDENING](./docs/SECURITY_HARDENING.md) | Security-hardening record            |
| [RELEASE CANDIDATE](./docs/RELEASE_CANDIDATE.md)   | Release verification record          |
| [DEFINITION OF DONE](./DEFINITION_OF_DONE.md)      | Technical completion criteria        |

---

## Contributing

Useful contributions include:

* bypass research;
* authorization edge cases;
* reproducibility reports;
* security testing;
* identity integrations;
* benchmark methodology;
* evidence integrity;
* documentation improvements;
* independent evaluation.

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

> **No action without authorization.
> No authorization without context.
> No security claim without evidence.**
