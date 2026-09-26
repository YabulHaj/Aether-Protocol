# Aether Release Notes

## Current Release

**Aether v0.1.0-rc.1**

> Draft release candidate — publication remains pending the final release gate.

---

## Overview

Aether is an open-source authorization control and security research platform for autonomous software agents.

The project focuses on the boundary between an autonomous software agent and the actions it attempts to perform.

The core authorization chain is:

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

---

## Included in This Release Candidate

### Authorization

* deterministic policy evaluation
* explicit authorization rules
* default-deny behavior
* action-envelope validation
* target and operation checking

### Identity

* pluggable identity boundary
* local mock identity mode for development
* SPIFFE/SPIRE integration boundary

### Security Controls

* freshness validation
* expiration checking
* anti-replay controls
* revocation controls
* enforcement before target forwarding

### Evidence

* structured authorization decision records
* evidence integrity protection
* request/decision correlation
* security-event evidence suitable for research and debugging

### Attack Lab

The repository contains a versioned adversarial test corpus designed to challenge defined authorization and enforcement invariants.

The tested categories include:

```text
Envelope Integrity
Freshness
Identity Boundaries
Method / Routing
Policy Abuse
Revocation
Input Boundaries
```

---

## Current Benchmark Observation

The supplied creator-controlled benchmark artifacts report:

**50/50 tested scenarios meeting their defined expected outcomes.**

This is a result from the project's documented test environment and scenario corpus.

It should not be interpreted as:

* proof of universal security
* proof that every attack class has been covered
* proof that no vulnerabilities remain
* independent security validation
* production security certification

Independent reproduction and external technical review remain separate objectives.

---

## Reproducibility

The repository includes documentation intended to make the core tests and benchmark reproducible by another technical evaluator.

The project prioritizes:

* reproducible commands
* documented methodology
* explicit expected outcomes
* machine-readable evidence
* transparent limitations

---

## Security Philosophy

Aether treats authorization as an action-level control problem.

A valid identity does not automatically mean every requested action is authorized.

The system evaluates the requested action against the configured security policy before forwarding it to the target.

---

## Known Limitations

This release candidate remains a research-stage implementation.

Known limitations include:

* creator-controlled benchmark execution
* no established independent security review
* no established independent clean-room reproduction
* local-development mock identity mode
* process-local revocation state
* evolving production-scale validation
* incomplete coverage of all possible autonomous-agent attack classes

These limitations are intentionally documented rather than hidden.

---

## Next Development Phase

The next phase focuses on:

1. independent reproduction
2. external technical review
3. additional adversarial scenarios
4. benchmark refinement
5. identity interoperability validation
6. security findings and regression tests
7. live authorization observability
8. research dissemination

---

## Evidence Principle

Material security claims should be traceable to:

```text
TEST
ARTIFACT
SOURCE
or
INDEPENDENT ACTION
```

Screenshots and demonstrations support the record but do not replace the underlying technical evidence.

---

## Release Status

**Status:** Release candidate

**Publication:** Pending final release gate

**Independent validation:** Not yet established

**Production security guarantee:** Not claimed
