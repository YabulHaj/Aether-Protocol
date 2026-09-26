# Aether — Definition of Done (v0.1)

## Purpose

This document defines the objective, testable technical gates required to declare the Aether v0.1 reference implementation complete.

Each gate is pass/fail. A gate is either satisfied or it is not.

The Definition of Done applies only to the technical implementation and documented scope of Aether v0.1

---

## 1. Clean Build

Aether must build successfully from a clean checkout using documented commands.

No undocumented manual modification may be required to produce a successful build.

Required checks must complete without unresolved build errors.

---

## 2. Automated Unit Tests

Core security components must have automated unit tests covering their defined behavior.

At minimum, testing must cover:

* action-envelope construction and validation;
* policy evaluation;
* identity verification;
* enforcement behavior;
* evidence generation;
* revocation;
* replay protection where implemented.

All unit tests must pass.

---

## 3. End-to-End Authorization Flow

The complete authorization path must be tested end-to-end:

**Identity → Action Envelope → Validation → Policy → Authorization Decision → Enforcement → Target Action → Evidence**

At least one valid representative action must successfully complete the entire path.

At least one invalid or unauthorized action must be denied before reaching the protected target.

---

## 4. Default Deny and Fail Closed

Requests containing missing, malformed, unverifiable, unsupported, or otherwise invalid authorization material must not be allowed through the security boundary.

Security-relevant uncertainty must result in denial rather than implicit authorization.

---

## 5. Identity Verification Boundary

Aether must reject requests when the supplied identity is:

* invalid;
* unverifiable;
* unrecognized;
* improperly bound to the requested authorization context.

A valid credential alone must not automatically authorize an action.

---

## 6. Authorization Scope

Authorization must be bound to the declared action context.

Tests must demonstrate that authorization granted for one combination of:

* identity;
* intent;
* capability;
* target;
* operation;
* applicable constraints;

cannot be silently reused to authorize a different protected action.

Aether must not widen authority during request processing or forwarding.

---

## 7. Freshness and Expiration

Expired or otherwise stale authorization material must be rejected.

Where expiration or freshness fields are part of the authorization model, their validation must be covered by automated tests.

---

## 8. Replay Protection

A previously consumed authorization must not be successfully reused where replay protection is required by the declared security model.

Concurrent reuse of the same authorization material must be tested where applicable.

The implementation must ensure that replay protection cannot be bypassed through ordinary request concurrency.

---

## 9. Enforcement Boundary

A denied authorization decision must prevent the protected action from reaching the target.

Tests must verify the enforcement boundary directly.

For rejected requests, the test harness must verify the expected outcome, including zero backend/target hits where the architecture requires the request to be stopped before forwarding.

An allowed request must be forwarded only within the authority granted by the authorization decision.

---

## 10. Evidence Generation

Every request that enters the defined Aether authorization boundary during testing must produce the corresponding structured evidence required by the implementation.

Evidence must record sufficient information to reconstruct the security decision and its result within the declared evidence model.

There must be no silent authorization decisions within the defined evidence boundary.

Requests that never enter the authorization boundary, such as unmatched outer-router routes, may be explicitly documented as outside the evidence scope.

---

## 11. Revocation

Where revocation is supported by the implementation, tests must demonstrate that revoked authority is denied for subsequent protected actions.

The revocation mechanism must operate according to its documented behavior and limitations.

Any propagation or time-to-enforcement characteristics that are implementation-dependent must be documented rather than assumed.

---

## 12. Attack and Misuse Testing

The v0.1 release must contain a minimum of 50 distinct documented attack or misuse scenarios.

Each scenario must contain:

* a unique scenario identifier;
* a description of the attempted misuse;
* defined preconditions;
* the attack or misuse input;
* the expected security invariant or response;
* a reproducible test;
* the observed result;
* the relevant evidence or test artifact.

Confirmed security bypasses must be converted into regression tests where appropriate.

Inconclusive and infrastructure-error results must remain explicitly classified as such and must not be presented as successful security findings.

---

## 13. Benchmark Reproducibility

Any benchmark or measured security claim included with the v0.1 release must have:

* a documented methodology;
* a defined test environment;
* versioned inputs or scenarios;
* machine-readable or otherwise inspectable results;
* documented limitations.

Claims must describe observed measurements rather than implying results that were not actually tested.

Independent third-party reproduction is outside the v0.1 technical completion gate and may be pursued as subsequent validation.

---

## 14. Clean-Environment Reproduction

The reference implementation must include documented instructions for setting up and running Aether in a clean environment.

The documented procedure must identify:

* prerequisites;
* required configuration;
* required commands;
* test execution;
* expected test artifacts.

Creator-controlled reproduction is sufficient for the v0.1 release gate.

Independent reproduction is a subsequent validation activity and is not required to declare the v0.1 implementation technically complete.

---

## 15. Security Review

Before release, the implementation must undergo a documented security review covering the security invariants defined by the Aether threat model.

The review must identify:

* tested controls;
* known limitations;
* unresolved issues;
* assumptions;
* security-relevant design decisions.

The review must not claim independent assurance unless an independent review has actually occurred.

---

## 16. Threat Model and Scope

The release must contain a documented threat model defining:

* protected assets;
* security boundaries;
* attacker capabilities;
* security invariants;
* in-scope threats;
* explicitly out-of-scope threats;
* known limitations.

Aether must not claim protection outside its documented threat model.

---

## 17. Documentation Consistency

The public technical documentation must accurately describe the released implementation.

At minimum, the following documents must be consistent with the implementation:

* `README.md`
* `CHARTER.md`
* `THREAT_MODEL.md`
* `DEFINITION_OF_DONE.md`
* `SECURITY.md`
* `CONTRIBUTING.md`

Documentation must not describe planned functionality as implemented functionality.

---

## 18. Release Integrity

The release must contain the required repository and licensing artifacts for the project.

At minimum:

* applicable open-source license;
* security reporting instructions;
* contribution instructions;
* third-party notices where required;
* trademark information where applicable;
* reproducible release/version information.

The released source tree must correspond to the tested release candidate.

---

## 19. Known Limitations

A release-specific limitations document must identify:

* what Aether v0.1 does not protect against;
* what has not been tested;
* what remains experimental;
* what depends on development/mock infrastructure;
* what has not been independently validated;
* what must not be interpreted as a production security guarantee.

Known limitations must be stated explicitly rather than inferred by users.

---

## 20. Release Gate

Aether v0.1 may be declared technically complete only when all required gates in Sections 1–19 are satisfied.

Any unresolved failure of a mandatory gate blocks the technical release.

The v0.1 release designation means:

> **The defined Aether v0.1 reference implementation has satisfied its documented technical release criteria under the declared test environment and threat model.**

It does not mean that Aether has been independently certified, universally secure, production-ready for every environment, or validated against threats outside the declared scope.
