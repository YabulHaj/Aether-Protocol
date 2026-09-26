# Aether — Preliminary IP Boundary

**Important disclaimer:** This document is a preliminary engineering and business planning document only. It does not state that any component is legally patentable, and it does not provide legal conclusions of any kind. Nothing in this document should be treated as legal advice. Anything flagged for "IP review" should be reviewed by a qualified intellectual-property professional before public disclosure.

## Purpose

This document draws a preliminary line between what is intended to be public/open-core and what may become private commercial surface later, so that early decisions (what to commit publicly, what to keep private) are made deliberately rather than accidentally.

## Public / Open-Core Candidates

These are currently intended to be public:

- **Reference authorization proxy** — the core implementation demonstrating the identity → envelope → policy → enforcement → evidence → revocation flow.
- **SDK / interfaces** — the client libraries and interface definitions used to integrate with Aether.
- **Attack Lab** — the suite of attack/misuse test scenarios described in DEFINITION_OF_DONE.md.
- **Benchmark methodology** — the documented approach used to measure and reproduce performance/security claims (not necessarily all raw results, if those reveal sensitive infrastructure detail).
- **Basic protocol documentation** — high-level description of the envelope format, decision flow, and evidence structure.
- **Examples** — sample integrations and usage examples.

## Potential Future Commercial Surface

These are **not** part of the v0.1 public release and may become private/commercial later:

- **Enterprise control plane** — centralized management UI/backend for multiple deployments.
- **Centralized fleet management** — tooling to manage many agents/identities across an organization.
- **Advanced analytics** — proprietary analysis of authorization/evidence data beyond basic audit needs.
- **Compliance automation** — tooling that maps evidence to specific regulatory/compliance frameworks.
- **Enterprise connectors** — integrations with specific commercial identity, ticketing, or policy systems.
- **Managed attack infrastructure** — a hosted/managed version of the Attack Lab.
- **Proprietary operational intelligence** — any internal tooling or data analysis developed from operating Aether at scale that goes beyond what's needed to understand the open-core project.

## What Must Remain Private Before the Publication/IP Gate

- Any specific implementation detail, algorithm, or technique that has not yet been reviewed for public disclosure and that the project may later want to protect or commercialize.
- Any internal roadmap, business strategy, or commercial pricing plan.
- Any unpublished benchmark data that has not been validated for public accuracy.
- Any draft documents (including these four) until they have been reviewed and approved for public release.

## What Can Be Safely Documented Publicly at a High Level

- The general architecture and flow described in CHARTER.md (identity → intent → capability → target/action → authorization → enforcement → evidence → revocation).
- The general threat model categories described in THREAT_MODEL.md (what is protected against, what is out of scope, the seven invariants), stated at the conceptual level.
- General Definition-of-Done categories (that there are default-deny tests, replay tests, etc.), without necessarily publishing every specific internal test case.

## What Requires Professional IP Review Before Publication

- Any specific technical mechanism used to implement the envelope binding, policy evaluation logic, or evidence structure, if there is any intention to seek patent protection or maintain trade-secret status for it.
- Any novel technique developed during the project that goes beyond assembling established cryptographic primitives and mature libraries.
- The exact wording and structure of the Attack Lab scenarios, if the project later wants to commercialize a "managed attack infrastructure" offering built on them.
- Any project name, logo, or branding material, for trademark considerations (separate from patent/IP considerations).

**Reminder:** This document identifies *what to review*, not *whether it qualifies for any specific form of IP protection*. That determination should be made by a qualified IP professional.