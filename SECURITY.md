# Security Policy

## Scope

Aether is an open-source research and engineering project focused on authorization, enforcement, evidence, and observability for autonomous software agents.

Security reports should focus on vulnerabilities that could cause the implemented security boundary to behave differently from its documented design.

Examples include:

* unauthorized requests being allowed;
* denied requests reaching the protected upstream;
* identity-to-envelope binding bypasses;
* replay or nonce-consumption bypasses;
* revocation bypasses;
* authorization scope widening;
* payload-integrity bypasses;
* telemetry influencing authorization;
* evidence integrity failures;
* sensitive security information being exposed.

## Current Security Boundary

The current implementation is a locally tested research system.

The project does not currently claim:

* production readiness;
* universal security;
* independent security certification;
* distributed replay or revocation guarantees;
* complete protection against all agentic or prompt-injection attacks.

## Reporting a Vulnerability

Please do not publish potentially exploitable security details in a public issue before the issue has been reviewed.

Use the repository's available private security-reporting mechanism, such as GitHub's private vulnerability-reporting feature when enabled.

A useful report should include:

* a clear description of the issue;
* affected component or file;
* reproduction steps;
* expected behavior;
* observed behavior;
* security impact;
* any proof-of-concept material that is safe to share privately.

## Reproducibility

Security reports are most useful when they include a minimal reproducible test or exact request sequence.

When possible, provide:

```text
Environment
Commit
Configuration
Request / test input
Expected result
Observed result
Backend result
Evidence result
```

## Research and Disclosure

Aether follows a build-and-verify approach.

Confirmed security findings should be:

1. reproduced;
2. documented;
3. classified;
4. fixed when appropriate;
5. regression-tested;
6. reflected in the relevant evidence record.

Historical failures and meaningful negative results should not be silently removed from the project's evidence history.

## Evidence Discipline

A screenshot, AI-generated analysis, or creator statement is not treated as independent security validation.

Security claims must remain traceable to:

* source code;
* reproducible tests;
* benchmark artifacts;
* structured evidence;
* or independently produced evidence.

## Status

This policy describes the security-reporting expectations for the current research-stage project.

The policy should be updated when the project establishes a formal private disclosure channel, production deployment process, or other materially different security-reporting requirements.
