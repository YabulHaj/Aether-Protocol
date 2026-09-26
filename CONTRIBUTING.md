# Contributing to Aether

Thank you for your interest in Aether.

Aether is a security-focused research and engineering project for authorization, enforcement, structured evidence, and observability for autonomous software agents.

The project follows a simple rule:

> Build what can be proved. Publish what can be defended. Measure what can be reproduced.

## Before Contributing

Please understand the project's security boundaries before changing code.

Read:

* `README.md`
* `docs/THREAT_MODEL.md`
* `DEFINITION_OF_DONE.md`
* `docs/KNOWN_LIMITATIONS.md`

## Security Changes

Security-related changes should be small, testable, and reproducible.

For a security change:

1. Describe the security property being protected.
2. Explain the existing behavior.
3. Add or update a regression test.
4. Run the relevant tests.
5. Run the broader test suite when appropriate.
6. Update documentation when the behavior or boundary changes.
7. Record important findings in the evidence system.

Do not change security behavior only to make a benchmark or demonstration look better.

## Tests

The normal repository test command is:

```powershell
go test -count=1 ./...
```

For concurrency-related changes, use the Go race detector where the environment supports it:

```powershell
go test -race -count=1 ./...
```

## Evidence Rules

Do not:

* invent benchmark results;
* invent users or deployments;
* present AI-generated analysis as independent review;
* describe creator-controlled testing as independent validation;
* remove failed results simply because they are inconvenient;
* treat screenshots as primary security evidence.

Important claims should be traceable to source code, tests, benchmark artifacts, structured evidence, or independently produced evidence.

## Pull Requests

A useful contribution should explain:

* what changed;
* why it changed;
* what security or engineering property it affects;
* what tests were added or changed;
* what commands were run;
* the actual results;
* any remaining limitations.

## Scope

Please avoid unrelated feature expansion in security-hardening changes.

Aether intentionally maintains a narrow security boundary around:

```text
Identity
→ Intent
→ Authority
→ Action
→ Enforcement
→ Evidence
```

Large architectural changes should be discussed before implementation.

## Development Identity

The mock identity provider is for local development and testing only.

Do not represent mock-identity results as production identity validation.

## External Validation

Independent validation must be performed independently of the project creator.

Contributions made by AI tools or AI-assisted workflows are not independent external validation.

## Code of Conduct

Contributors are expected to communicate professionally and to report security concerns responsibly.

## License

The project's applicable license will be defined in the repository's `LICENSE` file.
