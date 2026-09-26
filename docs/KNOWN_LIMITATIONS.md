# Aether — Known Limitations & Verification Status (v0.1)

This document explicitly defines the boundaries of what Aether v0.1 does and does not protect against, separating verified capabilities from experimental, unimplemented, and out-of-scope areas. Bounded automated test passes demonstrate conformance to specific invariants under tested conditions; they do not constitute mathematical "proof of absolute security."

---

## 1. Classification Taxonomy

To ensure complete transparency, system properties are classified into five explicit categories:

1. **PROVEN** — Formally verified or cryptographically bounded under standard mathematical primitives.
2. **TESTED** — Conforming to automated unit, integration, and attack lab test scenarios under reproducible conditions.
3. **EXPERIMENTAL** — Implemented in prototype form but lacking long-duration or production hardening.
4. **UNIMPLEMENTED** — Planned or referenced in future architecture blueprints but not present in v0.1 code.
5. **OUT OF SCOPE** — Explicitly outside the problem domain of Aether v0.1.

---

## 2. Classification Matrix

### PROVEN
* **Tamper-Evident Evidence Log Hashing**: SHA-256 canonical NDJSON evidence record hashing via constant-time comparison (`subtle.ConstantTimeCompare`) detects field mutation.
* **Payload Hash Fingerprint Verification**: Cryptographic SHA-256 verification of optional raw payload content against declared `payload_hash` using constant-time verification.

### TESTED
* **Default-Deny Policy Evaluation**: Rule evaluation fails closed. Any request not matching all four rule fields (`identity_ref`, `capability`, `target_resource`, `operation`) is denied.
* **Single-Use Nonce Anti-Replay**: In-memory registry atomically consumes nonces (`CheckAndConsumeNonce`), rejecting duplicate submissions of identical nonces with `REPLAY_DETECTED` and 0 backend hits.
* **Audience Boundary Enforcement**: The gateway validates that incoming action envelopes target `aether-gateway`, rejecting mismatched audience envelopes with 400 Bad Request.
* **Identity-Bearer Header Binding**: The authenticated caller identity derived from the bearer credential is confirmed against `identity_ref` in the envelope; mismatches are rejected with 401 Unauthorized.
* **Revocation Kill-Switch**: In-memory revocation of identities and nonces is enforced prior to policy evaluation, blocking revoked requests with 403 Forbidden.
* **Telemetry Non-Blocking Isolation**: Telemetry broadcast utilizes bounded non-blocking channel dispatch; slow or saturated consumers drop telemetry events without blocking authorization decisions.
* **Windows Toolchain Environment**: Tests pass under native Windows toolchains (`go test -count=1 ./...` and `go vet ./...`). Race detector (`-race`) execution on Windows requires CGO (`CGO_ENABLED=1`) and an external C compiler (`gcc`); when gcc is absent from `%PATH%`, race detection is unavailable in the local environment.

### EXPERIMENTAL
* **In-Memory Nonce Eviction**: The current replay cache stores consumed nonces in process memory. In a long-running gateway without periodic GC, memory usage grows proportionally with the volume of unique nonces received during the process lifetime.
* **Mock Identity Provider**: `MockIdentityProvider` uses a static in-memory lookup table strictly for local testing. It is insecure for production and requires explicit configuration (`AETHER_IDENTITY_MODE=mock`).
* **SPIFFE Workload API Integration**: `SpiffeIdentityProvider` implements JWT-SVID validation against SPIFFE Workload API endpoints; mTLS certificate verification is extracted but requires an upstream TLS terminating proxy.

### UNIMPLEMENTED
* **Persistent Distributed Storage**: Neither revocation lists nor replay caches persist across gateway restarts or synchronize across multiple gateway instances.
* **Direct TLS Termination**: Aether v0.1 operates as an HTTP reverse proxy gateway and expects TLS termination to be managed by an infrastructure edge (e.g. Envoy or ingress controller).
* **Multi-Tenant Policy Management**: Policy rules are statically loaded at process start (`v0.1.0`) and do not support dynamic runtime modification via API.

### OUT OF SCOPE
* **General AI Alignment**: Aether does not evaluate whether an agent's intent is morally desirable or aligned with human values.
* **Prompt Injection Detection**: Aether operates at the tool execution boundary. It does not inspect LLM context windows or detect prompt injection attacks.
* **Zero-Day Infrastructure Vulnerabilities**: Vulnerabilities in the Go runtime, operating system kernel, network stack, or hardware are outside Aether's enforcement boundary.

---

## 3. Maintenance

This document must be updated whenever security invariants, operational assumptions, or test coverage boundaries change. Any claim of security outside this matrix is invalid.
