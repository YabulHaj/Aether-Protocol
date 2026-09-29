# Aether Day 14 — Launch Candidate Verification

**Date:** September 27, 2026
**Milestone:** Day 14 — Launch Candidate Verification
**Launch-candidate baseline commit:** `22b0f9f`
**Branch:** `main`
**Go version:** `go1.27.1 windows/amd64`
**Evidence classification:** Creator-controlled launch-candidate verification

---

## 1. Purpose

Day 14 packages the completed Aether engineering work into a documented launch candidate.

The objective is to verify the repository, preserve actual observed results, verify release documentation, reproduce the documented workflow from a clean clone, and establish the evidence boundary for the planned public release.

This document records actual commands and observed outcomes.

It does not constitute independent security validation, independent review, production certification, or organizational adoption.

---

## 2. Day 11–13 Status

### Day 11

**Reproduction Packaging — COMPLETE**

Evidence:

`AET-EV-2026-0011`

### Day 12

**Research Package — COMPLETE**

Evidence:

`AET-EV-2026-0012`

### Day 13

**Security Hardening — COMPLETE**

Evidence:

`AET-EV-2026-0013`

Day 13 resolved the documented `405` / `413` evidence-coverage discrepancy within the defined Aether authorization boundary and added concurrent same-nonce replay testing.

---

## 3. Repository Verification

### Full test suite

Command:

```powershell
go test -count=1 ./...
```

Observed result:

**PASS**

Observed command-package duration during the September 27, 2026 verification run:

`81.883s`

All tested repository packages passed.

---

### Full race-detector suite

Commands:

```powershell
$env:CGO_ENABLED="1"
$env:Path="C:\msys64\ucrt64\bin;$env:Path"
go test -race ./...
```

Observed result:

**PASS**

Observed command-package duration during the September 27, 2026 clean-clone verification run:

`124.845s`

No data race was reported.

The race detector was executed successfully only after enabling CGO and making the installed MSYS2 UCRT64 GCC toolchain available on the process PATH.

---

### Attack Lab

Command:

```powershell
go test -count=1 -v ./cmd -run TestDay10Benchmark
```

Observed result:

**PASS**

Observed duration during the September 27, 2026 clean-clone verification run:

`77.524s`

The benchmark configuration recorded:

* 50 scenarios
* 100 measured iterations per scenario
* 5 warmup iterations per scenario

The benchmark report classifies the measurements as local loopback observations and does not present them as production-scale or remote-network performance evidence.

---

### Static analysis

Command:

```powershell
go vet ./...
```

Observed result:

**PASS**

No vet findings were reported.

---

### Build

Command:

```powershell
go build ./...
```

Observed result:

**PASS**

No build errors were reported.

---

### Go formatting

The release candidate initially contained Go files requiring formatting.

Those files were formatted with `gofmt`.

Final verification:

```powershell
gofmt -l .\cmd .\internal .\tools
```

Observed result:

**PASS**

No files were reported as requiring formatting.

---

## 4. Clean-Clone Reproduction

A fresh local clone of the launch candidate was created separately from the primary development directory:

```text
C:\Aether-Clean-Test
```

The clean clone was verified as a pristine working tree and confirmed to contain the launch-candidate baseline commit:

```text
22b0f9f Finalize reproducible quickstart and live UI state
```

The following commands were successfully executed from the clean clone:

```powershell
go test ./...
go test -race ./...
go vet ./...
go build ./...
go test -count=1 -v ./cmd -run TestDay10Benchmark
```

Observed result:

**PASS**

This establishes **creator-controlled clean-clone reproduction**.

It does **not** establish independent external reproduction because the clean clone and verification were performed by the project author.

---

## 5. Clean-Clone Live Quickstart Verification

The documented live workflow was reproduced from the clean clone.

### Protected backend

Command:

```powershell
go run ./tools/dummy-backend
```

Observed:

```text
Dummy backend listening on localhost:9090
```

### Aether gateway

Command:

```powershell
$env:AETHER_IDENTITY_MODE="mock"
go run ./cmd
```

Observed:

```text
Aether gateway listening on localhost:8080
```

The expected security warning for the mock identity provider was also observed.

### Live River

The browser UI successfully displayed:

```text
LIVE
REAL SSE
```

The connection state was also independently tested earlier against the same UI implementation:

```text
LIVE
→ gateway stopped
→ DISCONNECTED
→ gateway restarted
→ LIVE
```

---

## 6. Clean-Clone Authorized Action Verification

A valid authorization request was sent through the clean-clone gateway.

Configured demonstration policy:

```text
Identity:   agent://finance-bot-01
Intent:     summarize
Capability: read:invoices
Target:     invoice/12345
Operation:  GET
Audience:   aether-gateway
Rule:       R-001
```

Observed HTTP result:

```text
HTTP 200
{"status":"success","message":"Protected data accessed"}
```

The Live River displayed:

```text
ALLOWED
```

The Aether gateway generated structured evidence showing:

```text
allowed: true
rule_id: R-001
identity_ref: agent://finance-bot-01
target_resource: invoice/12345
reason_code: allow_matched_rule
policy_version: v0.1.0
```

The protected backend also recorded the request:

```text
[BACKEND] Securely received request: /v1/action
```

This demonstrates that the authorized request was permitted and reached the protected target in the tested local configuration.

---

## 7. Clean-Clone Denied Action Verification

A fresh denied request was then sent against a target not covered by the configured rule:

```text
Target: invoice/99999
```

Observed HTTP result:

```text
HTTP 403
```

The Live River displayed the denied/block state.

Structured Aether evidence recorded:

```text
allowed: false
reason_code: deny_no_matching_rule
policy_version: v0.1.0
```

After resetting the dummy backend, the backend console remained at:

```text
Dummy backend listening on localhost:9090
```

and produced **no new `[BACKEND]` request line** for the denied action.

This demonstrates, within the tested local implementation, that the denied request was blocked before reaching the protected backend.

---

## 8. Release Documentation Verification

The following release and project files were present and reviewed:

* `LICENSE`
* `SECURITY.md`
* `CONTRIBUTING.md`
* `THIRD-PARTY-NOTICES.md`
* `TRADEMARKS.md`
* `docs/CLEAN_REPRODUCTION.md`
* `docs/RESEARCH_PACKAGE.md`
* `docs/SECURITY_HARDENING.md`
* `docs/RELEASE_CANDIDATE.md`
* `evidence/AET-EV-2026-0013_Security_Hardening.md`

The README Quickstart was updated to document:

* repository setup;
* full test and build verification;
* protected dummy backend startup;
* Aether gateway startup;
* Live River access;
* authorized action reproduction;
* denied action reproduction;
* benchmark execution;
* evidence interpretation;
* security limitations.

---

## 9. Licensing and Intellectual-Property Preparation

Aether's repository contains the Apache License 2.0.

The repository does not contain a `vendor` directory or copied third-party dependency source tree.

The current Go dependency graph was previously inspected.

The `go-licenses report ./...` audit identified dependency licenses including:

* Apache-2.0
* MIT
* ISC
* BSD-3-Clause

The Aether module itself was reported with an unresolved source URL by the audit tool because `aether-protocol` is a local module name.

The repository separately contains the official Apache License 2.0 text in `LICENSE`.

The repository also contains:

* `THIRD-PARTY-NOTICES.md`
* `TRADEMARKS.md`

These documents separate Aether's software licensing from third-party licenses and project branding.

---

## 10. Security Boundary

The release candidate continues to use the server-side authorization path as the security authority.

The browser and Live River remain observational.

The release candidate does not claim:

* universal security;
* production readiness;
* independent security review;
* independent external reproduction;
* organizational adoption;
* distributed replay or revocation guarantees;
* production-scale performance;
* live production SPIFFE/SPIRE validation;
* prevention of all prompt-injection or agentic attack classes.

Aether's scope remains the authorization and enforcement boundary surrounding autonomous software actions.

---

## 11. Evidence Boundary

The current evidence remains **creator-controlled**.

The following are demonstrated by the current local implementation and executed tests:

* authorization and enforcement behavior;
* structured evidence generation within the defined authorization boundary;
* concurrent same-nonce replay protection in the tested process-local implementation;
* Attack Lab benchmark execution;
* race-detector validation;
* static analysis;
* reproducible local builds and tests;
* clean-clone reproduction performed by the project author;
* clean-clone authorized action reaching the protected backend;
* clean-clone denied action being blocked before reaching the protected backend.

These observations do **not** establish:

* independent external reproduction;
* independent security review;
* organizational evaluation;
* organizational deployment;
* broad real-world attack coverage;
* production-scale performance;
* absence of undiscovered vulnerabilities.

---

## 12. Release-Candidate Limitations

The current launch candidate remains bounded by:

* process-local revocation and replay state;
* mock identity in the local development path;
* absence of live end-to-end SPIFFE/SPIRE validation;
* absence of distributed multi-instance validation;
* absence of independent security review;
* absence of independent external clean-environment reproduction;
* absence of organizational evaluation;
* local benchmark scope;
* absence of a measured revocation time-to-enforce guarantee;
* limited attack-corpus scope relative to the full space of possible agent-security failures.

---

## 13. Launch-Candidate Status

The engineering and verification gates executed during the September 27, 2026 validation cycle passed.

The repository has therefore reached a **creator-controlled launch-candidate state**.

The launch candidate has been:

* tested;
* race-tested;
* statically analyzed;
* built;
* benchmarked;
* reproduced from a clean clone;
* exercised through the live authorization path;
* exercised through the live denial path.

The remaining distinction is important:

> A creator-controlled launch candidate is not the same as independently validated security software.

The planned public release should preserve that distinction.

This document does not represent:

* independent validation;
* independent security certification;
* production certification;
* organizational adoption;
* proof of universal security.

---

## 14. Governing Rule

> Build what can be proved.
> Publish what can be defended.
> Measure what can be reproduced.
> Visualize what actually happened.
> Never manufacture evidence.
