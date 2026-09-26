# Aether Day 14 — Release Candidate

**Date:** September 24, 2026
**Blueprint:** Aether Ultimate Project Blueprint v0.3
**Milestone:** Day 14 — Release Candidate and Evidence Freeze
**Starting Git commit:** `ab3324f`
**Branch:** `master`
**Go version:** `go1.27.1 windows/amd64`
**Evidence classification:** Creator-controlled release-candidate verification

---

## 1. Purpose

Day 14 packages the completed Aether engineering work into a documented release candidate.

The objective is to verify the current repository state, preserve the observed test results, verify release documentation, and prepare the project for evidence freeze.

This document records actual commands and observed outcomes.

It does not constitute independent security validation.

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

## 3. Final Repository Verification

### Full test suite

Command:

```powershell
go test -count=1 ./...
```

Observed result:

**PASS**

Command-package duration:

`70.337s`

All tested repository packages passed.

---

### Full race-detector suite

Commands:

```powershell
$env:CGO_ENABLED="1"
$env:Path="C:\msys64\ucrt64\bin;$env:Path"
go test -race -count=1 ./...
```

Observed result:

**PASS**

Command-package duration:

`93.900s`

No data race was reported.

---

### Attack Lab

Command:

```powershell
go test -count=1 ./cmd -run '^TestDay9AttackLab$'
```

Observed result:

**PASS**

Duration:

`0.722s`

This confirms the existing Day 9 attack-lab test remains green.

---

### Benchmark

Command:

```powershell
go test -count=1 ./cmd -run '^TestDay10Benchmark$'
```

Observed result:

**PASS**

Duration:

`64.961s`

This is a local benchmark observation and is not presented as production-scale performance evidence.

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

The release candidate initially contained five Go files requiring formatting.

Those files were formatted with `gofmt`.

Final verification:

```powershell
gofmt -l .\cmd .\internal .\tools
```

Observed result:

**PASS**

No files were reported as requiring formatting.

The full test suite and race-detector suite were rerun after formatting and both passed.

---

## 4. Release Documentation Verification

The following release and project files were present:

* `LICENSE`
* `SECURITY.md`
* `CONTRIBUTING.md`
* `THIRD-PARTY-NOTICES.md`
* `TRADEMARKS.md`
* `docs/DAY11_REPRODUCTION.md`
* `docs/DAY12_RESEARCH_PACKAGE.md`
* `docs/DAY13_SECURITY_HARDENING.md`
* `evidence/AET-EV-2026-0013_Day13_Security_Hardening.md`

The README was updated to reflect the completed Day 13 hardening work and the current Day 14 status.

A stale-claim search produced no matches for the previously unresolved `405` / `413` evidence-coverage language.

---

## 5. Licensing and Intellectual-Property Preparation

Aether's repository now contains the Apache License 2.0.

The repository does not contain a `vendor` directory or copied third-party dependency source tree.

The current Go dependency graph was inspected.

The `go-licenses report ./...` audit identified dependency licenses including:

* Apache-2.0;
* MIT;
* ISC;
* BSD-3-Clause.

The Aether module itself was reported with an unresolved source URL by the tool because `aether-protocol` is a local module name. The repository separately contains the official Apache License 2.0 text in `LICENSE`.

The repository also contains:

* `THIRD-PARTY-NOTICES.md`
* `TRADEMARKS.md`

These documents separate Aether's software licensing from third-party licenses and project branding.

---

## 6. Security Boundary

The release candidate continues to use the server-side authorization path as the security authority.

The browser and Live Control Plane remain observational.

The release candidate does not claim:

* universal security;
* production readiness;
* independent security review;
* independent reproduction;
* organizational adoption;
* distributed replay or revocation guarantees;
* production-scale performance;
* live production SPIFFE/SPIRE validation.

---

## 7. Evidence Boundary

The current evidence remains creator-controlled.

The following are demonstrated by the current local implementation and executed tests:

* authorization and enforcement behavior;
* structured evidence generation within the defined authorization boundary;
* concurrent same-nonce replay protection in the tested process-local implementation;
* the existing attack-lab result;
* benchmark execution;
* race-detector validation;
* reproducible local builds and tests.

These observations do not establish independent external validation.

---

## 8. Release-Candidate Limitations

The current release candidate remains bounded by:

* process-local revocation and replay state;
* mock identity in the local development path;
* absence of live end-to-end SPIFFE/SPIRE validation;
* absence of distributed multi-instance validation;
* absence of independent security review;
* absence of independent clean-environment reproduction;
* absence of organizational evaluation;
* local benchmark scope;
* absence of a measured revocation time-to-enforce guarantee.

---

## 9. Release-Candidate Status

The engineering and verification gates executed during Day 14 passed.

The repository is therefore ready to be treated as a **creator-controlled Aether v0.3 release candidate** pending final evidence indexing and repository freeze.

This document does not represent a public release, independent validation, or production certification.

---

## 10. Governing Rule

> Build what can be proved. Publish what can be defended. Measure what can be reproduced. Visualize what actually happened. Never manufacture evidence.
