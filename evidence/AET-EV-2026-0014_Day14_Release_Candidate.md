# Aether Day 14 — Release Candidate Evidence

**Evidence ID:** `AET-EV-2026-0014`
**Date:** September 24, 2026
**Blueprint:** Aether Ultimate Project Blueprint v0.3
**Milestone:** Day 14 — Release Candidate and Evidence Freeze
**Classification:** Creator-controlled release-candidate verification
**Independent verification:** NOT VERIFIED

---

## 1. Purpose

This record captures the creator-controlled verification performed for the Aether v0.3 release candidate.

The objective was to verify the current repository state, execute the final engineering gates, confirm release documentation, and preserve the observed results.

This record does not constitute independent security review, independent reproduction, organizational evaluation, or production certification.

---

## 2. Starting State

* Branch: `master`
* Starting Git commit: `ab3324f`
* Go version: `go1.27.1 windows/amd64`

The release-candidate work remained uncommitted during the verification phase so that the final candidate contents could be reviewed before the freeze checkpoint.

---

## 3. Final Verification Results

### Full test suite

```powershell
go test -count=1 ./...
```

Result:

**PASS**

Observed command-package duration:

`70.337s`

---

### Full race-detector suite

```powershell
$env:CGO_ENABLED="1"
$env:Path="C:\msys64\ucrt64\bin;$env:Path"
go test -race -count=1 ./...
```

Result:

**PASS**

Observed command-package duration:

`93.900s`

No data race was reported.

---

### Attack Lab

```powershell
go test -count=1 ./cmd -run '^TestDay9AttackLab$'
```

Result:

**PASS**

Observed duration:

`0.722s`

---

### Benchmark

```powershell
go test -count=1 ./cmd -run '^TestDay10Benchmark$'
```

Result:

**PASS**

Observed duration:

`64.961s`

This remains a local benchmark observation and is not a production-performance claim.

---

### Static analysis

```powershell
go vet ./...
```

Result:

**PASS**

No findings were reported.

---

### Build

```powershell
go build ./...
```

Result:

**PASS**

---

### Formatting

Initial `gofmt -l` identified five files requiring formatting.

They were formatted and rechecked.

Final:

```powershell
gofmt -l .\cmd .\internal .\tools
```

Result:

**PASS**

No files were reported as requiring formatting.

The complete test and race suites were rerun after formatting and passed.

---

## 4. Release Documentation

The following files were verified as present:

* `LICENSE`
* `SECURITY.md`
* `CONTRIBUTING.md`
* `THIRD-PARTY-NOTICES.md`
* `TRADEMARKS.md`
* `docs/DAY11_REPRODUCTION.md`
* `docs/DAY12_RESEARCH_PACKAGE.md`
* `docs/DAY13_SECURITY_HARDENING.md`
* `docs/DAY14_RELEASE_CANDIDATE.md`
* `evidence/AET-EV-2026-0013_Day13_Security_Hardening.md`
* `evidence/AET-EV-2026-0014_Day14_Release_Candidate.md`

The README was updated to:

* reflect Day 13 as complete;
* keep Day 14 active until its final freeze;
* remove stale `405` / `413` discrepancy language;
* document the current evidence boundary;
* link the license, security policy, contributing guide, third-party notices, and trademark notice.

---

## 5. Licensing Preparation

The Aether repository now contains the Apache License 2.0.

A dependency audit was performed using the Go module graph and `go-licenses report ./...`.

The audited dependency licenses included:

* Apache-2.0;
* MIT;
* ISC;
* BSD-3-Clause.

The repository does not contain a `vendor` directory or copied third-party dependency source tree.

`THIRD-PARTY-NOTICES.md` records the dependency-license information identified during the release-preparation audit.

---

## 6. Security Boundary

The release candidate preserves the server-side authorization boundary as the authoritative security mechanism.

The Live Control Plane and browser remain observational.

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

## 7. Day 13 Carry-Forward

Day 13 completed:

* `405 METHOD_NOT_ALLOWED` evidence generation;
* `413 REQUEST_TOO_LARGE` evidence generation;
* concurrent same-nonce anti-replay testing;
* race-detector validation;
* documentation and evidence packaging.

The `404` case remains outside the defined Aether authorization evidence boundary because unmatched routes are rejected before entering authorization processing.

---

## 8. Known Limitations

The candidate remains bounded by:

* process-local replay and revocation state;
* mock identity in the local development path;
* no live end-to-end SPIFFE/SPIRE validation;
* no distributed multi-instance validation;
* no independent security review;
* no independent clean-environment reproduction;
* no organizational evaluation;
* no measured revocation time-to-enforce bound;
* local benchmark scope.

---

## 9. Evidence Classification

All results in this record are:

**CREATOR-CONTROLLED RELEASE-CANDIDATE VERIFICATION**

They demonstrate the behavior observed in the tested repository and environment.

They do not become independent evidence merely because the tests passed.

---

## 10. Release-Candidate Status

The final engineering and documentation gates executed during Day 14 passed.

The repository is therefore ready for the final freeze checkpoint as a creator-controlled Aether v0.3 release candidate.

This record does not claim that the software is universally secure, production-certified, or independently validated.

---

## 11. Governing Rule

> Build what can be proved. Publish what can be defended. Measure what can be reproduced. Visualize what actually happened. Never manufacture evidence.
