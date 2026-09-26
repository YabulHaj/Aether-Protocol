# Evidence Record: AET-EV-2026-0011

**Evidence ID:** AET-EV-2026-0011
**Date:** 2026-09-22
**Day:** 11
**Run IDs:** reproduction_20260922_225514, reproduction_20260922_225859, reproduction_20260923_011320
**Git commit:** ab3324f358ffbf2ee90d9600a93d846947a06808
**Git branch:** master
**Reproduction mode:** Creator-controlled clean reproduction

**Commands actually executed:**
- go test -count=1 ./...
- powershell -ExecutionPolicy Bypass -File .\scripts\reproduce.ps1

**Expected result:** Complete test suite passes, benchmark executes successfully without environment-specific absolute paths.

**Observed result:** PASS (all three recorded creator-controlled reproduction runs)

**Core test result:** PASS

**Benchmark result:** PASS

**Artifact locations:**
- evidence/reproduction_20260922_225514/
- evidence/reproduction_20260922_225859/
- evidence/reproduction_20260923_011320/

**Independent verification status:** NOT VERIFIED.

**Classification:** Creator-controlled clean reproduction

**Caveats:** Local loopback only. Does not prove network latency, production infrastructure resilience, or remote SPIFFE/OIDC identity provider behavior. No external validation has been performed.

**Claim(s) supported:**
- The repository can successfully build and run its core security tests and Attack Lab corpus locally from a fresh directory without relying on the creator's machine-specific absolute paths.
