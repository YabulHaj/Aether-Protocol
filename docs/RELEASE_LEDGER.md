# Aether Public Release Ledger

This ledger records significant public Aether milestones, verification events, external findings, fixes, reproductions, and release-state changes.

The ledger records what actually happened.

It must not be used to imply independent validation, adoption, or security properties that have not been independently established.

---

## 2026-09-27 — Launch Candidate Prepared

**State:** Creator-controlled launch candidate

**Baseline commit:**

`22b0f9f`

**Branch:**

`main`

### Verification completed

```text
go test ./...        PASS
go test -race ./...  PASS
go vet ./...         PASS
go build ./...       PASS
```

### Clean-clone reproduction

A fresh clone was created and successfully reproduced:

* repository tests;
* race-detector tests;
* static analysis;
* build;
* benchmark execution;
* Live River startup;
* authorized action;
* denied action.

### Authorized-path observation

```text
HTTP 200
ALLOWED
Protected backend reached
```

### Denied-path observation

```text
HTTP 403
BLOCKED
Protected backend not reached
```

### Evidence classification

All observations above are **creator-controlled**.

They do not constitute:

* independent security review;
* independent external reproduction;
* organizational adoption;
* production certification;
* proof of universal security.

---

## 2026-09-28 — Planned Public Release

**Planned state:** Public Aether v0.1.0 release

This entry is a planned milestone and must only be marked complete after the repository is actually published and verified from an unauthenticated environment.

### Planned checks

* public repository accessible;
* README renders correctly;
* Quickstart works from a fresh clone;
* release artifact is accessible;
* Attack Lab is reproducible;
* security policy is visible;
* launch candidate commit is published.

---

## Future Entry Format

### YYYY-MM-DD — <Event>

**State:** <release / finding / reproduction / fix / review>

**Commit:**

`<commit>`

**Observed result:**

```text
<actual result>
```

**Evidence:**

* <artifact>
* <test>
* <issue>
* <reproduction>

**Classification:**

Creator-controlled / External reproduction / Independent review / Independent deployment

**Notes:**

<Brief factual description>

---

## Evidence Classification

### Creator-controlled

The Aether project author executed the test or reproduction.

### External reproduction

A person outside the project author independently reproduced the result.

### Independent review

An external technical evaluator reviewed a defined property or implementation.

### Independent deployment

An external organization deployed or evaluated Aether in a real test environment.

These classifications must not be conflated.

---

## Governing Rule

> Record what happened.
> Distinguish who verified it.
> Preserve the evidence.
> Never turn a plan into a result.
