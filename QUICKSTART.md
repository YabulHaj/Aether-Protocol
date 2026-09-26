# Aether Quickstart

## 1. Requirements

You need:

* Go
* Git
* Aether-Protocol

Aether is currently designed for local development and security research.

---

## 2. Download Aether

Open a terminal and run:

```bash
git clone https://github.com/YabulHaj/Aether-Protocol.git
cd Aether-Protocol
```

If you already have the repository on your computer, simply open the existing `Aether-Protocol` folder instead.

---

## 3. Build Aether

Run:

```bash
go build ./...
```

A successful build should finish without a build error.

---

## 4. Run the tests

Run:

```bash
go test ./...
```

The test suite should complete without test failures.

---

## 5. Start Aether in local development mode

Aether supports an explicit local mock identity mode for development and testing.

### Windows PowerShell

Run:

```powershell
$env:AETHER_IDENTITY_MODE="mock"
go run ./cmd
```

The gateway should start locally.

The mock identity provider is for development/testing only.

It is not a production identity configuration.

---

## 6. What Aether does

Aether evaluates an agent action before allowing it to reach the configured target.

The authorization flow is:

```text
IDENTITY
    ↓
INTENT
    ↓
AUTHORITY
    ↓
ACTION
    ↓
EVIDENCE
```

A request must satisfy the configured authorization requirements before it is forwarded.

---

## 7. Run the Attack Lab / Benchmark

From a second terminal opened in the Aether repository, run:

```powershell
go test -count=1 -v ./cmd -run TestDay10Benchmark
```

This executes the repository's benchmark test.

Benchmark results must always be interpreted together with their methodology and limitations.

---

## 8. Inspect the evidence

Review the generated evidence and benchmark artifacts in the repository's documented evidence locations.

The important security question is not only:

```text
Did Aether return DENY?
```

It is also:

```text
Did the unauthorized request reach the target?
```

For the defined enforcement tests, backend impact is part of the expected security behavior.

---

## 9. Important security limitation

Aether is a security research and authorization-control project.

It does not claim to:

* secure an AI model itself
* eliminate prompt injection
* eliminate every AI-agent vulnerability
* guarantee production security
* prove that all possible attacks have been prevented

The project evaluates defined authorization and enforcement properties.

---

## 10. Benchmark evidence

Creator-controlled benchmark artifacts currently report:

```text
50 / 50 tested scenarios
meeting their defined expected outcomes
```

This result is limited to the documented test corpus and test environment.

It is not independent security validation.

It does not establish universal attack coverage or the absence of undiscovered vulnerabilities.

Independent reproduction and external technical review are separate research objectives.

---

## 11. Research principle

Aether follows a simple rule:

```text
No action without authorization.
No authorization without context.
No security claim without evidence.
```

The goal is to make authorization behavior measurable, inspectable, and reproducible.
