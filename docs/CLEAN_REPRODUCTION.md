# Aether: Clean-Directory Reproduction Guide

## 1. Purpose

This guide explains how to reproduce Aether's local tests and benchmark workflow from a clean clone. Successful local execution is creator-controlled evidence unless an independent evaluator runs and verifies the procedure separately.

## 2. What this procedure checks

The reproduction script records execution context and runs the repository's test and benchmark commands.

A successful run provides evidence that:

- The documented Go test suite completed successfully in the tested environment.
- The Authorization Enforcement Benchmark completed successfully.
- The script recorded its execution context and command output.
- The Attack Lab tests executed their configured scenarios.

These results apply to the specific revision, environment, test corpus, and commands used.

## 3. What this procedure does NOT prove

A successful local run does not prove:

- Independent third-party validation.
- Absolute security or protection against every possible attack.
- Production-scale performance, availability, or resilience.
- Correct behavior under every possible concurrency pattern.
- Live end-to-end SPIFFE/SPIRE deployment behavior.
- That the X.509 mTLS identity path is reachable through the current HTTP server.
- That untested attack classes are blocked.

The current tests use local test infrastructure, including `httptest`. Their results must not be presented as production certification.

## 4. Prerequisites

- **Operating system:** Windows 10/11 for the provided PowerShell reproduction script.
- **Go:** Install a version compatible with the repository's `go.mod`.
- **Git:** Required to clone the repository.
- **PowerShell:** Required to run `scripts/reproduce.ps1`.

Check the installed tools with:

    go version
    git --version

## 5. Fresh clone procedure

Clone the public repository into a new directory:

    git clone https://github.com/YabulHaj/Aether-Protocol.git aether-repro
    Set-Location aether-repro

Run the reproduction procedure from the repository root.

## 6. Exact reproduction command

Run:

    .\scripts\reproduce.ps1

The script runs the full Go test suite with `TestAuthorizationEnforcementBenchmark` excluded, then runs the Authorization Enforcement Benchmark exactly once. Both commands and their output are recorded.

The exact commands are:

    go test -count=1 -skip '^TestAuthorizationEnforcementBenchmark$' ./...
    go test -count=1 -v ./cmd -run TestAuthorizationEnforcementBenchmark

If PowerShell blocks the script because of the execution policy, run this command from the repository root:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\reproduce.ps1

The execution-policy override applies to the launched PowerShell process; it does not permanently change the system-wide execution policy. Organizational policies may still restrict execution. Follow your organization's requirements rather than attempting to bypass them.

## 7. Expected output

A successful run prints:

    REPRODUCTION RESULT: PASS

A passing result means the commands managed by the script completed successfully. It does not imply independent validation or prove that all security properties hold.

If the result is FAIL, inspect the generated logs and the failing command before drawing conclusions.

## 8. Reproduction artifacts

The reproduction script writes its artifacts to:

    evidence/reproduction_<timestamp>/

The expected artifacts are:

- `reproduction_manifest.json` — execution context, configuration, and recorded results.
- `core_tests.log` — output from the core Go test suite.
- `benchmark_run.log` — output from the benchmark test.

Retain the logs associated with the exact source revision and environment being reported.

Before running the full reproduction workflow, back up any uncommitted benchmark reports or other generated files you need to preserve.

## 9. Attack Lab output locations

By default, the Attack Lab tests write generated corpus files to the private `Aether-Evidence` directory adjacent to the repository. Paths below are relative to the repository root:

    ../Aether-Evidence/attack-lab/core/
    ../Aether-Evidence/attack-lab/full/

The repository's `.gitignore` contains this rule for an `Aether-Evidence` directory inside the repository:

    /Aether-Evidence/

The default sibling-directory outputs are outside the Git working tree, so this repository's ignore rule does not apply to them.

The core corpus contains 20 scenarios. The extended corpus contains 50 scenario entries.

The output files include human-readable reports, structured JSON corpus files, and JSON Lines results. Re-running the tests replaces files with the same output names because the writers use `os.WriteFile`.

### Optional output override

To direct Attack Lab output to another dedicated test directory, set `AETHER_EVIDENCE_DIR` to an absolute path before running the tests.

Example:

    $env:AETHER_EVIDENCE_DIR = "C:\Aether-Test-Output"
    go test -count=1 ./cmd -run '^(TestAttackLabCore|TestAttackLabExtended)$'
    Remove-Item Env:AETHER_EVIDENCE_DIR

Choose a directory reserved for test output. Existing files with matching names may be replaced.

Do not point the override at a protected evidence archive during ordinary test runs.

## 10. Private evidence separation

By default, `Aether-Evidence` is a private sibling directory adjacent to the repository, not a repository-local folder. Relative to the repository root, its path is `../Aether-Evidence/`.

Ordinary Attack Lab tests use this sibling directory by default. Set `AETHER_EVIDENCE_DIR` to an absolute path to choose another output directory. If that path is inside the repository, verify its Git-ignore status before running tests. Do not copy private evidence into the public repository, and do not treat test-generated files as independent validation merely because the test suite produced them.

## 11. Security boundary

The Aether server remains responsible for authorization decisions and enforcement. The reproduction script does not independently validate the security design, turn a denied decision into an allowed decision, or establish that the browser is authoritative.

Evidence generated in the creator's environment remains creator-controlled evidence.

## 12. Independent evaluator procedure

An independent evaluator should:

1. Clone the public repository into a clean directory.
2. Record the commit or revision tested.
3. Check the installed Go version.
4. Follow the reproduction instructions.
5. Inspect the test and benchmark logs.
6. Report the observed results, failures, environment, and limitations.
7. Disclose any local changes made before or during execution.

Independent validation should be recorded only after a separate evaluator actually performs and reports the work.

## 13. Current known limitations

- Local tests do not establish production network behavior or organization-wide scale.
- Full end-to-end SPIFFE/SPIRE deployment validation requires the appropriate runtime infrastructure.
- The current server does not terminate TLS for the X.509 mTLS identity path.
- Successful execution covers the tested scenarios only.
- Results produced on the creator's machine are not independent validation.

## Generated benchmark output

By default, the benchmark test writes fresh reports to `../Aether-Evidence/benchmarks/authorization-enforcement/`, outside the repository. Set `AETHER_EVIDENCE_DIR` to an absolute path to choose another output directory. With the default configuration, the benchmark writer uses this separate destination and does not write to or regenerate the historical reference files under `evidence/10_benchmarks/`.
