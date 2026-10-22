# Aether Quickstart

This guide takes you from a clean checkout to a real local allow/deny demonstration. It uses three terminal windows so you can see whether a request reached the protected backend.

> **Local research demo only.** The `mock` identity mode uses hard-coded test tokens and is not a production identity configuration. Keep this demonstration on your own machine.

## 1. Requirements

- Git
- Go **1.27.1 or newer** (the version required by this repository's `go.mod`)
- Windows: PowerShell
- macOS/Linux: Bash, curl, and Python 3

## 2. Download the repository

Open a terminal and run:

```sh
git clone https://github.com/YabulHaj/Aether-Protocol.git
cd Aether-Protocol
```

If you already cloned the repository, open a terminal in that existing folder instead.

## 3. Run the local demonstration

Use three terminals. In each terminal, start from the repository root.

### Terminal 1 — Start the protected dummy backend

**Windows, macOS, and Linux:**

```sh
go run ./tools/dummy-backend
```

Leave this window open. The backend listens on `127.0.0.1:9090` and prints a `[BACKEND]` line each time a request reaches it.

### Terminal 2 — Start Aether

**Windows PowerShell:**

```powershell
$env:AETHER_IDENTITY_MODE = "mock"
go run ./cmd
```

**macOS/Linux (Bash):**

```bash
export AETHER_IDENTITY_MODE=mock
go run ./cmd
```

Leave this window open. Aether listens on `http://localhost:8080`. The mock identity provider is for local testing only.

You can open the read-only Live Control Plane at [http://localhost:8080/ui/](http://localhost:8080/ui/). Its display observes server decisions; it does not authorize requests.

### Terminal 3 — Send one allowed request and one denied request

The demonstration sends two requests:

- `invoice/12345` should be authorized.
- `invoice/99999` should be denied.

Each request uses a fresh timestamp and unique nonce. The HTTP request is a `POST` to Aether's `/v1/action` endpoint; the envelope's `operation` field describes the requested action as `GET`.

#### Windows PowerShell

Paste this complete block into Terminal 3:

```powershell
function Invoke-AetherDemoRequest {
    param([Parameter(Mandatory = $true)][string]$TargetResource)

    $now = [DateTime]::UtcNow
    $envelope = @{
        identity_ref    = "agent://finance-bot-01"
        intent          = "summarize"
        capability      = "read:invoices"
        target_resource = $TargetResource
        operation       = "GET"
        audience        = "aether-gateway"
        issued_at       = $now.AddMinutes(-1).ToString("o")
        expiry          = $now.AddMinutes(5).ToString("o")
        nonce_id        = [guid]::NewGuid().ToString()
        payload_hash    = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    } | ConvertTo-Json

    try {
        $response = Invoke-WebRequest -UseBasicParsing -Method Post `
            -Uri "http://localhost:8080/v1/action" `
            -Headers @{ Authorization = "Bearer mock-token-finance-bot" } `
            -ContentType "application/json" -Body $envelope

        Write-Host ("HTTP {0}" -f [int]$response.StatusCode)

        if ($response.Content) {
            Write-Host $response.Content
        }
    }
    catch {
        if ($_.Exception.Response) {
            $response = $_.Exception.Response
            Write-Host ("HTTP {0}" -f [int]$response.StatusCode)

            $stream = $response.GetResponseStream()

            if ($stream) {
                $reader = New-Object System.IO.StreamReader($stream)
                Write-Host $reader.ReadToEnd()
                $reader.Dispose()
            }
        }
        else {
            throw
        }
    }
}

Write-Host "`n--- Expected ALLOW: invoice/12345 ---" -ForegroundColor Green
Invoke-AetherDemoRequest -TargetResource "invoice/12345"

Write-Host "`n--- Expected DENY: invoice/99999 ---" -ForegroundColor Yellow
Invoke-AetherDemoRequest -TargetResource "invoice/99999"
```

#### macOS/Linux (Bash)

Paste this complete block into Terminal 3. Python creates the JSON safely, and curl applies connection and request timeouts. The function checks that each HTTP status matches its expected result, and the final result reports failure if either check fails.

```bash
aether_request() {
    local target_resource="$1"
    local expected_status="$2"
    local body response_file status curl_exit

    body="$(python3 - "$target_resource" <<'PY'
import datetime as dt
import json
import sys
import uuid

now = dt.datetime.now(dt.timezone.utc)

print(json.dumps({
    "identity_ref": "agent://finance-bot-01",
    "intent": "summarize",
    "capability": "read:invoices",
    "target_resource": sys.argv[1],
    "operation": "GET",
    "audience": "aether-gateway",
    "issued_at": (now - dt.timedelta(minutes=1)).isoformat(),
    "expiry": (now + dt.timedelta(minutes=5)).isoformat(),
    "nonce_id": str(uuid.uuid4()),
    "payload_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}))
PY
)" || return $?

    response_file="$(mktemp)" || return $?

    if status="$(curl --silent --show-error \
        --connect-timeout 5 \
        --max-time 10 \
        --output "$response_file" \
        --write-out '%{http_code}' \
        --request POST http://localhost:8080/v1/action \
        --header 'Authorization: Bearer mock-token-finance-bot' \
        --header 'Content-Type: application/json' \
        --data "$body")"; then

        printf 'Target: %s\n' "$target_resource"
        printf 'Expected HTTP %s; received HTTP %s\n' \
            "$expected_status" "$status"

        if [[ -s "$response_file" ]]; then
            cat "$response_file"
            printf '\n'
        fi

        rm -f "$response_file"

        if [[ "$status" != "$expected_status" ]]; then
            printf 'FAIL: Unexpected HTTP status.\n' >&2
            return 1
        fi

        printf 'PASS: HTTP status matched expectation.\n'
    else
        curl_exit=$?
        cat "$response_file" 2>/dev/null || true
        rm -f "$response_file"
        printf 'ERROR: curl failed with exit code %s.\n' "$curl_exit" >&2
        return "$curl_exit"
    fi
}

demo_failed=0

printf '\n--- Expected ALLOW: invoice/12345 ---\n'
if ! aether_request "invoice/12345" "200"; then
    demo_failed=1
fi

printf '\n--- Expected DENY: invoice/99999 ---\n'
if ! aether_request "invoice/99999" "403"; then
    demo_failed=1
fi

if [[ "$demo_failed" -ne 0 ]]; then
    printf 'FAIL: One or more demonstration checks failed.\n' >&2
    false
else
    printf 'PASS: Both authorization responses matched expectations.\n'
fi
```

### What you should observe

1. The allowed request should return **HTTP 200**, with a response from the dummy backend.
2. The denied request should return **HTTP 403**.
3. In Terminal 1, the fresh demonstration should show one `[BACKEND]` line for the allowed request. The denied request should **not** add a second line.

The Bash example checks HTTP status codes. For both platforms, inspect Terminal 1 to verify backend observations as well. An HTTP 403 alone does not prove that the unauthorized request was prevented from reaching the backend.

This is a creator-controlled local demonstration, not independent security validation.

### Stop the demo

Press `Ctrl+C` in Terminals 1 and 2.

## 4. Run the automated tests

From the repository root, run:

```sh
go test -count=1 -skip '^TestAuthorizationEnforcementBenchmark$' ./...
go vet ./...
go build ./...
```

These commands work in PowerShell and Bash.

The normal test suite includes the defined authorization scenarios but deliberately excludes `TestAuthorizationEnforcementBenchmark`, which is run separately below.

**Evidence-output warning:** By default, generated Attack Lab and benchmark artifacts are written to the private sibling directory `../Aether-Evidence/`, outside the repository. The repository's `.gitignore` does not govern this sibling directory. Generated files with matching names may be overwritten by later test runs.

If you need to preserve existing evidence, inspect the destination before running the tests and use a dedicated absolute `AETHER_EVIDENCE_DIR` path for generated output.

## 5. Run the authorization benchmark separately

From the repository root:

```sh
go test -count=1 -v ./cmd -run '^TestAuthorizationEnforcementBenchmark$'
```

This runs the benchmark test independently of the normal test suite.

Generated benchmark reports are written to `../Aether-Evidence/benchmarks/authorization-enforcement/` by default. The Attack Lab tests use `../Aether-Evidence/attack-lab/core/` and `../Aether-Evidence/attack-lab/full/`.

To choose a separate output location, set `AETHER_EVIDENCE_DIR` to an absolute path before executing the command. Make sure the directory does not contain evidence files you need to preserve.

## 6. Run the clean-reproduction script

**Windows PowerShell:**

```powershell
.\scripts\reproduce.ps1
```

The script writes a timestamped run manifest and logs under `evidence/reproduction_<timestamp>/`. These generated run folders are ignored by Git.

This reproduction script is a PowerShell script. The local allow/deny demonstration in Section 3 has separate instructions for Windows PowerShell and macOS/Linux Bash.

The benchmark and Attack Lab test artifacts are written by default to the private sibling directory `../Aether-Evidence/`, outside the repository and outside the scope of this repository's `.gitignore`.

## 7. Inspect results

- `../Aether-Evidence/attack-lab/core/` — core Attack Lab outputs
- `../Aether-Evidence/attack-lab/full/` — extended 50-scenario Attack Lab outputs
- `../Aether-Evidence/benchmarks/authorization-enforcement/` — locally generated benchmark reports
- `evidence/reproduction_<timestamp>/` — reproduction manifest and raw logs

The sibling `../Aether-Evidence/` directory is intended for generated artifacts. Set `AETHER_EVIDENCE_DIR` only when you deliberately want output written to another **absolute** path. If you point it at a directory that already contains matching filenames, those files may be overwritten.

Do not copy private generated evidence into the public repository or treat test-generated output as independent validation simply because the test suite produced it.

## 8. Scope and limitations

Aether evaluates defined authorization and enforcement behavior. The local mock identity provider is not a real identity system, and this demonstration does not establish production readiness, comprehensive attack coverage, or absence of undiscovered vulnerabilities.

Independent reproduction and external technical review remain separate objectives.

See the [clean reproduction guide](docs/CLEAN_REPRODUCTION.md), [threat model](docs/THREAT_MODEL.md), and [security policy](SECURITY.md) for more detail.
