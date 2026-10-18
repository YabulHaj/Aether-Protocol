# Aether Quickstart

This guide takes you from a clean checkout to a real local allow/deny demonstration. It uses three terminal windows so you can see whether a request reached the protected backend.

> **Local research demo only.** The `mock` identity mode uses hard-coded test tokens and is not a production identity configuration. Keep this demonstration on your own machine.

## 1. Requirements

- Git
- Go **1.27.1 or newer** (the version required by this repository's `go.mod`)
- Windows PowerShell, or an equivalent terminal

## 2. Download the repository

Open a terminal and run:

```powershell
git clone https://github.com/YabulHaj/Aether-Protocol.git
cd Aether-Protocol
```

If you already cloned the repository, open a terminal in that existing folder instead.

## 3. Run the local demonstration

Use three terminals. In each terminal, start from the repository root.

### Terminal 1 — start the protected dummy backend

```powershell
go run ./tools/dummy-backend
```

Leave this window open. It listens on `127.0.0.1:9090` and prints a `[BACKEND]` line each time a request reaches it.

### Terminal 2 — start Aether

```powershell
$env:AETHER_IDENTITY_MODE = "mock"
go run ./cmd
```

Leave this window open. Aether listens on `http://localhost:8080`. The mock identity provider is for local testing only.

You can open the read-only Live Control Plane at [http://localhost:8080/ui/](http://localhost:8080/ui/). Its display observes server decisions; it does not authorize requests.

### Terminal 3 — send one allowed request and one denied request

Paste this complete block into the third terminal. It creates fresh timestamps and a unique nonce for each request, so re-running the demonstration does not accidentally replay the same nonce.

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
        if ($response.Content) { Write-Host $response.Content }
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

### What you should observe

1. The allowed request should return **HTTP 200** with a response from the dummy backend.
2. The denied request should return **HTTP 403**.
3. In Terminal 1, a fresh run should show one `[BACKEND]` line for the allowed request. The denied request should **not** add a second line.

The envelope's `operation` field describes the requested action. The HTTP `POST` is the call to Aether's `/v1/action` endpoint.

This is a creator-controlled local demonstration, not independent security validation. A `403` by itself is not enough; checking that the denied request did not reach the backend is part of the observation.

### Stop the demo

Press `Ctrl+C` in Terminals 1 and 2.

## 4. Run the automated tests

From the repository root, run:

```powershell
go test -count=1 -skip '^TestAuthorizationEnforcementBenchmark$' ./...
go vet ./...
go build ./...
```

The tests include the defined authorization scenarios and the benchmark harness. By default, generated Attack Lab and benchmark artifacts are written to the private sibling directory `../Aether-Evidence/`, outside the repository. The repository's `.gitignore` does not govern this sibling directory. The default output location is separate from the historical reference reports under `evidence/`, although generated files with matching names may be overwritten on subsequent runs.

## 5. Re-run the Attack Lab / benchmark by itself

```powershell
go test -count=1 -v ./cmd -run TestAuthorizationEnforcementBenchmark
```

Generated benchmark reports are written to `../Aether-Evidence/benchmarks/authorization-enforcement/`. The Attack Lab tests use `../Aether-Evidence/attack-lab/core/` and `../Aether-Evidence/attack-lab/full/`.

## 6. Run the clean-reproduction script

From the repository root in Windows PowerShell:

```powershell
.\scripts\reproduce.ps1
```

The script writes a timestamped run manifest and logs under `evidence/reproduction_<timestamp>/`. These generated run folders are ignored by Git. The benchmark and Attack Lab test artifacts are written by default to the private sibling directory `../Aether-Evidence/`, outside the repository and outside the scope of this repository's `.gitignore`.

## 7. Inspect results

- `../Aether-Evidence/attack-lab/core/` — core Attack Lab outputs
- `../Aether-Evidence/attack-lab/full/` — extended 50-scenario Attack Lab outputs
- `../Aether-Evidence/benchmarks/authorization-enforcement/` — locally generated benchmark reports
- `evidence/reproduction_<timestamp>/` — reproduction manifest and raw logs

The sibling `../Aether-Evidence/` directory is intended for generated artifacts. Set `AETHER_EVIDENCE_DIR` only when you deliberately want output written to another **absolute** path. If you point it at a directory that already contains matching filenames, those files may be overwritten.

## 8. Scope and limitations

Aether evaluates defined authorization and enforcement behavior. The local mock identity provider is not a real identity system, and this demo does not establish production readiness, comprehensive attack coverage, or absence of undiscovered vulnerabilities. Independent reproduction and external technical review remain separate objectives. See the [clean reproduction guide](docs/CLEAN_REPRODUCTION.md), [threat model](docs/THREAT_MODEL.md), and [security policy](SECURITY.md) for more detail.
