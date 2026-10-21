#!/usr/bin/env bash
set -Eeuo pipefail

# End-to-end smoke test for Aether's documented local mock-identity demo.
# It verifies both HTTP decisions and whether the protected backend was reached.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

tmp_dir="$(mktemp -d)"
backend_log="$tmp_dir/backend.log"
aether_log="$tmp_dir/aether.log"
backend_pid=""
aether_pid=""

cleanup() {
  status=$?
  trap - EXIT

  if [[ -n "$aether_pid" ]]; then kill "$aether_pid" 2>/dev/null || true; fi
  if [[ -n "$backend_pid" ]]; then kill "$backend_pid" 2>/dev/null || true; fi
  if [[ -n "$aether_pid" ]]; then wait "$aether_pid" 2>/dev/null || true; fi
  if [[ -n "$backend_pid" ]]; then wait "$backend_pid" 2>/dev/null || true; fi

  printf '\n--- Aether log ---\n'
  cat "$aether_log" 2>/dev/null || true
  printf '\n--- Protected backend log ---\n'
  cat "$backend_log" 2>/dev/null || true
  rm -rf "$tmp_dir"
  exit "$status"
}
trap cleanup EXIT

printf '%s\n' 'Building Aether and the protected dummy backend...'
go build -o "$tmp_dir/dummy-backend" ./tools/dummy-backend
go build -o "$tmp_dir/aether" ./cmd

"$tmp_dir/dummy-backend" >"$backend_log" 2>&1 &
backend_pid=$!
AETHER_IDENTITY_MODE=mock "$tmp_dir/aether" >"$aether_log" 2>&1 &
aether_pid=$!

# Wait until the gateway answers its /health route over HTTP and the backend's
# TCP port accepts connections. The backend is only probed at the TCP level
# (open and close, no HTTP request) so the probe cannot inflate the backend-hit
# count. Every probe is time-bounded.
ready=0
for attempt in $(seq 1 30); do
  gateway_ready=0
  backend_ready=0

  if curl --silent --fail --connect-timeout 2 --max-time 3 \
      http://localhost:8080/health >/dev/null 2>&1; then
    gateway_ready=1
  fi
  if (exec 3<>/dev/tcp/127.0.0.1/9090) 2>/dev/null; then
    backend_ready=1
  fi

  if [[ "$gateway_ready" -eq 1 && "$backend_ready" -eq 1 ]]; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo 'ERROR: Aether or the dummy backend did not become ready within 30 seconds.'
  exit 1
fi

make_envelope() {
  python3 - "$1" <<'PY'
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
    "payload_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}))
PY
}

backend_hits() {
  grep -c '\[BACKEND\]' "$backend_log" || true
}

# Count hits BEFORE sending anything, so a startup banner that happens to
# contain "[BACKEND]" cannot make the test fail or pass by accident.
baseline_hits="$(backend_hits)"

assert_new_backend_hits() {
  expected_new="$1"
  total="$(backend_hits)"
  actual_new=$((total - baseline_hits))
  if [[ "$actual_new" -ne "$expected_new" ]]; then
    echo "ERROR: Expected $expected_new new backend hit(s), observed $actual_new."
    return 1
  fi
}

allow_body="$(make_envelope 'invoice/12345')"
allow_status="$(curl --silent --show-error --connect-timeout 5 --max-time 10 \
  --output "$tmp_dir/allow-response.json" \
  --write-out '%{http_code}' \
  --request POST http://localhost:8080/v1/action \
  --header 'Authorization: Bearer mock-token-finance-bot' \
  --header 'Content-Type: application/json' \
  --data "$allow_body")"

echo "Allowed invoice HTTP status: $allow_status"
if [[ "$allow_status" != '200' ]]; then
  cat "$tmp_dir/allow-response.json" 2>/dev/null || true
  echo 'ERROR: Expected HTTP 200 for invoice/12345.'
  exit 1
fi
sleep 1
assert_new_backend_hits 1

deny_body="$(make_envelope 'invoice/99999')"
deny_status="$(curl --silent --show-error --connect-timeout 5 --max-time 10 \
  --output "$tmp_dir/deny-response.json" \
  --write-out '%{http_code}' \
  --request POST http://localhost:8080/v1/action \
  --header 'Authorization: Bearer mock-token-finance-bot' \
  --header 'Content-Type: application/json' \
  --data "$deny_body")"

echo "Unauthorized invoice HTTP status: $deny_status"
if [[ "$deny_status" != '403' ]]; then
  cat "$tmp_dir/deny-response.json" 2>/dev/null || true
  echo 'ERROR: Expected HTTP 403 for invoice/99999.'
  exit 1
fi
# Give a wrongly-forwarded request time to show up in the backend log.
sleep 1
assert_new_backend_hits 1

echo 'PASS: invoice/12345 returned HTTP 200 and reached the backend once.'
echo 'PASS: invoice/99999 returned HTTP 403 and did not add a backend hit.'
