#!/usr/bin/env sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "Usage: $0 ENDPOINT READ_TOKEN WRITE_TOKEN" >&2
  exit 1
fi

ENDPOINT=${1%/}
READ_TOKEN=$2
WRITE_TOKEN=$3
RULE_NAME=${SMOKE_RULE_NAME:-smoke-$(date +%s)}

cleanup() {
  curl -fsS \
    -X POST \
    -H "Authorization: Bearer $WRITE_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"ruleName\":\"$RULE_NAME\"}" \
    "$ENDPOINT/api/delete" >/dev/null 2>&1 || true
}

trap cleanup EXIT

printf '==> GET %s/healthz\n' "$ENDPOINT"
healthz=$(curl -fsS "$ENDPOINT/healthz")
[ "$healthz" = "ok" ]

printf '==> POST %s/webhook\n' "$ENDPOINT"
webhook_response=$(curl -fsS \
  -X POST \
  -H "Authorization: Bearer $WRITE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"ruleName\":\"$RULE_NAME\",\"host\":\"edge.example.com\",\"port\":443,\"method\":\"aes-256-gcm\",\"password\":\"secret\"}" \
  "$ENDPOINT/webhook")
printf '%s' "$webhook_response" | python3 - "$RULE_NAME" <<'PY'
import json
import sys

rule_name = sys.argv[1]
payload = json.loads(sys.stdin.read())
if payload.get("ruleName") != rule_name or payload.get("type") != "ss":
    raise SystemExit(f"unexpected webhook response: {payload!r}")
PY

printf '==> GET %s/subscription?subtype=ss\n' "$ENDPOINT"
ss_subscription=$(curl -fsS "$ENDPOINT/subscription?subtype=ss&api_key=$READ_TOKEN")
printf '%s' "$ss_subscription" | python3 - "$RULE_NAME" <<'PY'
import base64
import sys

rule_name = sys.argv[1]
body = sys.stdin.read().strip()
decoded = base64.b64decode(body).decode("utf-8")
if f"#{rule_name}" not in decoded:
    raise SystemExit(f"unexpected ss subscription: {decoded!r}")
PY

printf '==> GET %s/subscription?subtype=clash\n' "$ENDPOINT"
clash_subscription=$(curl -fsS "$ENDPOINT/subscription?subtype=clash&api_key=$READ_TOKEN")
printf '%s' "$clash_subscription" | python3 - "$RULE_NAME" <<'PY'
import sys

rule_name = sys.argv[1]
body = sys.stdin.read()
needle = f'  - name: "{rule_name}"'
if needle not in body:
    raise SystemExit(f"unexpected clash subscription: {body!r}")
PY

printf '==> GET %s/api/records\n' "$ENDPOINT"
records_response=$(curl -fsS -H "Authorization: Bearer $READ_TOKEN" "$ENDPOINT/api/records")
printf '%s' "$records_response" | python3 - "$RULE_NAME" <<'PY'
import json
import sys

rule_name = sys.argv[1]
payload = json.loads(sys.stdin.read())
names = {record["ruleName"] for record in payload.get("records", [])}
if rule_name not in names:
    raise SystemExit(f"unexpected records payload: {payload!r}")
PY

printf '==> GET %s/dashboard?api_key=READ_TOKEN\n' "$ENDPOINT"
dashboard_status=$(curl -sS -o /dev/null -w '%{http_code}' "$ENDPOINT/dashboard?api_key=$READ_TOKEN")
[ "$dashboard_status" = "302" ]

printf '==> POST %s/api/delete\n' "$ENDPOINT"
delete_status=$(curl -sS -o /dev/null -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer $WRITE_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"ruleName\":\"$RULE_NAME\"}" \
  "$ENDPOINT/api/delete")
[ "$delete_status" = "204" ]

trap - EXIT
printf 'Smoke test passed for %s\n' "$ENDPOINT"
