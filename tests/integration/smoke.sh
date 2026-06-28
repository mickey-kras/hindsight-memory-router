#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
if [[ "$mode" != "fake" && "$mode" != "real" ]]; then
  echo "usage: $0 fake|real" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"

compose_file="tests/integration/docker-compose.yml"
if [[ "$mode" == "real" ]]; then
  compose_file="tests/integration/docker-compose.real.yml"
fi

project="hmr-${mode}-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
tmp_dir="tests/integration/tmp/${mode}"
review_file="${tmp_dir}/review/review.jsonl"
quarantine_dir="${tmp_dir}/quarantine"
state_file="${tmp_dir}/state/hindsight.jsonl"
router_url="http://127.0.0.1:8890"
router_token="test-router-token"
admin_token="test-admin-token"
raw_marker="RAW_${mode}_$(date +%s)_$RANDOM"
checks_total=0
checks_passed=0
current_check="startup"

begin_check() {
  current_check="$1"
  checks_total=$((checks_total + 1))
  printf 'check %02d - %s ... ' "$checks_total" "$current_check"
}

pass_check() {
  checks_passed=$((checks_passed + 1))
  echo "ok"
  current_check=""
}

run_check() {
  local name="$1"
  shift
  begin_check "$name"
  "$@"
  pass_check
}

fail_check() {
  local message="$1"
  echo "failed" >&2
  echo "${mode} integration smoke failed at check ${checks_total}: ${current_check}" >&2
  echo "$message" >&2
  exit 1
}

rm -rf "$tmp_dir"
mkdir -p "${tmp_dir}/review" "${quarantine_dir}/objects" "${tmp_dir}/state"
chmod -R ugo+rwX "$tmp_dir"

cleanup() {
  docker compose -p "$project" -f "$compose_file" down -v --remove-orphans >/dev/null 2>&1 || true
}

dump_debug() {
  local exit_code="$?"
  echo ""
  echo "${mode} integration smoke failed after ${checks_passed}/${checks_total} checks" >&2
  if [[ -n "$current_check" ]]; then
    echo "current check: ${current_check}" >&2
  fi
  echo "docker compose state follows" >&2
  docker compose -p "$project" -f "$compose_file" ps >&2 || true
  docker compose -p "$project" -f "$compose_file" logs --no-color --tail=250 >&2 || true
  exit "$exit_code"
}

trap dump_debug ERR
trap cleanup EXIT

run_check "generate disposable quarantine keypair" bash -c "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out '${tmp_dir}/private.pem' >/dev/null 2>&1 && openssl rsa -pubout -in '${tmp_dir}/private.pem' -out '${tmp_dir}/public.pem' >/dev/null 2>&1"
export QUARANTINE_PUBLIC_KEY="$(base64 -w0 "${tmp_dir}/public.pem")"
export QUARANTINE_PRIVATE_KEY="$(base64 -w0 "${tmp_dir}/private.pem")"

run_check "remove stale compose stack" cleanup
run_check "build memory-router image" docker build -t hindsight-memory-router:ci .
run_check "start compose stack" docker compose -p "$project" -f "$compose_file" up -d

begin_check "router health is reachable"
for _ in {1..60}; do
  if curl -fsS "${router_url}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS "${router_url}/health" >/dev/null
pass_check

begin_check "internal Hindsight health is reachable from router network"
for _ in {1..60}; do
  if docker compose -p "$project" -f "$compose_file" exec -T memory-router node -e "fetch('http://hindsight:8888/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
docker compose -p "$project" -f "$compose_file" exec -T memory-router node -e "fetch('http://hindsight:8888/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" >/dev/null
pass_check

begin_check "unauthenticated /version is denied"
status="$(curl -sS -o /dev/null -w '%{http_code}' "${router_url}/version")"
if [[ "$status" != "401" ]]; then
  fail_check "expected unauthorized /version to return 401, got ${status}"
fi
pass_check

begin_check "authenticated /version reports encrypted quarantine"
version="$(curl -fsS -H "Authorization: Bearer ${router_token}" "${router_url}/version")"
printf '%s' "$version" | grep -q 'encrypted_quarantine' || fail_check "router version missing encrypted_quarantine"
pass_check

begin_check "host port 8888 is not exposed"
if curl --max-time 2 -fsS "http://127.0.0.1:8888/health" >/dev/null 2>&1; then
  fail_check "internal Hindsight service is exposed on host port 8888"
fi
pass_check

post_router() {
  local path="$1"
  local body="$2"
  curl -fsS \
    -H "Authorization: Bearer ${router_token}" \
    -H "Content-Type: application/json" \
    -X POST \
    "${router_url}${path}" \
    -d "$body"
}

admin_get() {
  local path="$1"
  curl -fsS -H "Authorization: Bearer ${admin_token}" "${router_url}${path}"
}

admin_post() {
  local path="$1"
  local body="${2:-{}}"
  curl -fsS \
    -H "Authorization: Bearer ${admin_token}" \
    -H "Content-Type: application/json" \
    -X POST \
    "${router_url}${path}" \
    -d "$body"
}

retry_post_router() {
  local path="$1"
  local body="$2"
  local output=""
  for _ in {1..60}; do
    if output="$(post_router "$path" "$body" 2>/dev/null)"; then
      printf '%s' "$output"
      return 0
    fi
    sleep 2
  done
  post_router "$path" "$body"
}

begin_check "known writer retain succeeds"
known_response="$(retry_post_router "/v1/default/banks/main/memories" '{"items":[{"content":"CI smoke known retain","context":"integration smoke","document_id":"ci-known"}],"async":true}')"
printf '%s' "$known_response" | grep -q 'success' || fail_check "known retain failed: ${known_response}"
pass_check

begin_check "unknown writer is quarantined"
unknown_response="$(retry_post_router "/v1/default/banks/unknown-smoke/memories" "{\"items\":[{\"content\":\"${raw_marker}\",\"context\":\"integration quarantine smoke\",\"document_id\":\"ci-unknown\"}],\"async\":true}")"
printf '%s' "$unknown_response" | grep -q 'quarantine_id' || fail_check "unknown writer did not return quarantine_id: ${unknown_response}"
quarantine_id="$(printf '%s' "$unknown_response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["quarantine_id"])')"
pass_check

begin_check "review queue is written"
[[ -s "$review_file" ]] || fail_check "review queue was not written"
pass_check

begin_check "encrypted quarantine object is written"
object_count="$(find "${quarantine_dir}/objects" -type f -name '*.enc.json' | wc -l | tr -d ' ')"
if [[ "$object_count" -lt 1 ]]; then
  fail_check "encrypted quarantine object was not written"
fi
pass_check

begin_check "raw marker does not leak to queue or object plaintext"
if grep -R "$raw_marker" "${tmp_dir}/review" "${tmp_dir}/quarantine" >/dev/null 2>&1; then
  fail_check "raw quarantine payload leaked to review queue or object plaintext"
fi
pass_check

begin_check "router token cannot access admin queue"
admin_status="$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer ${router_token}" "${router_url}/admin/quarantine/queue")"
if [[ "$admin_status" != "401" ]]; then
  fail_check "expected router token admin queue access to return 401, got ${admin_status}"
fi
pass_check

begin_check "admin queue lists quarantine ref without raw payload"
queue_response="$(admin_get "/admin/quarantine/queue")"
printf '%s' "$queue_response" | grep -q "$quarantine_id" || fail_check "admin queue missing quarantine_id"
if printf '%s' "$queue_response" | grep -q "$raw_marker"; then
  fail_check "admin queue leaked raw payload"
fi
pass_check

begin_check "admin read decrypts quarantine payload"
read_response="$(admin_get "/admin/quarantine/items/${quarantine_id}")"
printf '%s' "$read_response" | grep -q "$raw_marker" || fail_check "admin read did not decrypt raw payload"
pass_check

begin_check "admin reject removes quarantine from pending queue"
reject_response="$(admin_post "/admin/quarantine/items/${quarantine_id}/reject")"
printf '%s' "$reject_response" | grep -q 'rejected' || fail_check "admin reject failed"
queue_after_reject="$(admin_get "/admin/quarantine/queue")"
if printf '%s' "$queue_after_reject" | grep -q "$quarantine_id"; then
  fail_check "rejected quarantine remained pending"
fi
pass_check

if [[ "$mode" == "fake" ]]; then
  begin_check "fake recall fanout excludes restricted banks"
  post_router "/v1/default/banks/main/memories/recall" '{"query":"CI smoke recall","max_tokens":512,"budget":"low","trace":false}' >/dev/null

  python3 - "$state_file" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
retains = [event for event in events if event.get("kind") == "retain"]
recalls = [event for event in events if event.get("kind") == "recall"]

banks_retained = [event["bank_id"] for event in retains]
banks_recalled = [event["bank_id"] for event in recalls]

assert "main" in banks_retained, banks_retained
assert "quarantine" in banks_retained, banks_retained
assert "research" not in banks_recalled, banks_recalled
assert "quarantine" not in banks_recalled, banks_recalled
assert {"main", "core", "ops", "dev", "creative", "personal"}.issubset(set(banks_recalled)), banks_recalled
PY
  pass_check
fi

echo "${mode} integration smoke passed ${checks_passed}/${checks_total} checks"
