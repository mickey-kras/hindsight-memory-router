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
raw_marker="RAW_${mode}_$(date +%s)_$RANDOM"

rm -rf "$tmp_dir"
mkdir -p "${tmp_dir}/review" "${quarantine_dir}/objects" "${tmp_dir}/state"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${tmp_dir}/private.pem" >/dev/null 2>&1
openssl rsa -pubout -in "${tmp_dir}/private.pem" -out "${tmp_dir}/public.pem" >/dev/null 2>&1
export QUARANTINE_PUBLIC_KEY="$(base64 -w0 "${tmp_dir}/public.pem")"

cleanup() {
  docker compose -p "$project" -f "$compose_file" down -v --remove-orphans >/dev/null 2>&1 || true
}

dump_debug() {
  local exit_code="$?"
  echo ""
  echo "${mode} integration smoke failed; docker compose state follows" >&2
  docker compose -p "$project" -f "$compose_file" ps >&2 || true
  docker compose -p "$project" -f "$compose_file" logs --no-color --tail=250 >&2 || true
  exit "$exit_code"
}

trap dump_debug ERR
trap cleanup EXIT

cleanup
docker build -t hindsight-memory-router:ci .
docker compose -p "$project" -f "$compose_file" up -d

for _ in {1..60}; do
  if curl -fsS "${router_url}/health" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS "${router_url}/health" >/dev/null

for _ in {1..60}; do
  if docker compose -p "$project" -f "$compose_file" exec -T memory-router node -e "fetch('http://hindsight:8888/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
docker compose -p "$project" -f "$compose_file" exec -T memory-router node -e "fetch('http://hindsight:8888/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" >/dev/null

status="$(curl -sS -o /dev/null -w '%{http_code}' "${router_url}/version")"
if [[ "$status" != "401" ]]; then
  echo "expected unauthorized /version to return 401, got ${status}" >&2
  exit 1
fi

version="$(curl -fsS -H "Authorization: Bearer ${router_token}" "${router_url}/version")"
printf '%s' "$version" | grep -q 'encrypted_quarantine' || {
  echo "router version missing encrypted_quarantine" >&2
  exit 1
}

if curl --max-time 2 -fsS "http://127.0.0.1:8888/health" >/dev/null 2>&1; then
  echo "internal Hindsight service is exposed on host port 8888" >&2
  exit 1
fi

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

known_response="$(retry_post_router "/v1/default/banks/main/memories" '{"items":[{"content":"CI smoke known retain","context":"integration smoke","document_id":"ci-known"}],"async":true}')"
printf '%s' "$known_response" | grep -q 'success' || {
  echo "known retain failed: ${known_response}" >&2
  exit 1
}

unknown_response="$(retry_post_router "/v1/default/banks/unknown-smoke/memories" "{\"items\":[{\"content\":\"${raw_marker}\",\"context\":\"integration quarantine smoke\",\"document_id\":\"ci-unknown\"}],\"async\":true}")"
printf '%s' "$unknown_response" | grep -q 'quarantine_id' || {
  echo "unknown writer did not return quarantine_id: ${unknown_response}" >&2
  exit 1
}

if [[ ! -s "$review_file" ]]; then
  echo "review queue was not written" >&2
  exit 1
fi

object_count="$(find "${quarantine_dir}/objects" -type f -name '*.enc.json' | wc -l | tr -d ' ')"
if [[ "$object_count" -lt 1 ]]; then
  echo "encrypted quarantine object was not written" >&2
  exit 1
fi

if grep -R "$raw_marker" "${tmp_dir}/review" "${tmp_dir}/quarantine" >/dev/null 2>&1; then
  echo "raw quarantine payload leaked to review queue or object plaintext" >&2
  exit 1
fi

if [[ "$mode" == "fake" ]]; then
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
fi

echo "${mode} integration smoke passed"
