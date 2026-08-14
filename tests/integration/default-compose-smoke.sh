#!/usr/bin/env bash
set -euo pipefail

export COMPOSE_PROJECT_NAME="memory-router-default-smoke"
export MEMORY_ROUTER_PORT="${MEMORY_ROUTER_SMOKE_PORT:-18890}"
compose=(docker compose -f compose.yaml)

key_dir="$(mktemp -d)"
cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$key_dir"
}
trap cleanup EXIT

umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "$key_dir/quarantine-private.pem" >/dev/null 2>&1
openssl pkey -in "$key_dir/quarantine-private.pem" -pubout -out "$key_dir/quarantine-public.pem" >/dev/null 2>&1
export QUARANTINE_PUBLIC_KEY="$(base64 < "$key_dir/quarantine-public.pem" | tr -d '\n')"
export QUARANTINE_PRIVATE_KEY="ci-private-key-must-not-pass-through"

wait_for_liveness() {
  for _ in {1..30}; do
    if curl --fail --silent --show-error "http://127.0.0.1:${MEMORY_ROUTER_PORT}/health/live" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  "${compose[@]}" ps
  return 1
}

assert_not_ready_without_hindsight() {
  local status
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${MEMORY_ROUTER_PORT}/health")"
  test "$status" = "503"
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' "http://127.0.0.1:${MEMORY_ROUTER_PORT}/health/ready")"
  test "$status" = "503"
}

resolved_compose="$("${compose[@]}" config)"
if grep -q 'QUARANTINE_PRIVATE_KEY' <<<"$resolved_compose"; then
  echo "resolved compose config contains quarantine private-key environment" >&2
  exit 1
fi

docker tag hindsight-memory-router:ci memory-router:local
"${compose[@]}" up -d --no-build
wait_for_liveness
assert_not_ready_without_hindsight

router_id="$("${compose[@]}" ps -q memory-router)"
test -n "$router_id"
healthcheck_test="$(docker inspect -f '{{json .Config.Healthcheck.Test}}' "$router_id")"
grep -Fq '"python"' <<<"$healthcheck_test"
grep -Fq 'urllib.request' <<<"$healthcheck_test"
grep -Fq 'MEMORY_ROUTER_PORT' <<<"$healthcheck_test"
grep -Fq '/health/ready' <<<"$healthcheck_test"
if grep -Eq 'node|curl|wget' <<<"$healthcheck_test"; then
  echo "runtime healthcheck depends on an unsupported executable" >&2
  exit 1
fi
test "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Name}}{{end}}{{end}}' "$router_id")" = "${COMPOSE_PROJECT_NAME}_memory-router-data"
test -z "$(docker inspect -f '{{range .Mounts}}{{if or (eq .Destination "/app/bootstrap/private") (eq .Destination "/app/bootstrap/public")}}{{.Destination}}{{end}}{{end}}' "$router_id")"

"${compose[@]}" exec -T memory-router sh -ec '
  test "$(id -u)" -ne 0
  test "$MEMORY_ROUTER_PORT" = "'"${MEMORY_ROUTER_PORT}"'"
  test -n "$QUARANTINE_PUBLIC_KEY"
  test -w /app/data
  test -f /app/data/quarantine.db
  printf "%s\n" persistent > /app/data/.persistence-probe
'

"${compose[@]}" rm -sf memory-router
"${compose[@]}" up -d --no-build memory-router
wait_for_liveness
assert_not_ready_without_hindsight
"${compose[@]}" exec -T memory-router sh -ec '
  test "$(cat /app/data/.persistence-probe)" = persistent
'
