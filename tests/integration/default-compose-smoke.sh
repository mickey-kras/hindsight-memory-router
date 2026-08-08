#!/usr/bin/env bash
set -euo pipefail

compose=(docker compose -f compose.yaml)

cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_health() {
  for _ in {1..30}; do
    if curl --fail --silent --show-error http://127.0.0.1:8890/health >/dev/null; then
      return 0
    fi
    sleep 1
  done
  "${compose[@]}" ps
  return 1
}

docker tag hindsight-memory-router:ci memory-router:local
"${compose[@]}" up -d --no-build
wait_for_health

"${compose[@]}" exec -T memory-router sh -ec '
  test "$(id -u)" -ne 0
  test -w /app/data
  test -f /app/data/quarantine.db
  test -r /app/bootstrap/public/quarantine-public.pem
  test ! -e /app/bootstrap/private/quarantine-private.pem
  printf "%s\n" persistent > /app/data/.persistence-probe
'

"${compose[@]}" run --rm --no-deps --entrypoint sh quarantine-key-init -ec '
  test "$(stat -c %a /app/bootstrap/private/quarantine-private.pem)" = 600
'

"${compose[@]}" rm -sf memory-router
"${compose[@]}" up -d --no-build memory-router
wait_for_health
"${compose[@]}" exec -T memory-router sh -ec '
  test "$(cat /app/data/.persistence-probe)" = persistent
  test ! -e /app/bootstrap/private/quarantine-private.pem
'
