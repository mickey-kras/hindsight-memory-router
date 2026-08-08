#!/usr/bin/env bash
set -euo pipefail

export COMPOSE_PROJECT_NAME="memory-router-default-smoke"
export MEMORY_ROUTER_PORT="${MEMORY_ROUTER_SMOKE_PORT:-18890}"
compose=(docker compose -f compose.yaml)

cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_for_health() {
  for _ in {1..30}; do
    if curl --fail --silent --show-error "http://127.0.0.1:${MEMORY_ROUTER_PORT}/health" >/dev/null; then
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

router_id="$("${compose[@]}" ps -q memory-router)"
init_id="$("${compose[@]}" ps -a -q quarantine-key-init)"
test -n "$router_id"
test -n "$init_id"
test "$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$init_id")" = none
test "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/app/data"}}{{.Name}}{{end}}{{end}}' "$router_id")" = "${COMPOSE_PROJECT_NAME}_memory-router-data"
test "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/app/bootstrap/public"}}{{.Name}}{{end}}{{end}}' "$router_id")" = "${COMPOSE_PROJECT_NAME}_memory-router-public-key"

"${compose[@]}" exec -T memory-router sh -ec '
  test "$(id -u)" -ne 0
  test "$MEMORY_ROUTER_PORT" = "'"${MEMORY_ROUTER_PORT}"'"
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
