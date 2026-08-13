#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="docs/architecture/workspace.dsl"
GENERATED="docs/architecture/generated"
SITE=".architecture-site"
VERSION="2026.06.28"

die() {
  printf 'architecture: %s\n' "$*" >&2
  exit 1
}

command -v docker >/dev/null 2>&1 || die "Docker is required to run Structurizr $VERSION."

case "$(uname -m)" in
  x86_64 | amd64)
    PLATFORM="linux/amd64"
    DIGEST="sha256:99119a0586c11e99db513915f1a5580088c6a07bcaded7d7d27f65fd2ee3c29e"
    ;;
  arm64 | aarch64)
    PLATFORM="linux/arm64"
    DIGEST="sha256:b669b5dbf931f4e0bf900586f6b1b98a66b35192d123c17824da2ed1f850268e"
    ;;
  *)
    die "Unsupported CPU architecture: $(uname -m)."
    ;;
esac

IMAGE="structurizr/structurizr:${VERSION}-playwright@${DIGEST}"

pull_image() {
  printf 'architecture: Structurizr %s (%s)\n' "$VERSION" "$PLATFORM"
  docker pull --platform "$PLATFORM" "$IMAGE" >/dev/null ||
    die "Failed to download or verify Structurizr image $IMAGE."
}

run_structurizr() {
  docker run --rm \
    --platform "$PLATFORM" \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --volume "$ROOT:/usr/local/structurizr" \
    --workdir /usr/local/structurizr \
    "$IMAGE" "$@"
}

validate() {
  run_structurizr validate -workspace "$WORKSPACE" ||
    die "Structurizr validation failed for $WORKSPACE."
}

generate_svg() {
  rm -rf "$ROOT/$GENERATED"
  mkdir -p "$ROOT/$GENERATED"
  run_structurizr export -workspace "$WORKSPACE" -format svg -output "$GENERATED" ||
    die "Structurizr SVG export failed."
  compgen -G "$ROOT/$GENERATED/*.svg" >/dev/null ||
    die "Structurizr SVG export produced no SVG files."
}

generate_site() {
  rm -rf "$ROOT/$SITE"
  mkdir -p "$ROOT/$SITE"
  run_structurizr export -workspace "$WORKSPACE" -format static -output "$SITE" ||
    die "Structurizr static-site export failed."
  [[ -f "$ROOT/$SITE/index.html" ]] ||
    die "Structurizr static-site export produced no index.html."
}

pull_image
case "${1:-svg}" in
  svg)
    validate
    generate_svg
    ;;
  site)
    validate
    generate_site
    ;;
  *)
    die "Usage: scripts/architecture.sh [svg|site]"
    ;;
esac
