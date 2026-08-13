#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="$ROOT/docs/architecture/workspace.dsl"
GENERATED="$ROOT/docs/architecture/generated"
CACHE="$ROOT/.cache/structurizr"
VERSION="2025.11.09"
ARCHIVE="$CACHE/structurizr-cli-$VERSION.zip"
CLI_DIR="$CACHE/structurizr-cli-$VERSION"
URL="https://github.com/structurizr/cli/releases/download/v$VERSION/structurizr-cli.zip"
SHA256="f5365a463fc44d539ed19bec00c48ba1e1ecda0ccfd1ba40d2e7472d264eb79a"

mkdir -p "$CACHE"
if [[ ! -f "$ARCHIVE" ]]; then
  curl --fail --location --silent --show-error "$URL" --output "$ARCHIVE"
fi
printf '%s  %s\n' "$SHA256" "$ARCHIVE" | sha256sum --check --status

if [[ ! -x "$CLI_DIR/structurizr.sh" ]]; then
  rm -rf "$CLI_DIR"
  mkdir -p "$CLI_DIR"
  unzip -q "$ARCHIVE" -d "$CLI_DIR"
fi

"$CLI_DIR/structurizr.sh" validate -workspace "$WORKSPACE"
rm -rf "$GENERATED"
mkdir -p "$GENERATED"
"$CLI_DIR/structurizr.sh" export -workspace "$WORKSPACE" -format mermaid -output "$GENERATED"
python "$ROOT/scripts/wrap_architecture_mermaid.py" "$GENERATED"
