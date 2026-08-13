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
  run_structurizr export -workspace "$WORKSPACE" -format svg -mode dark -output "$GENERATED" ||
    die "Structurizr SVG export failed."
  rm -f "$ROOT/$GENERATED"/*-key.svg
  compgen -G "$ROOT/$GENERATED/*.svg" >/dev/null ||
    die "Structurizr SVG export produced no SVG files."
}

add_site_view_selector() {
  command -v python3 >/dev/null 2>&1 || die "Python 3 is required to enhance the architecture site."
  python3 - "$ROOT/$SITE/index.html" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
html = path.read_text(encoding="utf-8")

style = """    <style>
        #architecture-view-nav {
            position: fixed !important;
            top: 12px !important;
            left: 12px !important;
            z-index: 2147483647 !important;
            display: block !important;
            visibility: visible !important;
            opacity: 1 !important;
            max-width: min(520px, calc(100vw - 24px));
        }
        #architecture-view-select {
            display: block !important;
            visibility: visible !important;
            opacity: 1 !important;
            width: 100%;
            min-width: 320px;
            max-width: min(520px, calc(100vw - 24px));
            padding: 7px 10px;
            border: 1px solid GrayText;
            border-radius: 6px;
            background: Canvas;
            color: CanvasText;
            color-scheme: light dark;
            font: 14px system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        @media (max-width: 480px) {
            #architecture-view-select {
                min-width: 0;
            }
        }
    </style>
"""
nav = """    <nav id="architecture-view-nav" aria-label="Architecture view">
        <select id="architecture-view-select" aria-label="Architecture view"></select>
    </nav>
"""
init_call = """        if (!embed) {
            initArchitectureViewNavigation();
        }
"""
functions = """    function architectureViewLabel(view) {
        const labels = {
            SystemContext: 'C1: System Context — Memory Router',
            Containers: 'C2: Containers — Memory Router',
            Components: 'C3: Components — Memory Router API',
            Retain: 'Dynamic: Retain',
            Recall: 'Dynamic: Recall',
            CompatibilityOperations: 'Dynamic: Compatibility Operations',
            QuarantineReview: 'Dynamic: Quarantine Review',
            StartupShutdown: 'Dynamic: Startup / Shutdown',
            SingleNode: 'Deployment: Single Node',
            Clustered: 'Deployment: Clustered'
        };
        return labels[view.key] || structurizr.ui.getTitleForView(view);
    }

    function initArchitectureViewNavigation() {
        const select = document.getElementById('architecture-view-select');
        structurizr.workspace.getViews().forEach(function(view) {
            const option = document.createElement('option');
            option.value = view.key;
            option.textContent = architectureViewLabel(view);
            select.appendChild(option);
        });
        select.addEventListener('change', function() {
            window.location.hash = '#' + select.value;
        });
    }

    function syncArchitectureViewNavigation(viewKey) {
        const select = document.getElementById('architecture-view-select');
        if (select) {
            select.value = viewKey;
        }
    }

"""

replacements = [
    ("</head>", style + "</head>"),
    ("<body>\n", "<body>\n" + nav),
    ("        const embed = getParameter('embed');\n", "        const embed = getParameter('embed');\n" + init_call),
    ("    function postDiagramAspectRatioToParentWindow() {\n", functions + "    function postDiagramAspectRatioToParentWindow() {\n"),
    (
        "            const view = structurizr.workspace.findViewByKey(diagramIdentifier);\n            if (view) {\n",
        "            const view = structurizr.workspace.findViewByKey(diagramIdentifier);\n            if (view) {\n                syncArchitectureViewNavigation(view.key);\n",
    ),
]

for before, after in replacements:
    if before not in html:
        raise SystemExit(f"architecture: static-site navigation marker not found: {before!r}")
    html = html.replace(before, after, 1)

path.write_text(html, encoding="utf-8")
PY
}

generate_site() {
  rm -rf "$ROOT/$SITE"
  mkdir -p "$ROOT/$SITE"
  run_structurizr export -workspace "$WORKSPACE" -format static -output "$SITE" ||
    die "Structurizr static-site export failed."
  [[ -f "$ROOT/$SITE/index.html" ]] ||
    die "Structurizr static-site export produced no index.html."
  add_site_view_selector
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
