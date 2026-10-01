#!/usr/bin/env python3
"""Render both README emphasis variants from one small, shared SVG topology."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "architecture"


def render(focus: str) -> str:
    title = "Memory Router ecosystem"
    description = (
        "Agent clients use Integrations, which send authenticated requests to Memory Router. "
        "The router enforces access rules, scanning and limits before Hindsight memory storage. "
        "Encrypted quarantine and human review are part of Memory Router. "
        f"The {focus} component is highlighted as this repository."
    )
    parts = [f'''<svg xmlns="http://www.w3.org/2000/svg" width="1120" height="420" viewBox="0 0 1120 420" role="img" aria-labelledby="title desc">
  <title id="title">{title}</title>
  <desc id="desc">{description}</desc>
  <defs>
    <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#64748b"/></marker>
  </defs>
  <rect width="1120" height="420" rx="20" fill="#f8fafc"/>
  <g font-family="Arial, Helvetica, sans-serif">
    <text x="32" y="39" fill="#0f172a" font-size="20" font-weight="700">How the projects fit together</text>
    <text x="32" y="65" fill="#475569" font-size="14">Follow a request from the agent to stored memory.</text>''']
    nodes = [
        (32, "agents", "Agent clients", ["OpenClaw · coding agents", "MCP clients"]),
        (310, "integrations", "Integrations", ["Agent identity", "Bank mapping"]),
        (588, "router", "Memory Router", ["Access rules", "Scanning · limits"]),
        (866, "hindsight", "Hindsight", ["Memory storage"]),
    ]
    for x, key, label, lines in nodes:
        active = key == focus
        fill, stroke, ink = ("#dbeafe", "#1d4ed8", "#1e3a8a") if active else ("#eef2f6", "#94a3b8", "#334155")
        parts.append(f'<rect x="{x}" y="111" width="222" height="141" rx="12" fill="{fill}" stroke="{stroke}" stroke-width="{3 if active else 1.5}"/>')
        if active:
            parts.append(f'<rect x="{x+18}" y="97" width="132" height="25" rx="12" fill="#1d4ed8"/><text x="{x+84}" y="114" text-anchor="middle" font-size="12" font-weight="700" fill="#ffffff">This repository</text>')
        parts.append(f'<text x="{x+18}" y="152" font-size="20" font-weight="700" fill="{ink}">{label}</text>')
        for i, line in enumerate(lines):
            parts.append(f'<text x="{x+18}" y="{188+i*23}" font-size="15" fill="{ink}">{line}</text>')
    for x in [260, 538, 816]:
        parts.append(f'<path d="M {x} 180 H {x+41}" fill="none" stroke="#64748b" stroke-width="2" marker-end="url(#arrow)"/>')
    parts.append('<text x="560" y="163" text-anchor="middle" font-size="11" fill="#475569">HTTPS</text>')
    active = focus == "router"
    fill, stroke, ink = ("#dbeafe", "#1d4ed8", "#1e3a8a") if active else ("#eef2f6", "#94a3b8", "#334155")
    parts.extend([
        '<path d="M 699 258 V 301" fill="none" stroke="#64748b" stroke-width="2" marker-end="url(#arrow)"/>',
        '<text x="714" y="285" font-size="12" fill="#475569">Held for review</text>',
        f'<rect x="545" y="309" width="308" height="80" rx="12" fill="{fill}" stroke="{stroke}" stroke-width="{3 if active else 1.5}"/>',
        f'<text x="699" y="340" text-anchor="middle" font-size="17" font-weight="700" fill="{ink}">Encrypted quarantine</text>',
        f'<text x="699" y="366" text-anchor="middle" font-size="15" fill="{ink}">Human review · router-owned</text>',
        '<text x="32" y="346" font-size="14" fill="#475569">Clients select banks.</text>',
        '<text x="32" y="368" font-size="14" fill="#475569">The router decides access.</text>',
        '</g></svg>\n',
    ])
    return "\n".join(parts)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for focus in ("router", "integrations"):
        (OUT / f"overview-{focus}.svg").write_text(render(focus), encoding="utf-8")
