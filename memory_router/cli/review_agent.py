"""Loopback-only, authenticated review agent for hardware and external unwrap providers."""

from __future__ import annotations

import argparse
import getpass
import hmac
import json
import os
import re
import sqlite3
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from memory_router.envelope import parse_envelope
from memory_router.review_unwrap import (
    Pkcs11RsaOaepProvider,
    ReviewProviderRegistry,
    load_review_provider,
)

MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_AUDIT_ROWS = 1000
REVIEWER_RE = re.compile(r"[A-Za-z0-9._@-]{1,128}")


class ReviewAudit:
    def __init__(self, path: Path) -> None:
        # Create with owner-only permissions and refuse existing shared files.
        fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        if path.stat().st_mode & 0o077:
            raise ValueError("review audit database must be accessible only by its owner")
        self._path = path
        self._lock = threading.Lock()
        with sqlite3.connect(path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS review_audit ("
                "id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, reviewer TEXT NOT NULL, "
                "quarantine_id TEXT, outcome TEXT NOT NULL)"
            )

    def record(self, reviewer: str, quarantine_id: str | None, outcome: str) -> None:
        with self._lock, sqlite3.connect(self._path) as db:
            db.execute(
                "INSERT INTO review_audit(timestamp, reviewer, quarantine_id, outcome) "
                "VALUES (?, ?, ?, ?)",
                (datetime.now(UTC).isoformat(), reviewer, quarantine_id, outcome),
            )
            db.execute(
                "DELETE FROM review_audit WHERE id NOT IN "
                "(SELECT id FROM review_audit ORDER BY id DESC LIMIT ?)",
                (MAX_AUDIT_ROWS,),
            )


class ReviewAgent(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        port: int,
        origin: str,
        credential: str,
        reviewer: str,
        providers: ReviewProviderRegistry,
        audit: ReviewAudit,
    ) -> None:
        parsed = urlsplit(origin)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("origin must be an exact http(s) origin")
        if not REVIEWER_RE.fullmatch(reviewer):
            raise ValueError("invalid reviewer identity")
        if len(credential) < 32:
            raise ValueError("review agent credential must be at least 32 characters")
        self.origin = origin.rstrip("/")
        self.credential = credential
        self.reviewer = reviewer
        self.providers = providers
        self.audit = audit
        self.unwrap_lock = threading.Lock()
        super().__init__(("127.0.0.1", port), ReviewHandler)


class ReviewHandler(BaseHTTPRequestHandler):
    server: ReviewAgent

    def log_message(self, format: str, *args: object) -> None:
        # HTTP paths, request bodies, credentials and exception text are not logged.
        pass

    def _trusted_origin(self) -> bool:
        return (
            self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"
            and self.headers.get("Origin") == self.server.origin
        )

    def _respond(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        if self._trusted_origin():
            self.send_header("Access-Control-Allow-Origin", self.server.origin)
            self.send_header("Vary", "Origin")
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self) -> None:
        if self.path != "/decrypt" or not self._trusted_origin():
            self._respond(403, {"error": "unauthorized"})
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", self.server.origin)
        self.send_header("Access-Control-Allow-Methods", "POST")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "0")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        token = self.headers.get("Authorization", "")
        if (
            self.path != "/decrypt"
            or not self._trusted_origin()
            or not hmac.compare_digest(token, f"Bearer {self.server.credential}")
        ):
            self.server.audit.record(self.server.reviewer, None, "unauthorized")
            self._respond(403, {"error": "unauthorized"})
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
            if not 0 < length <= MAX_REQUEST_BYTES:
                raise ValueError("invalid request size")
            if self.headers.get("Content-Type") != "application/json":
                raise ValueError("invalid content type")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict) or set(body) != {"envelope"}:
                raise ValueError("invalid request")
            envelope = parse_envelope(body["envelope"])
        except (ValueError, TypeError, KeyError, UnicodeDecodeError, json.JSONDecodeError):
            self.server.audit.record(self.server.reviewer, None, "failed")
            self._respond(400, {"error": "invalid_envelope"})
            return

        quarantine_id = envelope["quarantine_id"]
        try:
            # Serialize hardware operations to honor token session/PIN/touch policies.
            with self.server.unwrap_lock:
                decrypted = self.server.providers.decrypt(envelope)
            self.server.audit.record(self.server.reviewer, quarantine_id, "verified")
        except Exception:
            self.server.audit.record(self.server.reviewer, quarantine_id, "failed")
            self._respond(422, {"error": "review_decrypt_failed"})
            return
        self._respond(200, {"decrypted": decrypted})


def _read_credential(path: Path) -> str:
    if path.stat().st_mode & 0o077:
        raise ValueError("review agent credential file must be owner-only")
    credential = path.read_text(encoding="utf-8").strip()
    if len(credential) < 32:
        raise ValueError("review agent credential must be at least 32 characters")
    return credential


def main() -> None:
    parser = argparse.ArgumentParser(prog="memory-router-review-agent")
    parser.add_argument("--origin", required=True, help="Exact, trusted review console origin")
    parser.add_argument("--reviewer", required=True, help="Identity recorded in the local audit")
    parser.add_argument("--credential-file", type=Path, required=True)
    parser.add_argument("--audit-db", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--pkcs11-module", help="Path to local PKCS#11 driver")
    parser.add_argument("--pkcs11-token", help="Hardware token label")
    parser.add_argument("--pkcs11-key", help="Private-key object label")
    parser.add_argument("--external-provider", action="append", default=[], metavar="ENTRY_POINT")
    args = parser.parse_args()
    providers = [load_review_provider(name) for name in args.external_provider]
    if any((args.pkcs11_module, args.pkcs11_token, args.pkcs11_key)):
        if not all((args.pkcs11_module, args.pkcs11_token, args.pkcs11_key)):
            parser.error("all PKCS#11 options are required together")
        providers.append(
            Pkcs11RsaOaepProvider(
                args.pkcs11_module,
                args.pkcs11_token,
                args.pkcs11_key,
                getpass.getpass("Token PIN: "),
            )
        )
    if not providers:
        parser.error("configure a PKCS#11 key or an external review provider")
    agent = ReviewAgent(
        args.port,
        args.origin,
        _read_credential(args.credential_file),
        args.reviewer,
        ReviewProviderRegistry(providers),
        ReviewAudit(args.audit_db),
    )
    print(f"Review agent listening on loopback 127.0.0.1:{agent.server_port}")
    try:
        agent.serve_forever()
    except KeyboardInterrupt:
        print("Review agent stopping")
    finally:
        agent.server_close()


if __name__ == "__main__":
    main()
