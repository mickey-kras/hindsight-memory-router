from __future__ import annotations

import argparse
import asyncio
import re
import sys

from memory_router.config import load_settings
from memory_router.db import create_database
from memory_router.human_auth_config import generation_for, load_human_config
from memory_router.human_auth_store import HumanAuthStore
from memory_router.principals import load_principal_registry


def _key_id(value: str) -> str:
    if re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise argparse.ArgumentTypeError(
            "session key ID must be 32 lowercase hexadecimal characters"
        )
    return value


async def _operate(action: str, key_id: str | None) -> None:
    settings = load_settings()
    if not settings.memory_router_human_auth or not settings.memory_router_principals:
        raise RuntimeError("human authentication and principal configuration are required")
    registry = load_principal_registry(settings.memory_router_principals)
    config = load_human_config(settings.memory_router_human_auth, registry)
    database = await create_database(settings.quarantine_database_url)
    try:
        store = HumanAuthStore(database, generation_for(config, registry))
        await store.initialize(check_generation=False)
        if action == "activate":
            await store.activate()
        elif key_id is not None:
            await store.revoke(key_id)
    finally:
        await database.close()


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Activate human login policy or revoke a session.")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser(
        "activate", help="Activate configured policy and invalidate existing sessions."
    )
    revoke = commands.add_parser("revoke", help="Revoke a session by its public key ID.")
    revoke.add_argument("--key-id", required=True, type=_key_id)
    args = parser.parse_args(argv)
    try:
        asyncio.run(_operate(args.action, getattr(args, "key_id", None)))
    except Exception:
        # Configuration and database exceptions can contain credentials or identity claims.
        print(
            "Human authentication command failed; check configuration and database access.",
            file=sys.stderr,
        )
        return 1
    print(
        "Human authentication policy activated."
        if args.action == "activate"
        else "Session revoked."
    )
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
