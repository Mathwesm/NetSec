"""Expose typed WireGuard resource commands separately from the source-language grammar."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from pathlib import Path

from netsec.platforms.wireguard import apply_tunnel, remove_tunnel, tunnel_status
from netsec.platforms.wireguard_models import Tunnel, TunnelSecret
from netsec.runtime import RuntimeFailureError

_MAX_MANIFEST = 1_000_000


def register(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register an offline preview and explicit native lifecycle commands."""
    parser = commands.add_parser("vpn", help="Validate and manage an owned Linux WireGuard tunnel")
    parser.add_argument("operation", choices=("check", "preview", "up", "down", "status"))
    parser.add_argument("file", type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output", type=Path)


def run(arguments: argparse.Namespace) -> dict[str, object]:
    """Validate a public manifest and keep private keys exclusively in environment/stdin."""
    with arguments.file.open(encoding="utf-8-sig") as stream:
        text = stream.read(_MAX_MANIFEST + 1)
    if len(text) > _MAX_MANIFEST:
        raise RuntimeFailureError("VPN manifest exceeds 1000000 characters")
    tunnel = Tunnel.model_validate_json(text)
    if arguments.operation in {"check", "preview"}:
        return {
            "valid": True,
            "writes": False,
            "tunnel": tunnel.model_dump(mode="json"),
            "requires_environment": ["NETSEC_WG_PRIVATE_KEY"],
        }
    if arguments.operation == "status":
        return tunnel_status(tunnel)
    if arguments.operation == "down":
        return asdict(remove_tunnel(tunnel, apply=arguments.apply))
    secret = TunnelSecret()
    return asdict(apply_tunnel(tunnel, secret.private_key, apply=arguments.apply))
