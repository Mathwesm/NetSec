"""Prove an encrypted WireGuard path between two owned Linux test servers."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from loguru import logger

from netsec.platforms.process import command

TARGETS = ("netsec-professional-web01", "netsec-professional-web02")


def execute(executable: str, target: str, arguments: list[str], payload: object = None) -> str:
    """Use Docker only as the trusted control channel, not as the VPN data path."""
    return command(
        executable,
        ["exec", "-i", target, *arguments],
        json.dumps(payload) if payload is not None else None,
    )


def validate(executable: str) -> dict[str, object]:
    """Exchange public keys, configure tunnels and measure actual HTTP over the VPN."""
    for target in TARGETS:
        state = json.loads(command(executable, ["inspect", target]))[0]
        if state["Config"]["Labels"].get("org.netsec.lab") != "netsec-professional":
            raise RuntimeError("Refusing an unowned VPN test target")
    identity = ["python", "/app/lab/professional/vpn_identity.py"]
    public = [
        execute(executable, target, identity, {"operation": "identity"}).strip()
        for target in TARGETS
    ]
    results: list[dict[str, object]] = []
    try:
        for index, target in enumerate(TARGETS):
            peer = 1 - index
            tunnel = {
                "interface": "nswg0",
                "address": f"10.66.0.{index + 1}/24",
                "peers": [
                    {
                        "public_key": public[peer],
                        "allowed_ips": [f"10.66.0.{peer + 1}/32"],
                        "endpoint_address": f"172.30.250.{peer + 10}",
                        "keepalive": 25,
                    },
                ],
            }
            request = {"operation": "up", "tunnel": tunnel}
            first = json.loads(execute(executable, target, identity, request))
            repeat = json.loads(execute(executable, target, identity, request))
            results.append({"first": first, "repeat": repeat})
        http = json.loads(
            execute(
                executable, TARGETS[0], ["netsec", "probe", "10.66.0.2", "80", "--service", "http"]
            )
        )
        statuses = [
            json.loads(execute(executable, target, ["netsec", "vpn", "status", "/app/vpn.json"]))
            for target in TARGETS
        ]
        success = (
            http["success"]
            and all(item["repeat"]["status"] == "unchanged" for item in results)
            and all(
                status["peers"] and all(peer["latest_handshake_utc"] for peer in status["peers"])
                for status in statuses
            )
        )
        return {
            "success": success,
            "lifecycle": results,
            "http_over_vpn": http,
            "statuses": statuses,
        }
    finally:
        for target in TARGETS:
            execute(executable, target, ["netsec", "vpn", "down", "/app/vpn.json", "--apply"])


def main() -> int:
    """Retain only public VPN evidence in a new timestamped directory."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker-executable", default="docker")
    arguments = parser.parse_args()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = Path("data/processed") / f"vpn-{stamp}-{uuid4().hex[:8]}"
    destination.mkdir(parents=True, exist_ok=False)
    evidence = validate(arguments.docker_executable)
    (destination / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    logger.info(
        "WireGuard integration completed | success={} evidence={}", evidence["success"], destination
    )
    return 0 if evidence["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
