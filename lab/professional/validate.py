"""Measure real SSH policy convergence from an isolated controller container."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from loguru import logger

from netsec.platforms.process import command

CONTROLLER = "netsec-professional-controller"
TARGETS = (
    ("netsec-professional-web01", "172.30.250.10"),
    ("netsec-professional-web02", "172.30.250.11"),
)


def run(executable: str, container: str, arguments: list[str], payload: str | None = None) -> str:
    """Execute only within already verified project containers."""
    return command(executable, ["exec", "-i", container, *arguments], payload)


def provision(executable: str) -> None:
    """Pin host keys read through Docker, never from an unauthenticated network scan."""
    for container in (CONTROLLER, *(name for name, _ in TARGETS)):
        inspection = json.loads(command(executable, ["inspect", container]))[0]
        if inspection["Config"]["Labels"].get("org.netsec.lab") != "netsec-professional":
            raise RuntimeError("Refusing to configure an unowned container")
        if not inspection["State"]["Running"]:
            raise RuntimeError("Professional laboratory is not running")
    configure = ["python", "/app/lab/professional/configure.py"]
    public = run(executable, CONTROLLER, configure, '{"operation":"identity"}')
    known: list[str] = []
    for container, address in TARGETS:
        run(
            executable,
            container,
            configure,
            json.dumps({"operation": "authorize", "public": public}),
        )
        host_key = run(executable, container, ["cat", "/etc/ssh/ssh_host_ed25519_key.pub"])
        known.append(f"{address} {host_key.strip()}\n")
    run(
        executable,
        CONTROLLER,
        configure,
        json.dumps(
            {
                "operation": "inventory",
                "known_hosts": "".join(known),
                "addresses": [address for _, address in TARGETS],
            }
        ),
    )


def observations(executable: str, port: int) -> list[dict[str, object]]:
    """Probe both servers from the external controller namespace."""
    return [
        json.loads(
            run(executable, CONTROLLER, ["netsec", "probe", address, str(port), "--timeout", "0.2"])
        )
        for _, address in TARGETS
    ]


def validate(executable: str, destination: Path) -> dict[str, bool]:
    """Apply, repeat, observe actual packet drops and remove the selected policy."""
    provision(executable)
    policy = "/app/lab/professional/protect.netsec"
    options = [policy, "--mode", "ssh", "--inventory", "/app/inventory.json", "--apply"]
    run(executable, CONTROLLER, ["netsec", "firewall-remove", *options])
    before = observations(executable, 23)
    applied = json.loads(run(executable, CONTROLLER, ["netsec", "run", *options, "--fail-fast"]))
    repeated = json.loads(run(executable, CONTROLLER, ["netsec", "run", *options, "--fail-fast"]))
    blocked = observations(executable, 23)
    removed = json.loads(run(executable, CONTROLLER, ["netsec", "firewall-remove", *options]))
    restored = observations(executable, 23)
    dns_result = json.loads(
        run(
            executable,
            CONTROLLER,
            ["netsec", "run", "/app/lab/professional/dns.netsec", "--mode", "network"],
        )
    )
    checks = {
        "baseline_reachable": all(item["success"] for item in before),
        "ssh_policy_and_preserved_services": applied["success"],
        "idempotent_reapplication": repeated["success"]
        and all(
            item["status"] == "unchanged"
            for item in repeated["records"]
            if item["instruction"]["operation"] == "deny"
        ),
        "real_packet_drops": all(
            not item["success"] and item["status"] == "timeout" for item in blocked
        ),
        "owned_rule_removal": removed["success"] and all(item["success"] for item in restored),
        "dns_a_and_aaaa": dns_result["success"] and len(dns_result["records"]) == 2 * len(TARGETS),
    }
    evidence = {
        "checks": checks,
        "before": before,
        "applied": applied,
        "repeated": repeated,
        "blocked": blocked,
        "removed": removed,
        "restored": restored,
        "dns": dns_result,
    }
    (destination / "evidence.json").write_text(
        json.dumps(evidence, indent=2) + "\n", encoding="utf-8"
    )
    return checks


def main() -> int:
    """Retain a distinct timestamped evidence directory for every integration run."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--docker-executable", default="docker")
    arguments = parser.parse_args()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = Path("data/processed") / f"professional-{stamp}-{uuid4().hex[:8]}"
    destination.mkdir(parents=True, exist_ok=False)
    checks = validate(arguments.docker_executable, destination)
    logger.info("Professional integration completed | checks={} evidence={}", checks, destination)
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
