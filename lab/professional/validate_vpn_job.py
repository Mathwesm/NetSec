"""Validate boot-ready VPN reconciliation through a real systemd job in a disposable VM."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from loguru import logger
from pydantic import SecretStr

from netsec.automation import AutomationJob
from netsec.platforms import systemd
from netsec.platforms.process import command
from netsec.platforms.scheduler import manage
from netsec.platforms.wireguard import apply_tunnel, remove_tunnel
from netsec.platforms.wireguard_models import Peer, Tunnel

_EXPECTED_RUNS = 2


def validate(job: AutomationJob, private_key: SecretStr) -> dict[str, object]:
    """Exercise creation, repeat installation and recovery of a stopped interface."""
    if job.tunnel is None:
        raise ValueError("VPN validation requires a tunnel")
    first = manage(job, "install", apply=True)
    repeated = manage(job, "install", apply=True)
    unit = f"netsec-job-{job.name}.service"
    command("systemctl", ["start", unit])
    created = apply_tunnel(job.tunnel, private_key, apply=True).status == "unchanged"
    command("ip", ["link", "set", "dev", job.tunnel.interface, "down"])
    command("systemctl", ["start", unit])
    recovered = apply_tunnel(job.tunnel, private_key, apply=True).status == "unchanged"
    runs = list((Path("/var/lib/netsec/jobs") / job.name).glob("*/result.json"))
    durable = len(runs) >= _EXPECTED_RUNS and all(
        json.loads(path.read_text(encoding="utf-8"))["success"] for path in runs
    )
    enabled = systemd.unit_state(f"netsec-job-{job.name}.timer", "UnitFileState") == "enabled"
    return {
        "success": created
        and recovered
        and durable
        and enabled
        and repeated["status"] == "unchanged",
        "install": first["status"],
        "repeat": repeated["status"],
        "created_by_job": created,
        "stopped_interface_recovered": recovered,
        "durable_runs": len(runs),
        "timer_enabled": enabled,
        "traffic_test": "Separate two-peer WireGuard laboratory",
    }


def main() -> int:
    """Generate ephemeral secrets locally; retain only non-secret verification evidence."""
    systemd.require_systemd()
    interfaces = json.loads(command("ip", ["-j", "link", "show"]))
    if any(item["ifname"] == "nswg99" for item in interfaces):
        raise RuntimeError("VPN test interface already exists; refusing to replace it")
    token = uuid4().hex[:8]
    directory = Path("data/processed") / f"vpn-job-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{token}"
    directory.mkdir(parents=True)
    private_key = SecretStr(command("wg", ["genkey"]).strip())
    peer_private = command("wg", ["genkey"]).strip()
    public = command("wg", ["pubkey"], peer_private + "\n").strip()
    tunnel = Tunnel.model_validate(
        {
            "interface": "nswg99",
            "address": "10.233.197.1/24",
            "listen_port": 51999,
            "peers": [Peer(public_key=public, allowed_ips=("10.233.197.2/32",)).model_dump()],
        }
    )
    secret_file = systemd.CONFIG / f"lab-vpn-{token}.env"
    systemd.protected_path(secret_file)
    secret_file.parent.mkdir(parents=True, exist_ok=True)
    with secret_file.open("x", encoding="utf-8", newline="\n") as stream:
        secret_file.chmod(0o600)
        stream.write("NETSEC_WG_PRIVATE_KEY=" + private_key.get_secret_value() + "\n")
    job = AutomationJob(name=f"vpn-{token}", kind="vpn", tunnel=tunnel, secrets_file=secret_file)
    result: dict[str, object] = {"success": False}
    try:
        result = validate(job, private_key)
    finally:
        try:
            result["job_removal"] = manage(job, "remove", apply=True)
            result["tunnel_removal"] = remove_tunnel(tunnel, apply=True).status
        finally:
            secret_file.unlink()
            (directory / "evidence.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    logger.info("VPN job validation | success={} evidence={}", result["success"], directory)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
