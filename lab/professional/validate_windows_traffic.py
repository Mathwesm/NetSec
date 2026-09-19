"""Measure actual inbound Windows filtering from an isolated Windows container."""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import ip_address
from pathlib import Path
from shutil import which
from threading import Thread
from uuid import uuid4

from loguru import logger

from netsec.platforms.models import FirewallRule
from netsec.platforms.windows import WindowsFirewall

PORT = 59174
IMAGE = "mcr.microsoft.com/windows/nanoserver:ltsc2025"
LABEL = "netsec-windows-traffic"


class FixtureServer(HTTPServer):
    """Record the actual peer IP observed by the Windows TCP stack."""

    def __init__(self, host: str) -> None:
        self.peers: list[str] = []
        super().__init__((host, PORT), FixtureHandler)


class FixtureHandler(BaseHTTPRequestHandler):
    """Return fixed local content without accessing the filesystem."""

    def do_GET(self) -> None:
        """Record the separate network endpoint before replying."""
        if isinstance(self.server, FixtureServer):
            self.server.peers.append(self.client_address[0])
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"NetSec-firewall-fixture")

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib callback signature.
        """Keep operational endpoint data out of shared CI logs."""


def docker(arguments: list[str], *, timeout: float = 60) -> str:
    """Execute bounded commands on an explicitly named disposable container."""
    executable = which("docker")
    if executable is None:
        raise RuntimeError("Docker Windows engine is required for this integration")
    result = subprocess.run(  # noqa: S603 - resolved CLI and separate argv, no shell.
        [executable, *arguments],
        capture_output=True,
        timeout=timeout,
        check=False,
        encoding="utf-8",
    )
    if result.returncode:
        raise RuntimeError(f"Docker integration failed: {result.stderr[:2000]}")
    return result.stdout


def main() -> int:
    """Prove allow, block, idempotence and restored reachability outside loopback."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", required=True)
    parser.add_argument("--probe", type=Path, required=True)
    arguments = parser.parse_args()
    if docker(["info", "--format", "{{.OSType}}"]).strip() != "windows":
        raise RuntimeError("This test requires process-isolated Windows containers")
    backend = WindowsFirewall()
    state = backend.inspect()
    if not state.can_manage or not state.firewall_enabled:
        raise RuntimeError("An elevated disposable runner with enabled profiles is required")
    token = uuid4().hex[:8]
    name = "netsec-traffic-" + token
    destination = (
        Path("data/processed") / f"windows-traffic-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{token}"
    )
    destination.mkdir(parents=True)
    results: dict[str, object] = {}
    docker(["pull", IMAGE], timeout=600)
    docker(
        [
            "run",
            "-d",
            "--name",
            name,
            "--label",
            f"org.netsec.lab={LABEL}",
            "--isolation",
            "process",
            IMAGE,
            "cmd",
            "/c",
            "ping -t 127.0.0.1",
        ],
        timeout=120,
    )
    rule: FirewallRule | None = None
    try:
        details = json.loads(docker(["inspect", name]))[0]
        if details["Config"]["Labels"].get("org.netsec.lab") != LABEL:
            raise RuntimeError("Container ownership mismatch")
        network = next(iter(details["NetworkSettings"]["Networks"].values()))
        gateway, peer = network["Gateway"], network["IPAddress"]
        if ip_address(peer).is_loopback or gateway == peer:
            raise RuntimeError("Probe must originate in a separate network compartment")
        candidate = FirewallRule(host=gateway, port=PORT, protocol="tcp", action="allow")
        if backend.exists(candidate):
            raise RuntimeError("Integration endpoint already has an owned policy")
        rule = candidate
        docker(["cp", str(arguments.probe.resolve()), name + ":C:\\netsec-probe.exe"])
        results.update(_exercise(backend, rule, name, peer))
    finally:
        if rule is not None:
            results["removed"] = backend.remove(rule).status
        # Only stop the uniquely named container created above; retain it for debugging.
        docker(["stop", "--time", "5", name])
        (destination / "evidence.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    logger.info(
        "External Windows firewall test | success={} evidence={}",
        results.get("success"),
        destination,
    )
    return 0 if results.get("success") else 1


def _exercise(
    backend: WindowsFirewall, rule: FirewallRule, name: str, peer: str
) -> dict[str, object]:
    results: dict[str, object] = {}
    with FixtureServer(rule.host) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            results["allow"] = backend.ensure(rule).status
            results["reachable_before"] = _probe(name, rule.host)
            results["deny"] = backend.ensure(rule.model_copy(update={"action": "deny"})).status
            results["deny_repeat"] = backend.ensure(
                rule.model_copy(update={"action": "deny"})
            ).status
            results["blocked"] = not _probe(name, rule.host)
            results["restore"] = backend.ensure(rule).status
            results["reachable_after"] = _probe(name, rule.host)
            results["external_peer_verified"] = bool(server.peers) and all(
                address == peer for address in server.peers
            )
            results["success"] = (
                results["reachable_before"]
                and results["blocked"]
                and results["reachable_after"]
                and results["external_peer_verified"]
                and results["deny_repeat"] == "unchanged"
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)
    return results


def _probe(container: str, address: str) -> bool:
    result = json.loads(docker(["exec", container, "C:\\netsec-probe.exe", address, str(PORT)]))
    return result.get("connected") is True and result.get("body") == "NetSec-firewall-fixture"


if __name__ == "__main__":
    raise SystemExit(main())
