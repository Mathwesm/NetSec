"""Apply policies only to labelled, explicitly inventoried Docker lab containers."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import asdict
from ipaddress import ip_address
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from netsec.core.compiler import Instruction, Plan
from netsec.runtime import RuntimeFailureError
from netsec.services.probes import ProbeResult

_LAB_LABEL = "org.netsec.lab"
_LAB_VALUE = "netsec-language"


class Inventory(BaseModel):
    """Validate the exact containers authorized for a lab run."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    probe_container: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    targets: dict[str, str]

    @field_validator("targets")
    @classmethod
    def validate_targets(cls, targets: dict[str, str]) -> dict[str, str]:
        """Reject invalid container identifiers and noncanonical IP keys."""
        canonical: dict[str, str] = {}
        for address, container in targets.items():
            if (
                not container
                or container.startswith("-")
                or any(
                    not (char.isascii() and (char.isalnum() or char in "_.-")) for char in container
                )
            ):
                raise ValueError("Invalid container identifier")
            canonical[str(ip_address(address))] = container
        if len(canonical) != len(targets):
            raise ValueError("Duplicate canonical inventory IP")
        return canonical


class DockerAdapter:
    """Keep firewall changes inside containers carrying the lab ownership label."""

    def __init__(self, inventory: Inventory, timeout: float, executable: str = "docker") -> None:
        self.inventory = inventory
        self.timeout = timeout
        resolved = shutil.which(executable)
        if resolved is None:
            raise RuntimeFailureError(
                "Docker executable was not found; configure --docker-executable"
            )
        self.executable = str(Path(resolved).resolve())

    def preflight(self, plan: Plan) -> None:
        """Check ownership labels and actual container IPs before any mutation."""
        self._inspect(self.inventory.probe_container)
        hosts = {item.host for item in plan.instructions if item.host}
        for host in sorted(hosts):
            container = self.inventory.targets.get(host)
            if container is None:
                raise RuntimeFailureError("Program target is absent from the lab inventory")
            details = self._inspect(container)
            network_settings = details.get("NetworkSettings", {})
            addresses = _container_addresses(network_settings)
            if host not in addresses:
                raise RuntimeFailureError("Inventory IP does not match the inspected container")

    def _inspect(self, container: str) -> dict[str, object]:
        data = _decode(self._call(["inspect", container]).stdout)
        if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
            raise RuntimeFailureError("Unexpected Docker inspect response")
        details: dict[str, object] = data[0]
        config = details.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        state = details.get("State")
        if not isinstance(labels, dict) or labels.get(_LAB_LABEL) != _LAB_VALUE:
            raise RuntimeFailureError("Container is not owned by the NetSec laboratory")
        if not isinstance(state, dict) or state.get("Running") is not True:
            raise RuntimeFailureError("Laboratory container is not running")
        return details

    def check(self, instruction: Instruction) -> ProbeResult:
        """Run the same protocol probe from the isolated probe container."""
        command = [
            "exec",
            self.inventory.probe_container,
            "netsec",
            "probe",
            instruction.host,
            str(instruction.port),
            "--timeout",
            str(self.timeout),
        ]
        if instruction.operation == "check_dns":
            command.extend(["--dns-name", instruction.message, "--expect", instruction.expected])
        elif instruction.message:
            command.extend(["--service", instruction.message])
        output = self._call(command)
        try:
            data = ProbePayload.model_validate_json(output.stdout)
        except ValueError as error:
            raise RuntimeFailureError("Invalid probe subprocess response") from error
        return ProbeResult(data.success, data.status, data.detail)

    def firewall(self, instruction: Instruction) -> ProbeResult:
        """Add a tagged rule at most once, touching only the NetSec table."""
        container = self.inventory.targets[instruction.host]
        existing = self._call(["exec", container, "nft", "-j", "list", "tables"])
        if not _has_table(existing.stdout):
            initial = (
                "add table inet netsec\n"
                "add chain inet netsec input { "
                "type filter hook input priority 0; policy accept; }\n"
            )
            self._call(["exec", "-i", container, "nft", "-f", "-"], initial)
        chain = self._call(
            ["exec", container, "nft", "-j", "list", "chain", "inet", "netsec", "input"]
        )
        prefix = f"netsec:{instruction.host}:{instruction.protocol}:{instruction.port}:"
        tag = prefix + instruction.operation
        replacements = _replacements(chain.stdout, prefix, tag)
        if replacements is None:
            return ProbeResult(True, "unchanged", "Lab firewall rule already present")
        verdict = "accept" if instruction.operation == "allow" else "drop"
        family = "ip6" if ":" in instruction.host else "ip"
        rule = (
            f"add rule inet netsec input {family} daddr {instruction.host} "
            f'{instruction.protocol} dport {instruction.port} {verdict} comment "{tag}"\n'
        )
        self._call(["exec", "-i", container, "nft", "-f", "-"], replacements + rule)
        return ProbeResult(True, "applied", "Lab firewall rule applied")

    def reset_managed_rules(self, plan: Plan) -> None:
        """Reset only tagged rules on validated lab targets before a lab test.

        Args:
            plan: The test inventory compiled from NetSec source.

        Raises:
            RuntimeFailureError: If ownership, inventory or Docker validation fails.
        """
        self.preflight(plan)
        for host in sorted({item.host for item in plan.instructions if item.host}):
            container = self.inventory.targets[host]
            tables = self._call(["exec", container, "nft", "-j", "list", "tables"])
            if not _has_table(tables.stdout):
                continue
            chain = self._call(
                ["exec", container, "nft", "-j", "list", "chain", "inet", "netsec", "input"]
            )
            rules = [
                item
                for item in _objects(chain.stdout, "rule")
                if str(item.get("comment", "")).startswith(f"netsec:{host}:")
            ]
            if rules:
                self._call(["exec", "-i", container, "nft", "-f", "-"], _deletions(rules))

    def _call(
        self, arguments: list[str], text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        try:
            # Arguments are separate, validated values; never invoke a shell.
            result = subprocess.run(  # noqa: S603 - resolved executable and explicit argv.
                [self.executable, *arguments],
                input=text.encode("utf-8") if text is not None else None,
                capture_output=True,
                timeout=max(15.0, self.timeout * 5),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RuntimeFailureError("Docker command failed or exceeded its deadline") from error
        if result.returncode != 0:
            raise RuntimeFailureError(f"Docker command failed with exit code {result.returncode}")
        # Binary stdin preserves LF across Windows-to-Linux boundaries.
        return subprocess.CompletedProcess(
            result.args,
            result.returncode,
            stdout=result.stdout.decode("utf-8", errors="replace"),
            stderr=result.stderr.decode("utf-8", errors="replace"),
        )


class ProbePayload(BaseModel):
    """Validate data received across the Docker process boundary."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    success: bool
    status: str
    detail: str


def probe_json(result: ProbeResult) -> str:
    """Serialize a validated probe result for subprocess transport."""
    return json.dumps(asdict(result))


def _container_addresses(settings: object) -> set[str]:
    if not isinstance(settings, dict) or not isinstance(settings.get("Networks"), dict):
        return set()
    return {
        str(ip_address(address))
        for network in settings["Networks"].values()
        if isinstance(network, dict)
        for key in ("IPAddress", "GlobalIPv6Address")
        if isinstance(address := network.get(key), str) and address
    }


def _objects(text: str, key: str) -> list[dict[str, object]]:
    data = _decode(text)
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        raise RuntimeFailureError("Invalid nftables response")
    return [
        item[key]
        for item in data["nftables"]
        if isinstance(item, dict) and isinstance(item.get(key), dict)
    ]


def _has_table(text: str) -> bool:
    return any(
        item.get("family") == "inet" and item.get("name") == "netsec"
        for item in _objects(text, "table")
    )


def _replacements(text: str, prefix: str, tag: str) -> str | None:
    rules = [
        item
        for item in _objects(text, "rule")
        if isinstance(item.get("comment"), str) and str(item["comment"]).startswith(prefix)
    ]
    if len(rules) == 1 and rules[0]["comment"] == tag:
        return None
    return _deletions(rules)


def _deletions(rules: list[dict[str, object]]) -> str:
    deletions: list[str] = []
    for rule in rules:
        handle = rule.get("handle")
        if type(handle) is not int or handle < 1:
            raise RuntimeFailureError("Managed nftables rule has no valid handle")
        deletions.append(f"delete rule inet netsec input handle {handle}\n")
    return "".join(deletions)


def _decode(text: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise RuntimeFailureError("Invalid JSON from Docker subprocess") from error
