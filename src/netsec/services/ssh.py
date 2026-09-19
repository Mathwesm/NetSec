"""Orchestrate owned Linux firewall rules through authenticated OpenSSH."""

from __future__ import annotations

import subprocess
from ipaddress import ip_address
from pathlib import Path
from shutil import which

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from netsec.agent import AgentRequest
from netsec.core.compiler import Instruction, Plan, compile_source
from netsec.core.model import Source
from netsec.platforms.windows import BridgeResult
from netsec.runtime import RuntimeFailureError
from netsec.services.observations import observe
from netsec.services.probes import ProbeResult


class SshTarget(BaseModel):
    """Declare key-based noninteractive authentication without embedding secrets."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    user: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    port: int = Field(default=22, ge=1, le=65535, strict=True)
    identity_file: Path
    known_hosts_file: Path
    sudo: bool = Field(default=False, strict=True)


class SshInventory(BaseModel):
    """Map canonical endpoint addresses to SSH connection settings."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    targets: dict[str, SshTarget] = Field(min_length=1, max_length=128)

    @field_validator("targets")
    @classmethod
    def canonical(cls, values: dict[str, SshTarget]) -> dict[str, SshTarget]:
        """Reject duplicate aliases and scoped IPs before opening connections."""
        if any("%" in key for key in values):
            raise ValueError("Scoped addresses are unsupported")
        normalized = {str(ip_address(key)): target for key, target in values.items()}
        if len(normalized) != len(values):
            raise ValueError("Duplicate canonical inventory address")
        return normalized


def _arguments(host: str, target: SshTarget) -> list[str]:
    for path in (target.identity_file, target.known_hosts_file):
        if not path.is_file() or any(character in str(path) for character in '\r\n"'):
            raise RuntimeFailureError("SSH key and known_hosts must be existing local files")
    # Explicit settings prevent user SSH config from introducing proxies or forwarding.
    return [
        "-F",
        "none",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "GlobalKnownHostsFile=none",
        "-o",
        f'UserKnownHostsFile="{target.known_hosts_file.resolve()}"',
        "-i",
        str(target.identity_file.resolve()),
        "-p",
        str(target.port),
        "-l",
        target.user,
        host,
        "sudo -n -- netsec agent" if target.sudo else "netsec agent",
    ]


def request_remote(host: str, target: SshTarget, request: AgentRequest) -> ProbeResult:
    """Send bounded JSON over a fixed remote command; never interpolate source into a shell."""
    executable = which("ssh")
    if executable is None:
        raise RuntimeFailureError("OpenSSH client is required")
    arguments = _arguments(host, target)
    try:
        response = subprocess.run(  # noqa: S603 - resolved executable, fixed command and typed arguments
            [executable, *arguments],
            input=request.model_dump_json().encode("utf-8"),
            capture_output=True,
            timeout=45,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeFailureError(
            "SSH request failed or timed out; reconcile before retry"
        ) from error
    if response.returncode:
        raise RuntimeFailureError(
            f"SSH agent exited with {response.returncode}; verify pinned host key, authentication "
            "and remote privileges; remote state may require reconciliation"
        )
    try:
        result = BridgeResult.model_validate_json(response.stdout)
    except ValidationError as error:
        raise RuntimeFailureError("Invalid SSH agent response; reconcile remote state") from error
    return ProbeResult(result.success, result.status, result.detail)


class SshAdapter:
    """Preflight the complete fleet, then preserve source order from the controller."""

    def __init__(
        self, source: Source, inventory: SshInventory, timeout: float, *, apply: bool = False
    ) -> None:
        self.source = source
        self.inventory = inventory
        self.timeout = timeout
        self.apply = apply
        self.plan = compile_source(source.text, source.filename, modules=source.modules)
        self.ready = False

    def preflight(self, plan: Plan) -> None:
        """Validate every remote firewall target before starting any observation or write."""
        self.ready = False
        if plan != self.plan:
            raise RuntimeFailureError("SSH plan does not match the submitted source")
        hosts = dict.fromkeys(
            item.host for item in plan.instructions if item.operation in {"allow", "deny", "server"}
        )
        if hosts and not self.apply:
            raise RuntimeFailureError("SSH firewall writes require --apply; inspect preview first")
        if any(host not in self.inventory.targets for host in hosts):
            raise RuntimeFailureError("SSH inventory is missing a firewall target")
        if any(
            item.operation == "deny" and item.port == self.inventory.targets[item.host].port
            for item in plan.instructions
            if item.operation in {"allow", "deny"}
        ):
            raise RuntimeFailureError("Refusing to block the inventory SSH management port")
        for host in hosts:
            result = self._request(host, "preflight")
            if not result.success:
                raise RuntimeFailureError("Remote preflight refused the planned policy")
        self.ready = True

    def _request(self, host: str, operation: str, index: int = 0) -> ProbeResult:
        request = AgentRequest.model_validate(
            {
                "source": self.source,
                "host": host,
                "operation": operation,
                "index": index,
                "apply": self.apply,
            }
        )
        return request_remote(host, self.inventory.targets[host], request)

    def check(self, instruction: Instruction) -> ProbeResult:
        """Observe target ports from the controller, not from target loopback."""
        return observe(instruction, self.timeout)

    def firewall(self, instruction: Instruction) -> ProbeResult:
        """Apply the exact source-linked instruction after the fleet is ready."""
        if not self.ready or instruction not in self.plan.instructions:
            raise RuntimeFailureError("SSH instruction did not pass fleet preflight")
        return self._request(instruction.host, "ensure", self.plan.instructions.index(instruction))

    def remove(self, plan: Plan) -> list[ProbeResult]:
        """Remove only owned endpoint rules listed in the fully preflighted source."""
        self.preflight(plan)
        return [
            self._request(item.host, "remove", index)
            for index, item in enumerate(plan.instructions)
            if item.operation in {"allow", "deny"}
        ]

    def server(self, instruction: Instruction) -> ProbeResult:
        """Deploy the exact typed resource through the constrained remote agent."""
        return self.firewall(instruction)

    def remove_servers(self, plan: Plan) -> list[ProbeResult]:
        """Stop source-linked owned services after fleet-wide authorization."""
        self.preflight(plan)
        return [
            self._request(item.host, "remove", index)
            for index, item in enumerate(plan.instructions)
            if item.operation == "server"
        ]
