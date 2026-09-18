"""Validate operating-system policy inputs independently of compiler internals."""

from __future__ import annotations

import hashlib
from ipaddress import ip_address
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from netsec.core.compiler import Instruction
from netsec.services.probes import ProbeResult

OWNER = "netsec-managed-v1"
MANAGEMENT_PORTS = frozenset({22, 3389, 5985, 5986})


class FirewallRule(BaseModel):
    """Describe one inbound endpoint rule, with no executable strings."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    host: str
    port: int = Field(ge=1, le=65535, strict=True)
    protocol: Literal["tcp", "udp"]
    action: Literal["allow", "deny"]

    @field_validator("host")
    @classmethod
    def address(cls, value: str) -> str:
        """Normalize literal addresses and reject zone identifiers."""
        if "%" in value:
            raise ValueError("Scoped IPv6 addresses are not supported")
        return str(ip_address(value))

    @classmethod
    def from_instruction(cls, instruction: Instruction) -> FirewallRule:
        """Validate a compiled instruction before using a system backend."""
        return cls.model_validate(
            {
                "host": instruction.host,
                "port": instruction.port,
                "protocol": instruction.protocol,
                "action": instruction.operation,
            }
        )

    @property
    def key(self) -> str:
        """Return a deterministic platform-safe identity independent of action."""
        value = f"{self.host}|{self.protocol}|{self.port}".encode("ascii")
        return "NetSec-" + hashlib.sha256(value).hexdigest()[:24]

    @property
    def tag(self) -> str:
        """Return a human-readable ownership comment."""
        return f"{OWNER}:{self.key}:{self.action}"


class NativeState(BaseModel):
    """Report local addresses and effective firewall administration capability."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    platform: Literal["linux", "windows"]
    addresses: tuple[str, ...]
    can_manage: bool
    firewall_enabled: bool = True
    detail: str = ""


class FirewallBackend(Protocol):
    """Expose ownership-limited native firewall operations."""

    def inspect(self) -> NativeState:
        """Read platform prerequisites without writing firewall rules."""
        ...

    def ensure(self, rule: FirewallRule) -> ProbeResult:
        """Reconcile one managed inbound rule."""
        ...

    def remove(self, rule: FirewallRule) -> ProbeResult:
        """Remove only an exactly identified managed rule."""
        ...
