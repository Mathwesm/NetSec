"""Recompile constrained source requests on a server before native operations."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from netsec.core.compiler import Plan, compile_source
from netsec.core.model import Source
from netsec.platforms.native import NativeAdapter
from netsec.runtime import RuntimeFailureError
from netsec.services.probes import ProbeResult


class AgentRequest(BaseModel):
    """Accept source, not arbitrary executable commands or unvalidated plans."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    version: Literal[1] = 1
    source: Source
    host: str
    operation: Literal["preflight", "ensure", "remove"]
    index: int = Field(default=0, ge=0, le=9999, strict=True)
    apply: bool = Field(default=False, strict=True)

    @field_validator("host")
    @classmethod
    def validate_host(cls, host: str) -> str:
        """Require a literal unscoped server IP."""
        if "%" in host:
            raise ValueError("Scoped addresses are unsupported")
        return str(ip_address(host))


def handle(request: AgentRequest, adapter: NativeAdapter | None = None) -> ProbeResult:
    """Compile the complete program and authorize only this local target.

    Management-port overrides are intentionally unavailable through SSH.
    """
    plan = compile_source(
        request.source.text, request.source.filename, modules=request.source.modules
    )
    selected = Plan(
        instructions=tuple(item for item in plan.instructions if item.host == request.host)
    )
    if not selected.instructions:
        raise RuntimeFailureError("Agent target is absent from the compiled program")
    native = adapter if adapter is not None else NativeAdapter(2, apply=request.apply)
    native.preflight(selected)
    if request.operation == "preflight":
        return ProbeResult(True, "ready", "Remote compilation and native preflight succeeded")
    if request.index >= len(plan.instructions):
        raise RuntimeFailureError("Agent instruction index is outside the compiled plan")
    instruction = plan.instructions[request.index]
    if instruction.host != request.host or instruction.operation not in {"allow", "deny", "server"}:
        raise RuntimeFailureError("Agent instruction is not a managed resource for this target")
    if instruction.operation == "server":
        if request.operation == "remove":
            return native.remove_servers(Plan(instructions=(instruction,)))[0]
        return native.server(instruction)
    if request.operation == "remove":
        return native.remove(Plan(instructions=(instruction,)))[0]
    return native.firewall(instruction)
