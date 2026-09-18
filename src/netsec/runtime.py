"""Execute NetSec instructions using explicit, interchangeable network adapters."""

from __future__ import annotations

from collections.abc import Callable
from ipaddress import ip_address
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from netsec.core.compiler import Instruction, Plan
from netsec.core.values import MAX_PORT
from netsec.services.observations import observe
from netsec.services.probes import ProbeResult


class RuntimeFailureError(Exception):
    """Report an adapter or execution failure without hiding partial results."""


class Adapter(Protocol):
    """Define operations that the instruction executor may invoke."""

    def preflight(self, plan: Plan) -> None:
        """Validate all targets and required capabilities before execution."""
        ...

    def check(self, instruction: Instruction) -> ProbeResult:
        """Observe a port or service."""
        ...

    def firewall(self, instruction: Instruction) -> ProbeResult:
        """Converge a firewall rule toward its declared state."""
        ...


class SimulatedHost(BaseModel):
    """Validate deterministic scenario data."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
    open_ports: tuple[int, ...] = ()
    services: tuple[Literal["ssh", "http", "https"], ...] = ()
    dns_records: dict[str, tuple[str, ...]] = Field(default_factory=dict)

    @field_validator("open_ports")
    @classmethod
    def validate_ports(cls, ports: tuple[int, ...]) -> tuple[int, ...]:
        """Reject invalid or duplicate scenario ports."""
        if any(not 1 <= port <= MAX_PORT for port in ports) or len(ports) != len(set(ports)):
            raise ValueError("Scenario ports must be unique and between 1 and 65535")
        return ports


class Scenario(BaseModel):
    """Map explicit canonical IP addresses to simulated responses."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    hosts: dict[str, SimulatedHost]

    @field_validator("hosts")
    @classmethod
    def canonical_hosts(cls, hosts: dict[str, SimulatedHost]) -> dict[str, SimulatedHost]:
        """Normalize IP keys without silently merging aliases."""
        canonical = {str(ip_address(key)): value for key, value in hosts.items()}
        if len(canonical) != len(hosts):
            raise ValueError("Duplicate canonical scenario IP")
        return canonical


class SimulationAdapter:
    """Execute against an explicit scenario and in-memory firewall state."""

    def __init__(self, scenario: Scenario) -> None:
        self.scenario = scenario
        self.rules: dict[tuple[str, int, str], str] = {}

    def preflight(self, plan: Plan) -> None:
        """Require every target to exist in the supplied simulation."""
        missing = {
            item.host for item in plan.instructions if item.host
        } - self.scenario.hosts.keys()
        if missing:
            raise RuntimeFailureError("Simulation scenario is missing one or more program targets")

    def check(self, instruction: Instruction) -> ProbeResult:
        """Observe scenario services after applying simulated policies."""
        host = self.scenario.hosts[instruction.host]
        key = (instruction.host, instruction.port, instruction.protocol)
        if self.rules.get(key) == "deny":
            return ProbeResult(False, "blocked", "Blocked by simulated firewall")
        if instruction.operation == "check_dns":
            matches = instruction.expected in host.dns_records.get(instruction.message, ())
            return ProbeResult(
                matches,
                "resolved" if matches else "unexpected_address",
                "Explicit simulated DNS record",
            )
        if instruction.port not in host.open_ports:
            return ProbeResult(False, "closed", "Port is closed in scenario")
        if instruction.operation == "check_service" and instruction.message not in host.services:
            return ProbeResult(False, "protocol_mismatch", "Service is absent from scenario")
        return ProbeResult(
            True, "active" if instruction.message else "open", "Scenario observation"
        )

    def firewall(self, instruction: Instruction) -> ProbeResult:
        """Apply an idempotent simulated rule."""
        key = (instruction.host, instruction.port, instruction.protocol)
        unchanged = self.rules.get(key) == instruction.operation
        self.rules[key] = instruction.operation
        return ProbeResult(True, "unchanged" if unchanged else "applied", "Simulated policy")


class NetworkAdapter:
    """Make real probes from this computer without firewall privileges."""

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout

    def preflight(self, plan: Plan) -> None:
        """Reject unsupported writes before even a read-only probe starts."""
        if any(item.operation in {"allow", "deny"} for item in plan.instructions):
            raise RuntimeFailureError(
                "Network mode cannot apply firewall rules; use the Docker lab adapter"
            )

    def check(self, instruction: Instruction) -> ProbeResult:
        """Probe exactly the IP and port contained in the validated plan."""
        return observe(instruction, self.timeout)

    def firewall(self, instruction: Instruction) -> ProbeResult:
        """Refuse an unsupported operation regardless of caller behavior."""
        raise RuntimeFailureError(f"Unsupported firewall operation: {instruction.operation}")


class Record(BaseModel):
    """Store one source-linked execution observation."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    instruction: Instruction
    success: bool
    status: str
    detail: str


class Execution(BaseModel):
    """Separate failed observations from successful command completion."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    mode: str
    records: tuple[Record, ...] = Field(default=())

    @property
    def success(self) -> bool:
        """Whether every executed instruction succeeded."""
        return all(record.success for record in self.records)


def execute(
    plan: Plan,
    adapter: Adapter,
    mode: str,
    *,
    fail_fast: bool = False,
    on_record: Callable[[Record], None] | None = None,
) -> Execution:
    """Run a fully validated plan, preserving individual adapter failures.

    Args:
        plan: Complete compilation output.
        adapter: Explicit execution environment.
        mode: Label included in exported evidence.
        fail_fast: Stop after the first failed operation while retaining prior results.
        on_record: Optional durable journal callback after each completed instruction.

    Returns:
        Ordered results for every instruction.

    Raises:
        RuntimeFailureError: If preflight fails, before any instruction is executed.
    """
    adapter.preflight(plan)
    records: list[Record] = []
    for instruction in plan.instructions:
        try:
            result = _execute_instruction(instruction, adapter)
        except RuntimeFailureError as error:
            result = ProbeResult(False, "adapter_error", str(error))
        records.append(
            Record(
                instruction=instruction,
                success=result.success,
                status=result.status,
                detail=result.detail,
            )
        )
        if on_record is not None:
            on_record(records[-1])
        if fail_fast and not result.success:
            break
    return Execution(mode=mode, records=tuple(records))


def _execute_instruction(instruction: Instruction, adapter: Adapter) -> ProbeResult:
    if instruction.operation == "report":
        return ProbeResult(True, "reported", instruction.message)
    if instruction.operation in {"allow", "deny"}:
        return adapter.firewall(instruction)
    return adapter.check(instruction)
