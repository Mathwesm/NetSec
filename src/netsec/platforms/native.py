"""Select a native backend and guard local execution before any writes."""

from __future__ import annotations

import platform

from netsec.core.compiler import Instruction, Plan
from netsec.platforms.linux import LinuxFirewall
from netsec.platforms.models import MANAGEMENT_PORTS, FirewallBackend, FirewallRule
from netsec.platforms.windows import WindowsFirewall
from netsec.runtime import RuntimeFailureError
from netsec.services.observations import observe
from netsec.services.probes import ProbeResult


def native_backend() -> FirewallBackend:
    """Choose the operating-system backend without requesting elevation."""
    if platform.system() == "Linux":
        return LinuxFirewall()
    if platform.system() == "Windows":
        return WindowsFirewall()
    raise RuntimeFailureError("Native firewall supports Linux and Windows only")


def policy_rules(plan: Plan) -> tuple[FirewallRule, ...]:
    """Return unique validated rules in program order."""
    rules = [
        FirewallRule.from_instruction(item)
        for item in plan.instructions
        if item.operation in {"allow", "deny"}
    ]
    return tuple({rule.key: rule for rule in rules}.values())


class NativeAdapter:
    """Perform local probes and apply only explicitly authorized local policies."""

    def __init__(
        self,
        timeout: float,
        *,
        apply: bool = False,
        allow_management_port: bool = False,
        backend: FirewallBackend | None = None,
    ) -> None:
        self.timeout = timeout
        self.apply = apply
        self.allow_management_port = allow_management_port
        self.backend = backend if backend is not None else native_backend()
        self.authorized: frozenset[FirewallRule] = frozenset()

    def preflight(self, plan: Plan) -> None:
        """Validate the full local target set, privileges and management protection."""
        self.authorized = frozenset()
        rules = policy_rules(plan)
        if not rules:
            return
        if not self.apply:
            raise RuntimeFailureError(
                "Native firewall writes require --apply; inspect preview first"
            )
        state = self.backend.inspect()
        if not state.can_manage or not state.firewall_enabled:
            raise RuntimeFailureError(
                "Native firewall unavailable or not elevated: " + state.detail
            )
        if any(rule.host not in state.addresses for rule in rules):
            raise RuntimeFailureError("Firewall target is not an address assigned to this computer")
        if not self.allow_management_port and any(
            rule.action == "deny" and rule.port in MANAGEMENT_PORTS for rule in rules
        ):
            raise RuntimeFailureError("Blocking management ports requires --allow-management-port")
        self.authorized = frozenset(rules)

    def check(self, instruction: Instruction) -> ProbeResult:
        """Probe the explicit endpoint from this machine."""
        return observe(instruction, self.timeout)

    def firewall(self, instruction: Instruction) -> ProbeResult:
        """Apply only a rule that passed the complete preflight."""
        rule = FirewallRule.from_instruction(instruction)
        if rule not in self.authorized:
            raise RuntimeFailureError("Firewall rule did not pass native preflight")
        return self.backend.ensure(rule)

    def remove(self, plan: Plan) -> list[ProbeResult]:
        """Remove owned rules named by this source after validating local authority."""
        self.preflight(plan)
        return [self.backend.remove(rule) for rule in policy_rules(plan)]
