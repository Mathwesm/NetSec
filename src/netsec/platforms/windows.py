"""Exchange typed JSON with the packaged, non-interactive NetSecurity bridge."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from netsec.platforms.models import FirewallRule, NativeState
from netsec.platforms.process import command
from netsec.runtime import RuntimeFailureError
from netsec.services.probes import ProbeResult


class BridgeResult(BaseModel):
    """Validate the native bridge response instead of trusting arbitrary output."""

    model_config = ConfigDict(extra="forbid", strict=True)
    success: bool
    status: str
    detail: str


class WindowsFirewall:
    """Manage only persistent inbound rules carrying the NetSec ownership group."""

    def _request(self, operation: str, rule: FirewallRule | None = None) -> str:
        payload = {
            "operation": operation,
            "rule": rule.model_dump() if rule else None,
            "key": rule.key if rule else None,
            "tag": rule.tag if rule else None,
        }
        script = Path(__file__).with_name("windows_bridge.ps1")
        return command(
            "powershell.exe",
            [
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "RemoteSigned",
                "-File",
                str(script),
            ],
            json.dumps(payload),
        )

    def inspect(self) -> NativeState:
        """Read local addresses, elevation and firewall profiles without changing them."""
        try:
            return NativeState.model_validate_json(self._request("inspect"))
        except ValidationError as error:
            raise RuntimeFailureError("Invalid Windows firewall state response") from error

    def _change(self, operation: str, rule: FirewallRule) -> ProbeResult:
        try:
            result = BridgeResult.model_validate_json(self._request(operation, rule))
        except ValidationError as error:
            raise RuntimeFailureError("Invalid Windows firewall change response") from error
        return ProbeResult(result.success, result.status, result.detail)

    def ensure(self, rule: FirewallRule) -> ProbeResult:
        """Converge a named persistent rule without changing profile defaults."""
        return self._change("ensure", rule)

    def exists(self, rule: FirewallRule) -> bool:
        """Check whether the selected endpoint already has an owned persistent rule."""
        return self._change("exists", rule).status == "present"

    def remove(self, rule: FirewallRule) -> ProbeResult:
        """Remove only the endpoint's rule with the matching ownership marker."""
        return self._change("remove", rule)
