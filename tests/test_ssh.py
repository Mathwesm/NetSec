from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from netsec.agent import AgentRequest, handle
from netsec.core.compiler import compile_source
from netsec.core.model import Source
from netsec.evaluation import wrap
from netsec.platforms.models import NativeState
from netsec.platforms.native import NativeAdapter
from netsec.runtime import RuntimeFailureError, execute
from netsec.services.probes import ProbeResult
from netsec.services.ssh import SshAdapter, SshInventory, SshTarget, request_remote


def target(tmp_path: Path) -> SshTarget:
    key = tmp_path / "key"
    known = tmp_path / "known hosts"
    key.write_text("fixture", encoding="utf-8")
    known.write_text("fixture", encoding="utf-8")
    return SshTarget(user="netsec", identity_file=key, known_hosts_file=known)


def source() -> Source:
    return Source(text=wrap("firewall deny port 23 protocol tcp;"))


def test_ssh_uses_pinned_keys_and_source_only_on_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = Mock(
        return_value=subprocess.CompletedProcess(
            [], 0, b'{"success":true,"status":"ready","detail":"ready"}', b""
        )
    )
    monkeypatch.setattr("netsec.services.ssh.which", lambda _: "ssh")
    monkeypatch.setattr("netsec.services.ssh.subprocess.run", run)
    request = AgentRequest(source=source(), host="192.0.2.10", operation="preflight", apply=True)
    assert request_remote(request.host, target(tmp_path), request).status == "ready"
    arguments = run.call_args.args[0]
    assert "StrictHostKeyChecking=yes" in arguments
    assert "BatchMode=yes" in arguments
    assert arguments[-1] == "netsec agent"
    assert source().text not in " ".join(arguments)
    assert run.call_args.kwargs["input"] == request.model_dump_json().encode("utf-8")
    assert run.call_args.kwargs["timeout"] == 45


@pytest.mark.parametrize("user", ["-oProxyCommand=bad", "root;sh", "root\n", ""])
def test_ssh_inventory_rejects_executable_usernames(user: str, tmp_path: Path) -> None:
    with pytest.raises(ValidationError):
        SshTarget(user=user, identity_file=tmp_path, known_hosts_file=tmp_path)


def test_remote_preflight_failure_prevents_every_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remote = Mock(side_effect=RuntimeFailureError("Remote privileges unavailable"))
    monkeypatch.setattr("netsec.services.ssh.request_remote", remote)
    text = source()
    adapter = SshAdapter(
        text, SshInventory(targets={"192.0.2.10": target(tmp_path)}), 1, apply=True
    )
    with pytest.raises(RuntimeFailureError, match="privileges"):
        execute(compile_source(text.text), adapter, "ssh")
    assert remote.call_count == 1
    assert remote.call_args.args[2].operation == "preflight"


@pytest.mark.parametrize("index", [1, 9999])
def test_agent_recompiles_and_rejects_unselected_instruction(index: int) -> None:
    backend = Mock()
    backend.inspect.return_value = NativeState(
        platform="linux", addresses=("192.0.2.10",), can_manage=True
    )
    adapter = NativeAdapter(1, apply=True, backend=backend)
    request = AgentRequest(
        source=source(), host="192.0.2.10", operation="ensure", index=index, apply=True
    )
    with pytest.raises(RuntimeFailureError, match="outside"):
        handle(request, adapter)
    backend.ensure.assert_not_called()


def test_agent_applies_compiled_policy_without_accepting_raw_command() -> None:
    backend = Mock()
    backend.inspect.return_value = NativeState(
        platform="linux", addresses=("192.0.2.10",), can_manage=True
    )
    backend.ensure.return_value = ProbeResult(True, "applied", "test")
    adapter = NativeAdapter(1, apply=True, backend=backend)
    request = AgentRequest(source=source(), host="192.0.2.10", operation="ensure", apply=True)
    assert handle(request, adapter).status == "applied"
    assert backend.ensure.call_args.args[0].port == 23
    with pytest.raises(ValidationError):
        AgentRequest.model_validate({**request.model_dump(), "command": "arbitrary"})
