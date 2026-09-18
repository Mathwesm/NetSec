from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

import pytest

from netsec.core.compiler import compile_source
from netsec.evaluation import wrap
from netsec.runtime import RuntimeFailureError
from netsec.services.docker import DockerAdapter, Inventory


class FakeDocker:
    """Emulate external Docker responses without running a container."""

    def __init__(self, label: str = "netsec-language", existing: str = "") -> None:
        self.label = label
        self.existing = existing
        self.writes: list[str] = []
        self.inputs: list[bytes | str] = []

    def run(self, command: list[str], **options: Any) -> subprocess.CompletedProcess[Any]:
        """Return controlled process output and record firewall transactions."""
        if command[1] == "inspect":
            data: object = [
                {
                    "Config": {"Labels": {"org.netsec.lab": self.label}},
                    "State": {"Running": True},
                    "NetworkSettings": {"Networks": {"lab": {"IPAddress": "192.0.2.10"}}},
                }
            ]
        elif command[-1] == "tables":
            data = {"nftables": [{"table": {"family": "inet", "name": "netsec"}}]}
        elif command[-1] == "input":
            data = {"nftables": [{"rule": {"comment": self.existing, "handle": 7}}]}
        else:
            payload = options.get("input", "")
            self.inputs.append(payload)
            self.writes.append(payload.decode("utf-8") if isinstance(payload, bytes) else payload)
            data = {}
        if options.get("text"):
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(data), stderr="")
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(data).encode(), stderr=b"")


def adapter(monkeypatch: pytest.MonkeyPatch, fake: FakeDocker) -> DockerAdapter:
    monkeypatch.setattr(shutil, "which", lambda _: "docker")
    monkeypatch.setattr(subprocess, "run", fake.run)
    return DockerAdapter(Inventory(probe_container="probe", targets={"192.0.2.10": "target"}), 0.1)


def test_unlabelled_container_is_rejected_without_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeDocker(label="unrelated-project")
    selected = adapter(monkeypatch, fake)
    with pytest.raises(RuntimeFailureError, match="not owned"):
        selected.preflight(compile_source(wrap("firewall deny port 23 protocol tcp;")))
    assert fake.writes == []


def test_identical_rule_is_not_duplicated(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeDocker(existing="netsec:192.0.2.10:tcp:22:allow")
    selected = adapter(monkeypatch, fake)
    rule = compile_source(wrap("firewall allow port 22 protocol tcp;")).instructions[0]
    assert selected.firewall(rule).status == "unchanged"
    assert fake.writes == []


def test_new_policy_replaces_opposite_owned_rule_atomically(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker(existing="netsec:192.0.2.10:tcp:22:deny")
    selected = adapter(monkeypatch, fake)
    rule = compile_source(wrap("firewall allow port 22 protocol tcp;")).instructions[0]
    assert selected.firewall(rule).status == "applied"
    assert len(fake.writes) == 1
    assert "delete rule inet netsec input handle 7\n" in fake.writes[0]
    assert "tcp dport 22 accept" in fake.writes[0]


def test_nft_input_is_bytes_to_prevent_windows_crlf_translation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker()
    selected = adapter(monkeypatch, fake)
    rule = compile_source(wrap("firewall deny port 23 protocol tcp;")).instructions[0]
    selected.firewall(rule)
    assert isinstance(fake.inputs[0], bytes)
    assert b"\r\n" not in fake.inputs[0]
