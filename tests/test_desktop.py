from __future__ import annotations

import subprocess
import sys
from unittest.mock import Mock

import pytest

from netsec.desktop_process import cli_command, request_elevation, run_command
from netsec.runtime import RuntimeFailureError


def test_desktop_paths_are_arguments_never_shell_text() -> None:
    path = "C:/policies/a file; & invalid.netsec"
    assert cli_command(["check", path]) == [sys.executable, "-m", "netsec", "check", path]


def test_desktop_preserves_failure_diagnostics(monkeypatch: pytest.MonkeyPatch) -> None:
    process = Mock(return_value=subprocess.CompletedProcess([], 2, "", "policy.netsec:3:2: E_TYPE"))
    monkeypatch.setattr("netsec.desktop_process.subprocess.run", process)
    code, output = run_command(["check", "policy.netsec"])
    assert code == 2 and "E_TYPE" in output
    assert process.call_args.kwargs["timeout"] == 120
    assert process.call_args.kwargs.get("shell", False) is False


def test_desktop_timeout_does_not_report_success(monkeypatch: pytest.MonkeyPatch) -> None:
    process = Mock(side_effect=subprocess.TimeoutExpired("netsec", 120))
    monkeypatch.setattr("netsec.desktop_process.subprocess.run", process)
    with pytest.raises(RuntimeFailureError, match="inspect state"):
        run_command(["doctor"])


def test_windows_uac_cancellation_remains_visible(monkeypatch: pytest.MonkeyPatch) -> None:
    shell = Mock(return_value=5)
    library = Mock()
    library.shell32.ShellExecuteW = shell
    monkeypatch.setattr("netsec.desktop_process.sys.platform", "win32")
    monkeypatch.setattr("netsec.desktop_process.ctypes.windll", library, raising=False)
    with pytest.raises(RuntimeFailureError, match="cancelled or denied"):
        request_elevation()
    assert shell.call_args.args[1] == "runas"
    assert "--apply" not in shell.call_args.args[3]
