"""Build desktop process requests without shell interpolation or silent elevation."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path

from netsec.runtime import RuntimeFailureError

_SHELL_EXECUTE_ERROR_LIMIT = 32


def cli_command(arguments: list[str]) -> list[str]:
    """Use the sibling packaged CLI, or the exact interpreter of this installation."""
    if getattr(sys, "frozen", False):
        executable = Path(sys.executable).parent / "cli" / "NetSec.exe"
        if not executable.is_file():
            raise RuntimeFailureError("The packaged NetSec.exe command line tool is missing")
        return [str(executable), *arguments]
    return [sys.executable, "-m", "netsec", *arguments]


def is_elevated() -> bool:
    """Read Windows administrator status without opening a consent dialog."""
    return sys.platform == "win32" and bool(ctypes.windll.shell32.IsUserAnAdmin())


def request_elevation() -> None:
    """Ask Windows UAC to open a separate administrator window; never bypass consent."""
    if sys.platform != "win32":
        raise RuntimeFailureError("Use sudo explicitly on Linux; this button is Windows-only")
    arguments = [] if getattr(sys, "frozen", False) else ["-m", "netsec.desktop"]
    shell = ctypes.windll.shell32.ShellExecuteW
    shell.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    shell.restype = ctypes.c_void_p
    result = shell(None, "runas", sys.executable, subprocess.list2cmdline(arguments), None, 1)
    if result is None or result <= _SHELL_EXECUTE_ERROR_LIMIT:
        raise RuntimeFailureError("Administrator request was cancelled or denied by Windows")


def run_command(arguments: list[str]) -> tuple[int, str]:
    """Run asynchronously from the GUI thread with UTF-8 output and no console popup."""
    environment = dict(os.environ)
    environment["PYTHONUTF8"] = "1"
    environment["NETSEC_LOG_DIR"] = str(Path.home() / ".netsec" / "logs")
    try:
        result = subprocess.run(  # noqa: S603 - internal CLI executable and separate arguments, no shell.
            cli_command(arguments),
            capture_output=True,
            timeout=120,
            check=False,
            encoding="utf-8",
            errors="replace",
            env=environment,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeFailureError(
            "Execution failed or timed out; inspect state before retrying"
        ) from error
    return result.returncode, result.stdout + result.stderr
