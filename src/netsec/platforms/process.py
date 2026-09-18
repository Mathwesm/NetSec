"""Bound subprocess execution without invoking an application shell."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from netsec.runtime import RuntimeFailureError


def command(executable: str, arguments: list[str], payload: str | None = None) -> str:
    """Run an installed tool with binary UTF-8 stdin and a fixed deadline.

    Args:
        executable: Executable name or explicit trusted path.
        arguments: Separate arguments, never a shell command string.
        payload: Optional structured stdin, preserved with LF line endings.

    Returns:
        Decoded UTF-8 stdout.

    Raises:
        RuntimeFailureError: If the dependency, permission or execution fails.
    """
    resolved = shutil.which(executable)
    if resolved is None:
        raise RuntimeFailureError(f"Required executable is unavailable: {executable}")
    try:
        result = subprocess.run(  # noqa: S603 - resolved executable, no shell, validated argv.
            [str(Path(resolved).resolve()), *arguments],
            input=payload.encode("utf-8") if payload is not None else None,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeFailureError(f"{executable} failed or exceeded 30 seconds") from error
    if result.returncode:
        raise RuntimeFailureError(
            f"{executable} exited with {result.returncode}; check privileges and system policy"
        )
    return result.stdout.decode("utf-8-sig")


def decode(text: str) -> object:
    """Decode a process response without including submitted content in errors."""
    try:
        return json.loads(text)
    except (ValueError, UnicodeError) as error:
        raise RuntimeFailureError("Invalid JSON from platform command") from error
