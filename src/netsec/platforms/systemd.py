"""Install exclusively owned systemd units and immutable configuration revisions."""

from __future__ import annotations

import hashlib
import os
import platform
import stat
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import uuid4

from netsec.platforms.process import command
from netsec.runtime import RuntimeFailureError

OWNER = "# netsec-systemd-v1"
UNITS = Path("/etc/systemd/system")
CONFIG = Path("/etc/netsec")
_WRITE_BITS = stat.S_IWGRP | stat.S_IWOTH
_FIRST_PRINTABLE = 32


def require_systemd() -> None:
    """Require real root and a running systemd manager before installation."""
    if platform.system() != "Linux" or getattr(os, "geteuid", lambda: -1)() != 0:
        raise RuntimeFailureError("Systemd deployment requires Linux root")
    command("systemctl", ["show", "--property=Version", "--value"])


def protected_path(path: Path) -> None:
    """Reject symlinks and writable non-root ancestors of privileged configuration."""
    for entry in (path, *path.parents):
        if entry.is_symlink():
            raise RuntimeFailureError("Privileged configuration cannot traverse symlinks")
        if entry.exists():
            info = entry.stat()
            if info.st_uid != 0 or info.st_mode & _WRITE_BITS:
                raise RuntimeFailureError(
                    f"Privileged path must be root-owned and protected: {entry}"
                )


def quote(value: str) -> str:
    """Quote one systemd argument without environment or specifier expansion."""
    if any(ord(char) < _FIRST_PRINTABLE for char in value):
        raise RuntimeFailureError("Systemd arguments cannot contain control characters")
    return (
        '"'
        + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$")
        + '"'
    )


def owned_text(path: Path) -> str | None:
    """Read before replacing and refuse unrelated units, including symbolic links."""
    protected_path(path)
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    if not text.startswith(OWNER + "\n"):
        raise RuntimeFailureError("Existing systemd unit lacks the NetSec ownership marker")
    return text


def atomic_unit(path: Path, text: str) -> None:
    """Replace an inspected owned unit atomically after preparing its full contents."""
    owned_text(path)
    with NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="\n", dir=path.parent, prefix=".netsec-", delete=False
    ) as stream:
        temporary = Path(stream.name)
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o644)
    temporary.replace(path)


def revision(root: Path, files: dict[str, str], *, private: bool = False) -> Path:
    """Reuse intact revisions; retain damaged ones and write a new immutable revision."""
    protected_path(root)
    digest = hashlib.sha256(repr(sorted(files.items())).encode("utf-8")).hexdigest()[:20]
    destination = root / digest
    if destination.exists():
        candidates = [destination, *sorted(root.glob(f"{digest}-*"))]
        for candidate in candidates:
            if _intact(candidate, files):
                return candidate
        destination = root / f"{digest}-{uuid4().hex[:8]}"
    destination.mkdir(parents=True, mode=0o700 if private else 0o755)
    for name, content in files.items():
        path = destination / name
        with path.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        path.chmod(0o600 if private else 0o644)
    return destination


def _intact(directory: Path, files: dict[str, str]) -> bool:
    try:
        protected_path(directory)
        for name, content in files.items():
            path = directory / name
            protected_path(path)
            if not path.is_file() or path.read_text(encoding="utf-8") != content:
                return False
    except (RuntimeFailureError, OSError, UnicodeError):
        return False
    return True


def unit_state(name: str, property_name: str) -> str:
    """Read one systemd state without parsing localized prose."""
    return command("systemctl", ["show", name, f"--property={property_name}", "--value"]).strip()


def install_unit(name: str, text: str, *, start: bool = True) -> bool:
    """Reconcile an owned service; return whether configuration or runtime state changed."""
    path = UNITS / name
    current = owned_text(path)
    changed = current != text
    if changed:
        atomic_unit(path, text)
        command("systemctl", ["daemon-reload"])
    if unit_state(name, "UnitFileState") != "enabled":
        command("systemctl", ["enable", name])
        changed = True
    if start and (changed or unit_state(name, "ActiveState") != "active"):
        command("systemctl", ["restart", name])
        changed = True
    return changed


def remove_unit(name: str) -> bool:
    """Disable an owned unit and archive its definition instead of deleting configuration."""
    path = UNITS / name
    if owned_text(path) is None:
        return False
    command("systemctl", ["disable", "--now", name])
    path.replace(UNITS / f"{name}.{uuid4().hex}.retired")
    command("systemctl", ["daemon-reload"])
    return True
