"""Persist validated jobs with systemd or the Windows Task Scheduler."""

from __future__ import annotations

import json
import platform
import stat
import subprocess
import sys
from pathlib import Path

from netsec.automation import AutomationJob
from netsec.platforms import systemd
from netsec.platforms.process import command, decode
from netsec.runtime import RuntimeFailureError


def cli_arguments() -> list[str]:
    """Locate the current CLI without relying on an interactive PATH."""
    return [sys.executable] if getattr(sys, "frozen", False) else [sys.executable, "-m", "netsec"]


def _linux_preflight(job: AutomationJob, *, install: bool) -> None:
    systemd.require_systemd()
    if install and job.kind == "vpn" and job.secrets_file is None:
        raise RuntimeFailureError("Persistent VPN jobs require a secrets_file available at boot")
    # A privileged job must never load interpreter/package code writable by regular users.
    if install:
        systemd.protected_path(Path(sys.executable).resolve())
        systemd.protected_path(Path(__file__).resolve())
    systemd.protected_path(systemd.CONFIG)
    if install and job.secrets_file is not None:
        systemd.protected_path(job.secrets_file)
        if not job.secrets_file.is_file() or job.secrets_file.stat().st_mode & (
            stat.S_IRWXG | stat.S_IRWXO
        ):
            raise RuntimeFailureError("Secrets file must exist with root-only permissions (0600)")
    for suffix in ("service", "timer"):
        systemd.owned_text(systemd.UNITS / f"netsec-job-{job.name}.{suffix}")


def service_text(job: AutomationJob, manifest: Path, executable: list[str]) -> str:
    """Render a fixed runner invocation, never an arbitrary source-controlled shell."""
    arguments = [
        *executable,
        "automation",
        "execute",
        manifest.as_posix(),
        "--apply",
        "--output-root",
        f"/var/lib/netsec/jobs/{job.name}",
    ]
    environment = _environment_file(job.secrets_file) if job.secrets_file else ""
    return (
        f"{systemd.OWNER}\n[Unit]\nDescription=NetSec job {job.name}\n"
        "Wants=network-online.target\nAfter=network-online.target\n"
        "[Service]\nType=oneshot\nUser=root\nUMask=0077\n"
        f"{environment}ExecStart={' '.join(map(systemd.quote, arguments))}\n"
        "WorkingDirectory=/\nTimeoutStartSec=300\nTimeoutStopSec=15\n"
        "[Install]\nWantedBy=multi-user.target\n"
    )


def _environment_file(path: Path) -> str:
    # Unlike ExecStart, EnvironmentFile parses a literal path, not a quoted argument.
    value = path.as_posix()
    if value != value.strip() or any(not char.isprintable() or char in "*?[]\\" for char in value):
        raise RuntimeFailureError("Secrets path cannot contain glob patterns or control characters")
    return "EnvironmentFile=" + value.replace("%", "%%") + "\n"


def timer_text(job: AutomationJob) -> str:
    """Schedule boot reconciliation and recurring non-overlapping executions."""
    return (
        f"{systemd.OWNER}\n[Unit]\nDescription=NetSec timer {job.name}\n"
        f"[Timer]\nOnBootSec=30\nOnUnitInactiveSec={job.interval_seconds}\n"
        "RandomizedDelaySec=10\nAccuracySec=1\n"
        f"Unit=netsec-job-{job.name}.service\n[Install]\nWantedBy=timers.target\n"
    )


def manage(job: AutomationJob, operation: str, *, apply: bool) -> dict[str, object]:
    """Install/remove only owned jobs; status does not change scheduler state."""
    if operation != "status" and not apply:
        raise RuntimeFailureError("Persistent scheduler changes require --apply")
    if platform.system() == "Windows":
        return _windows(job, operation)
    if platform.system() != "Linux":
        raise RuntimeFailureError("Persistent jobs support Windows and systemd Linux")
    _linux_preflight(job, install=operation == "install")
    name = f"netsec-job-{job.name}"
    if operation == "status":
        return {
            "timer": systemd.unit_state(name + ".timer", "ActiveState"),
            "enabled": systemd.unit_state(name + ".timer", "UnitFileState"),
            "last_result": systemd.unit_state(name + ".service", "Result"),
        }
    if operation == "remove":
        timer = systemd.remove_unit(name + ".timer")
        service = systemd.remove_unit(name + ".service")
        return {"status": "removed" if timer or service else "unchanged"}
    directory = systemd.revision(
        systemd.CONFIG / "jobs" / name, {"job.json": job.model_dump_json(indent=2)}, private=True
    )
    service = systemd.install_unit(
        name + ".service", service_text(job, directory / "job.json", cli_arguments()), start=False
    )
    timer = systemd.install_unit(name + ".timer", timer_text(job))
    return {
        "status": "applied" if service or timer else "unchanged",
        "manifest": str(directory / "job.json"),
    }


def _windows(job: AutomationJob, operation: str) -> dict[str, object]:
    if job.kind == "vpn" or job.mode == "ssh" or job.secrets_file is not None:
        raise RuntimeFailureError(
            "Windows scheduled jobs currently require local/network policies without secrets files"
        )
    bridge = Path(__file__).with_name("scheduler_bridge.ps1")
    payload = {
        "operation": operation,
        "job": job.model_dump(mode="json"),
        "executable": cli_arguments()[0],
        "arguments": cli_arguments()[1:],
    }
    result = decode(
        command(
            "powershell",
            [
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "RemoteSigned",
                "-File",
                str(bridge),
            ],
            json.dumps(payload),
        )
    )
    if not isinstance(result, dict):
        raise RuntimeFailureError("Invalid Windows scheduler response")
    if result.get("success") is False:
        raise RuntimeFailureError(
            f"Scheduler bridge failed at line {result.get('line')}: {result.get('error_id')}"
        )
    return result


def windows_argument_line(arguments: list[str]) -> str:
    """Quote argv using the Windows runtime convention for tests and packaging tools."""
    return subprocess.list2cmdline(arguments)
