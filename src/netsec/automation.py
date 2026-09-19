"""Validate and execute persistent, bounded network reconciliation jobs."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Literal, Self
from uuid import uuid4

from loguru import logger
from pydantic import BaseModel, ConfigDict, Field, model_validator

from netsec.core.compiler import compile_source
from netsec.core.model import Source
from netsec.journal import Journal
from netsec.platforms.native import NativeAdapter
from netsec.platforms.wireguard import apply_tunnel
from netsec.platforms.wireguard_models import Tunnel, TunnelSecret
from netsec.runtime import Adapter, NetworkAdapter, RuntimeFailureError, execute
from netsec.services.notifier import notify_failure
from netsec.services.ssh import SshAdapter, SshInventory
from netsec.utils.logger import setup_logging


class AutomationJob(BaseModel):
    """Describe a pinned source bundle or VPN reconciliation without arbitrary commands."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    version: Literal[1] = 1
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    kind: Literal["policy", "vpn"] = "policy"
    interval_seconds: int = Field(default=300, ge=60, le=43200, strict=True)
    source: Source | None = None
    mode: Literal["network", "local", "ssh"] = "network"
    inventory: SshInventory | None = None
    tunnel: Tunnel | None = None
    timeout: float = Field(default=2.0, ge=0.1, le=30)
    workers: int = Field(default=4, ge=1, le=32, strict=True)
    secrets_file: Path | None = None
    alert_on_failure: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def coherent(self) -> Self:
        """Reject ignored or contradictory fields before a privileged scheduler is touched."""
        if self.kind == "vpn":
            if self.tunnel is None or self.source is not None or self.inventory is not None:
                raise ValueError("VPN jobs require only a tunnel manifest")
        else:
            if self.source is None or self.tunnel is not None:
                raise ValueError("Policy jobs require only a source bundle")
            if (self.mode == "ssh") != (self.inventory is not None):
                raise ValueError("SSH jobs require an inventory; other modes cannot use one")
            plan = compile_source(
                self.source.text, self.source.filename, modules=self.source.modules
            )
            if self.mode == "network":
                NetworkAdapter(self.timeout).preflight(plan)
        if self.secrets_file is not None and not self.secrets_file.is_absolute():
            raise ValueError("Persistent jobs require an absolute protected secrets path")
        if self.inventory is not None and any(
            not path.is_absolute()
            for target in self.inventory.targets.values()
            for path in (target.identity_file, target.known_hosts_file)
        ):
            raise ValueError("Persistent jobs require absolute SSH key and known_hosts paths")
        return self


def job_adapter(job: AutomationJob) -> Adapter:
    """Choose only explicitly supported execution modes."""
    if job.mode == "local":
        return NativeAdapter(job.timeout, apply=True)
    if job.mode == "ssh" and job.source is not None and job.inventory is not None:
        return SshAdapter(job.source, job.inventory, job.timeout, apply=True)
    return NetworkAdapter(job.timeout)


def run_job(job: AutomationJob, output_root: Path) -> dict[str, object]:
    """Reconcile one run and retain correlated metrics and instruction-level journals.

    Args:
        job: Validated pinned automation input.
        output_root: Dedicated persistent run directory; each execution uses a new child.

    Returns:
        Public execution metrics and the unique evidence location.

    Raises:
        RuntimeFailureError: If preflight, execution or configured failure notification fails.
    """
    run_id = uuid4().hex
    directory = output_root / f"{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{run_id}"
    directory.mkdir(parents=True)
    setup_logging(output_root / "logs")
    started = perf_counter()
    error_code = ""
    error_message = ""
    try:
        success, total, failed = _perform(job, directory)
    except (RuntimeFailureError, OSError, ValueError) as error:
        success, total, failed = False, 0, 1
        error_code = type(error).__name__
        error_message = (
            str(error)
            if isinstance(error, RuntimeFailureError)
            else "Invalid input or OS I/O failure"
        )
    metrics: dict[str, object] = {
        "run_id": run_id,
        "job": job.name,
        "success": success,
        "instructions": total,
        "failed": failed,
        "duration_seconds": round(perf_counter() - started, 6),
        "finished_at": datetime.now(UTC).isoformat(),
        "error_type": error_code,
        "error_message": error_message,
        "evidence": str(directory),
    }
    with (directory / "result.json").open("x", encoding="utf-8") as stream:
        json.dump(metrics, stream, indent=2)
    logger.bind(run_id=run_id, job=job.name).info(
        "Automation completed | success={} failed={}", success, failed
    )
    if not success and job.alert_on_failure:
        notify_failure(job.name, run_id)
    return metrics


def _perform(job: AutomationJob, directory: Path) -> tuple[bool, int, int]:
    if job.tunnel is not None:
        result = apply_tunnel(job.tunnel, TunnelSecret().private_key, apply=True)
        return result.success, 1, int(not result.success)
    if job.source is None:
        raise RuntimeFailureError("Policy job has no source")
    plan = compile_source(job.source.text, job.source.filename, modules=job.source.modules)
    journal = Journal(plan, job.mode, directory)
    execution = execute(
        plan, job_adapter(job), job.mode, on_record=journal.append, workers=job.workers
    )
    return (
        execution.success,
        len(execution.records),
        sum(not item.success for item in execution.records),
    )
