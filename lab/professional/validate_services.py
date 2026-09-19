"""Validate actual systemd service deployment and persistent job execution in a disposable VM."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from http import HTTPStatus
from pathlib import Path
from uuid import uuid4

import httpx
from loguru import logger

from netsec.automation import AutomationJob
from netsec.core.compiler import compile_source
from netsec.core.model import Source
from netsec.platforms import systemd
from netsec.platforms.native import NativeAdapter
from netsec.platforms.process import command
from netsec.platforms.scheduler import manage
from netsec.platforms.servers import resource_id
from netsec.runtime import RuntimeFailureError, execute


def main() -> int:
    """Exercise HTTP content, DNS answers, drift repair, boot activation and owned removal."""
    systemd.require_systemd()
    token = uuid4().hex[:8]
    source = Source(
        text=f"""
class Web {{ port endpoint; }}
Web app = Web(port(18089));
group local {{ host "local" address "127.0.0.1"; }}
play "deploy" targets local {{
  server http "site-{token}" port app.endpoint response "NetSec deployed {token}";
  server dns "dns-{token}" port 15357 record "app.netsec.test" address current_host;
  check dns "app.netsec.test" port 15357 expect current_host;
}}
"""
    )
    plan = compile_source(source.text)
    adapter = NativeAdapter(2, apply=True)
    job = AutomationJob(name=f"services-{token}", source=source, mode="local", interval_seconds=60)
    destination = Path("data/processed") / f"services-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{token}"
    destination.mkdir(parents=True)
    results: dict[str, object] = {}
    try:
        first = execute(plan, adapter, "local", fail_fast=True)
        results["first"] = first.model_dump(mode="json")
        if not first.success:
            raise RuntimeError("Initial service deployment failed")
        with httpx.Client(timeout=3, trust_env=False) as client:
            response = client.get("http://127.0.0.1:18089/")
            results["http_content"] = (
                response.status_code == HTTPStatus.OK
                and response.text == f"NetSec deployed {token}"
            )
        repeated = execute(plan, adapter, "local", fail_fast=True)
        results["idempotent"] = repeated.success and all(
            item.status == "unchanged" for item in repeated.records[:2]
        )
        resource = plan.instructions[0].resource
        if resource is None:
            raise RuntimeError("Missing compiled HTTP resource")
        unit = resource_id(resource) + ".service"
        command("systemctl", ["stop", unit])
        repaired = execute(plan, adapter, "local", fail_fast=True)
        results["stopped_service_recovered"] = (
            repaired.success and repaired.records[0].status == "applied"
        )
        _validate_job(job, results)
        results["service_enabled"] = systemd.unit_state(unit, "UnitFileState")
        success = (
            results["http_content"]
            and results["idempotent"]
            and results["stopped_service_recovered"]
            and results["job_result"] == "success"
            and results["timer_enabled"] == "enabled"
            and results["service_enabled"] == "enabled"
            and results["durable_evidence"]
        )
        results["success"] = bool(success)
    finally:
        try:
            results["job_removal"] = manage(job, "remove", apply=True)
        except RuntimeFailureError as error:
            results["job_cleanup_error"] = str(error)
            results["success"] = False
        try:
            results["server_removal"] = [item.status for item in adapter.remove_servers(plan)]
        except RuntimeFailureError as error:
            results["server_cleanup_error"] = str(error)
            results["success"] = False
        (destination / "evidence.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    logger.info(
        "Systemd integration finished | success={} evidence={}", results.get("success"), destination
    )
    return 0 if results.get("success") else 1


def _validate_job(job: AutomationJob, results: dict[str, object]) -> None:
    results["job_install"] = manage(job, "install", apply=True)
    results["job_repeat"] = manage(job, "install", apply=True)
    job_unit = f"netsec-job-{job.name}.service"
    command("systemctl", ["start", job_unit])
    deadline = time.monotonic() + 20
    while (
        systemd.unit_state(job_unit, "ActiveState") == "activating" and time.monotonic() < deadline
    ):
        time.sleep(0.2)
    results["job_result"] = systemd.unit_state(job_unit, "Result")
    results["timer_enabled"] = systemd.unit_state(f"netsec-job-{job.name}.timer", "UnitFileState")
    runs = list((Path("/var/lib/netsec/jobs") / job.name).glob("*/result.json"))
    results["durable_evidence"] = bool(runs) and all(
        json.loads(path.read_text(encoding="utf-8"))["success"] for path in runs
    )


if __name__ == "__main__":
    raise SystemExit(main())
