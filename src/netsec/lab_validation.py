"""Demonstrate real firewall behavior and retain timestamped evidence."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from tenacity import Retrying, retry_if_result, stop_after_delay, wait_random_exponential

from netsec.core.compiler import Plan, compile_source
from netsec.runtime import Execution, execute
from netsec.services.docker import DockerAdapter, Inventory


def _save(destination: Path, name: str, execution: Execution) -> None:
    with (destination / f"{name}.json").open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(execution.model_dump_json(indent=2) + "\n")


def _baseline(plan: Plan, adapter: DockerAdapter) -> Execution:
    retrying = Retrying(
        stop=stop_after_delay(30),
        wait=wait_random_exponential(max=2),
        retry=retry_if_result(lambda result: not result.success),
        retry_error_callback=lambda state: state.outcome.result() if state.outcome else None,
    )
    result = retrying(execute, plan, adapter, "docker")
    if not isinstance(result, Execution):
        raise TypeError("Unexpected readiness result")
    return result


def validate_lab(inventory_path: Path, executable: str, output_root: Path) -> tuple[Path, bool]:
    """Check baseline, policy application, idempotence and blocked connections.

    Args:
        inventory_path: Explicit inventory of owned containers.
        executable: Docker executable to invoke without a shell.
        output_root: Root for new evidence directories.

    Returns:
        Evidence directory and combined validation outcome.
    """
    plans = {
        name: compile_source(
            Path(f"lab/{name}.netsec").read_text(encoding="utf-8"), f"lab/{name}.netsec"
        )
        for name in ("before", "protect", "after")
    }
    inventory = Inventory.model_validate_json(inventory_path.read_text(encoding="utf-8"))
    adapter = DockerAdapter(inventory, 1.0, executable)
    adapter.reset_managed_rules(plans["before"])
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = output_root / f"lab-{stamp}-{uuid4().hex[:8]}"
    destination.mkdir(parents=True, exist_ok=False)
    before = _baseline(plans["before"], adapter)
    _save(destination, "before", before)
    if not before.success:
        return destination, False
    applied = execute(plans["protect"], adapter, "docker")
    _save(destination, "protect", applied)
    repeated = execute(plans["protect"], adapter, "docker")
    _save(destination, "repeat", repeated)
    after = execute(plans["after"], adapter, "docker")
    _save(destination, "after", after)
    checks = {
        "baseline_reachable": before.success,
        "policy_applied_and_services_preserved": applied.success,
        "reapplication_unchanged": repeated.success
        and all(
            record.status == "unchanged"
            for record in repeated.records
            if record.instruction.operation in {"allow", "deny"}
        ),
        "port_23_blocked": bool(after.records)
        and all(record.status == "timeout" for record in after.records),
    }
    with (destination / "summary.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(checks, stream, indent=2)
    return destination, all(checks.values())
