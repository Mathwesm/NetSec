"""Expose explicit job bundling, validation, installation and execution commands."""

from __future__ import annotations

import argparse
from pathlib import Path

from netsec.automation import AutomationJob, run_job
from netsec.core.modules import load_source
from netsec.platforms.scheduler import manage
from netsec.runtime import RuntimeFailureError

_MAX_MANIFEST = 6_100_000


def register(commands: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register persistent jobs without implicitly enabling them."""
    parser = commands.add_parser("automation", help="Manage persistent typed network jobs")
    parser.add_argument(
        "operation",
        choices=("bundle", "check", "preview", "install", "remove", "status", "execute"),
    )
    parser.add_argument("file", type=Path)
    parser.add_argument("--name", default="network-audit")
    parser.add_argument("--mode", choices=("network", "local"), default="network")
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--output-root", type=Path, default=Path("data/processed/automation"))


def run(arguments: argparse.Namespace) -> dict[str, object]:
    """Create a portable pinned source bundle or operate on an existing job manifest."""
    if arguments.operation == "bundle":
        return AutomationJob(
            name=arguments.name,
            source=load_source(arguments.file),
            mode=arguments.mode,
            interval_seconds=arguments.interval,
        ).model_dump(mode="json")
    with arguments.file.open(encoding="utf-8-sig") as stream:
        text = stream.read(_MAX_MANIFEST + 1)
    if len(text) > _MAX_MANIFEST:
        raise RuntimeFailureError("Automation manifest exceeds the input limit")
    job = AutomationJob.model_validate_json(text)
    if arguments.operation in {"check", "preview"}:
        return {"valid": True, "writes": False, "job": job.model_dump(mode="json")}
    if arguments.operation == "execute":
        if not arguments.apply:
            raise RuntimeFailureError("Executing a persistent job requires --apply")
        return run_job(job, arguments.output_root)
    return manage(job, arguments.operation, apply=arguments.apply)
