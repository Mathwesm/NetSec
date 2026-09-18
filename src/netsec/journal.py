"""Retain source-linked execution evidence without overwriting an earlier run."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from netsec.core.compiler import Plan
from netsec.runtime import Record


class Journal:
    """Persist the intended plan and each completed instruction in a fresh directory."""

    def __init__(self, plan: Plan, mode: str, root: Path) -> None:
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        self.directory = root / f"run-{stamp}-{uuid4().hex[:8]}"
        self.directory.mkdir(parents=True, exist_ok=False)
        with (self.directory / "plan.json").open("x", encoding="utf-8") as stream:
            json.dump({"mode": mode, "plan": plan.model_dump(mode="json")}, stream, indent=2)
        self.records = self.directory / "records.jsonl"
        self.records.touch(exist_ok=False)

    def append(self, record: Record) -> None:
        """Flush each finished observation; replay still rechecks state before converging."""
        with self.records.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(record.model_dump_json() + "\n")
            stream.flush()
            os.fsync(stream.fileno())
