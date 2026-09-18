from __future__ import annotations

import json
from pathlib import Path

from netsec.core.compiler import compile_source
from netsec.evaluation import wrap
from netsec.journal import Journal
from netsec.runtime import Scenario, SimulationAdapter, execute


def test_fail_fast_keeps_failed_record_and_never_runs_following_rule(tmp_path: Path) -> None:
    plan = compile_source(wrap("check port 23 protocol tcp; firewall deny port 80 protocol tcp;"))
    adapter = SimulationAdapter(Scenario.model_validate_json('{"hosts":{"192.0.2.10":{}}}'))
    journal = Journal(plan, "simulate", tmp_path)
    result = execute(plan, adapter, "simulate", fail_fast=True, on_record=journal.append)
    assert not result.success and len(result.records) == 1
    assert adapter.rules == {}
    records = [
        json.loads(line) for line in journal.records.read_text(encoding="utf-8").splitlines()
    ]
    assert records[0]["success"] is False
    assert records[0]["instruction"]["port"] == 23
    second = Journal(plan, "simulate", tmp_path)
    assert second.directory != journal.directory
    assert journal.records.read_text(encoding="utf-8").strip()
