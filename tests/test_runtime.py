from __future__ import annotations

import json
from pathlib import Path

import pytest

from netsec.cli import main
from netsec.core.compiler import compile_source
from netsec.evaluation import corpus, run_evaluation, wrap
from netsec.runtime import NetworkAdapter, RuntimeFailureError, Scenario, SimulationAdapter, execute


def scenario() -> Scenario:
    return Scenario.model_validate_json(
        '{"hosts":{"192.0.2.10":{"open_ports":[22,23],"services":["ssh"]}}}'
    )


def test_firewall_changes_later_checks_and_is_idempotent() -> None:
    adapter = SimulationAdapter(scenario())
    policy = compile_source(
        wrap(
            "check port 23 protocol tcp; firewall deny port 23 protocol tcp; "
            'check port 23 protocol tcp; check service "ssh";'
        )
    )
    execution = execute(policy, adapter, "simulate")
    assert [record.status for record in execution.records] == [
        "open",
        "applied",
        "blocked",
        "active",
    ]
    assert execution.success is False
    repeated = execute(policy, adapter, "simulate")
    assert repeated.records[1].status == "unchanged"


def test_missing_scenario_target_fails_before_any_rule_is_applied() -> None:
    adapter = SimulationAdapter(Scenario(hosts={}))
    with pytest.raises(RuntimeFailureError, match="missing"):
        execute(compile_source(wrap("firewall deny port 23 protocol tcp;")), adapter, "simulate")
    assert adapter.rules == {}


def test_network_mode_rejects_mixed_writes_during_preflight() -> None:
    plan = compile_source(wrap("check port 22 protocol tcp; firewall deny port 23 protocol tcp;"))
    with pytest.raises(RuntimeFailureError, match="cannot apply firewall"):
        execute(plan, NetworkAdapter(0.1), "network")


def test_evaluation_measures_all_cases_and_retains_previous_runs(tmp_path: Path) -> None:
    first, first_success = run_evaluation(tmp_path)
    second, second_success = run_evaluation(tmp_path)
    metrics = json.loads((second / "evaluation.json").read_text(encoding="utf-8"))["metrics"]
    assert len(corpus()) == 35
    assert first_success and second_success
    assert first != second and (first / "evaluation.json").is_file()
    assert metrics == {
        "invalid_programs": 25,
        "valid_controls": 10,
        "true_positives": 25,
        "false_negatives": 0,
        "false_positives": 0,
        "true_negatives": 10,
        "exact_diagnostics": 35,
    }
    assert (tmp_path / "latest.txt").read_text(encoding="utf-8").strip() == second.name


def test_cli_emits_ast_and_does_not_overwrite_outputs(tmp_path: Path) -> None:
    source = tmp_path / "policy.netsec"
    output = tmp_path / "ast.json"
    source.write_text("report 1 + 2 * 3;", encoding="utf-8")
    assert main(["ast", str(source), "--output", str(output)]) == 0
    tree = json.loads(output.read_text(encoding="utf-8"))
    assert tree["statements"][0]["expression"]["value"] == "+"
    previous = output.read_bytes()
    assert main(["compile", str(source), "--output", str(output)]) == 2
    assert output.read_bytes() == previous


def test_cli_invalid_program_has_nonzero_exit_and_location(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "bad.netsec"
    source.write_text("int value = true;", encoding="utf-8")
    assert main(["check", str(source)]) == 2
    assert "bad.netsec:1:13: E_TYPE" in capsys.readouterr().err
