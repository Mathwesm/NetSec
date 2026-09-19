from threading import Barrier

import pytest

from netsec.core.compiler import Instruction, compile_source
from netsec.evaluation import wrap
from netsec.runtime import RuntimeFailureError, Scenario, SimulationAdapter, execute
from netsec.services.probes import ProbeResult


def test_parallel_checks_preserve_record_order_and_wait_before_writes() -> None:
    barrier = Barrier(3, timeout=3)

    class ConcurrentAdapter(SimulationAdapter):
        def check(self, instruction: Instruction) -> ProbeResult:
            if not self.rules:
                barrier.wait()
            return super().check(instruction)

    adapter = ConcurrentAdapter(
        Scenario.model_validate({"hosts": {"192.0.2.10": {"open_ports": (21, 22, 23)}}})
    )
    plan = compile_source(
        wrap(
            "check port 21 protocol tcp; check port 22 protocol tcp; "
            "check port 23 protocol tcp; firewall deny port 23 protocol tcp; "
            "check port 23 protocol tcp;"
        )
    )
    result = execute(plan, adapter, "simulate", workers=3)
    assert [record.status for record in result.records] == [
        "open",
        "open",
        "open",
        "applied",
        "blocked",
    ]
    assert [record.instruction.port for record in result.records] == [21, 22, 23, 23, 23]


def test_invalid_parallelism_fails_before_mutation() -> None:
    adapter = SimulationAdapter(Scenario(hosts={}))
    with pytest.raises(RuntimeFailureError, match="Workers must"):
        execute(compile_source("report 1;"), adapter, "simulate", workers=0)
    assert adapter.rules == {}
