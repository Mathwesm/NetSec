"""Measure semantic detection using declared errors and valid controls."""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from netsec.core.compiler import compile_source
from netsec.core.model import NetSecError, Source
from netsec.core.parser import parse


@dataclass(frozen=True, slots=True)
class Case:
    """Store a manually specified expected semantic outcome."""

    name: str
    source: str
    expected: str | None


def wrap(body: str) -> str:
    """Embed a play body in a fixed, nonproduction inventory."""
    return (
        'group servers { host "one" address "192.0.2.10"; }\n'
        f'play "audit" targets servers {{ {body} }}'
    )


def corpus() -> tuple[Case, ...]:
    """Return 25 deliberate semantic errors and 10 valid controls."""
    invalid = (
        ("port_zero", wrap("check port 0 protocol tcp;"), "E_PORT"),
        ("port_overflow", wrap("check port 65536 protocol tcp;"), "E_PORT"),
        ("port_negative", wrap("firewall deny port -1 protocol tcp;"), "E_PORT"),
        ("port_boolean", wrap("check port true protocol tcp;"), "E_TYPE"),
        ("port_string", wrap('check port "22" protocol tcp;'), "E_TYPE"),
        ("bad_ipv4", 'ip node = ip("999.0.0.1");', "E_ADDRESS"),
        ("bad_ipv6", 'ip node = ip("2001:::1");', "E_ADDRESS"),
        ("network_host_bits", 'network lan = network("192.0.2.1/24");', "E_ADDRESS"),
        ("bad_prefix", 'network lan = network("192.0.2.0/33");', "E_ADDRESS"),
        ("undefined_name", "report missing;", "E_UNDEFINED"),
        ("duplicate_name", "int value = 1; int value = 2;", "E_DUPLICATE"),
        ("wrong_declared_type", 'int value = "text";', "E_TYPE"),
        ("no_implicit_port", "port admin = 22;", "E_TYPE"),
        ("scope_leak", wrap("if true { int local = 1; } report local;"), "E_UNDEFINED"),
        ("bad_condition", wrap("if 1 { report 1; }"), "E_TYPE"),
        ("negative_repeat", wrap("repeat -1 { report 1; }"), "E_REPEAT"),
        ("boolean_repeat", wrap("repeat true { report 1; }"), "E_TYPE"),
        ("zero_division", "report 2 / 0;", "E_ZERO_DIVISION"),
        ("zero_remainder", "report 2 % 0;", "E_ZERO_DIVISION"),
        ("invalid_protocol", 'protocol transport = protocol("sctp");', "E_PROTOCOL"),
        ("unknown_service", wrap('check service "smtp";'), "E_SERVICE"),
        ("udp_probe", wrap("check port 53 protocol udp;"), "E_UDP_CHECK"),
        (
            "contradiction",
            wrap("firewall allow port 22 protocol tcp; firewall deny port 22 protocol tcp;"),
            "E_FIREWALL_CONFLICT",
        ),
        ("empty_group", "group empty {}", "E_GROUP_SIZE"),
        (
            "duplicate_host",
            'group nodes { host "one" address "::1"; host "two" address "0:0:0:0:0:0:0:1"; }',
            "E_DUPLICATE_HOST",
        ),
    )
    valid = (
        ("minimum_port", wrap("check port 1 protocol tcp;")),
        ("maximum_port", wrap("check port 65535 protocol tcp;")),
        ("precedence", "report 1 + 2 * 3;"),
        ("typed_ipv6", 'ip node = ip("2001:db8::1"); report node;'),
        ("network_membership", 'report ip("192.0.2.10") in network("192.0.2.0/24");'),
        ("inner_shadow", wrap("int count = 1; if true { int count = 2; report count; }")),
        ("zero_repeat", wrap("repeat 0 { report 1; }")),
        (
            "different_protocols",
            wrap("firewall allow port 53 protocol tcp; firewall deny port 53 protocol udp;"),
        ),
        (
            "identical_policies",
            wrap("firewall allow port 22 protocol tcp; firewall allow port 22 protocol tcp;"),
        ),
        (
            "dead_alternative",
            wrap(
                "if true { firewall allow port 22 protocol tcp; } "
                "else { firewall deny port 22 protocol tcp; }"
            ),
        ),
    )
    return tuple(Case(*item) for item in invalid) + tuple(
        Case(name, source, None) for name, source in valid
    )


def _measure(case: Case) -> dict[str, object]:
    # A syntax failure would invalidate this semantic experiment, so fail loudly.
    parse(Source(text=case.source, filename=case.name))
    elapsed: list[float] = []
    actual: str | None = None
    for _ in range(10):
        started = time.perf_counter_ns()
        try:
            compile_source(case.source, case.name)
            actual = None
        except NetSecError as error:
            actual = error.diagnostic.code
        elapsed.append((time.perf_counter_ns() - started) / 1000)
    return {
        **asdict(case),
        "actual": actual,
        "correct": actual == case.expected,
        "median_microseconds": statistics.median(elapsed),
    }


def run_evaluation(output_root: Path) -> tuple[Path, bool]:
    """Write reproducible cases and measured outcomes into a fresh run directory.

    Args:
        output_root: Parent directory for timestamped evaluation outputs.

    Returns:
        Output directory and whether every diagnostic matched its declared expectation.
    """
    cases = [_measure(case) for case in corpus()]
    metrics = {
        "invalid_programs": sum(case["expected"] is not None for case in cases),
        "valid_controls": sum(case["expected"] is None for case in cases),
        "true_positives": sum(
            case["expected"] is not None and case["actual"] is not None for case in cases
        ),
        "false_negatives": sum(
            case["expected"] is not None and case["actual"] is None for case in cases
        ),
        "false_positives": sum(
            case["expected"] is None and case["actual"] is not None for case in cases
        ),
        "true_negatives": sum(
            case["expected"] is None and case["actual"] is None for case in cases
        ),
        "exact_diagnostics": sum(bool(case["correct"]) for case in cases),
    }
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = output_root / f"{timestamp}-{uuid4().hex[:8]}"
    destination.mkdir(parents=True, exist_ok=False)
    payload = {"recorded_at_utc": timestamp, "repetitions": 10, "metrics": metrics, "cases": cases}
    _write_new(destination / "evaluation.json", json.dumps(payload, indent=2, ensure_ascii=False))
    rows = "\n".join(f"| {name} | {value} |" for name, value in metrics.items())
    report = (
        "# Avaliação semântica\n\nCorpus sintético: 25 erros e 10 controles válidos.\n\n"
        "| Métrica | Resultado |\n|---|---:|\n" + rows + "\n\n"
        "Cada programa foi compilado 10 vezes; o JSON registra a mediana em microssegundos. "
        "Os resultados medem este corpus. Não estimam a frequência de erros de usuários "
        "nem provam ausência de defeitos. Casos adicionais devem testar regras novas.\n"
    )
    _write_new(destination / "evaluation.md", report)
    # The pointer identifies the latest complete run; result files remain immutable.
    pointer = output_root / f".latest-{uuid4().hex}.txt"
    _write_new(pointer, destination.name)
    pointer.replace(output_root / "latest.txt")
    return destination, all(bool(case["correct"]) for case in cases)


def _write_new(path: Path, text: str) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text + "\n")
