"""Command-line interface for every compiler phase and execution adapter."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid4

from loguru import logger
from pydantic import ValidationError

from netsec.config import Settings
from netsec.core.compiler import compile_source
from netsec.core.lexer import tokenize
from netsec.core.model import NetSecError, Source
from netsec.core.parser import parse
from netsec.core.values import MAX_PORT
from netsec.editor import EditorRequest, analyze
from netsec.evaluation import run_evaluation
from netsec.lab_validation import validate_lab
from netsec.runtime import (
    Adapter,
    NetworkAdapter,
    RuntimeFailureError,
    Scenario,
    SimulationAdapter,
    execute,
)
from netsec.services.docker import DockerAdapter, Inventory, probe_json
from netsec.services.probes import probe
from netsec.utils.logger import setup_logging

_MAX_INPUT = 1_000_000


def argument_parser() -> argparse.ArgumentParser:
    """Define discoverable commands without hidden network side effects."""
    parser = argparse.ArgumentParser(prog="netsec", description="Typed network security language")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("tokens", "ast", "check", "compile", "run"):
        command = commands.add_parser(name)
        command.add_argument("file", type=Path)
        command.add_argument("--output", type=Path, help="New output file; never overwrites")
        if name == "run":
            _run_arguments(command)
    commands.add_parser("editor", help="Analyze a JSON request from stdin; no execution")
    evaluation = commands.add_parser("evaluate", help="Measure the semantic rejection corpus")
    evaluation.add_argument("--output-root", type=Path, default=Path("data/processed"))
    laboratory = commands.add_parser("lab-test", help="Validate owned lab firewall behavior")
    laboratory.add_argument("--inventory", type=Path, default=Path("lab/inventory.json"))
    laboratory.add_argument("--docker-executable", default="docker")
    laboratory.add_argument("--output-root", type=Path, default=Path("data/processed"))
    probe_parser = commands.add_parser("probe", help="Probe one explicit IP endpoint")
    probe_parser.add_argument("host", type=ip_address)
    probe_parser.add_argument("port", type=int)
    probe_parser.add_argument("--service", choices=("ssh", "http", "https"), default="")
    probe_parser.add_argument("--timeout", type=float, default=2.0)
    return parser


def _run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mode", choices=("simulate", "network", "docker"), default="simulate")
    parser.add_argument("--scenario", type=Path, help="Required JSON scenario for simulate mode")
    parser.add_argument("--inventory", type=Path, help="Required labelled-container inventory")
    parser.add_argument("--docker-executable", default="docker")
    parser.add_argument("--timeout", type=float)


def _read(path: Path) -> str:
    with path.open("r", encoding="utf-8-sig") as stream:
        text = stream.read(_MAX_INPUT + 1)
    if len(text) > _MAX_INPUT:
        raise RuntimeFailureError("Input file exceeds 1000000 characters")
    return text


def _emit(value: object, output: Path | None = None) -> None:
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if output is None:
        sys.stdout.write(text)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)


def _adapter(arguments: argparse.Namespace, settings: Settings) -> Adapter:
    if arguments.mode == "network":
        return NetworkAdapter(settings.timeout)
    if arguments.mode == "docker":
        if arguments.inventory is None:
            raise RuntimeFailureError("Docker mode requires --inventory")
        inventory = Inventory.model_validate_json(_read(arguments.inventory))
        return DockerAdapter(inventory, settings.timeout, arguments.docker_executable)
    if arguments.scenario is None:
        raise RuntimeFailureError("Simulation requires --scenario; responses are never invented")
    return SimulationAdapter(Scenario.model_validate_json(_read(arguments.scenario)))


def _source_command(arguments: argparse.Namespace) -> int:
    source = Source(text=_read(arguments.file), filename=str(arguments.file))
    if arguments.command == "tokens":
        _emit([asdict(token) for token in tokenize(source)], arguments.output)
        return 0
    if arguments.command == "ast":
        _emit(asdict(parse(source)), arguments.output)
        return 0
    plan = compile_source(source.text, source.filename)
    if arguments.command == "check":
        _emit({"valid": True, "instructions": len(plan.instructions)}, arguments.output)
        return 0
    if arguments.command == "compile":
        _emit(plan.model_dump(mode="json"), arguments.output)
        return 0
    settings = Settings() if arguments.timeout is None else Settings(timeout=arguments.timeout)
    setup_logging(settings.log_dir)
    result = execute(plan, _adapter(arguments, settings), arguments.mode)
    logger.bind(run_id=str(uuid4())).info(
        "Execution completed | instructions={} failed={}",
        len(result.records),
        sum(not record.success for record in result.records),
    )
    _emit({"success": result.success, **result.model_dump(mode="json")}, arguments.output)
    return 0 if result.success else 1


def _dispatch(arguments: argparse.Namespace) -> int:
    if arguments.command == "lab-test":
        destination, success = validate_lab(
            arguments.inventory, arguments.docker_executable, arguments.output_root
        )
        _emit({"output": str(destination), "success": success})
        return 0 if success else 1
    if arguments.command == "editor":
        request = EditorRequest.model_validate_json(sys.stdin.read(_MAX_INPUT + 1))
        _emit(analyze(request))
        return 0
    if arguments.command == "probe":
        if not 1 <= arguments.port <= MAX_PORT:
            raise RuntimeFailureError("Port must be between 1 and 65535")
        settings = Settings(timeout=arguments.timeout)
        sys.stdout.write(
            probe_json(
                probe(str(arguments.host), arguments.port, arguments.service, settings.timeout)
            )
            + "\n"
        )
        return 0
    if arguments.command == "evaluate":
        destination, success = run_evaluation(arguments.output_root)
        _emit({"output": str(destination), "success": success})
        return 0 if success else 1
    return _source_command(arguments)


@logger.catch(reraise=True)
def main(argv: list[str] | None = None) -> int:
    """Run a command and return a truthful exit status.

    Args:
        argv: Optional argument list, excluding the executable name.

    Returns:
        Zero for success, one for failed observations, two for invalid inputs.
    """
    arguments = argument_parser().parse_args(argv)
    try:
        return _dispatch(arguments)
    except NetSecError as error:
        sys.stderr.write(f"{error}\n")
        return 2
    except ValidationError as error:
        # Do not echo entire submitted input or environment values into diagnostics.
        fields = ", ".join(".".join(map(str, item["loc"])) for item in error.errors())
        sys.stderr.write(f"Invalid input fields: {fields}\n")
        return 2
    except (OSError, RuntimeFailureError) as error:
        sys.stderr.write(f"Execution error: {error}\n")
        return 2
