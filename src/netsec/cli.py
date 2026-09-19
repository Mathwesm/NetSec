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

from netsec import automation_cli, vpn_cli
from netsec.agent import AgentRequest, handle
from netsec.config import Settings
from netsec.core.compiler import Plan, compile_source
from netsec.core.lexer import tokenize
from netsec.core.model import NetSecError, Source
from netsec.core.modules import load_source
from netsec.core.parser import parse
from netsec.core.values import MAX_PORT
from netsec.editor import EditorRequest, analyze
from netsec.evaluation import run_evaluation
from netsec.journal import Journal
from netsec.lab_validation import validate_lab
from netsec.platforms.native import NativeAdapter, native_backend, policy_rules
from netsec.runtime import (
    Adapter,
    NetworkAdapter,
    RuntimeFailureError,
    Scenario,
    SimulationAdapter,
    execute,
)
from netsec.services.dns import probe_dns
from netsec.services.docker import DockerAdapter, Inventory, probe_json
from netsec.services.probes import probe
from netsec.services.ssh import SshAdapter, SshInventory
from netsec.utils.logger import setup_logging

_MAX_INPUT = 1_000_000


def argument_parser() -> argparse.ArgumentParser:
    """Define discoverable commands without hidden network side effects."""
    parser = argparse.ArgumentParser(prog="netsec", description="Typed network security language")
    commands = parser.add_subparsers(dest="command", required=True)
    vpn_cli.register(commands)
    automation_cli.register(commands)
    for name in (
        "tokens",
        "ast",
        "check",
        "compile",
        "preview",
        "run",
        "firewall-remove",
        "server-remove",
    ):
        command = commands.add_parser(name)
        command.add_argument("file", type=Path)
        command.add_argument("--output", type=Path, help="New output file; never overwrites")
        if name in {"run", "firewall-remove", "server-remove"}:
            _run_arguments(command)
    commands.add_parser("doctor", help="Read native firewall prerequisites without elevation")
    commands.add_parser("agent", help="Process one constrained SSH source request from stdin")
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
    probe_parser.add_argument("--dns-name", default="")
    probe_parser.add_argument("--expect", default="")
    return parser


def _run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mode", choices=("simulate", "network", "docker", "local", "ssh"), default="simulate"
    )
    parser.add_argument(
        "--apply", action="store_true", help="Authorize local or SSH firewall writes"
    )
    parser.add_argument(
        "--allow-management-port", action="store_true", help="Local-only explicit override"
    )
    parser.add_argument(
        "--fail-fast", action="store_true", help="Stop after the first failed instruction"
    )
    parser.add_argument("--scenario", type=Path, help="Required JSON scenario for simulate mode")
    parser.add_argument("--inventory", type=Path, help="Required labelled-container inventory")
    parser.add_argument("--docker-executable", default="docker")
    parser.add_argument("--timeout", type=float)
    parser.add_argument(
        "--workers", type=int, default=1, help="Parallel checks (1..32); fail-fast remains serial"
    )
    parser.add_argument("--journal-root", type=Path, default=Path("data/processed"))


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


def _adapter(arguments: argparse.Namespace, settings: Settings, source: Source) -> Adapter:
    if arguments.mode == "local":
        return NativeAdapter(
            settings.timeout,
            apply=arguments.apply,
            allow_management_port=arguments.allow_management_port,
        )
    if arguments.mode == "ssh":
        if arguments.inventory is None:
            raise RuntimeFailureError("SSH mode requires --inventory")
        if arguments.allow_management_port:
            raise RuntimeFailureError("Management-port override is unavailable through SSH")
        return SshAdapter(
            source,
            SshInventory.model_validate_json(_read(arguments.inventory)),
            settings.timeout,
            apply=arguments.apply,
        )
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
    if arguments.output is not None and arguments.output.exists():
        raise RuntimeFailureError("Output file already exists; choose a new path before execution")
    source = load_source(arguments.file)
    if arguments.command == "tokens":
        _emit([asdict(token) for token in tokenize(source)], arguments.output)
        return 0
    if arguments.command == "ast":
        _emit(asdict(parse(source)), arguments.output)
        return 0
    plan = compile_source(source.text, source.filename, modules=source.modules)
    if arguments.command == "check":
        _emit({"valid": True, "instructions": len(plan.instructions)}, arguments.output)
        return 0
    if arguments.command == "compile":
        _emit(plan.model_dump(mode="json"), arguments.output)
        return 0
    if arguments.command == "preview":
        _emit(
            {
                "writes": False,
                "note": "Desired policy only; no live state was queried",
                "rules": [dict(rule.model_dump(), key=rule.key) for rule in policy_rules(plan)],
                "plan": plan.model_dump(mode="json"),
            },
            arguments.output,
        )
        return 0
    return _execute_source(arguments, source, plan)


def _execute_source(arguments: argparse.Namespace, source: Source, plan: Plan) -> int:
    settings = Settings() if arguments.timeout is None else Settings(timeout=arguments.timeout)
    setup_logging(settings.log_dir)
    adapter = _adapter(arguments, settings, source)
    if arguments.command in {"firewall-remove", "server-remove"}:
        if not isinstance(adapter, NativeAdapter | SshAdapter):
            raise RuntimeFailureError("Firewall removal requires --mode local or ssh")
        results = (
            adapter.remove_servers(plan)
            if arguments.command == "server-remove"
            else adapter.remove(plan)
        )
        success = all(item.success for item in results)
        _emit({"success": success, "results": [asdict(item) for item in results]}, arguments.output)
        return 0 if success else 1
    return _run_plan(arguments, plan, adapter)


def _run_plan(arguments: argparse.Namespace, plan: Plan, adapter: Adapter) -> int:
    journal = (
        Journal(plan, arguments.mode, arguments.journal_root)
        if arguments.mode in {"local", "ssh"}
        else None
    )
    result = execute(
        plan,
        adapter,
        arguments.mode,
        fail_fast=arguments.fail_fast,
        on_record=journal.append if journal else None,
        workers=arguments.workers,
    )
    logger.bind(run_id=str(uuid4())).info(
        "Execution completed | instructions={} failed={}",
        len(result.records),
        sum(not record.success for record in result.records),
    )
    _emit(
        {
            "success": result.success,
            "journal": str(journal.directory) if journal else None,
            **result.model_dump(mode="json"),
        },
        arguments.output,
    )
    return 0 if result.success else 1


def _dispatch(arguments: argparse.Namespace) -> int:
    if arguments.command in {"automation", "vpn"}:
        if arguments.output is not None and arguments.output.exists():
            raise RuntimeFailureError("Output file already exists")
        handler = automation_cli.run if arguments.command == "automation" else vpn_cli.run
        result = handler(arguments)
        _emit(result, arguments.output)
        return 1 if result.get("success") is False else 0
    if arguments.command in {"doctor", "agent", "editor"}:
        return _utility_command(arguments.command)
    if arguments.command == "lab-test":
        destination, success = validate_lab(
            arguments.inventory, arguments.docker_executable, arguments.output_root
        )
        _emit({"output": str(destination), "success": success})
        return 0 if success else 1
    if arguments.command == "probe":
        return _probe_command(arguments)
    if arguments.command == "evaluate":
        destination, success = run_evaluation(arguments.output_root)
        _emit({"output": str(destination), "success": success})
        return 0 if success else 1
    return _source_command(arguments)


def _utility_command(command: str) -> int:
    if command == "doctor":
        _emit(native_backend().inspect().model_dump(mode="json"))
    elif command == "agent":
        request = AgentRequest.model_validate_json(sys.stdin.read(6_100_001))
        _emit(asdict(handle(request)))
    else:
        editor_request = EditorRequest.model_validate_json(sys.stdin.read(6_100_001))
        _emit(analyze(editor_request))
    return 0


def _probe_command(arguments: argparse.Namespace) -> int:
    if not 1 <= arguments.port <= MAX_PORT:
        raise RuntimeFailureError("Port must be between 1 and 65535")
    settings = Settings(timeout=arguments.timeout)
    if arguments.dns_name or arguments.expect:
        if not arguments.dns_name or not arguments.expect or arguments.service:
            raise RuntimeFailureError(
                "DNS probes require --dns-name and --expect without --service"
            )
        result = probe_dns(
            str(arguments.host),
            arguments.dns_name,
            arguments.expect,
            settings.timeout,
            port=arguments.port,
        )
    else:
        result = probe(str(arguments.host), arguments.port, arguments.service, settings.timeout)
    sys.stdout.write(probe_json(result) + "\n")
    return 0


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
