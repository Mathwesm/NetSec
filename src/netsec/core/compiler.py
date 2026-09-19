"""Resolve scopes, check domain semantics and lower source into executable plans."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from netsec.core.domains import dns_name
from netsec.core.functions import declare_class, declare_function, validate_type
from netsec.core.lexer import TYPES
from netsec.core.model import Expression, Program, Source, Span, Statement, fail
from netsec.core.modules import expand
from netsec.core.resources import ServerResource
from netsec.core.values import Scope, Value, convert, evaluate, require

MAX_INSTRUCTIONS = 10_000
MAX_HOSTS = 128
MAX_REPEAT = 100
MAX_EXPRESSION_DEPTH = 100
MAX_PLAN_TEXT = 1_000_000
SERVICES = MappingProxyType({"ssh": 22, "http": 80, "https": 443})


class Instruction(BaseModel):
    """A validated instruction consumed by NetSec's own executor."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    operation: Literal[
        "check_port", "check_service", "check_dns", "allow", "deny", "report", "server"
    ]
    host: str = ""
    port: int = Field(default=0, ge=0, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    message: str = ""
    expected: str = ""
    resource: ServerResource | None = None
    source: Span


class Plan(BaseModel):
    """Versioned compilation output with a bounded instruction count."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    format_version: Literal[3] = 3
    instructions: tuple[Instruction, ...] = Field(max_length=MAX_INSTRUCTIONS)


@dataclass(frozen=True, slots=True)
class Host:
    """Associate a display label with a canonical IP address."""

    name: str
    address: str
    span: Span


def expression_of(statement: Statement) -> Expression:
    """Require a value expression on a command that consumes one."""
    if statement.expression is None:
        fail("E_SYNTAX", "Expected a value expression", statement.span)
    return statement.expression


def value_of(statement: Statement, scope: Scope) -> Value:
    """Evaluate a statement's expression after enforcing a recursion bound."""
    expression = expression_of(statement)
    pending = [(expression, 1)]
    while pending:
        current, depth = pending.pop()
        if depth > MAX_EXPRESSION_DEPTH:
            fail("E_LIMIT", "Expression tree exceeds 100 levels", current.span)
        pending.extend((operand, depth + 1) for operand in current.operands)
    return evaluate(expression, scope)


class Compiler:
    """Implement static typing and domain checks independently of the parser."""

    def __init__(self) -> None:
        self.scope = Scope()
        self.groups: dict[str, tuple[Host, ...]] = {}
        self.plays: dict[str, Span] = {}

    def compile(self, program: Program) -> Plan:
        """Validate a full tree before exposing any executable instructions."""
        instructions: list[Instruction] = []
        for statement in program.statements:
            instructions.extend(self._top_level(statement))
            _check_size(instructions, statement.span)
        _check_conflicts(instructions)
        _check_resources(instructions)
        if (
            sum(
                len(item.message) + (len(item.resource.content) if item.resource else 0)
                for item in instructions
            )
            > MAX_PLAN_TEXT
        ):
            fail(
                "E_LIMIT", "Expanded plan text exceeds 1000000 characters", instructions[-1].source
            )
        return Plan(instructions=tuple(instructions))

    def _top_level(self, statement: Statement) -> list[Instruction]:
        match statement.kind:
            case "binding":
                _binding(statement, self.scope)
            case "function":
                declare_function(statement, self.scope)
            case "class":
                declare_class(statement, self.scope)
            case "group":
                self._group(statement)
            case "play":
                return self._play(statement)
            case "report":
                return [_report(statement, self.scope, "")]
            case _:
                fail("E_CONTEXT", f"{statement.kind} is not allowed at top level", statement.span)
        return []

    def _group(self, statement: Statement) -> None:
        self.scope.define(statement.name, Value("group", statement.name), statement.span)
        hosts: list[Host] = []
        for node in statement.body:
            if node.kind != "host":
                fail("E_CONTEXT", "Groups may contain only host declarations", node.span)
            value = value_of(node, self.scope)
            address = convert("ip", value, node.span)
            host = Host(node.name, str(address.data), node.span)
            _unique_host(host, hosts)
            hosts.append(host)
        if not hosts or len(hosts) > MAX_HOSTS:
            fail("E_GROUP_SIZE", "A group must contain between 1 and 128 hosts", statement.span)
        self.groups[statement.name] = tuple(hosts)

    def _play(self, statement: Statement) -> list[Instruction]:
        if statement.name in self.plays:
            fail(
                "E_DUPLICATE",
                f"Play {statement.name!r} is already declared",
                statement.span,
                self.plays[statement.name],
            )
        self.plays[statement.name] = statement.span
        target = self.scope.lookup(statement.target, statement.span)
        require(target, "group", statement.span)
        instructions: list[Instruction] = []
        for host in self.groups[statement.target]:
            scope = Scope(self.scope)
            scope.define("current_host", Value("ip", host.address), statement.span)
            instructions.extend(_block(statement.body, scope, host.address))
            _check_size(instructions, statement.span)
        return instructions


def _unique_host(host: Host, hosts: list[Host]) -> None:
    if not host.name:
        fail("E_HOST", "Host label cannot be empty", host.span)
    for existing in hosts:
        if existing.name == host.name or existing.address == host.address:
            fail(
                "E_DUPLICATE_HOST", "Duplicate host label or IP in group", host.span, existing.span
            )


def _binding(statement: Statement, scope: Scope) -> None:
    validate_type(statement.type_name, scope, statement.span)
    value = value_of(statement, scope)
    require(value, statement.type_name, expression_of(statement).span)
    scope.define(statement.name, value, statement.span)


def _report(statement: Statement, scope: Scope, host: str) -> Instruction:
    value = value_of(statement, scope)
    if value.type_name not in TYPES:
        fail("E_TYPE", "Cannot report a non-scalar value; select a field", statement.span)
    message = str(value.data).lower() if value.type_name == "bool" else str(value.data)
    return Instruction(operation="report", host=host, message=message, source=statement.span)


def _block(statements: tuple[Statement, ...], scope: Scope, host: str) -> list[Instruction]:
    instructions: list[Instruction] = []
    for statement in statements:
        instructions.extend(_statement(statement, scope, host))
        _check_size(instructions, statement.span)
    return instructions


def _statement(statement: Statement, scope: Scope, host: str) -> list[Instruction]:
    match statement.kind:
        case "binding":
            _binding(statement, scope)
            return []
        case "report":
            return [_report(statement, scope, host)]
        case "if":
            return _conditional(statement, scope, host)
        case "repeat":
            count = int(require(value_of(statement, scope), "int", statement.span).data)
            if not 0 <= count <= MAX_REPEAT:
                fail("E_REPEAT", "Repeat count must be between 0 and 100", statement.span)
            body = _block(statement.body, Scope(scope), host)
            if len(body) * count > MAX_INSTRUCTIONS:
                fail("E_LIMIT", "Expanded program exceeds 10000 instructions", statement.span)
            return body * count
        case "port" | "service" | "firewall":
            return [_network(statement, scope, host)]
        case "dns" | "server":
            handler = _dns if statement.kind == "dns" else _server
            return [handler(statement, scope, host)]
        case _:
            fail("E_CONTEXT", f"{statement.kind} is not allowed in a play", statement.span)


def _conditional(statement: Statement, scope: Scope, host: str) -> list[Instruction]:
    condition = require(value_of(statement, scope), "bool", statement.span)
    # Both branches must be well typed; only the selected policy is lowered.
    body = _block(statement.body, Scope(scope), host)
    alternate = _block(statement.alternate, Scope(scope), host)
    return body if condition.data else alternate


def _network(statement: Statement, scope: Scope, host: str) -> Instruction:
    if statement.kind == "service":
        service = str(require(value_of(statement, scope), "string", statement.span).data)
        if service not in SERVICES:
            fail("E_SERVICE", "Supported services: ssh, http, https", statement.span)
        endpoint = (
            int(convert("port", evaluate(statement.protocol, scope), statement.span).data)
            if statement.protocol
            else SERVICES[service]
        )
        return Instruction(
            operation="check_service",
            host=host,
            port=endpoint,
            message=service,
            source=statement.span,
        )
    port = int(convert("port", value_of(statement, scope), statement.span).data)
    if statement.protocol is None:
        fail("E_PROTOCOL", "Missing transport protocol", statement.span)
    protocol = require(evaluate(statement.protocol, scope), "protocol", statement.protocol.span)
    transport: Literal["tcp", "udp"] = "tcp" if protocol.data == "tcp" else "udp"
    if statement.kind == "port" and transport == "udp":
        fail(
            "E_UDP_CHECK",
            "Generic UDP checks cannot establish whether a port is open",
            statement.span,
        )
    operation: Literal["check_port", "allow", "deny"] = "check_port"
    if statement.kind == "firewall":
        operation = "allow" if statement.name == "allow" else "deny"
    return Instruction(
        operation=operation, host=host, port=port, protocol=transport, source=statement.span
    )


def _dns(statement: Statement, scope: Scope, host: str) -> Instruction:
    value = str(require(value_of(statement, scope), "string", statement.span).data)
    try:
        name = dns_name(value)
    except ValueError as error:
        fail("E_DNS_NAME", str(error), statement.span)
    if statement.expected is None:
        fail("E_DNS_EXPECT", "DNS check requires an expected IP address", statement.span)
    expected = convert("ip", evaluate(statement.expected, scope), statement.expected.span)
    port = (
        int(convert("port", evaluate(statement.protocol, scope), statement.span).data)
        if statement.protocol
        else 53
    )
    return Instruction(
        operation="check_dns",
        host=host,
        port=port,
        protocol="udp",
        message=name,
        expected=str(expected.data),
        source=statement.span,
    )


def _check_size(instructions: list[Instruction], span: Span) -> None:
    if len(instructions) > MAX_INSTRUCTIONS:
        fail("E_LIMIT", "Expanded program exceeds 10000 instructions", span)


def _server(statement: Statement, scope: Scope, host: str) -> Instruction:
    port = int(convert("port", value_of(statement, scope), statement.span).data)
    if statement.protocol is None:
        fail("E_SERVER", "Missing server content or DNS record", statement.span)
    content = str(require(evaluate(statement.protocol, scope), "string", statement.span).data)
    fields: dict[str, object] = {
        "name": statement.name,
        "kind": statement.type_name,
        "host": host,
        "port": port,
    }
    if statement.type_name == "http":
        fields["content"] = content
    else:
        if statement.expected is None:
            fail("E_SERVER", "DNS server requires an answer address", statement.span)
        fields["address"] = str(
            convert("ip", evaluate(statement.expected, scope), statement.span).data
        )
        try:
            fields["record"] = dns_name(content)
        except ValueError:
            fail("E_SERVER", "Invalid DNS record name", statement.span)
    try:
        resource = ServerResource.model_validate(fields)
    except ValidationError:
        fail("E_SERVER", "Invalid server name, address or configuration", statement.span)
    return Instruction(
        operation="server",
        host=host,
        port=port,
        resource=resource,
        protocol="tcp" if resource.kind == "http" else "udp",
        source=statement.span,
    )


def _check_resources(instructions: list[Instruction]) -> None:
    names: dict[tuple[str, str], Instruction] = {}
    ports: dict[tuple[str, int], Instruction] = {}
    for item in instructions:
        if item.resource is None:
            continue
        for key, entries in (((item.host, item.resource.name), names),):
            previous = entries.get(key)
            if previous and previous.resource != item.resource:
                fail(
                    "E_SERVER_CONFLICT",
                    "Conflicting server configurations",
                    item.source,
                    previous.source,
                )
            entries[key] = item
        endpoint = (item.host, item.port)
        previous = ports.get(endpoint)
        if previous and previous.resource != item.resource:
            fail(
                "E_SERVER_CONFLICT",
                "Servers compete for one endpoint",
                item.source,
                previous.source,
            )
        ports[endpoint] = item


def _check_conflicts(instructions: list[Instruction]) -> None:
    rules: dict[tuple[str, int, str], Instruction] = {}
    for instruction in instructions:
        if instruction.operation not in {"allow", "deny"}:
            continue
        key = (instruction.host, instruction.port, instruction.protocol)
        previous = rules.get(key)
        if previous is not None and previous.operation != instruction.operation:
            fail(
                "E_FIREWALL_CONFLICT",
                f"Contradictory policies for {key[0]}:{key[1]}/{key[2]}",
                instruction.source,
                previous.source,
            )
        rules[key] = instruction


def compile_source(
    text: str, filename: str = "<input>", *, modules: dict[str, str] | None = None
) -> Plan:
    """Compile source entirely before allowing any network activity.

    Args:
        text: NetSec program in Unicode.
        filename: Filename shown in diagnostics.
        modules: Optional self-contained relative-path module bundle.

    Returns:
        A validated executable instruction plan.

    Raises:
        NetSecError: If lexical, syntactic, type or domain validation fails.
        ValidationError: If input exceeds the source size limit.
    """
    return Compiler().compile(expand(Source(text=text, filename=filename, modules=modules or {})))
