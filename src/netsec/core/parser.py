"""Parse NetSec with recursive descent and precedence climbing."""

from __future__ import annotations

import json
from collections.abc import Callable
from types import MappingProxyType

from netsec.core.lexer import TYPES, tokenize
from netsec.core.model import Expression, Parameter, Program, Source, Statement, Token, fail

_PRECEDENCE = MappingProxyType(
    {
        "or": 1,
        "and": 2,
        "==": 3,
        "!=": 3,
        "<": 4,
        "<=": 4,
        ">": 4,
        ">=": 4,
        "in": 4,
        "+": 5,
        "-": 5,
        "*": 6,
        "/": 6,
        "%": 6,
    }
)
_UNARY_PRECEDENCE = 7
_MAX_DEPTH = 80
_SURROGATE_START, _SURROGATE_END = 0xD800, 0xDFFF


class Parser:
    """Consume a token stream while retaining source ranges."""

    def __init__(self, tokens: tuple[Token, ...]) -> None:
        self.tokens = tokens
        self.position = 0
        self.depth = 0

    @property
    def current(self) -> Token:
        """Return the lookahead token."""
        return self.tokens[self.position]

    def take(self, kind: str) -> Token:
        """Consume a required token or report a located syntax error."""
        token = self.current
        if token.kind != kind:
            fail(
                "E_SYNTAX", f"Expected {kind!r}, found {token.text or 'end of file'!r}", token.span
            )
        self.position += 1
        return token

    def accept(self, kind: str) -> bool:
        """Consume an optional token and report whether it was present."""
        if self.current.kind != kind:
            return False
        self.take(kind)
        return True

    def parse(self) -> Program:
        """Build the complete tree, rejecting trailing invalid constructs."""
        statements: list[Statement] = []
        while self.current.kind != "EOF":
            statements.append(self.statement())
        return Program(tuple(statements))

    def statement(self) -> Statement:
        """Dispatch a declaration or command from its leading keyword."""
        if self.current.kind in TYPES or self.current.kind == "NAME":
            return self.binding()
        handlers: dict[str, Callable[[], Statement]] = {
            "group": self.group,
            "host": self.host,
            "play": self.play,
            "check": self.check,
            "firewall": self.firewall,
            "report": self.report,
            "if": self.conditional,
            "repeat": self.repeat,
            "fn": self.function,
            "class": self.class_definition,
            "import": self.import_module,
            "server": self.server,
        }
        handler = handlers.get(self.current.kind)
        if handler is None:
            fail("E_SYNTAX", "Expected a declaration or NetSec command", self.current.span)
        return handler()

    def block(self) -> tuple[Statement, ...]:
        """Read a brace-delimited lexical scope."""
        self.take("{")
        self._enter()
        statements: list[Statement] = []
        while self.current.kind not in {"}", "EOF"}:
            statements.append(self.statement())
        self.take("}")
        self.depth -= 1
        return tuple(statements)

    def binding(self) -> Statement:
        """Read an explicitly typed immutable binding."""
        token = self.take(self.current.kind)
        name = self.take("NAME").text
        self.take("=")
        value = self.expression()
        self.take(";")
        return Statement("binding", token.span, name, token.text, value)

    def import_module(self) -> Statement:
        """Read a relative source module reference."""
        token = self.take("import")
        name = self._string(self.take("STRING"))
        self.take(";")
        return Statement("import", token.span, name=name)

    def class_definition(self) -> Statement:
        """Read immutable fields and expression-bodied methods."""
        token = self.take("class")
        name = self.take("NAME").text
        self.take("{")
        fields: list[Parameter] = []
        methods: list[Statement] = []
        while self.current.kind not in {"}", "EOF"}:
            if self.current.kind == "fn":
                methods.append(self.function())
            else:
                type_name = self._type()
                field = self.take("NAME")
                fields.append(Parameter(field.text, type_name, field.span))
                self.take(";")
        self.take("}")
        return Statement(
            "class", token.span, name=name, parameters=tuple(fields), body=tuple(methods)
        )

    def group(self) -> Statement:
        """Read an inventory group."""
        token = self.take("group")
        name = self.take("NAME").text
        return Statement("group", token.span, name=name, body=self.block())

    def function(self) -> Statement:
        """Parse a pure, expression-bodied function with typed parameters and result."""
        token = self.take("fn")
        name = self.take("NAME").text
        self.take("(")
        parameters: list[Parameter] = []
        if self.current.kind != ")":
            while True:
                type_name = self._type()
                parameter = self.take("NAME")
                parameters.append(Parameter(parameter.text, type_name, parameter.span))
                if not self.accept(","):
                    break
        self.take(")")
        self.take("->")
        result_type = self._type()
        self.take("=")
        expression = self.expression()
        self.take(";")
        return Statement(
            "function",
            token.span,
            name=name,
            type_name=result_type,
            expression=expression,
            parameters=tuple(parameters),
        )

    def _type(self) -> str:
        if self.current.kind not in TYPES and self.current.kind != "NAME":
            fail("E_TYPE", "Expected an explicit NetSec type", self.current.span)
        return self.take(self.current.kind).text

    def host(self) -> Statement:
        """Read a host label and an IP expression."""
        token = self.take("host")
        name = self._string(self.take("STRING"))
        self.take("address")
        value = self.expression()
        self.take(";")
        return Statement("host", token.span, name=name, expression=value)

    def server(self) -> Statement:
        """Read a declarative HTTP or DNS server resource inside a play."""
        token = self.take("server")
        kind = self.current.kind
        if kind not in {"http", "dns"}:
            fail("E_SYNTAX", "Expected http or dns server", self.current.span)
        self.take(kind)
        name = self._string(self.take("STRING"))
        self.take("port")
        port = self.expression()
        self.take("response" if kind == "http" else "record")
        content = self.expression()
        expected = None
        if kind == "dns":
            self.take("address")
            expected = self.expression()
        self.take(";")
        return Statement(
            "server",
            token.span,
            name=name,
            type_name=kind,
            expression=port,
            protocol=content,
            expected=expected,
        )

    def play(self) -> Statement:
        """Read a named automation targeting a declared group."""
        token = self.take("play")
        name = self._string(self.take("STRING"))
        self.take("targets")
        target = self.take("NAME").text
        return Statement("play", token.span, name=name, target=target, body=self.block())

    def check(self) -> Statement:
        """Read a transport or application-layer check."""
        token = self.take("check")
        if self.accept("dns"):
            value = self.expression()
            port = self.expression() if self.accept("port") else None
            self.take("expect")
            expected = self.expression()
            self.take(";")
            return Statement("dns", token.span, expression=value, expected=expected, protocol=port)
        if self.accept("service"):
            value = self.expression()
            port = self.expression() if self.accept("port") else None
            self.take(";")
            return Statement("service", token.span, expression=value, protocol=port)
        self.take("port")
        value = self.expression()
        self.take("protocol")
        protocol = self.expression()
        self.take(";")
        return Statement("port", token.span, expression=value, protocol=protocol)

    def firewall(self) -> Statement:
        """Read a firewall policy declaration."""
        token = self.take("firewall")
        action = self.current.kind
        if action not in {"allow", "deny"}:
            fail("E_SYNTAX", "Expected allow or deny", self.current.span)
        self.take(action)
        self.take("port")
        value = self.expression()
        self.take("protocol")
        protocol = self.expression()
        self.take(";")
        return Statement("firewall", token.span, name=action, expression=value, protocol=protocol)

    def report(self) -> Statement:
        """Read a scalar output expression."""
        token = self.take("report")
        value = self.expression()
        self.take(";")
        return Statement("report", token.span, expression=value)

    def conditional(self) -> Statement:
        """Read a statically evaluated conditional and optional alternative."""
        token = self.take("if")
        condition = self.expression()
        body = self.block()
        alternate = self.block() if self.accept("else") else ()
        return Statement("if", token.span, expression=condition, body=body, alternate=alternate)

    def repeat(self) -> Statement:
        """Read a bounded repetition."""
        token = self.take("repeat")
        count = self.expression()
        return Statement("repeat", token.span, expression=count, body=self.block())

    def expression(self, minimum: int = 1) -> Expression:
        """Parse left-associative operators according to their precedence."""
        self._enter()
        left = self.postfix()
        while _PRECEDENCE.get(self.current.kind, 0) >= minimum:
            operator = self.take(self.current.kind)
            right = self.expression(_PRECEDENCE[operator.kind] + 1)
            left = Expression("binary", operator.kind, operator.span, (left, right))
        self.depth -= 1
        return left

    def postfix(self) -> Expression:
        """Resolve chained field accesses and method calls after a primary."""
        value = self.primary()
        while self.accept("."):
            token = self.take("NAME")
            if self.accept("("):
                value = Expression("method", token.text, token.span, (value, *self.arguments()))
            else:
                value = Expression("member", token.text, token.span, (value,))
        return value

    def primary(self) -> Expression:
        """Parse a literal, name, constructor, unary operation or parentheses."""
        token = self.take(self.current.kind)
        if token.kind == "(":
            expression = self.expression()
            self.take(")")
            return expression
        if token.kind in {"not", "-", "+"}:
            return Expression(
                "unary", token.kind, token.span, (self.expression(_UNARY_PRECEDENCE),)
            )
        if token.kind in TYPES:
            self.take("(")
            value = self.expression()
            self.take(")")
            return Expression("convert", token.kind, token.span, (value,))
        if token.kind == "NAME":
            return self._name_or_call(token)
        return self._literal(token)

    def _name_or_call(self, token: Token) -> Expression:
        if not self.accept("("):
            return Expression("name", token.text, token.span)
        return Expression("call", token.text, token.span, self.arguments())

    def arguments(self) -> tuple[Expression, ...]:
        """Read arguments after an opening parenthesis."""
        arguments: list[Expression] = []
        if self.current.kind != ")":
            while True:
                arguments.append(self.expression())
                if not self.accept(","):
                    break
        self.take(")")
        return tuple(arguments)

    def _literal(self, token: Token) -> Expression:
        if token.kind == "INT":
            return Expression("literal", int(token.text), token.span, type_name="int")
        if token.kind == "STRING":
            return Expression("literal", self._string(token), token.span, type_name="string")
        if token.kind in {"true", "false"}:
            return Expression("literal", token.kind == "true", token.span, type_name="bool")
        if token.kind in {"tcp", "udp"}:
            return Expression("literal", token.kind, token.span, type_name="protocol")
        fail("E_SYNTAX", "Expected an expression", token.span)

    def _string(self, token: Token) -> str:
        try:
            value: object = json.loads(token.text)
        except json.JSONDecodeError:
            fail("E_STRING", "Invalid string escape", token.span)
        if not isinstance(value, str) or any(
            _SURROGATE_START <= ord(char) <= _SURROGATE_END for char in value
        ):
            fail("E_STRING", "String must contain valid Unicode characters", token.span)
        return value

    def _enter(self) -> None:
        self.depth += 1
        if self.depth > _MAX_DEPTH:
            fail("E_LIMIT", "Nesting exceeds 80 levels", self.current.span)


def parse(source: Source) -> Program:
    """Tokenize and parse validated source text."""
    return Parser(tokenize(source)).parse()
