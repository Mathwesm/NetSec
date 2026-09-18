"""Check expression types and evaluate immutable compile-time values."""

from __future__ import annotations

import operator
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address, ip_network

from netsec.core.model import Expression, Scalar, Span, fail

MIN_PORT, MAX_PORT = 1, 65535
MAX_VALUE_BITS = 512


@dataclass(frozen=True, slots=True)
class Value:
    """Keep a domain type distinct from its Python representation."""

    type_name: str
    data: Scalar


@dataclass(frozen=True, slots=True)
class Symbol:
    """Associate a typed value with its declaration location."""

    value: Value
    span: Span


class Scope:
    """Resolve immutable names through lexical parent scopes."""

    def __init__(self, parent: Scope | None = None) -> None:
        self.parent = parent
        self.symbols: dict[str, Symbol] = {}

    def define(self, name: str, value: Value, span: Span) -> None:
        """Declare a name once in this scope, allowing inner shadowing."""
        if name in self.symbols:
            fail(
                "E_DUPLICATE",
                f"Name {name!r} is already declared in this scope",
                span,
                self.symbols[name].span,
            )
        self.symbols[name] = Symbol(value, span)

    def lookup(self, name: str, span: Span) -> Value:
        """Find a visible binding or reject use before declaration."""
        if name in self.symbols:
            return self.symbols[name].value
        if self.parent is not None:
            return self.parent.lookup(name, span)
        fail("E_UNDEFINED", f"Name {name!r} is not declared in this scope", span)


def require(value: Value, expected: str, span: Span) -> Value:
    """Require an exact type without implicit declaration inference."""
    if value.type_name != expected:
        fail("E_TYPE", f"Expected {expected}, received {value.type_name}", span)
    return value


def convert(type_name: str, value: Value, span: Span) -> Value:
    """Construct a validated domain value from an explicitly typed argument."""
    if type_name == value.type_name:
        return value
    if type_name == "port":
        require(value, "int", span)
        number = int(value.data)
        if not MIN_PORT <= number <= MAX_PORT:
            fail("E_PORT", "Port must be between 1 and 65535", span)
        return Value("port", number)
    if type_name in {"ip", "network", "protocol"}:
        return _domain(type_name, value, span)
    fail("E_TYPE", f"Cannot convert {value.type_name} to {type_name}", span)


def _domain(type_name: str, value: Value, span: Span) -> Value:
    require(value, "string", span)
    text = str(value.data)
    if type_name == "protocol":
        if text not in {"tcp", "udp"}:
            fail("E_PROTOCOL", "Protocol must be tcp or udp", span)
        return Value(type_name, text)
    try:
        if "%" in text:
            raise ValueError("Scoped addresses are not supported")
        parsed = ip_address(text) if type_name == "ip" else ip_network(text, strict=True)
    except ValueError:
        fail("E_ADDRESS", f"Invalid {type_name} literal {text!r}", span)
    return Value(type_name, str(parsed))


def evaluate(expression: Expression, scope: Scope) -> Value:
    """Evaluate a type-checked expression without eval or exec."""
    match expression.kind:
        case "literal":
            return Value(expression.type_name, expression.value)
        case "name":
            return scope.lookup(str(expression.value), expression.span)
        case "convert":
            return convert(
                str(expression.value), evaluate(expression.operands[0], scope), expression.span
            )
        case "unary":
            return _unary(expression, evaluate(expression.operands[0], scope))
        case "binary":
            left, right = (evaluate(item, scope) for item in expression.operands)
            return _binary(expression, left, right)


def _unary(expression: Expression, value: Value) -> Value:
    if expression.value == "not":
        require(value, "bool", expression.span)
        return Value("bool", not value.data)
    require(value, "int", expression.span)
    return Value("int", -int(value.data) if expression.value == "-" else int(value.data))


def _binary(expression: Expression, left: Value, right: Value) -> Value:
    name, span = str(expression.value), expression.span
    if name == "in":
        require(left, "ip", span)
        require(right, "network", span)
        return Value("bool", ip_address(str(left.data)) in ip_network(str(right.data)))
    require(right, left.type_name, span)
    if name in {"==", "!="}:
        result = left.data == right.data
        return Value("bool", result if name == "==" else not result)
    if name in {"and", "or"}:
        require(left, "bool", span)
        result = (
            bool(left.data) and bool(right.data)
            if name == "and"
            else bool(left.data) or bool(right.data)
        )
        return Value("bool", result)
    return _numeric(name, left, right, span)


def _numeric(name: str, left: Value, right: Value, span: Span) -> Value:
    require(left, "int", span)
    first, second = int(left.data), int(right.data)
    comparisons: dict[str, Callable[[int, int], bool]] = {
        "<": operator.lt,
        "<=": operator.le,
        ">": operator.gt,
        ">=": operator.ge,
    }
    if name in comparisons:
        return Value("bool", comparisons[name](first, second))
    if name in {"/", "%"} and second == 0:
        fail("E_ZERO_DIVISION", "Division or remainder by zero", span)
    arithmetic: dict[str, Callable[[int, int], int]] = {
        "+": operator.add,
        "-": operator.sub,
        "*": operator.mul,
        "/": operator.floordiv,
        "%": operator.mod,
    }
    result = arithmetic[name](first, second)
    if result.bit_length() > MAX_VALUE_BITS:
        fail("E_LIMIT", "Integer result exceeds 512 bits", span)
    return Value("int", result)
