"""Check expression types and evaluate immutable compile-time values."""

from __future__ import annotations

import operator
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network

from netsec.core.model import Expression, Parameter, Scalar, Span, fail

MIN_PORT, MAX_PORT = 1, 65535
MAX_VALUE_BITS = 512
MAX_EVALUATION_STEPS = 100_000
MAX_CALL_DEPTH = 32


@dataclass(slots=True)
class EvaluationBudget:
    """Bound total expression work for one compilation, including nested calls."""

    steps: int = 0


@dataclass(frozen=True, slots=True)
class Function:
    """Capture a typed expression and its lexical declaration environment."""

    parameters: tuple[Parameter, ...]
    result_type: str
    expression: Expression
    closure: Scope


@dataclass(frozen=True, slots=True)
class Value:
    """Keep a domain type distinct from its Python representation."""

    type_name: str
    data: Scalar
    fields: tuple[tuple[str, Value], ...] = ()


@dataclass(slots=True)
class ClassType:
    """Describe nominal immutable fields and pure methods."""

    fields: tuple[Parameter, ...]
    depth: int = 1
    methods: dict[str, Function] = field(default_factory=dict)


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
        self.functions: dict[str, Function] = {}
        self.classes: dict[str, ClassType] = {}
        self.budget: EvaluationBudget = parent.budget if parent else EvaluationBudget()
        self.call_depth: int = parent.call_depth if parent else 0

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

    def function(self, name: str, span: Span) -> Function:
        """Resolve a callable lexically, respecting local variable shadowing."""
        if name in self.symbols:
            if name not in self.functions:
                fail("E_NOT_CALLABLE", f"Name {name!r} is not a function", span)
            return self.functions[name]
        if self.parent is not None:
            return self.parent.function(name, span)
        fail("E_UNDEFINED", f"Function {name!r} is not declared", span)

    def class_type(self, name: str, span: Span) -> ClassType:
        """Resolve an explicitly declared nominal class."""
        if name in self.classes:
            return self.classes[name]
        if self.parent is not None:
            return self.parent.class_type(name, span)
        fail("E_TYPE", f"Unknown class type {name!r}", span)


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
    scope.budget.steps += 1
    if scope.budget.steps > MAX_EVALUATION_STEPS:
        fail("E_LIMIT", "Compilation exceeds 100000 expression evaluations", expression.span)
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
            return _binary(expression, left, right, scope.budget)
        case _:
            return _object_expression(expression, scope)


def _object_expression(expression: Expression, scope: Scope) -> Value:
    if expression.kind == "call":
        if scope.lookup(str(expression.value), expression.span).type_name == "class":
            return _construct(expression, scope)
        return _call(expression, scope)
    receiver = evaluate(expression.operands[0], scope)
    if expression.kind == "member":
        for name, value in receiver.fields:
            if name == expression.value:
                return value
        fail("E_MEMBER", f"Unknown field {expression.value!r}", expression.span)
    shape = scope.class_type(receiver.type_name, expression.span)
    function = shape.methods.get(str(expression.value))
    if function is None:
        fail("E_MEMBER", f"Unknown method {expression.value!r}", expression.span)
    return _invoke(function, expression, scope, receiver)


def _construct(expression: Expression, scope: Scope) -> Value:
    name = str(expression.value)
    shape = scope.class_type(name, expression.span)
    if len(shape.fields) != len(expression.operands):
        fail("E_ARITY", "Constructor argument count does not match fields", expression.span)
    fields = tuple(
        (field.name, require(evaluate(argument, scope), field.type_name, argument.span))
        for field, argument in zip(shape.fields, expression.operands, strict=True)
    )
    return Value(name, "", fields)


def _equal(left: Value, right: Value, budget: EvaluationBudget, span: Span) -> bool:
    pending = [(left, right)]
    seen: set[tuple[int, int]] = set()
    while pending:
        first, second = pending.pop()
        key = (id(first), id(second))
        if first is second or key in seen:
            continue
        seen.add(key)
        budget.steps += 1
        if budget.steps > MAX_EVALUATION_STEPS:
            fail("E_LIMIT", "Compilation exceeds 100000 expression evaluations", span)
        if (
            first.type_name != second.type_name
            or first.data != second.data
            or len(first.fields) != len(second.fields)
        ):
            return False
        for (first_name, first_value), (second_name, second_value) in zip(
            first.fields, second.fields, strict=True
        ):
            if first_name != second_name:
                return False
            pending.append((first_value, second_value))
    return True


def _call(expression: Expression, scope: Scope) -> Value:
    function = scope.function(str(expression.value), expression.span)
    return _invoke(function, expression, scope)


def _invoke(
    function: Function, expression: Expression, scope: Scope, receiver: Value | None = None
) -> Value:
    arguments = expression.operands if receiver is None else expression.operands[1:]
    if len(arguments) != len(function.parameters):
        fail("E_ARITY", "Function argument count does not match its declaration", expression.span)
    if scope.call_depth >= MAX_CALL_DEPTH:
        fail("E_LIMIT", "Function call depth exceeds 32", expression.span)
    local = Scope(function.closure)
    local.budget = scope.budget
    local.call_depth = scope.call_depth + 1
    if receiver is not None:
        local.define("self", receiver, expression.span)
    for parameter, argument in zip(function.parameters, arguments, strict=True):
        value = require(evaluate(argument, scope), parameter.type_name, argument.span)
        local.define(parameter.name, value, parameter.span)
    return require(evaluate(function.expression, local), function.result_type, expression.span)


def _unary(expression: Expression, value: Value) -> Value:
    if expression.value == "not":
        require(value, "bool", expression.span)
        return Value("bool", not value.data)
    require(value, "int", expression.span)
    return Value("int", -int(value.data) if expression.value == "-" else int(value.data))


def _binary(expression: Expression, left: Value, right: Value, budget: EvaluationBudget) -> Value:
    name, span = str(expression.value), expression.span
    if name == "in":
        require(left, "ip", span)
        require(right, "network", span)
        return Value("bool", ip_address(str(left.data)) in ip_network(str(right.data)))
    require(right, left.type_name, span)
    if name in {"==", "!="}:
        equal = _equal(left, right, budget, span)
        return Value("bool", equal if name == "==" else not equal)
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
