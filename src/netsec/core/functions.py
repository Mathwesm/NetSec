"""Check pure function bodies symbolically, including unused declarations."""

from netsec.core.model import Expression, Statement, fail
from netsec.core.values import Function, Scope, Value, convert, require


def declare_function(statement: Statement, scope: Scope) -> None:
    """Validate a declaration before making it callable; recursive definitions are rejected."""
    if statement.expression is None:
        fail("E_FUNCTION", "Function requires a result expression", statement.span)
    local = Scope(scope)
    for parameter in statement.parameters:
        local.define(parameter.name, Value(parameter.type_name, 0), parameter.span)
    result = infer(statement.expression, local)
    require(Value(result, 0), statement.type_name, statement.expression.span)
    scope.define(statement.name, Value("function", statement.name), statement.span)
    scope.functions[statement.name] = Function(
        statement.parameters, statement.type_name, statement.expression, scope
    )


def infer(expression: Expression, scope: Scope) -> str:
    """Infer expression types without substituting fake runtime parameter values."""
    if expression.kind == "literal":
        return expression.type_name
    if expression.kind == "name":
        return scope.lookup(str(expression.value), expression.span).type_name
    arguments = [infer(item, scope) for item in expression.operands]
    if expression.kind == "call":
        function = scope.function(str(expression.value), expression.span)
        if len(arguments) != len(function.parameters):
            fail(
                "E_ARITY", "Function argument count does not match its declaration", expression.span
            )
        for actual, parameter in zip(arguments, function.parameters, strict=True):
            require(Value(actual, 0), parameter.type_name, expression.span)
        return function.result_type
    if expression.kind == "convert":
        return _conversion(expression, arguments[0])
    if expression.kind == "unary":
        expected = "bool" if expression.value == "not" else "int"
        require(Value(arguments[0], 0), expected, expression.span)
        return expected
    return _binary(expression, arguments)


def _conversion(expression: Expression, actual: str) -> str:
    target = str(expression.value)
    expected = "int" if target == "port" else "string"
    if target != actual:
        if target not in {"port", "ip", "network", "protocol"}:
            fail("E_TYPE", f"Cannot convert {actual} to {target}", expression.span)
        require(Value(actual, 0), expected, expression.span)
    operand = expression.operands[0]
    if operand.kind == "literal":
        convert(target, Value(actual, operand.value), expression.span)
    return target


def _binary(expression: Expression, arguments: list[str]) -> str:
    left, right = arguments
    operator = expression.value
    if operator == "in":
        require(Value(left, 0), "ip", expression.span)
        require(Value(right, 0), "network", expression.span)
        return "bool"
    require(Value(right, 0), left, expression.span)
    if operator in {"==", "!="}:
        return "bool"
    expected = "bool" if operator in {"and", "or"} else "int"
    require(Value(left, 0), expected, expression.span)
    return "bool" if operator in {"and", "or", "<", "<=", ">", ">="} else "int"
