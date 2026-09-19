"""Check pure function bodies symbolically, including unused declarations."""

from netsec.core.lexer import TYPES
from netsec.core.model import MAX_EXPRESSION_HEIGHT, Expression, Parameter, Span, Statement, fail
from netsec.core.values import ClassType, Function, Scope, Value, convert, require


def declare_function(statement: Statement, scope: Scope) -> None:
    """Validate a declaration before making it callable; recursive definitions are rejected."""
    function = _validate_function(statement, scope)
    scope.define(statement.name, Value("function", statement.name), statement.span)
    scope.functions[statement.name] = function


def validate_type(name: str, scope: Scope, span: Span) -> None:
    """Reject undeclared field, parameter and return types even in unused code."""
    if name not in TYPES:
        scope.class_type(name, span)


def _validate_function(statement: Statement, scope: Scope, receiver: str = "") -> Function:
    if statement.expression is None:
        fail("E_FUNCTION", "Function requires a result expression", statement.span)
    local = Scope(scope)
    if receiver:
        local.define("self", Value(receiver, ""), statement.span)
    validate_type(statement.type_name, scope, statement.span)
    for parameter in statement.parameters:
        validate_type(parameter.type_name, scope, parameter.span)
        local.define(parameter.name, Value(parameter.type_name, 0), parameter.span)
    result = infer(statement.expression, local)
    require(Value(result, 0), statement.type_name, statement.expression.span)
    return Function(statement.parameters, statement.type_name, statement.expression, scope)


def declare_class(statement: Statement, scope: Scope) -> None:
    """Validate immutable class fields before registering ordered pure methods."""
    names = Scope()
    for field in statement.parameters:
        validate_type(field.type_name, scope, field.span)
        names.define(field.name, Value(field.type_name, ""), field.span)
    scope.define(statement.name, Value("class", statement.name), statement.span)
    depth = 1 + max(
        (
            scope.class_type(field.type_name, field.span).depth
            for field in statement.parameters
            if field.type_name not in TYPES
        ),
        default=0,
    )
    if depth > MAX_EXPRESSION_HEIGHT:
        fail("E_LIMIT", "Class composition exceeds 100 levels", statement.span)
    shape = ClassType(statement.parameters, depth)
    scope.classes[statement.name] = shape
    for method in statement.body:
        names.define(method.name, Value("function", ""), method.span)
        shape.methods[method.name] = _validate_function(method, scope, statement.name)


def infer(expression: Expression, scope: Scope) -> str:
    """Infer expression types without substituting fake runtime parameter values."""
    if expression.kind == "literal":
        return expression.type_name
    if expression.kind == "name":
        return scope.lookup(str(expression.value), expression.span).type_name
    arguments = [infer(item, scope) for item in expression.operands]
    if expression.kind in {"call", "member", "method"}:
        handler = _call_type if expression.kind == "call" else _member_type
        return handler(expression, scope, arguments)
    if expression.kind == "convert":
        return _conversion(expression, arguments[0])
    if expression.kind == "unary":
        expected = "bool" if expression.value == "not" else "int"
        require(Value(arguments[0], 0), expected, expression.span)
        return expected
    return _binary(expression, arguments)


def _check_arguments(arguments: list[str], parameters: tuple[Parameter, ...], span: Span) -> None:
    if len(arguments) != len(parameters):
        fail("E_ARITY", "Argument count does not match declaration", span)
    for actual, parameter in zip(arguments, parameters, strict=True):
        require(Value(actual, 0), parameter.type_name, span)


def _call_type(expression: Expression, scope: Scope, arguments: list[str]) -> str:
    name = str(expression.value)
    if scope.lookup(name, expression.span).type_name == "class":
        _check_arguments(arguments, scope.class_type(name, expression.span).fields, expression.span)
        return name
    function = scope.function(name, expression.span)
    _check_arguments(arguments, function.parameters, expression.span)
    return function.result_type


def _member_type(expression: Expression, scope: Scope, arguments: list[str]) -> str:
    shape = scope.class_type(arguments[0], expression.span)
    if expression.kind == "member":
        for field in shape.fields:
            if field.name == expression.value:
                return field.type_name
    else:
        method = shape.methods.get(str(expression.value))
        if method is not None:
            _check_arguments(arguments[1:], method.parameters, expression.span)
            return method.result_type
    fail("E_MEMBER", f"Unknown member {expression.value!r}", expression.span)


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
