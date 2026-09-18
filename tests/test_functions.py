from __future__ import annotations

import pytest

from netsec.core.compiler import compile_source
from netsec.core.model import NetSecError


def test_pure_functions_have_typed_parameters_results_and_lexical_scope() -> None:
    source = """
int offset = 100;
fn shifted(int base) -> port = port(base + offset);
fn belongs(ip endpoint, network subnet) -> bool = endpoint in subnet;
group servers { host "server" address "192.0.2.10"; }
play "audit" targets servers {
    int offset = 900;
    check port shifted(22) protocol tcp;
    report belongs(current_host, network("192.0.2.0/24"));
}
"""
    plan = compile_source(source)
    assert plan.instructions[0].port == 122
    assert plan.instructions[1].message == "true"


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ("fn unused(int value) -> bool = value + 1;", "E_TYPE"),
        ("fn unused(int value) -> int = value + true;", "E_TYPE"),
        ("fn unused(int value, int value) -> int = value;", "E_DUPLICATE"),
        ("fn recursive(int value) -> int = recursive(value);", "E_UNDEFINED"),
        (
            "fn first(int value) -> int = later(value); fn later(int value) -> int = value;",
            "E_UNDEFINED",
        ),
        ("fn valid(int value) -> int = value; report valid();", "E_ARITY"),
        ("fn valid(int value) -> int = value; report valid(true);", "E_TYPE"),
        ('fn invalid() -> ip = ip("invalid");', "E_ADDRESS"),
        ("int value = 2; report value();", "E_NOT_CALLABLE"),
        ("fn divide(int value) -> int = 10 / value; report divide(0);", "E_ZERO_DIVISION"),
        ("fn endpoint(int value) -> port = port(value); report endpoint(65536);", "E_PORT"),
    ],
)
def test_function_static_and_domain_failures(source: str, code: str) -> None:
    with pytest.raises(NetSecError, match=code):
        compile_source(source)


def test_zero_parameter_and_composed_functions() -> None:
    plan = compile_source(
        "fn first() -> int = 22; fn next() -> port = port(first() + 1); report next();"
    )
    assert plan.instructions[0].message == "23"


def test_exponential_expansion_has_a_shared_compilation_budget() -> None:
    source = "fn f0(int value) -> int = value;\n"
    source += "\n".join(
        f"fn f{i}(int value) -> int = f{i - 1}(value) + f{i - 1}(value);" for i in range(1, 18)
    )
    with pytest.raises(NetSecError, match="100000 expression"):
        compile_source(source + "\nreport f17(1);")


def test_function_depth_cannot_exhaust_python_recursion() -> None:
    source = "fn f0(int value) -> int = value;\n"
    source += "\n".join(f"fn f{i}(int value) -> int = f{i - 1}(value);" for i in range(1, 35))
    with pytest.raises(NetSecError, match="call depth exceeds"):
        compile_source(source + "\nreport f34(1);")
