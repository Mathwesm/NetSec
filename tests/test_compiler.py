from __future__ import annotations

import pytest

from netsec.core.compiler import compile_source
from netsec.core.lexer import tokenize
from netsec.core.model import NetSecError, Source
from netsec.core.parser import parse

GROUP = 'group servers { host "one" address "192.0.2.10"; }'


def program(body: str) -> str:
    return f'{GROUP}\nplay "audit" targets servers {{ {body} }}'


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("1 + 2 * 3", "7"),
        ("(1 + 2) * 3", "9"),
        ("20 / 4 / 2", "2"),
        ("true or false and false", "true"),
        ("not false and 2 + 3 * 2 == 8", "true"),
        ('ip("192.0.2.10") in network("192.0.2.0/24")', "true"),
        ('ip("2001:db8::1") in network("192.0.2.0/24")', "false"),
        ("-7 / 2", "-4"),
        ("7 % 3", "1"),
    ],
)
def test_expression_precedence_and_domain_membership(expression: str, expected: str) -> None:
    assert compile_source(f"report {expression};").instructions[0].message == expected


@pytest.mark.parametrize(
    ("source", "code"),
    [
        (program("check port 65536 protocol tcp;"), "E_PORT"),
        (program("check port 0 protocol tcp;"), "E_PORT"),
        (program("check port true protocol tcp;"), "E_TYPE"),
        (program("check port 53 protocol udp;"), "E_UDP_CHECK"),
        ('ip address_value = ip("999.1.1.1");', "E_ADDRESS"),
        ('network lan = network("192.0.2.10/24");', "E_ADDRESS"),
        ('int count = "one";', "E_TYPE"),
        ("port ssh_port = 22;", "E_TYPE"),
        ("report missing;", "E_UNDEFINED"),
        (program("repeat -1 { report 1; }"), "E_REPEAT"),
        (program("if 1 { report 1; }"), "E_TYPE"),
        (program('check service "smtp";'), "E_SERVICE"),
        ("int value = 2; int value = 3;", "E_DUPLICATE"),
        (program("int value = 2; if true { int inside = 3; } report inside;"), "E_UNDEFINED"),
        (program('if false { int value = "bad"; }'), "E_TYPE"),
        ("report 1 / 0;", "E_ZERO_DIVISION"),
        ("group empty {}", "E_GROUP_SIZE"),
        ("check port 22 protocol tcp;", "E_CONTEXT"),
    ],
)
def test_well_formed_but_invalid_programs_are_rejected(source: str, code: str) -> None:
    parse(Source(text=source))
    with pytest.raises(NetSecError, match=code) as captured:
        compile_source(source, "policy.netsec")
    assert captured.value.diagnostic.span.filename == "policy.netsec"
    assert captured.value.diagnostic.span.line >= 1
    assert captured.value.diagnostic.span.column >= 1


def test_lexical_scopes_shadow_without_leaking_and_repeat_executes() -> None:
    plan = compile_source(
        program(
            "int value = 1; if true { int value = 2; report value; } repeat 2 { report value; }"
        )
    )
    assert [item.message for item in plan.instructions] == ["2", "1", "1"]


def test_conflict_detected_across_overlapping_groups_and_reports_both_locations() -> None:
    source = GROUP + '\ngroup alias { host "other" address "192.0.2.10"; }\n'
    source += 'play "first" targets servers { firewall allow port 22 protocol tcp; }\n'
    source += 'play "second" targets alias { firewall deny port 22 protocol tcp; }'
    with pytest.raises(NetSecError, match="E_FIREWALL_CONFLICT") as captured:
        compile_source(source, "conflict.netsec")
    assert captured.value.diagnostic.span.line == 4
    assert captured.value.diagnostic.related is not None
    assert captured.value.diagnostic.related.line == 3


def test_unreachable_conflicting_rule_is_not_part_of_the_policy() -> None:
    plan = compile_source(
        program(
            "firewall allow port 22 protocol tcp; if false { firewall deny port 22 protocol tcp; }"
        )
    )
    assert [item.operation for item in plan.instructions] == ["allow"]


def test_duplicate_ipv6_aliases_are_rejected() -> None:
    source = 'group machines { host "a" address "::1"; host "b" address "0:0:0:0:0:0:0:1"; }'
    with pytest.raises(NetSecError, match="E_DUPLICATE_HOST"):
        compile_source(source)


def test_token_position_after_comments_crlf_and_unicode_string() -> None:
    tokens = tokenize(Source(text='// first\r\nreport "ação";\r\n', filename="test.netsec"))
    assert tokens[0].kind == "report"
    assert (tokens[0].span.line, tokens[0].span.column) == (2, 1)
    assert tokens[-1].span.line == 3


@pytest.mark.parametrize("source", ['report "unterminated;', 'report "\\q";', "report 1", "@"])
def test_invalid_syntax_is_located(source: str) -> None:
    with pytest.raises(NetSecError, match=r"test\.netsec:1:"):
        compile_source(source, "test.netsec")


def test_excessive_expansion_is_rejected_before_allocating_it() -> None:
    with pytest.raises(NetSecError, match="E_LIMIT"):
        compile_source(program("repeat 100 { repeat 100 { repeat 100 { report 1; } } }"))


def test_long_protocol_expression_reports_limit_instead_of_python_recursion() -> None:
    expression = " == ".join(["tcp"] * 1500)
    with pytest.raises(NetSecError, match="E_LIMIT"):
        compile_source(program(f"check port 22 protocol {expression};"))


def test_repetition_cannot_expand_small_source_into_an_excessive_report() -> None:
    body = 'report "' + "x" * 200 + '";'
    with pytest.raises(NetSecError, match="plan text exceeds"):
        compile_source(program("repeat 100 { repeat 100 { " + body + " } }"))
