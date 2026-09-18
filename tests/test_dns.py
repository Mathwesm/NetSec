from __future__ import annotations

from unittest.mock import Mock

import dns.exception
import dns.resolver
import pytest

from netsec.core.compiler import compile_source
from netsec.core.model import NetSecError
from netsec.evaluation import wrap
from netsec.services.dns import probe_dns


def test_dns_compilation_is_typed_and_canonical() -> None:
    plan = compile_source(wrap('check dns "APP.Example.test" expect ip("2001:db8::10");'))
    check = plan.instructions[0]
    assert (check.operation, check.message, check.expected, check.port) == (
        "check_dns",
        "app.example.test.",
        "2001:db8::10",
        53,
    )
    assert plan.format_version == 2


@pytest.mark.parametrize(
    ("source", "code"),
    [
        ('check dns "bad;name" expect "192.0.2.1";', "E_DNS_NAME"),
        ('check dns "name..test" expect "192.0.2.1";', "E_DNS_NAME"),
        ('check dns "-name.test" expect "192.0.2.1";', "E_DNS_NAME"),
        ('check dns "name.test" expect true;', "E_TYPE"),
        ('check dns 5 expect "192.0.2.1";', "E_TYPE"),
    ],
)
def test_dns_static_errors_are_located(source: str, code: str) -> None:
    with pytest.raises(NetSecError, match=code) as error:
        compile_source(wrap(source), "dns.netsec")
    assert error.value.diagnostic.span.filename == "dns.netsec"


@pytest.mark.parametrize(
    ("response", "expected", "status"),
    [
        ("192.0.2.1", "192.0.2.1", "resolved"),
        ("192.0.2.2", "192.0.2.1", "unexpected_address"),
        ("2001:db8:0::1", "2001:db8::1", "resolved"),
    ],
)
def test_dns_uses_only_selected_resolver_and_expected_address(
    response: str,
    expected: str,
    status: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = Mock()
    record.to_text.return_value = response
    resolver = Mock()
    resolver.resolve.return_value = [record]
    factory = Mock(return_value=resolver)
    monkeypatch.setattr("netsec.services.dns.dns.resolver.Resolver", factory)
    result = probe_dns("192.0.2.53", "app.test", expected, 0.1)
    assert result.status == status
    assert result.success == (status == "resolved")
    factory.assert_called_once_with(configure=False)
    assert resolver.nameservers == ["192.0.2.53"]
    assert resolver.resolve.call_args.kwargs == {"search": False, "lifetime": 0.1}
    assert resolver.resolve.call_args.args[1] == ("AAAA" if ":" in expected else "A")


@pytest.mark.parametrize(
    ("error", "status", "calls"),
    [
        (dns.resolver.NXDOMAIN(), "nxdomain", 1),
        (dns.resolver.NoAnswer(), "no_answer", 1),
        (dns.exception.Timeout(), "timeout", 2),
        (dns.resolver.NoNameservers(), "dns_error", 1),
    ],
)
def test_dns_failure_is_not_mistaken_for_health(
    error: Exception,
    status: str,
    calls: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = Mock()
    resolver.resolve.side_effect = error
    monkeypatch.setattr("netsec.services.dns.dns.resolver.Resolver", lambda **_: resolver)
    result = probe_dns("192.0.2.53", "app.test", "192.0.2.1", 0.1)
    assert not result.success and result.status == status
    assert resolver.resolve.call_count == calls
