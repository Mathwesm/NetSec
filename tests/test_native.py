from __future__ import annotations

import json
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from netsec.core.compiler import compile_source
from netsec.evaluation import wrap
from netsec.platforms.linux import LinuxFirewall, expression
from netsec.platforms.models import OWNER, FirewallRule, NativeState
from netsec.platforms.native import NativeAdapter
from netsec.runtime import RuntimeFailureError, execute
from netsec.services.probes import ProbeResult


def rule() -> FirewallRule:
    return FirewallRule(host="192.0.2.10", port=23, protocol="tcp", action="deny")


def inventory(*, verdict: str = "drop", comment: str | None = None) -> str:
    desired = rule()
    expressions = expression(desired)
    expressions[-1] = {verdict: None}
    return json.dumps(
        {
            "nftables": [
                {"table": {"name": "netsec_native", "family": "inet", "comment": OWNER}},
                {
                    "chain": {
                        "name": "input",
                        "type": "filter",
                        "hook": "input",
                        "prio": 0,
                        "policy": "accept",
                        "comment": OWNER,
                    }
                },
                {
                    "rule": {
                        "handle": 8,
                        "comment": desired.tag if comment is None else comment,
                        "expr": expressions,
                    }
                },
            ]
        }
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"host": "192.0.2.1; flush ruleset"},
        {"host": "fe80::1%eth0"},
        {"port": True},
        {"port": 0},
        {"port": 65536},
        {"protocol": "tcp;"},
        {"action": "flush"},
    ],
)
def test_rule_rejects_invalid_or_executable_inputs(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        FirewallRule.model_validate({**rule().model_dump(), **changes})


def test_ipv6_aliases_have_one_identity_independent_of_action() -> None:
    first = FirewallRule(host="2001:db8:0::1", port=65535, protocol="udp", action="allow")
    second = FirewallRule(host="2001:db8::1", port=65535, protocol="udp", action="deny")
    assert first.key == second.key
    assert first.tag != second.tag
    assert expression(first)[0]["match"]["right"] == "2001:db8::1"


@pytest.mark.parametrize(
    ("apply", "addresses", "can_manage", "port", "message"),
    [
        (False, ("192.0.2.10",), True, 23, "require --apply"),
        (True, ("192.0.2.11",), True, 23, "not an address"),
        (True, ("192.0.2.10",), False, 23, "not elevated"),
        (True, ("192.0.2.10",), True, 22, "management ports"),
    ],
)
def test_native_preflight_never_partially_applies(
    apply: bool,
    addresses: tuple[str, ...],
    can_manage: bool,
    port: int,
    message: str,
) -> None:
    backend = Mock()
    backend.inspect.return_value = NativeState(
        platform="linux", addresses=addresses, can_manage=can_manage
    )
    adapter = NativeAdapter(1, apply=apply, backend=backend)
    plan = compile_source(wrap(f"firewall deny port {port} protocol tcp;"))
    with pytest.raises(RuntimeFailureError, match=message):
        execute(plan, adapter, "local")
    backend.ensure.assert_not_called()
    backend.remove.assert_not_called()


def test_native_needs_preflight_and_can_remove_only_selected_policy() -> None:
    backend = Mock()
    backend.inspect.return_value = NativeState(
        platform="linux", addresses=("192.0.2.10",), can_manage=True
    )
    backend.ensure.return_value = ProbeResult(True, "applied", "test")
    backend.remove.return_value = ProbeResult(True, "removed", "test")
    adapter = NativeAdapter(1, apply=True, backend=backend)
    plan = compile_source(wrap("firewall deny port 23 protocol tcp;"))
    with pytest.raises(RuntimeFailureError, match="did not pass"):
        adapter.firewall(plan.instructions[0])
    assert execute(plan, adapter, "local").success
    assert adapter.remove(plan)[0].status == "removed"
    backend.remove.assert_called_once_with(rule())


def test_nft_idempotence_checks_expression_not_only_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    call = Mock(side_effect=[inventory(), inventory()])
    monkeypatch.setattr("netsec.platforms.linux.command", call)
    assert LinuxFirewall().ensure(rule()).status == "unchanged"
    assert call.call_count == 2


def test_nft_repairs_drift_atomically_and_checks_syntax_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    call = Mock(side_effect=[inventory(), inventory(verdict="accept"), "", ""])
    monkeypatch.setattr("netsec.platforms.linux.command", call)
    assert LinuxFirewall().ensure(rule()).status == "applied"
    validation = call.call_args_list[-2].args
    application = call.call_args_list[-1].args
    assert validation[1] == ["--check", "-f", "-"]
    assert validation[2] == application[2]
    assert "delete rule inet netsec_native input handle 8\nadd rule" in application[2]
    assert "tcp dport 23 drop" in application[2]
    assert "flush" not in application[2]


def test_nft_preserves_unowned_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    call = Mock(side_effect=[inventory(), inventory(comment="external-admin")])
    monkeypatch.setattr("netsec.platforms.linux.command", call)
    with pytest.raises(RuntimeFailureError, match="Unowned rule"):
        LinuxFirewall().remove(rule())
    assert call.call_count == 2


def test_nft_first_use_creates_only_owned_table(monkeypatch: pytest.MonkeyPatch) -> None:
    call = Mock(side_effect=['{"nftables": []}', "", ""])
    monkeypatch.setattr("netsec.platforms.linux.command", call)
    assert LinuxFirewall().ensure(rule()).success
    transaction = call.call_args.args[2]
    assert "add table inet netsec_native" in transaction
    assert "policy accept" in transaction
    assert "flush" not in transaction


def test_nft_legacy_json_uses_text_to_verify_actual_ownership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = json.loads(inventory())
    del legacy["nftables"][0]["table"]["comment"]
    del legacy["nftables"][1]["chain"]["comment"]
    text = (
        'table inet netsec_native {\n\tcomment "netsec-managed-v1"\n'
        '\tchain input {\n\t\tcomment "netsec-managed-v1"\n\t}\n}\n'
    )
    call = Mock(side_effect=[json.dumps(legacy), json.dumps(legacy), text])
    monkeypatch.setattr("netsec.platforms.linux.command", call)
    assert LinuxFirewall().ensure(rule()).status == "unchanged"
    assert call.call_args.args[1] == ["list", "table", "inet", "netsec_native"]
