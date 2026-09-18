from __future__ import annotations

import base64
import json
from unittest.mock import Mock

import pytest
from pydantic import SecretStr, ValidationError

from netsec.platforms.wireguard import apply_tunnel, remove_tunnel
from netsec.platforms.wireguard_models import Tunnel, TunnelSecret, native_config
from netsec.runtime import RuntimeFailureError


def public_key(seed: int = 1) -> str:
    return base64.b64encode(bytes([seed]) * 32).decode("ascii")


def manifest() -> dict[str, object]:
    return {
        "interface": "nswg0",
        "address": "10.66.0.1/24",
        "peers": [
            {
                "public_key": public_key(),
                "allowed_ips": ["10.66.0.2/32"],
                "endpoint_address": "192.0.2.2",
                "keepalive": 25,
            },
        ],
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("interface", "eth0"),
        ("interface", "nswg0;sh"),
        ("address", "127.0.0.1/24"),
        ("listen_port", 0),
        ("mtu", 0),
        ("peers", []),
    ],
)
def test_tunnel_rejects_unsafe_structure(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        Tunnel.model_validate({**manifest(), field: value})


@pytest.mark.parametrize(
    "allowed", [["0.0.0.0/0"], ["10.67.0.2/32"], ["10.66.0.1/32"], ["10.66.0.2/32", "10.66.0.2/32"]]
)
def test_tunnel_rejects_full_routes_wrong_subnets_and_duplicate_peers(allowed: list[str]) -> None:
    peer = {"public_key": public_key(), "allowed_ips": allowed}
    with pytest.raises(ValidationError):
        Tunnel.model_validate({**manifest(), "peers": [peer]})


def test_secret_is_not_in_public_manifest_or_settings_repr() -> None:
    tunnel = Tunnel.model_validate(manifest())
    secret = TunnelSecret(private_key=SecretStr(public_key(2)))
    assert secret.private_key.get_secret_value() not in repr(secret)
    assert secret.private_key.get_secret_value() not in tunnel.model_dump_json()
    config = native_config(tunnel, secret.private_key)
    assert "AllowedIPs = 10.66.0.2/32" in config
    assert "Endpoint = 192.0.2.2:51820" in config


def test_unowned_interface_is_never_modified(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("netsec.platforms.wireguard.platform.system", lambda: "Linux")
    call = Mock(return_value=json.dumps([{"ifname": "nswg0", "ifalias": "another-owner"}]))
    monkeypatch.setattr("netsec.platforms.wireguard.command", call)
    with pytest.raises(RuntimeFailureError, match="not an owned"):
        remove_tunnel(Tunnel.model_validate(manifest()), apply=True)
    assert call.call_count == 1


def test_overlapping_lan_blocks_tunnel_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("netsec.platforms.wireguard.platform.system", lambda: "Linux")
    call = Mock(
        return_value=json.dumps(
            [
                {
                    "ifname": "eth0",
                    "addr_info": [
                        {"local": "10.66.0.5", "prefixlen": 24},
                    ],
                }
            ]
        )
    )
    monkeypatch.setattr("netsec.platforms.wireguard.command", call)
    with pytest.raises(RuntimeFailureError, match="overlaps"):
        apply_tunnel(Tunnel.model_validate(manifest()), SecretStr(public_key(2)), apply=True)
    assert call.call_count == 1


def test_failed_new_tunnel_is_removed_and_private_key_never_enters_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("netsec.platforms.wireguard.platform.system", lambda: "Linux")
    call = Mock(
        side_effect=["[]", public_key(3), "", "", RuntimeFailureError("setconf failed"), ""]
    )
    monkeypatch.setattr("netsec.platforms.wireguard.command", call)
    secret = SecretStr(public_key(2))
    with pytest.raises(RuntimeFailureError, match="setconf failed"):
        apply_tunnel(Tunnel.model_validate(manifest()), secret, apply=True)
    assert call.call_args.args == ("ip", ["link", "delete", "dev", "nswg0"])
    assert all(
        secret.get_secret_value() not in " ".join(item.args[1]) for item in call.call_args_list
    )


def test_tunnel_without_apply_never_queries_or_changes_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("netsec.platforms.wireguard.platform.system", lambda: "Linux")
    call = Mock()
    monkeypatch.setattr("netsec.platforms.wireguard.command", call)
    with pytest.raises(RuntimeFailureError, match="require --apply"):
        apply_tunnel(Tunnel.model_validate(manifest()), SecretStr(public_key(2)), apply=False)
    call.assert_not_called()


def test_vpn_endpoint_rejects_ipv6_scope_config_injection() -> None:
    peer = {
        "public_key": public_key(),
        "allowed_ips": ["10.66.0.2/32"],
        "endpoint_address": "fe80::1%eth0\nExtra = invalid",
    }
    with pytest.raises(ValidationError, match="Scoped"):
        Tunnel.model_validate({**manifest(), "peers": [peer]})
