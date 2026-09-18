"""Converge an owned WireGuard interface without touching host NAT or default routes."""

from __future__ import annotations

import platform
from datetime import UTC, datetime
from ipaddress import ip_interface

from pydantic import SecretStr

from netsec.platforms.process import command, decode
from netsec.platforms.wireguard_models import InterfaceAddress, Tunnel, native_config
from netsec.runtime import RuntimeFailureError
from netsec.services.probes import ProbeResult

OWNER = "netsec-wireguard-v1"
_PUBLIC_FIELDS = 2


def _interfaces() -> list[dict[str, object]]:
    data = decode(command("ip", ["-details", "-j", "address", "show"]))
    if not isinstance(data, list) or any(not isinstance(item, dict) for item in data):
        raise RuntimeFailureError("Invalid native interface inventory")
    return data


def _owned(tunnel: Tunnel) -> dict[str, object] | None:
    interfaces = _interfaces()
    current = next((item for item in interfaces if item.get("ifname") == tunnel.interface), None)
    if current is not None:
        details = current.get("linkinfo")
        if (
            current.get("ifalias") != OWNER
            or not isinstance(details, dict)
            or details.get("info_kind") != "wireguard"
        ):
            raise RuntimeFailureError("Interface is not an owned NetSec WireGuard tunnel")
    for interface in interfaces:
        if interface is current:
            continue
        for address in _addresses(interface):
            if address.version == tunnel.address.version and address.network.overlaps(
                tunnel.address.network
            ):
                raise RuntimeFailureError("Tunnel subnet overlaps another local interface")
    return current


def _addresses(interface: dict[str, object]) -> list[InterfaceAddress]:
    data = interface.get("addr_info", [])
    if not isinstance(data, list):
        raise RuntimeFailureError("Invalid interface addresses")
    return [
        ip_interface(f"{item['local']}/{item['prefixlen']}")
        for item in data
        if isinstance(item, dict) and "local" in item and "prefixlen" in item
    ]


def _peer_map(tunnel: Tunnel, field: str) -> dict[str, str]:
    lines = command("wg", ["show", tunnel.interface, field]).strip().splitlines()
    result: dict[str, str] = {}
    for line in lines:
        pieces = line.split("\t", 1)
        if len(pieces) != _PUBLIC_FIELDS:
            raise RuntimeFailureError("Invalid WireGuard public state")
        result[pieces[0]] = pieces[1]
    return result


def _matches(tunnel: Tunnel, current: dict[str, object], public_key: str) -> bool:
    if command("wg", ["show", tunnel.interface, "public-key"]).strip() != public_key:
        return False
    if command("wg", ["show", tunnel.interface, "listen-port"]).strip() != str(tunnel.listen_port):
        return False
    allowed = _peer_map(tunnel, "allowed-ips")
    expected = {
        peer.public_key: {str(network) for network in peer.allowed_ips} for peer in tunnel.peers
    }
    observed = {key: set(value.replace(",", " ").split()) for key, value in allowed.items()}
    if observed != expected:
        return False
    keepalive = _peer_map(tunnel, "persistent-keepalive")
    endpoints = _peer_map(tunnel, "endpoints")
    flags = current.get("flags", [])
    return (
        current.get("mtu") == tunnel.mtu
        and isinstance(flags, list)
        and "UP" in flags
        and all(
            keepalive.get(peer.public_key) == (str(peer.keepalive) if peer.keepalive else "off")
            and (peer.endpoint is None or endpoints.get(peer.public_key) == peer.endpoint)
            for peer in tunnel.peers
        )
    )


def apply_tunnel(tunnel: Tunnel, private_key: SecretStr, *, apply: bool) -> ProbeResult:
    """Create/repair one owned interface, sending its secret exclusively through stdin."""
    _require_apply(apply)
    current = _owned(tunnel)
    public = command("wg", ["pubkey"], private_key.get_secret_value() + "\n").strip()
    if public in {peer.public_key for peer in tunnel.peers}:
        raise RuntimeFailureError("Local and peer public keys cannot be identical")
    if current is not None:
        if _addresses(current) != [tunnel.address]:
            raise RuntimeFailureError(
                "Owned tunnel address changed; remove it explicitly before reprovisioning"
            )
        if _matches(tunnel, current, public):
            return ProbeResult(True, "unchanged", "WireGuard public state matches desired topology")
    created = current is None
    if created:
        command("ip", ["link", "add", "dev", tunnel.interface, "type", "wireguard"])
    try:
        command("ip", ["link", "set", "dev", tunnel.interface, "alias", OWNER])
        command(
            "wg", ["setconf", tunnel.interface, "/dev/stdin"], native_config(tunnel, private_key)
        )
        if created:
            command("ip", ["address", "add", str(tunnel.address), "dev", tunnel.interface])
        command("ip", ["link", "set", "dev", tunnel.interface, "mtu", str(tunnel.mtu), "up"])
    except RuntimeFailureError:
        if created:
            command("ip", ["link", "delete", "dev", tunnel.interface])
        raise
    return ProbeResult(
        True, "applied", "Owned WireGuard tunnel configured; verify peer handshake separately"
    )


def remove_tunnel(tunnel: Tunnel, *, apply: bool) -> ProbeResult:
    """Remove only the owned interface; never remove another application's VPN."""
    _require_apply(apply)
    if _owned(tunnel) is None:
        return ProbeResult(True, "unchanged", "Owned WireGuard tunnel is already absent")
    command("ip", ["link", "delete", "dev", tunnel.interface])
    return ProbeResult(True, "removed", "Owned WireGuard interface removed")


def tunnel_status(tunnel: Tunnel) -> dict[str, object]:
    """Read only public VPN state and handshake times, never a private-key dump."""
    if platform.system() != "Linux":
        raise RuntimeFailureError("Native WireGuard status currently supports Linux only")
    if _owned(tunnel) is None:
        return {"present": False, "interface": tunnel.interface, "peers": []}
    timestamps = _peer_map(tunnel, "latest-handshakes")
    peers: list[dict[str, object]] = []
    for public, value in timestamps.items():
        try:
            timestamp = int(value)
            date = datetime.fromtimestamp(timestamp, UTC).isoformat() if timestamp else None
        except (ValueError, OverflowError, OSError) as error:
            raise RuntimeFailureError("Invalid WireGuard handshake timestamp") from error
        peers.append({"public_key": public, "latest_handshake_utc": date})
    return {"present": True, "interface": tunnel.interface, "peers": peers}


def _require_apply(apply: bool) -> None:
    if platform.system() != "Linux":
        raise RuntimeFailureError("Native WireGuard provisioning currently supports Linux only")
    if not apply:
        raise RuntimeFailureError("WireGuard changes require --apply")
