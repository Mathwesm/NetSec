"""Validate a bounded WireGuard server/peer topology before native changes."""

from __future__ import annotations

import base64
import binascii
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    IPvAnyInterface,
    IPvAnyNetwork,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

KEY_BYTES = 32


def validate_key(value: str) -> str:
    """Require canonical base64 encoding of exactly one WireGuard key."""
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("WireGuard key must be canonical base64") from error
    if len(raw) != KEY_BYTES or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("WireGuard key must contain exactly 32 bytes")
    return value


class Peer(BaseModel):
    """Describe one public peer without carrying its private identity."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    public_key: str
    allowed_ips: tuple[IPvAnyNetwork, ...] = Field(min_length=1, max_length=16)
    endpoint_address: IPvAnyAddress | None = None
    endpoint_port: int = Field(default=51820, ge=1, le=65535, strict=True)
    keepalive: int = Field(default=0, ge=0, le=65535, strict=True)

    @field_validator("public_key")
    @classmethod
    def key(cls, value: str) -> str:
        """Validate the public half of the peer identity."""
        return validate_key(value)

    @property
    def endpoint(self) -> str | None:
        """Render a literal endpoint with IPv6 brackets where required."""
        if self.endpoint_address is None:
            return None
        host = str(self.endpoint_address)
        return f"[{host}]:{self.endpoint_port}" if ":" in host else f"{host}:{self.endpoint_port}"

    @field_validator("endpoint_address")
    @classmethod
    def unscoped_endpoint(
        cls, value: IPv4Address | IPv6Address | None
    ) -> IPv4Address | IPv6Address | None:
        """Disallow IPv6 zones that could introduce native configuration syntax."""
        if value is not None and "%" in str(value):
            raise ValueError("Scoped IPv6 endpoints are unsupported")
        return value

    @field_validator("allowed_ips")
    @classmethod
    def unscoped_networks(
        cls, values: tuple[IPv4Network | IPv6Network, ...]
    ) -> tuple[IPv4Network | IPv6Network, ...]:
        """Keep every network an unscoped canonical literal."""
        if any("%" in str(value) for value in values):
            raise ValueError("Scoped IPv6 networks are unsupported")
        return values


class Tunnel(BaseModel):
    """Own one routed VPN subnet without modifying NAT or the machine's default route."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    interface: str = Field(pattern=r"^nswg[0-9]{1,2}$")
    address: IPvAnyInterface
    listen_port: int = Field(default=51820, ge=1, le=65535, strict=True)
    mtu: int = Field(default=1420, ge=1280, le=9000, strict=True)
    peers: tuple[Peer, ...] = Field(min_length=1, max_length=128)

    @field_validator("address")
    @classmethod
    def unscoped_address(
        cls, value: IPv4Interface | IPv6Interface
    ) -> IPv4Interface | IPv6Interface:
        """Reject zone-bearing addresses before constructing iproute2 arguments."""
        if "%" in str(value):
            raise ValueError("Scoped IPv6 tunnel addresses are unsupported")
        return value

    @model_validator(mode="after")
    def topology(self) -> Tunnel:
        """Reject duplicate identities, overlapping peers and implicit full-tunnel routes."""
        if (
            self.address.ip.is_loopback
            or self.address.ip.is_multicast
            or self.address.ip.is_unspecified
        ):
            raise ValueError("Tunnel address must be a unicast non-loopback address")
        if len({peer.public_key for peer in self.peers}) != len(self.peers):
            raise ValueError("Duplicate peer public key")
        occupied: set[IPv4Address | IPv6Address] = set()
        for peer in self.peers:
            for network in peer.allowed_ips:
                self._peer_network(network)
                if network.network_address in occupied:
                    raise ValueError("Peer addresses overlap")
                occupied.add(network.network_address)
        return self

    def _peer_network(self, network: IPv4Network | IPv6Network) -> None:
        if network.prefixlen != network.max_prefixlen:
            raise ValueError("This backend requires explicit /32 or /128 peer addresses")
        if (
            network.version != self.address.version
            or network.network_address not in self.address.network
        ):
            raise ValueError("Peer address must belong to the declared tunnel subnet")
        if network.network_address == self.address.ip:
            raise ValueError("Peer address cannot equal the local tunnel address")


class TunnelSecret(BaseSettings):
    """Load only the local private key from the process environment, never a manifest."""

    model_config = SettingsConfigDict(env_prefix="NETSEC_WG_", extra="forbid")
    private_key: SecretStr

    @field_validator("private_key")
    @classmethod
    def key(cls, value: SecretStr) -> SecretStr:
        """Validate without exposing a private key in the model representation."""
        validate_key(value.get_secret_value())
        return value


def native_config(tunnel: Tunnel, private_key: SecretStr) -> str:
    """Render secret configuration for stdin only; callers must never log or persist it."""
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key.get_secret_value()}",
        f"ListenPort = {tunnel.listen_port}",
    ]
    for peer in tunnel.peers:
        lines.extend(
            [
                "",
                "[Peer]",
                f"PublicKey = {peer.public_key}",
                "AllowedIPs = " + ", ".join(map(str, peer.allowed_ips)),
                f"PersistentKeepalive = {peer.keepalive}",
            ]
        )
        if peer.endpoint:
            lines.append("Endpoint = " + peer.endpoint)
    return "\n".join(lines) + "\n"


type InterfaceAddress = IPv4Interface | IPv6Interface
