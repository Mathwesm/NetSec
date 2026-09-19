"""Validate declarative server resources independently of operating-system backends."""

from ipaddress import ip_address
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from netsec.core.domains import dns_name


class ServerResource(BaseModel):
    """Describe one owned HTTP or authoritative-only DNS endpoint."""

    model_config = ConfigDict(frozen=True, extra="forbid")
    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,31}$")
    kind: Literal["http", "dns"]
    host: str
    port: int = Field(ge=1, le=65535, strict=True)
    content: str = Field(default="", max_length=100_000)
    record: str = Field(default="", max_length=253)
    address: str = ""

    @field_validator("host", "address")
    @classmethod
    def canonical_address(cls, value: str) -> str:
        """Reject scoped or nonliteral bind and answer addresses."""
        if not value:
            return value
        if "%" in value:
            raise ValueError("Scoped addresses are unsupported")
        address = ip_address(value)
        if address.is_multicast or address.is_unspecified:
            raise ValueError("A specific unicast address is required")
        return str(address)

    @model_validator(mode="after")
    def validate_kind(self) -> Self:
        """Reject ambiguous manifests instead of ignoring incompatible fields."""
        if not self.host:
            raise ValueError("Server bind address is required")
        if self.kind == "dns":
            if self.content or not self.address or dns_name(self.record) != self.record:
                raise ValueError("DNS requires a canonical record and answer, without HTTP content")
        elif self.record or self.address:
            raise ValueError("HTTP does not accept DNS fields")
        return self
