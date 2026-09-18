"""Validate DNS names without performing resolution during compilation."""

import re

MAX_DOMAIN_LENGTH = 253


def dns_name(value: str) -> str:
    """Normalize an ASCII hostname and reject ambiguous search-list syntax."""
    name = value.rstrip(".").lower()
    if not name or len(name) > MAX_DOMAIN_LENGTH or value.endswith(".."):
        raise ValueError("DNS hostname must contain between 1 and 253 characters")
    if any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in name.split(".")
    ):
        raise ValueError("DNS hostname contains an invalid label; use ASCII or punycode")
    return name + "."
