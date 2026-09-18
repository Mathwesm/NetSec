"""Manage a dedicated nftables table on the local Linux network namespace."""

from __future__ import annotations

from netsec.platforms.models import OWNER, FirewallRule, NativeState
from netsec.platforms.process import command, decode
from netsec.runtime import RuntimeFailureError
from netsec.services.probes import ProbeResult

TABLE = "netsec_native"


def _objects(text: str, kind: str) -> list[dict[str, object]]:
    data = decode(text)
    if not isinstance(data, dict) or not isinstance(data.get("nftables"), list):
        raise RuntimeFailureError("Invalid nftables inventory")
    return [
        entry[kind]
        for entry in data["nftables"]
        if isinstance(entry, dict) and isinstance(entry.get(kind), dict)
    ]


def _addresses(text: str) -> tuple[str, ...]:
    data = decode(text)
    if not isinstance(data, list):
        raise RuntimeFailureError("Invalid iproute2 address inventory")
    addresses: list[str] = []
    for interface in data:
        if not isinstance(interface, dict) or not isinstance(interface.get("addr_info"), list):
            raise RuntimeFailureError("Invalid interface address data")
        for address in interface["addr_info"]:
            if isinstance(address, dict) and isinstance(address.get("local"), str):
                addresses.append(address["local"])
    return tuple(addresses)


def expression(rule: FirewallRule) -> list[dict[str, object]]:
    """Describe the expected kernel rule to detect manually introduced drift."""
    family = "ip6" if ":" in rule.host else "ip"
    return [
        {
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": family, "field": "daddr"}},
                "right": rule.host,
            }
        },
        {
            "match": {
                "op": "==",
                "left": {"payload": {"protocol": rule.protocol, "field": "dport"}},
                "right": rule.port,
            }
        },
        {"accept" if rule.action == "allow" else "drop": None},
    ]


class LinuxFirewall:
    """Preserve all tables except the explicitly owned NetSec namespace."""

    def inspect(self) -> NativeState:
        """Require iproute2 and query nftables to test actual NET_ADMIN access."""
        addresses = _addresses(command("ip", ["-j", "address", "show"]))
        try:
            self._inventory()
        except RuntimeFailureError as error:
            return NativeState(
                platform="linux", addresses=addresses, can_manage=False, detail=str(error)
            )
        return NativeState(
            platform="linux",
            addresses=addresses,
            can_manage=True,
            detail="nftables available in this network namespace",
        )

    def _inventory(self) -> str | None:
        tables = _objects(command("nft", ["-j", "list", "tables"]), "table")
        if not any(
            table.get("family") == "inet" and table.get("name") == TABLE for table in tables
        ):
            return None
        text = command("nft", ["-j", "list", "table", "inet", TABLE])
        owned = _objects(text, "table")
        chains = _objects(text, "chain")
        _legacy_comments(owned, chains)
        if len(owned) != 1 or owned[0].get("comment") != OWNER:
            raise RuntimeFailureError("Existing NetSec table has no matching ownership marker")
        if len(chains) != 1 or not _valid_chain(chains[0]):
            raise RuntimeFailureError("Managed nftables chain configuration has changed")
        if any(
            not str(rule.get("comment", "")).startswith(f"{OWNER}:")
            for rule in _objects(text, "rule")
        ):
            raise RuntimeFailureError("Unowned rule found in the managed nftables table")
        return text

    def ensure(self, rule: FirewallRule) -> ProbeResult:
        """Create or repair one rule in a single nftables transaction."""
        inventory = self._inventory()
        initial = (
            ""
            if inventory
            else (
                f'add table inet {TABLE} {{ comment "{OWNER}"; }}\n'
                f"add chain inet {TABLE} input {{ type filter hook input priority 0; "
                f'policy accept; comment "{OWNER}"; }}\n'
            )
        )
        matches = _matching(inventory, rule)
        if (
            len(matches) == 1
            and matches[0].get("comment") == rule.tag
            and (matches[0].get("expr") == expression(rule))
        ):
            return ProbeResult(True, "unchanged", "Native Linux rule matches desired policy")
        family = "ip6" if ":" in rule.host else "ip"
        verdict = "accept" if rule.action == "allow" else "drop"
        transaction = (
            initial
            + _deletions(matches)
            + (
                f"add rule inet {TABLE} input {family} daddr {rule.host} "
                f'{rule.protocol} dport {rule.port} {verdict} comment "{rule.tag}"\n'
            )
        )
        command("nft", ["--check", "-f", "-"], transaction)
        command("nft", ["-f", "-"], transaction)
        return ProbeResult(True, "applied", "Native Linux inbound rule applied")

    def remove(self, rule: FirewallRule) -> ProbeResult:
        """Delete the matching owned rule, leaving unrelated endpoints intact."""
        matches = _matching(self._inventory(), rule)
        if not matches:
            return ProbeResult(True, "unchanged", "Managed rule is already absent")
        command("nft", ["-f", "-"], _deletions(matches))
        return ProbeResult(True, "removed", "Managed Linux rule removed")


def _valid_chain(chain: dict[str, object]) -> bool:
    return (
        chain.get("name") == "input"
        and chain.get("type") == "filter"
        and chain.get("hook") == "input"
        and chain.get("prio") == 0
        and chain.get("policy") == "accept"
        and chain.get("comment") == OWNER
    )


def _legacy_comments(tables: list[dict[str, object]], chains: list[dict[str, object]]) -> None:
    # nft 1.0.6 omits table/chain comments from JSON; verify its canonical text output.
    if len(tables) != 1 or len(chains) != 1:
        return
    if "comment" in tables[0] and "comment" in chains[0]:
        return
    lines = command("nft", ["list", "table", "inet", TABLE]).splitlines()
    if "comment" not in tables[0] and f'\tcomment "{OWNER}"' in lines:
        tables[0]["comment"] = OWNER
    if "comment" not in chains[0] and f'\t\tcomment "{OWNER}"' in lines:
        chains[0]["comment"] = OWNER


def _matching(inventory: str | None, rule: FirewallRule) -> list[dict[str, object]]:
    if inventory is None:
        return []
    prefix = f"{OWNER}:{rule.key}:"
    return [
        item
        for item in _objects(inventory, "rule")
        if str(item.get("comment", "")).startswith(prefix)
    ]


def _deletions(rules: list[dict[str, object]]) -> str:
    lines: list[str] = []
    for rule in rules:
        handle = rule.get("handle")
        if type(handle) is not int or handle < 1:
            raise RuntimeFailureError("Invalid nftables rule handle")
        lines.append(f"delete rule inet {TABLE} input handle {handle}\n")
    return "".join(lines)
