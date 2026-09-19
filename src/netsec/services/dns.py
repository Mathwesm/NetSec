"""Verify A or AAAA answers from one explicitly selected DNS server."""

from __future__ import annotations

from ipaddress import IPv6Address, ip_address

import dns.exception
import dns.resolver
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_random_exponential

from netsec.core.domains import dns_name
from netsec.services.probes import ProbeResult


def probe_dns(
    server: str, name: str, expected: str, timeout: float, *, port: int = 53
) -> ProbeResult:
    """Validate a typed DNS answer with a bounded lifetime and no OS search suffixes."""
    address = ip_address(expected)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [str(ip_address(server))]
    resolver.port = port
    resolver.timeout = timeout
    resolver.lifetime = timeout
    record_type = "AAAA" if isinstance(address, IPv6Address) else "A"
    try:
        retries = Retrying(
            stop=stop_after_attempt(2),
            wait=wait_random_exponential(max=0.2),
            retry=retry_if_exception_type(dns.exception.Timeout),
            reraise=True,
        )
        answer = retries(
            resolver.resolve, dns_name(name), record_type, search=False, lifetime=timeout
        )
        values = sorted(str(ip_address(item.to_text())) for item in answer)
    except dns.resolver.NXDOMAIN:
        return ProbeResult(False, "nxdomain", "DNS name does not exist")
    except dns.resolver.NoAnswer:
        return ProbeResult(False, "no_answer", "DNS response has no record of the required type")
    except dns.exception.Timeout:
        return ProbeResult(False, "timeout", "DNS server did not answer before the deadline")
    except (dns.exception.DNSException, OSError, ValueError):
        return ProbeResult(False, "dns_error", "DNS server returned an unusable response")
    matches = str(address) in values
    return ProbeResult(
        matches,
        "resolved" if matches else "unexpected_address",
        "DNS answers: " + ", ".join(values),
    )
