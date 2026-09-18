"""Bounded TCP, SSH and HTTP probes with protocol-aware service validation."""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass
from ipaddress import ip_address

from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_random_exponential

_MAX_REPLY = 4096
_HTTP_MIN_FIELDS = 2
_HTTP_STATUS_DIGITS = 3
_HTTP_MIN_STATUS, _HTTP_MAX_STATUS = 100, 599


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Represent an observation without claiming a full security audit."""

    success: bool
    status: str
    detail: str


def probe(host: str, port: int, service: str = "", timeout: float = 2.0) -> ProbeResult:
    """Observe one explicitly selected TCP endpoint.

    Args:
        host: Literal IPv4 or IPv6 address.
        port: TCP destination port.
        service: Empty for connectivity, or ssh/http/https for protocol validation.
        timeout: Total deadline per connection attempt in seconds; at most two attempts.

    Returns:
        A connection or protocol observation; failures are explicit.
    """
    ip_address(host)
    try:
        retrying = Retrying(
            stop=stop_after_attempt(2),
            wait=wait_random_exponential(max=0.2),
            retry=retry_if_exception_type(TimeoutError),
            reraise=True,
        )
        return retrying(_connect, host, port, service, timeout)
    except TimeoutError:
        return ProbeResult(False, "timeout", "No response before the probe deadline")
    except ConnectionRefusedError:
        return ProbeResult(False, "closed", "Connection refused")
    except ssl.SSLError:
        return ProbeResult(False, "tls_error", "TLS handshake or certificate validation failed")
    except OSError:
        return ProbeResult(False, "unreachable", "Network connection failed")


def _connect(host: str, port: int, service: str, timeout: float) -> ProbeResult:
    deadline = time.monotonic() + timeout
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(_remaining(deadline))
        if not service:
            return ProbeResult(True, "open", "TCP connection established")
        if service == "https":
            context = ssl.create_default_context()
            with context.wrap_socket(connection, server_hostname=host) as secure:
                return _http(secure, host, deadline)
        if service == "ssh":
            return _ssh(connection, deadline)
        if service == "http":
            return _http(connection, host, deadline)
        return ProbeResult(False, "unsupported", "Unsupported application protocol")


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Probe deadline exceeded")
    return remaining


def _read_line(connection: socket.socket, deadline: float) -> bytes:
    response = bytearray()
    while len(response) < _MAX_REPLY and not response.endswith(b"\n"):
        connection.settimeout(_remaining(deadline))
        piece = connection.recv(1)
        _remaining(deadline)
        if not piece:
            break
        response.extend(piece)
    return bytes(response)


def _ssh(connection: socket.socket, deadline: float) -> ProbeResult:
    banner = _read_line(connection, deadline)
    valid = banner.startswith((b"SSH-2.0-", b"SSH-1.99-")) and banner.endswith(b"\n")
    return ProbeResult(
        valid,
        "active" if valid else "protocol_mismatch",
        "SSH identification received" if valid else "Missing SSH identification",
    )


def _http(connection: socket.socket, host: str, deadline: float) -> ProbeResult:
    authority = f"[{host}]" if ":" in host else host
    request = f"HEAD / HTTP/1.0\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    connection.settimeout(_remaining(deadline))
    connection.sendall(request.encode("ascii"))
    first_line = _read_line(connection, deadline)
    parts = first_line.split(b" ", 2)
    valid = (
        len(parts) >= _HTTP_MIN_FIELDS
        and parts[0] in {b"HTTP/1.0", b"HTTP/1.1"}
        and len(parts[1]) == _HTTP_STATUS_DIGITS
        and parts[1].isdigit()
        and _HTTP_MIN_STATUS <= int(parts[1]) <= _HTTP_MAX_STATUS
    )
    return ProbeResult(
        valid,
        "active" if valid else "protocol_mismatch",
        "HTTP response received" if valid else "Missing HTTP status line",
    )
