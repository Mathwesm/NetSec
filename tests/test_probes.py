from __future__ import annotations

import socket
import ssl
import time
from types import TracebackType

import pytest

from netsec.services.probes import probe


class FakeSocket:
    """Deliver controlled bytes without a real network connection."""

    def __init__(self, response: bytes, clock: list[float] | None = None) -> None:
        self.response = response
        self.sent = b""
        self.clock = clock

    def __enter__(self) -> FakeSocket:
        """Open the fake connection."""
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the fake connection."""
        return None

    def settimeout(self, timeout: float) -> None:
        """Record the remaining probe budget."""
        self.timeout = timeout

    def recv(self, size: int) -> bytes:
        """Return the next bounded chunk and optionally advance a fake clock."""
        if self.clock is not None:
            self.clock[0] += 0.3
        data, self.response = self.response[:size], self.response[size:]
        return data

    def sendall(self, data: bytes) -> None:
        """Record the outgoing application request."""
        self.sent += data


@pytest.mark.parametrize(
    ("service", "response", "success"),
    [
        ("ssh", b"SSH-2.0-OpenSSH_9.2\r\n", True),
        ("ssh", b"HTTP/1.1 200 OK\r\n", False),
        ("ssh", b"", False),
        ("http", b"HTTP/1.1 404 Not Found\r\n", True),
        ("http", b"HTTP/1.1 999 Invalid\r\n", False),
        ("http", b"SSH-2.0-server\r\n", False),
    ],
)
def test_service_requires_application_protocol(
    monkeypatch: pytest.MonkeyPatch, service: str, response: bytes, success: bool
) -> None:
    fake = FakeSocket(response)
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: fake)
    result = probe("192.0.2.10", 22, service, 0.1)
    assert result.success is success
    if service == "http":
        assert fake.sent.startswith(b"HEAD / HTTP/1.0\r\n")


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ConnectionRefusedError(), "closed"),
        (OSError("network"), "unreachable"),
        (ssl.SSLError("certificate"), "tls_error"),
    ],
)
def test_network_failures_have_distinct_meanings(
    monkeypatch: pytest.MonkeyPatch, error: OSError, expected: str
) -> None:
    def connect(*args: object, **kwargs: object) -> None:
        raise error

    monkeypatch.setattr(socket, "create_connection", connect)
    result = probe("192.0.2.10", 22)
    assert not result.success and result.status == expected


def test_drip_feed_cannot_extend_the_total_probe_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = [0.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: FakeSocket(b"HTTP/1.1 200 OK\r\n", clock),
    )
    assert probe("192.0.2.10", 80, "http", 1.0).status == "timeout"
