"""Serve a real HTTP endpoint and a plaintext TCP test listener inside the lab."""

from __future__ import annotations

import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from loguru import logger

LAB_BIND = "0.0.0.0"  # noqa: S104 - container-only endpoints on an internal network, no published ports.


class HTTPHandler(BaseHTTPRequestHandler):
    """Return a deterministic health response without logging client addresses."""

    def do_HEAD(self) -> None:
        """Answer the HTTP service probe."""
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature.
        """Record only that a request was handled."""
        logger.debug("HTTP request handled | fields={} template_chars={}", len(args), len(format))


class PlaintextHandler(socketserver.BaseRequestHandler):
    """Provide a TCP/23 fixture; this is not a complete Telnet implementation."""

    def handle(self) -> None:
        """Send a small banner with a bounded write deadline."""
        self.request.settimeout(2.0)
        self.request.sendall(b"NetSec plaintext lab listener\r\n")


def main() -> None:
    """Start both demonstration endpoints within the container namespace."""
    with socketserver.ThreadingTCPServer((LAB_BIND, 23), PlaintextHandler) as plaintext:
        plaintext.daemon_threads = True
        threading.Thread(target=plaintext.serve_forever, daemon=True).start()
        with ThreadingHTTPServer((LAB_BIND, 80), HTTPHandler) as http:
            http.serve_forever()


if __name__ == "__main__":
    main()
