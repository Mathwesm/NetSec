"""Measure compiler throughput and real loopback HTTP check concurrency."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from statistics import median
from threading import Thread
from uuid import uuid4

from loguru import logger

from netsec.core.compiler import compile_source
from netsec.runtime import NetworkAdapter, execute


class DelayedServer(ThreadingHTTPServer):
    """Provide enough backlog to measure latency rather than accept-queue overflow."""

    request_queue_size = 32
    daemon_threads = True


class DelayedHandler(BaseHTTPRequestHandler):
    """Return a deterministic bounded application-layer response."""

    def do_HEAD(self) -> None:
        """Introduce controlled application latency on loopback only."""
        time.sleep(0.05)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib callback.
        """Do not pollute benchmark measurements with request logging."""


def main() -> int:
    """Write measured, reproducible workload results without promising universal speedups."""
    hosts = "\n".join(f'host "node{i}" address "192.0.2.{i}";' for i in range(1, 129))
    source = (
        f'group fleet {{ {hosts} }} play "audit" targets fleet '
        "{ repeat 20 { check port 22 protocol tcp; } }"
    )
    durations: list[float] = []
    for _ in range(20):
        started = time.perf_counter()
        plan = compile_source(source)
        durations.append(time.perf_counter() - started)
    measurements: dict[str, object] = {
        "hosts": 128,
        "instructions": len(plan.instructions),
        "compiler_median_seconds": median(durations),
        "compile_repeats": 20,
    }
    with DelayedServer(("127.0.0.1", 0), DelayedHandler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_port
        checks = compile_source(
            'group local { host "fixture" address "127.0.0.1"; } '
            f'play "latency" targets local {{ repeat 24 {{ check service "http" port {port}; }} }}'
        )
        try:
            for workers in (1, 8):
                started = time.perf_counter()
                result = execute(checks, NetworkAdapter(2), "network", workers=workers)
                measurements[f"http_workers_{workers}_seconds"] = time.perf_counter() - started
                if not result.success:
                    raise RuntimeError("Benchmark observations failed; timings are not valid")
        finally:
            server.shutdown()
            thread.join(timeout=5)
    directory = (
        Path("data/processed") / f"benchmark-{datetime.now(UTC):%Y%m%dT%H%M%S%fZ}-{uuid4().hex[:8]}"
    )
    directory.mkdir(parents=True)
    (directory / "measurements.json").write_text(
        json.dumps(measurements, indent=2), encoding="utf-8"
    )
    logger.info("Measured benchmark | results={} evidence={}", measurements, directory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
