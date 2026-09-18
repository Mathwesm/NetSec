"""Exercise native rule lifecycle on an explicitly authorized elevated test machine."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from loguru import logger

from netsec.platforms.models import FirewallRule
from netsec.platforms.windows import WindowsFirewall


def main() -> int:
    """Test a loopback-only high port without changing profiles or asserting packet filtering."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", required=True)
    parser.parse_args()
    if sys.platform != "win32":
        raise RuntimeError("Windows native integration requires Windows")
    backend = WindowsFirewall()
    state = backend.inspect()
    if not state.can_manage:
        raise RuntimeError("Run in an elevated disposable Windows runner")
    rule = FirewallRule(host="127.0.0.1", port=59173, protocol="tcp", action="allow")
    # An existing managed endpoint is not removed or overwritten by this integration test.
    if backend.exists(rule):
        raise RuntimeError("The integration endpoint is already managed; refusing to change it")
    logger.info("Testing isolated loopback rule lifecycle; packet filtering is not asserted")
    results: dict[str, str] = {}
    try:
        results["first"] = backend.ensure(rule).status
        results["repeat"] = backend.ensure(rule).status
        denied = rule.model_copy(update={"action": "deny"})
        results["changed"] = backend.ensure(denied).status
        results["repeat_changed"] = backend.ensure(denied).status
    finally:
        results["removed"] = backend.remove(rule).status
    results["absent"] = backend.remove(rule).status
    expected = {
        "first": "applied",
        "repeat": "unchanged",
        "changed": "applied",
        "repeat_changed": "unchanged",
        "removed": "removed",
        "absent": "unchanged",
    }
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = Path("data/processed") / f"windows-{stamp}-{uuid4().hex[:8]}"
    destination.mkdir(parents=True, exist_ok=False)
    # Do not export host addresses from the diagnostic snapshot.
    evidence = {
        "can_manage": state.can_manage,
        "results": results,
        "packet_filtering_tested": False,
        "success": results == expected,
    }
    (destination / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    logger.info("Windows native lifecycle completed | results={} evidence={}", results, destination)
    return 0 if results == expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
