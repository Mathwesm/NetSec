"""Turn detect-secrets findings into a failing quality-gate exit code."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

_EXCLUDE = (
    r"(^|[/\\])(\.git|\.venv|node_modules|data|logs|dist|build|__pycache__|"
    r"\.pytest_cache|\.mypy_cache|\.ruff_cache)([/\\]|$)|"
    r"(^|[/\\])(poetry\.lock|package-lock\.json|\.coverage.*)$"
)


def main() -> int:
    """Scan source files and report only counts, without echoing potential secrets."""
    executable = shutil.which("detect-secrets")
    if executable is None:
        sys.stderr.write("detect-secrets is missing; run poetry install\n")
        return 1
    result = subprocess.run(  # noqa: S603 - resolved quality tool, fixed argv, no shell.
        [executable, "scan", "--all-files", "--exclude-files", _EXCLUDE],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        check=False,
    )
    if result.returncode:
        sys.stderr.write("Secret scan failed to execute\n")
        return 1
    payload: object = json.loads(result.stdout)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), dict):
        sys.stderr.write("Invalid secret scan response\n")
        return 1
    count = sum(len(findings) for findings in payload["results"].values())
    sys.stdout.write(f"Secret scan: {count} findings\n")
    return 1 if count else 0


if __name__ == "__main__":
    raise SystemExit(main())
