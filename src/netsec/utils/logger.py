"""Centralized operational logging; program output uses a separate stream."""

import sys
from pathlib import Path

from loguru import logger


def setup_logging(log_dir: Path) -> None:
    """Configure INFO console and rotated DEBUG JSON files without local values.

    Args:
        log_dir: Directory for operational logs, excluding program payloads.
    """
    logger.remove()
    logger.add(sys.stderr, level="INFO", diagnose=False)
    log_dir.mkdir(parents=True, exist_ok=True)
    logger.add(
        log_dir / "netsec.log",
        level="DEBUG",
        rotation="10 MB",
        retention="30 days",
        compression="zip",
        encoding="utf-8",
        serialize=True,
        diagnose=False,
    )
