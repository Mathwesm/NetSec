"""Validated runtime settings without import-time mutable state."""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Read settings when a command starts."""

    model_config = SettingsConfigDict(
        env_prefix="NETSEC_",
        env_file=".env",
        env_file_encoding="utf-8",
        frozen=True,
        extra="ignore",
    )
    timeout: float = Field(default=2.0, ge=0.1, le=30.0)
    log_dir: Path = Path("logs")
