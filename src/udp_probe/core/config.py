"""Configuration: env + optional config.json."""

import json
import os
from pathlib import Path
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PROBE_", env_file=".env", extra="ignore")

    # Server / API
    host: str = Field(default="0.0.0.0", description="API bind host")
    port: int = Field(default=8000, description="API port")

    # Database (set PROBE_DATABASE_URL or DATABASE_URL in Docker)
    database_url: str = Field(
        default="postgresql://probe:probe@localhost:5432/probe",
        description="PostgreSQL connection URL",
    )

    # Probe server (UDP listener)
    probe_host: str = Field(default="127.0.0.1", description="UDP probe listener host")
    probe_port: int = Field(default=12345, description="UDP probe listener port")
    probe_log_file: str = Field(default="udp_probe_log.txt", description="Probe session log path")
    probe_timeout: int = Field(default=10, description="Probe timeout seconds")
    probe_echo: bool = Field(default=True, description="Echo ACK to probe client")

    # Capture
    capture_interface: str = Field(default="", description="Default capture interface (empty = default)")
    pcap_dir: str = Field(default="data/pcap", description="Directory for PCAP files")

    # Paths
    data_dir: str = Field(default="data", description="Base data directory")


_settings: Settings | None = None
_config_file: dict[str, Any] = {}


def _load_config_file() -> dict[str, Any]:
    global _config_file
    if _config_file:
        return _config_file
    for path in ("config.json", "config.json.example"):
        p = Path(path)
        if p.exists():
            try:
                with open(p) as f:
                    _config_file = json.load(f)
                return _config_file
            except (json.JSONDecodeError, OSError):
                pass
    return {}


def load_config() -> None:
    """Reload config file (e.g. after config set)."""
    global _config_file
    _config_file = {}
    _load_config_file()


def get_config() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def get_config_file_value(key: str, default: Any = None) -> Any:
    """Get value from config.json (legacy)."""
    cfg = _load_config_file()
    return cfg.get(key, default)
