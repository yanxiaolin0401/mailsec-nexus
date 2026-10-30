"""Environment-backed settings. Secrets are never stored in the repository."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path = Path("./var")
    datasets_dir: Path = Path("./data")
    max_message_bytes: int = 15 * 1024 * 1024
    max_spool_bytes: int = 5 * 1024 * 1024 * 1024
    parse_timeout_seconds: float = 10.0
    clickhouse_host: str = "127.0.0.1"
    clickhouse_port: int = 8123
    clickhouse_secure: bool = False
    clickhouse_user: str = "mailsec"
    clickhouse_password: str = field(default="", repr=False)
    clickhouse_database: str = "mailsec"
    rspamd_url: str = "http://127.0.0.1:11333"
    clamd_host: str = "127.0.0.1"
    clamd_port: int = 3310
    llm_provider: str = ""
    llm_base_url: str = ""
    llm_model: str = ""
    llm_api_key: str = field(default="", repr=False)
    llm_external_authorized: bool = False
    llm_timeout_seconds: float = 15.0
    max_llm_calls_per_run: int = 10
    api_token: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if self.clickhouse_host.endswith('.clickhouse.cloud'):
            object.__setattr__(self, 'clickhouse_secure', True)
        if not 1 <= self.max_message_bytes <= 20 * 1024 * 1024:
            raise ValueError("MAILSEC_MAX_MESSAGE_BYTES must be 1..20 MiB")
        if self.max_spool_bytes < 1:
            raise ValueError("spool quota must be positive")
        if not 0 < self.parse_timeout_seconds <= 120 or not 0 < self.llm_timeout_seconds <= 120:
            raise ValueError("timeouts must be positive and <=120 seconds")
        if not 1 <= self.max_llm_calls_per_run <= 100:
            raise ValueError("model call budget must be 1..100")

    @classmethod
    def from_env(cls) -> Settings:
        def integer(name: str, default: int) -> int:
            return int(os.getenv(name, str(default)))

        def number(name: str, default: float) -> float:
            return float(os.getenv(name, str(default)))

        return cls(
            data_dir=Path(os.getenv("MAILSEC_DATA_DIR", "./var")).resolve(),
            datasets_dir=Path(os.getenv("MAILSEC_DATASETS_DIR", "./data")).resolve(),
            max_message_bytes=integer("MAILSEC_MAX_MESSAGE_BYTES", 15 * 1024 * 1024),
            max_spool_bytes=integer("MAILSEC_MAX_SPOOL_BYTES", 5 * 1024 * 1024 * 1024),
            parse_timeout_seconds=number("MAILSEC_PARSE_TIMEOUT", 10.0),
            clickhouse_host=os.getenv("CLICKHOUSE_HOST", "127.0.0.1"),
            clickhouse_port=integer("CLICKHOUSE_PORT", 8123),
            clickhouse_secure=os.getenv("CLICKHOUSE_SECURE", "").lower() == "true",
            clickhouse_user=os.getenv("CLICKHOUSE_USER", "mailsec"),
            clickhouse_password=os.getenv("CLICKHOUSE_PASSWORD", ""),
            clickhouse_database=os.getenv("CLICKHOUSE_DB", "mailsec"),
            rspamd_url=os.getenv("RSPAMD_URL", "http://127.0.0.1:11333"),
            clamd_host=os.getenv("CLAMD_HOST", "127.0.0.1"),
            clamd_port=integer("CLAMD_PORT", 3310),
            llm_provider=os.getenv("MAILSEC_LLM_PROVIDER", ""),
            llm_base_url=os.getenv("MAILSEC_LLM_BASE_URL", ""),
            llm_model=os.getenv("MAILSEC_LLM_MODEL", ""),
            llm_api_key=os.getenv("MAILSEC_LLM_API_KEY", ""),
            llm_external_authorized=os.getenv("MAILSEC_LLM_EXTERNAL_AUTHORIZED", "").lower() == "true",
            llm_timeout_seconds=number("MAILSEC_LLM_TIMEOUT", 15.0),
            max_llm_calls_per_run=integer("MAILSEC_MAX_LLM_CALLS_PER_RUN", 10),
            api_token=os.getenv("MAILSEC_API_TOKEN", ""),
        )
