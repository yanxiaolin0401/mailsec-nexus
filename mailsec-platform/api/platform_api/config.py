from __future__ import annotations

import os
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str
    smart_search_url: str
    smart_search_token: str
    smart_search_tenant_id: int | None
    smart_search_dedicated: bool
    cookie_secure: bool
    session_hours: int = 12
    csrf_secret: str = ""
    platform_origin: str = ""

    @classmethod
    def from_env(cls) -> Settings:
        tenant = os.getenv("SMART_SEARCH_TENANT_ID", "").strip()
        return cls(
            database_url=os.getenv("DATABASE_URL", "sqlite:///./platform.db"),
            smart_search_url=os.getenv("SMART_SEARCH_URL", "").rstrip("/"),
            smart_search_token=os.getenv("SMART_SEARCH_TOKEN", ""),
            smart_search_tenant_id=int(tenant) if tenant else None,
            smart_search_dedicated=os.getenv("SMART_SEARCH_DEDICATED", "").lower() == "true",
            cookie_secure=os.getenv("COOKIE_SECURE", "true").lower() == "true",
            csrf_secret=os.getenv("CSRF_SECRET") or secrets.token_urlsafe(32),
            platform_origin=os.getenv("PLATFORM_ORIGIN", "").rstrip("/"),
        )
