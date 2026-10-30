"""Destructive-only-to-self smoke: platform -> in-process HTTP -> real ClickHouse.

Run from any working directory with mailsec-smart-search/.venv/bin/python.
Only synthetic events enter a fresh platform_smoke_<random> database; its name is
created without IF NOT EXISTS and dropped in finally only after creation succeeds.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "mailsec-smart-search" / "src"))
sys.path.insert(0, str(ROOT / "mailsec-platform" / "api"))
# The smart-search venv has ClickHouse; platform dependencies live in its venv.
sys.path.insert(0, str(next((ROOT / "mailsec-platform" / "api" / ".venv" / "lib").glob("python*/site-packages"))))

import httpx
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from mailsec_smart_search.api import create_app as create_smart_app
from mailsec_smart_search.config import Settings as SmartSettings
from mailsec_smart_search.event_storage import EventRepository
from mailsec_smart_search.events import normalize_event
from mailsec_smart_search.storage import ClickHouseRepository
from platform_api.app import PREFIX, make_app
from platform_api.config import Settings as PlatformSettings
from platform_api.models import Base, User
from platform_api.security import password_hash

REPORT = ROOT / "mailsec-platform" / "docs" / "reports" / "integration-smoke.json"
STAGE = "initialization"


def read_secret(name: str) -> str:
    """Read existing local test credential without exporting or displaying it."""
    if name in os.environ:
        return os.environ[name]
    env_file = ROOT / "mailsec-smart-search" / ".env"
    if not env_file.exists():
        return ""
    for line in env_file.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().removeprefix("export ") == name:
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            return value
    return ""


class InProcessSmartTransport(httpx.AsyncBaseTransport):
    """HTTPX ASGI bridge; the API calls are HTTP semantics, not network hops."""

    def __init__(self, app: Any):
        self._inner = httpx.ASGITransport(app=app)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def require(response: httpx.Response, status: int, label: str) -> dict[str, Any]:
    if response.status_code != status:
        raise AssertionError(f"{label}: expected HTTP {status}, got {response.status_code}")
    return response.json()


def run() -> dict[str, Any]:
    global STAGE
    database = "platform_smoke_" + secrets.token_hex(8)
    token = secrets.token_urlsafe(32)
    admin_password = secrets.token_urlsafe(24)
    user_password = secrets.token_urlsafe(24)
    new_password = secrets.token_urlsafe(24)
    subject = "synthetic-platform-smoke-" + secrets.token_hex(5)
    checks: list[str] = []
    created = False
    with tempfile.TemporaryDirectory(prefix="platform-smoke-") as temp:
        smart_settings = SmartSettings(
            data_dir=Path(temp) / "smart-data",
            datasets_dir=Path(temp) / "empty-datasets",
            clickhouse_host=os.getenv("CLICKHOUSE_HOST", "127.0.0.1"),
            clickhouse_port=int(os.getenv("CLICKHOUSE_PORT", "8123")),
            clickhouse_user=os.getenv("CLICKHOUSE_USER", "mailsec"),
            clickhouse_password=read_secret("CLICKHOUSE_PASSWORD"),
            clickhouse_database=database,
            api_token=token,
        )
        repository = ClickHouseRepository(smart_settings)
        try:
            STAGE = "create_clickhouse_database"
            # No IF NOT EXISTS: this process may clean up only a database it created.
            repository.client.command(f"CREATE DATABASE `{database}`")
            created = True
            STAGE = "create_clickhouse_schema"
            event_repository = EventRepository(repository)
            event_repository.ensure_schema()
            STAGE = "insert_synthetic_event"
            event = normalize_event({
                "sourceSystemId": "platform-smoke",
                "sourceEventId": secrets.token_hex(12),
                "eventTime": datetime.now(timezone.utc).isoformat(),
                "mail": {
                    "senderaccount": "synthetic@example.test",
                    "toaccount": "recipient@example.test",
                    "subject": subject,
                    "textContent": "Synthetic integration check; no real mail.",
                },
            }, now=datetime.now(timezone.utc))
            assert event_repository.insert_batch([event]) == 1
            checks.append("real_clickhouse_synthetic_insert")

            smart_app = create_smart_app(smart_settings, repository=repository,
                                         event_repository=event_repository)
            sqlite_url = f"sqlite:///{Path(temp) / 'platform.sqlite3'}"
            base_settings = PlatformSettings.from_env()
            platform_settings = replace(
                base_settings, database_url=sqlite_url,
                smart_search_url="http://smart-search.local",
                smart_search_token=token, smart_search_dedicated=True,
                smart_search_tenant_id=1, cookie_secure=False,
                csrf_secret=secrets.token_urlsafe(32),
            )
            platform_app = make_app(platform_settings, transport=InProcessSmartTransport(smart_app))
            Base.metadata.create_all(platform_app.state.engine)
            with Session(platform_app.state.engine) as db:
                db.add(User(username="smoke-admin", display_name="Smoke Admin", role="admin",
                            tenant_id=None, password_hash=password_hash(admin_password)))
                db.commit()

            with TestClient(platform_app) as admin:
                STAGE = "admin_login"
                login = require(admin.post(PREFIX + "/auth/login", json={
                    "username": "smoke-admin", "password": admin_password, "mode": "admin",
                }), 200, "admin login")
                admin_csrf = login["csrf_token"]
                checks.append("admin_login")
                headers = {"X-CSRF-Token": admin_csrf}
                STAGE = "admin_create_tenants_and_user"
                tenant = require(admin.post(PREFIX + "/admin/tenants", json={
                    "name": "Synthetic Smoke", "slug": "smoke",
                }, headers=headers), 201, "create bound tenant")
                assert tenant["id"] == 1, "dedicated tenant binding changed"
                other = require(admin.post(PREFIX + "/admin/tenants", json={
                    "name": "Other Synthetic", "slug": "smoke-other",
                }, headers=headers), 201, "create other tenant")
                created_user = require(admin.post(PREFIX + "/admin/users", json={
                    "username": "smoke-user", "display_name": "Smoke User",
                    "password": user_password, "role": "user", "tenant_id": tenant["id"],
                }, headers=headers), 201, "create tenant user")
                checks.append("admin_creates_tenant_and_user")

                with TestClient(platform_app) as user:
                    STAGE = "user_login"
                    user_login = require(user.post(PREFIX + "/auth/login", json={
                        "username": "smoke-user", "password": user_password,
                        "mode": "user", "tenant_slug": "smoke",
                    }), 200, "user login")
                    user_headers = {"X-CSRF-Token": user_login["csrf_token"]}
                    checks.append("tenant_user_login")
                    STAGE = "search_and_detail"
                    found = require(user.post(PREFIX + "/mail/search", json={"q": subject},
                                              headers=user_headers), 200, "real search")
                    assert found["total"] == 1 and found["items"][0]["event_id"] == event["event_id"]
                    checks.append("real_clickhouse_search_via_platform")
                    detail = require(user.get(PREFIX + "/mail/" + event["event_id"]),
                                     200, "real detail")
                    assert detail["subject"] == subject and detail["event_id"] == event["event_id"]
                    checks.append("real_clickhouse_detail_via_platform")
                    STAGE = "tenant_isolation_and_token_exposure"
                    require(user.post(PREFIX + "/mail/search", json={
                        "q": subject, "tenant_id": other["id"],
                    }, headers=user_headers), 403, "cross-tenant user search")
                    checks.append("cross_tenant_user_denied")
                    require(admin.post(PREFIX + "/mail/search", json={
                        "q": subject, "tenant_id": other["id"],
                    }, headers=headers), 403, "unbound admin tenant search")
                    checks.append("unbound_admin_tenant_denied")
                    status = require(user.get(PREFIX + "/integration/status"), 200,
                                     "integration status")
                    assert status["smart_search"]["status"] == "ready"
                    assert token not in json.dumps(status) and token not in json.dumps(found)
                    checks.append("server_token_not_exposed")

                    STAGE = "admin_password_reset"
                    require(admin.patch(PREFIX + f"/admin/users/{created_user['id']}",
                                        json={"password": new_password}, headers=headers),
                            200, "admin password reset")
                    require(user.get(PREFIX + "/session"), 401, "old session revoked")
                    checks.append("admin_password_reset_revokes_session")
                with TestClient(platform_app) as new_user:
                    STAGE = "new_password_login"
                    require(new_user.post(PREFIX + "/auth/login", json={
                        "username": "smoke-user", "password": new_password,
                        "mode": "user", "tenant_slug": "smoke",
                    }), 200, "new password login")
                    checks.append("new_password_login")
        finally:
            if created:
                STAGE = "drop_clickhouse_database"
                repository.client.command(f"DROP DATABASE `{database}` SYNC")
    return {"status": "passed", "checks": checks,
            "transport": "in-process HTTPX ASGI bridge; ClickHouse is real TCP/HTTP",
            "clickhouse_database": "unique platform_smoke_<random>, dropped in finally",
            "command": "mailsec-smart-search/.venv/bin/python mailsec-platform/scripts/smoke_integration.py"}


def main() -> int:
    try:
        result = run()
    except Exception as exc:
        # Do not serialize exception messages: lower-level DB errors can contain credentials.
        result = {"status": "failed", "error_type": type(exc).__name__, "error_stage": STAGE,
                  "transport": "in-process HTTPX ASGI bridge; ClickHouse intended real TCP/HTTP",
                  "command": "mailsec-smart-search/.venv/bin/python mailsec-platform/scripts/smoke_integration.py"}
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"integration smoke: {result['status']}; report={REPORT.relative_to(ROOT)}")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
