from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from datetime import timedelta
from typing import Any, Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings
from .llm_providers import PROVIDERS
from .models import Audit, LoginAttempt, SessionRecord, Tenant, User, utcnow
from .schemas import (
    LlmConfigUpdate,
    Login,
    MailSearch,
    NaturalPlan,
    PasswordChange,
    PlanExecute,
    Registration,
    TenantCreate,
    UserCreate,
    UserPatch,
)
from .security import password_hash, random_token, token_hash, verify_password

PREFIX = "/api/platform/v1"
COOKIE = "mailsec_session"
GENERIC_LOGIN_ERROR = "Invalid credentials"
_DUMMY_PASSWORD_HASH = password_hash("non-account-timing-placeholder")
DUMMY_PASSWORD_HASH = password_hash("not-a-real-user-password")


def make_app(settings: Settings | None = None, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if not settings.csrf_secret:
        raise ValueError("CSRF_SECRET required")
    engine = create_engine(settings.database_url, pool_pre_ping=True, connect_args={"check_same_thread": False} if settings.database_url.startswith("sqlite") else {})
    SessionLocal = sessionmaker(engine, expire_on_commit=False)
    app = FastAPI(title="MailSec Platform API")
    app.state.engine = engine
    app.state.settings = settings
    app.state.transport = transport

    def search_transport() -> httpx.AsyncBaseTransport | None:
        # A test transport is supplied by callers; socket transports are per-request
        # because AsyncClient closes the transport at the end of each request.
        return transport if transport is not None else (
            httpx.AsyncHTTPTransport(uds=settings.smart_search_socket)
            if settings.smart_search_socket else None)

    @app.middleware("http")
    async def no_store(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith(PREFIX):
            response.headers["Cache-Control"] = "no-store"
        return response

    def db_session():
        with SessionLocal() as db:
            yield db

    def csrf_value(cookie: str) -> str:
        return hmac.new(settings.csrf_secret.encode(), cookie.encode(), hashlib.sha256).hexdigest()

    def current(request: Request, db: Session = Depends(db_session)) -> tuple[User, SessionRecord, str]:
        cookie = request.cookies.get(COOKIE, "")
        if not cookie:
            raise HTTPException(401, "Authentication required")
        record = db.scalar(select(SessionRecord).where(SessionRecord.token_hash == token_hash(cookie)))
        if record is None or record.revoked_at is not None or record.expires_at.replace(tzinfo=None) <= utcnow().replace(tzinfo=None) or not record.user.is_active:
            raise HTTPException(401, "Authentication required")
        csrf = csrf_value(cookie)
        if not hmac.compare_digest(record.csrf_token_hash, token_hash(csrf)):
            raise HTTPException(401, "Authentication required")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            supplied = request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(supplied, csrf):
                raise HTTPException(403, "CSRF token required")
        return record.user, record, csrf

    def admin(auth: tuple[User, SessionRecord, str] = Depends(current)) -> User:
        if auth[0].role != "admin":
            raise HTTPException(403, "Admin required")
        return auth[0]

    def user_json(user: User) -> dict[str, Any]:
        return {"id": user.id, "username": user.username, "display_name": user.display_name, "role": user.role, "tenant_id": user.tenant_id, "is_active": user.is_active}

    def audit(db: Session, actor: int | None, action: str, target: str, detail: str = "") -> None:
        db.add(Audit(actor_user_id=actor, action=action, target=target, detail=detail))

    def revoke(db: Session, user_id: int) -> None:
        for session in db.scalars(select(SessionRecord).where(SessionRecord.user_id == user_id, SessionRecord.revoked_at.is_(None))):
            session.revoked_at = utcnow()

    def check_auth_origin(request: Request) -> None:
        origin = request.headers.get("Origin")
        expected = settings.platform_origin or str(request.base_url).rstrip("/")
        if (origin and origin != expected) or request.headers.get("Sec-Fetch-Site", "") == "cross-site":
            raise HTTPException(403, "Cross-origin authentication denied")

    @app.post(PREFIX + "/auth/register", status_code=201)
    def register(payload: Registration, request: Request, db: Session = Depends(db_session)):
        check_auth_origin(request)
        # Independent, persistent per-peer registration limit, including successful
        # requests and rotating usernames. Never trust a client-supplied IP header.
        key = token_hash(f"register|{request.client.host if request.client else 'unknown'}")
        now = utcnow()
        attempt = db.scalar(select(LoginAttempt).where(LoginAttempt.key == key))
        if attempt is None:
            attempt = LoginAttempt(key=key, count=0, window_started_at=now)
            db.add(attempt)
        elif attempt.window_started_at.replace(tzinfo=None) < (now - timedelta(minutes=15)).replace(tzinfo=None):
            attempt.count = 0
            attempt.window_started_at = now
            attempt.locked_until = None
        if attempt.count >= 5:
            db.commit()
            raise HTTPException(429, "Too many registrations; retry later")
        attempt.count += 1
        tenant = db.scalar(select(Tenant).where(Tenant.slug == payload.tenant_slug))
        if tenant is None:
            db.commit()
            raise HTTPException(404, "Tenant identifier not found")
        username = payload.username.lower()
        if db.scalar(select(User.id).where(User.username == username)) is not None:
            db.commit()
            raise HTTPException(409, "Username already exists")
        user = User(username=username, display_name=payload.display_name, role="user",
                    tenant_id=tenant.id, password_hash=password_hash(payload.password), is_active=False)
        db.add(user)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Username already exists") from None
        audit(db, None, "auth.register", str(user.id), "pending_admin_approval")
        db.commit()
        return {"message": "Registration pending administrator approval"}

    @app.post(PREFIX + "/auth/login")
    def login(payload: Login, request: Request, response: Response, db: Session = Depends(db_session)):
        check_auth_origin(request)
        # Persisted per username + direct peer address; no passwords or raw usernames in key.
        key = token_hash(f"{payload.username.lower()}|{request.client.host if request.client else 'unknown'}")
        now = utcnow()
        attempt = db.scalar(select(LoginAttempt).where(LoginAttempt.key == key))
        if attempt is None:
            attempt = LoginAttempt(key=key, count=0, window_started_at=now)
            db.add(attempt)
        elif attempt.window_started_at.replace(tzinfo=None) < (now - timedelta(minutes=15)).replace(tzinfo=None):
            attempt.count = 0
            attempt.window_started_at = now
            attempt.locked_until = None
        if attempt.locked_until and attempt.locked_until.replace(tzinfo=None) > now.replace(tzinfo=None):
            db.commit()
            raise HTTPException(429, "Too many attempts; retry later")
        user = db.scalar(select(User).where(User.username == payload.username.lower()))
        password_valid = verify_password(payload.password, user.password_hash if user else DUMMY_PASSWORD_HASH)
        valid = bool(user and password_valid and user.is_active and user.role == payload.mode)
        valid = valid and ((payload.mode == "admin" and payload.tenant_slug is None and user.tenant_id is None) or
                           (payload.mode == "user" and bool(payload.tenant_slug) and user.tenant is not None and user.tenant.slug == payload.tenant_slug))
        if not valid:
            attempt.count += 1
            if attempt.count >= 5:
                attempt.locked_until = now + timedelta(minutes=15)
            db.commit()
            raise HTTPException(401, GENERIC_LOGIN_ERROR)
        attempt.count = 0
        attempt.locked_until = None
        cookie = random_token()
        csrf = csrf_value(cookie)
        db.add(SessionRecord(user_id=user.id, token_hash=token_hash(cookie), csrf_token_hash=token_hash(csrf), expires_at=now + timedelta(hours=settings.session_hours)))
        audit(db, user.id, "auth.login", str(user.id))
        db.commit()
        response.set_cookie(COOKIE, cookie, httponly=True, secure=settings.cookie_secure, samesite="lax", max_age=settings.session_hours * 3600, path="/")
        return {"user": user_json(user), "csrf_token": csrf}

    @app.get(PREFIX + "/session")
    def session(auth: tuple[User, SessionRecord, str] = Depends(current)):
        return {"user": user_json(auth[0]), "csrf_token": auth[2]}

    @app.post(PREFIX + "/session/logout")
    def logout(response: Response, auth: tuple[User, SessionRecord, str] = Depends(current), db: Session = Depends(db_session)):
        auth[1].revoked_at = utcnow()
        audit(db, auth[0].id, "auth.logout", str(auth[0].id))
        db.commit()
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.post(PREFIX + "/session/password")
    def change_password(payload: PasswordChange, auth: tuple[User, SessionRecord, str] = Depends(current), db: Session = Depends(db_session)):
        user = auth[0]
        if not verify_password(payload.current_password, user.password_hash):
            raise HTTPException(400, "Current password is incorrect")
        user.password_hash = password_hash(payload.new_password)
        revoke(db, user.id)
        audit(db, user.id, "auth.password_change", str(user.id))
        db.commit()
        return {"ok": True}

    @app.get(PREFIX + "/admin/users")
    def list_users(_: User = Depends(admin), db: Session = Depends(db_session)):
        return {"items": [user_json(u) for u in db.scalars(select(User).order_by(User.id))]}

    @app.post(PREFIX + "/admin/users", status_code=201)
    def create_user(payload: UserCreate, actor: User = Depends(admin), db: Session = Depends(db_session)):
        if payload.tenant_id is not None and db.get(Tenant, payload.tenant_id) is None:
            raise HTTPException(404, "Tenant not found")
        user = User(username=payload.username.lower(), display_name=payload.display_name, role=payload.role, tenant_id=payload.tenant_id, password_hash=password_hash(payload.password))
        db.add(user)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Username already exists") from None
        audit(db, actor.id, "admin.user_create", str(user.id))
        db.commit()
        return user_json(user)

    @app.patch(PREFIX + "/admin/users/{user_id}")
    def patch_user(user_id: int, payload: UserPatch, actor: User = Depends(admin), db: Session = Depends(db_session)):
        target = db.get(User, user_id)
        if target is None:
            raise HTTPException(404, "User not found")
        if payload.is_active is False and actor.id == user_id:
            raise HTTPException(400, "Cannot deactivate self")
        if payload.display_name is not None:
            target.display_name = payload.display_name
        if payload.password is not None:
            target.password_hash = password_hash(payload.password)
        if payload.is_active is not None:
            target.is_active = payload.is_active
        if payload.password is not None or payload.is_active is False:
            revoke(db, user_id)
        audit(db, actor.id, "admin.user_update", str(user_id), json.dumps(sorted(payload.model_fields_set)))
        db.commit()
        return user_json(target)

    @app.get(PREFIX + "/admin/tenants")
    def list_tenants(_: User = Depends(admin), db: Session = Depends(db_session)):
        return {"items": [{"id": t.id, "name": t.name, "slug": t.slug} for t in db.scalars(select(Tenant).order_by(Tenant.id))]}

    @app.post(PREFIX + "/admin/tenants", status_code=201)
    def create_tenant(payload: TenantCreate, actor: User = Depends(admin), db: Session = Depends(db_session)):
        tenant = Tenant(name=payload.name, slug=payload.slug)
        db.add(tenant)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "Tenant slug already exists") from None
        audit(db, actor.id, "admin.tenant_create", str(tenant.id))
        db.commit()
        return {"id": tenant.id, "name": tenant.name, "slug": tenant.slug}

    @app.get(PREFIX + "/admin/audit")
    def list_audit(_: User = Depends(admin), db: Session = Depends(db_session)):
        rows = db.scalars(select(Audit).order_by(Audit.id.desc()).limit(100)).all()
        return {"items": [{"id": r.id, "actor_user_id": r.actor_user_id, "action": r.action, "target": r.target, "detail": r.detail, "created_at": r.created_at.isoformat()} for r in rows]}

    @app.get(PREFIX + "/modules")
    async def modules(auth: tuple[User, SessionRecord, str] = Depends(current)):
        status = await integration_state(auth[0])
        return {"items": [{"name": "smart-search", "status": status}, {"name": "header-parser", "status": "not_implemented"}, {"name": "threat-trace", "status": "not_implemented"}]}

    @app.post(PREFIX + "/modules/{name}/invoke")
    def invoke(name: str, _: tuple[User, SessionRecord, str] = Depends(current)):
        if name not in ("header-parser", "threat-trace"):
            raise HTTPException(404, "Module not found")
        raise HTTPException(501, "Module not implemented")

    def ready() -> bool:
        return bool(settings.smart_search_dedicated and settings.smart_search_tenant_id and settings.smart_search_url and settings.smart_search_token)

    async def integration_state(user: User) -> str:
        if not ready() or (user.role != "admin" and user.tenant_id != settings.smart_search_tenant_id):
            return "disabled"
        try:
            async with httpx.AsyncClient(base_url=settings.smart_search_url, transport=search_transport(), timeout=3, trust_env=False) as client:
                response = await client.get("/health/ready")
            return "ready" if response.status_code == 200 else "unavailable"
        except httpx.HTTPError:
            return "unavailable"

    def target_tenant(auth: tuple[User, SessionRecord, str], tenant_id: int | None, db: Session) -> int:
        user = auth[0]
        if user.role == "admin":
            if tenant_id is None:
                raise HTTPException(422, "tenant_id required")
            if db.get(Tenant, tenant_id) is None:
                raise HTTPException(404, "Tenant not found")
            target = tenant_id
        else:
            if tenant_id is not None and tenant_id != user.tenant_id:
                raise HTTPException(403, "Tenant forbidden")
            target = user.tenant_id
        if not ready():
            raise HTTPException(503, "Search integration unavailable")
        if target != settings.smart_search_tenant_id:
            raise HTTPException(403, "Tenant not bound to search instance")
        return target

    async def upstream(path: str, params: dict[str, Any], *, method: str = "GET", detail: bool = False) -> Any:
        try:
            async with httpx.AsyncClient(base_url=settings.smart_search_url, transport=search_transport(),
                                         timeout=settings.smart_search_timeout_seconds, trust_env=False) as client:
                response = await client.request(method, path,
                                                **({"json": params} if method == "POST" else {"params": params}),
                                                headers={"X-Mailsec-Token": settings.smart_search_token})
            if detail and response.status_code == 404:
                raise HTTPException(404, "Mail not found")
            if response.status_code != 200:
                raise HTTPException(503, "Search integration unavailable")
            return response.json()
        except HTTPException:
            raise
        except (httpx.HTTPError, ValueError):
            raise HTTPException(503, "Search integration unavailable") from None

    async def model_upstream(path: str, params: dict[str, Any] | None = None, *, method: str = "GET") -> dict[str, Any]:
        if not ready():
            raise HTTPException(503, "Search integration unavailable")
        try:
            async with httpx.AsyncClient(base_url=settings.smart_search_url, transport=search_transport(),
                                         timeout=max(settings.smart_search_timeout_seconds, 35), trust_env=False) as client:
                response = await client.request(method, path, json=params if method in ("POST", "PUT") else None,
                                                headers={"X-Mailsec-Token": settings.smart_search_token})
            if response.status_code == 422:
                raise HTTPException(422, "智能查询条件无效")
            if response.status_code != 200:
                raise HTTPException(503, "模型或检索服务不可用")
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("invalid upstream response")
            return data
        except HTTPException:
            raise
        except (httpx.HTTPError, ValueError):
            raise HTTPException(503, "模型或检索服务不可用") from None

    legacy_keys = set("from_time to_time sender sender_domain recipient subject_contains body_contains has_attachment attachment_suffix limit offset".split())
    event_keys = set("from_time to_time sender sender_domain recipient account subject_contains body_contains q sender_ip attachment_md5 url risk_level risk_verdict source_system_id source_event_id event_id mailbox has_attachment attachment_suffix attachment_name_contains subject_or_attachment_contains limit offset".split())

    def sign_plan(data: dict[str, Any]) -> str:
        raw = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        body = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        sig = hmac.new(settings.csrf_secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        return body + "." + sig

    def read_plan(token: str) -> dict[str, Any]:
        try:
            body, sig = token.rsplit(".", 1)
            expected = hmac.new(settings.csrf_secret.encode(), body.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                raise ValueError("signature")
            data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
            if not isinstance(data, dict) or data["expires"] < utcnow().timestamp():
                raise ValueError("expired")
            return data
        except (ValueError, KeyError, TypeError, binascii.Error):
            raise HTTPException(422, "查询计划无效或已过期") from None

    def checked_filters(source: str, plan: Any) -> tuple[str, dict[str, Any]]:
        if not isinstance(plan, dict) or plan.get("tool") not in ("search", "stats") or not isinstance(plan.get("filters"), dict):
            raise HTTPException(422, "查询计划无效")
        filters = plan["filters"]
        allowed = event_keys if source == "event" else legacy_keys
        if len(filters) > 32 or set(filters) - allowed or any(value is not None and not isinstance(value, (str, int, bool)) for value in filters.values()):
            raise HTTPException(422, "查询计划含不支持的条件")
        if "limit" in filters and (type(filters["limit"]) is not int or not 1 <= filters["limit"] <= 200):
            raise HTTPException(422, "查询计划分页无效")
        if "offset" in filters and (type(filters["offset"]) is not int or not 0 <= filters["offset"] <= 10000):
            raise HTTPException(422, "查询计划分页无效")
        return plan["tool"], {key: value for key, value in filters.items() if value is not None}

    @app.post(PREFIX + "/mail/nl/plan")
    async def mail_nl_plan(payload: NaturalPlan, auth: tuple[User, SessionRecord, str] = Depends(current), db: Session = Depends(db_session)):
        tenant = target_tenant(auth, payload.tenant_id, db)
        path = "/api/v1/nl/query" if payload.source == "event" else "/v1/nl/query"
        response = await model_upstream(path, {"text": payload.text, "execute": False}, method="POST")
        tool, filters = checked_filters(payload.source, response.get("plan"))
        token = sign_plan({"source": payload.source, "tenant": tenant, "actor": auth[0].id,
                           "tool": tool, "filters": filters, "expires": (utcnow() + timedelta(minutes=10)).timestamp()})
        audit(db, auth[0].id, "mail.nl.plan", f"{tenant}:{payload.source}:{tool}")
        db.commit()
        return {"plan": {"tool": tool, "filters": filters}, "executed": False, "plan_token": token}

    @app.post(PREFIX + "/mail/plan/execute")
    async def mail_plan_execute(payload: PlanExecute, auth: tuple[User, SessionRecord, str] = Depends(current), db: Session = Depends(db_session)):
        tenant = target_tenant(auth, payload.tenant_id, db)
        plan = read_plan(payload.plan_token)
        if plan.get("source") != payload.source or plan.get("tenant") != tenant or plan.get("actor") != auth[0].id:
            raise HTTPException(403, "查询计划不属于当前用户或租户")
        tool, filters = checked_filters(payload.source, plan)
        if tool == "stats" and (payload.limit is not None or payload.offset is not None):
            raise HTTPException(422, "统计计划不接受分页")
        if tool == "search":
            filters.update({key: value for key, value in {"limit": payload.limit, "offset": payload.offset}.items() if value is not None})
        if payload.source == "legacy":
            result = await model_upstream("/v1/stats" if tool == "stats" else "/v1/search", filters, method="POST")
            if tool == "search":
                if not isinstance(result.get("items"), list) or not isinstance(result.get("may_have_more"), bool):
                    raise HTTPException(503, "Search integration unavailable")
                result = {"items": result["items"], "total": None, "limit": filters.get("limit", result.get("limit", 50)),
                          "offset": filters.get("offset", result.get("offset", 0)), "may_have_more": result["may_have_more"]}
        else:
            path = "/api/v1/stats" if tool == "stats" else "/api/v1/mails"
            result = await upstream(path, filters)
        audit(db, auth[0].id, "mail.nl.execute", f"{tenant}:{payload.source}:{tool}")
        db.commit()
        return {"plan": {"tool": tool, "filters": filters}, "executed": True, "result": result}

    @app.get(PREFIX + "/llm/providers")
    def llm_providers(_: tuple[User, SessionRecord, str] = Depends(current)):
        return {"items": PROVIDERS}

    @app.get(PREFIX + "/llm/config")
    async def llm_config(_: tuple[User, SessionRecord, str] = Depends(current)):
        result = await model_upstream("/api/v1/llm/config")
        return {key: result.get(key) for key in ("provider", "base_url", "model", "configured", "external_authorized", "api_key_set")}

    @app.put(PREFIX + "/admin/llm/config")
    async def admin_llm_config(payload: LlmConfigUpdate, actor: User = Depends(admin), db: Session = Depends(db_session)):
        result = await model_upstream("/api/v1/llm/config", payload.model_dump(exclude_unset=True), method="PUT")
        audit(db, actor.id, "admin.llm_config", "smart-search", payload.provider)
        db.commit()
        return {key: result.get(key) for key in ("provider", "base_url", "model", "configured", "external_authorized", "api_key_set")}

    def search_filters(payload: MailSearch) -> dict[str, Any]:
        filters = payload.model_dump(mode="json", exclude_none=True, exclude={"tenant_id", "source", "subject"})
        if payload.subject is not None:
            filters["subject_contains"] = payload.subject
        if payload.source == "legacy" and payload.q is not None:
            filters["body_contains"] = filters.pop("q")
        return filters

    @app.post(PREFIX + "/mail/search")
    async def mail_search(payload: MailSearch, auth: tuple[User, SessionRecord, str] = Depends(current), db: Session = Depends(db_session)):
        target = target_tenant(auth, payload.tenant_id, db)
        audit(db, auth[0].id, "mail.search", f"{target}:{payload.source}")
        db.commit()
        filters = search_filters(payload)
        if payload.source == "event":
            return await upstream("/api/v1/mails", filters)
        result = await upstream("/v1/search", filters, method="POST")
        if (not isinstance(result, dict) or not isinstance(result.get("items"), list)
                or not isinstance(result.get("limit"), int) or not isinstance(result.get("offset"), int)
                or not isinstance(result.get("may_have_more"), bool)):
            raise HTTPException(503, "Search integration unavailable")
        return {"items": result["items"], "total": None, "limit": result["limit"],
                "offset": result["offset"], "may_have_more": result["may_have_more"]}

    @app.post(PREFIX + "/mail/stats")
    async def mail_stats(payload: MailSearch, auth: tuple[User, SessionRecord, str] = Depends(current),
                         db: Session = Depends(db_session)):
        target = target_tenant(auth, payload.tenant_id, db)
        audit(db, auth[0].id, "mail.stats", f"{target}:{payload.source}")
        db.commit()
        filters = search_filters(payload)
        if payload.source == "event":
            return await upstream("/api/v1/stats", filters)
        return await upstream("/v1/stats", filters, method="POST")

    @app.get(PREFIX + "/mail/{mail_id}")
    async def mail_detail(mail_id: str, tenant_id: int | None = None, source: Literal["event", "legacy"] = "event",
                          auth: tuple[User, SessionRecord, str] = Depends(current), db: Session = Depends(db_session)):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", mail_id):
            raise HTTPException(422, "Invalid mail ID")
        target = target_tenant(auth, tenant_id, db)
        audit(db, auth[0].id, "mail.detail", f"{target}:{source}:{mail_id}")
        db.commit()
        path = f"/api/v1/mails/{mail_id}" if source == "event" else f"/v1/mail/{mail_id}"
        return await upstream(path, {}, detail=True)

    @app.get(PREFIX + "/mail/{mail_id}/analyses")
    async def mail_analyses(mail_id: str, tenant_id: int | None = None,
                            source: Literal["event", "legacy"] = "event",
                            auth: tuple[User, SessionRecord, str] = Depends(current),
                            db: Session = Depends(db_session)):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", mail_id):
            raise HTTPException(422, "Invalid mail ID")
        target_tenant(auth, tenant_id, db)
        path = f"/api/v1/mails/{mail_id}/analyses" if source == "event" else f"/v1/mail/{mail_id}/analyses"
        return await upstream(path, {})

    @app.post(PREFIX + "/mail/{mail_id}/analysis")
    async def mail_analyze(mail_id: str, tenant_id: int | None = None,
                           source: Literal["event", "legacy"] = "event",
                           auth: tuple[User, SessionRecord, str] = Depends(current),
                           db: Session = Depends(db_session)):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", mail_id):
            raise HTTPException(422, "Invalid mail ID")
        target = target_tenant(auth, tenant_id, db)
        audit(db, auth[0].id, "mail.analysis", f"{target}:{source}:{mail_id}")
        db.commit()
        path = f"/api/v1/mails/{mail_id}/analysis" if source == "event" else f"/v1/mail/{mail_id}/analysis"
        return await model_upstream(path, {}, method="POST")

    @app.get(PREFIX + "/admin/mail/storage")
    async def mail_storage(_: User = Depends(admin)):
        return await model_upstream("/api/v1/storage")

    @app.get(PREFIX + "/admin/mail/queue")
    async def mail_queue(_: User = Depends(admin)):
        return await model_upstream("/api/v2/queue")

    @app.get(PREFIX + "/admin/mail/jobs")
    async def mail_jobs(status: Literal["pending", "retry", "done"] | None = None,
                        limit: int = 20, _: User = Depends(admin)):
        if not 1 <= limit <= 100:
            raise HTTPException(422, "Invalid job limit")
        if not ready():
            raise HTTPException(503, "Search integration unavailable")
        return await upstream("/api/v2/jobs", {"limit": limit, **({"status": status} if status else {})})

    @app.get(PREFIX + "/integration/status")
    async def integration_status(auth: tuple[User, SessionRecord, str] = Depends(current)):
        status = await integration_state(auth[0])
        return {"smart_search": {"status": status, "tenant_id": settings.smart_search_tenant_id if status == "ready" else None}}

    return app


app = make_app()
