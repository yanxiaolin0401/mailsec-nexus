from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import timedelta
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .config import Settings
from .models import Audit, LoginAttempt, SessionRecord, Tenant, User, utcnow
from .schemas import Login, MailSearch, PasswordChange, TenantCreate, UserCreate, UserPatch
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

    @app.post(PREFIX + "/auth/login")
    def login(payload: Login, request: Request, response: Response, db: Session = Depends(db_session)):
        origin = request.headers.get("Origin")
        expected = settings.platform_origin or str(request.base_url).rstrip("/")
        if (origin and origin != expected) or request.headers.get("Sec-Fetch-Site", "") == "cross-site":
            raise HTTPException(403, "Cross-origin login denied")
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
            async with httpx.AsyncClient(base_url=settings.smart_search_url, transport=transport, timeout=3, trust_env=False) as client:
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

    async def upstream(path: str, params: dict[str, Any]) -> Any:
        try:
            async with httpx.AsyncClient(base_url=settings.smart_search_url, transport=transport, timeout=10, trust_env=False) as client:
                response = await client.get(path, params=params, headers={"X-Mailsec-Token": settings.smart_search_token})
            if response.status_code == 404:
                raise HTTPException(404, "Mail not found")
            if response.status_code != 200:
                raise HTTPException(503, "Search integration unavailable")
            return response.json()
        except HTTPException:
            raise
        except (httpx.HTTPError, ValueError):
            raise HTTPException(503, "Search integration unavailable") from None

    @app.post(PREFIX + "/mail/search")
    async def mail_search(payload: MailSearch, auth: tuple[User, SessionRecord, str] = Depends(current), db: Session = Depends(db_session)):
        target = target_tenant(auth, payload.tenant_id, db)
        audit(db, auth[0].id, "mail.search", str(target))
        db.commit()
        return await upstream("/api/v1/mails", payload.model_dump(exclude_none=True, exclude={"tenant_id"}))

    @app.get(PREFIX + "/mail/{mail_id}")
    async def mail_detail(mail_id: str, tenant_id: int | None = None, auth: tuple[User, SessionRecord, str] = Depends(current), db: Session = Depends(db_session)):
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,160}", mail_id):
            raise HTTPException(422, "Invalid mail ID")
        target = target_tenant(auth, tenant_id, db)
        audit(db, auth[0].id, "mail.detail", f"{target}:{mail_id}")
        db.commit()
        return await upstream(f"/api/v1/mails/{mail_id}", {})

    @app.get(PREFIX + "/integration/status")
    async def integration_status(auth: tuple[User, SessionRecord, str] = Depends(current)):
        status = await integration_state(auth[0])
        return {"smart_search": {"status": status, "tenant_id": settings.smart_search_tenant_id if status == "ready" else None}}

    return app


app = make_app()
