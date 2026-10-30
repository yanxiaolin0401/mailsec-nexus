"""Bounded HTTP interface for ingest, search, and on-demand analysis."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .config import Settings
from .domain import MailRecord, SearchQuery

_LOG = logging.getLogger(__name__)
_BODY_READ_TIMEOUT_SECONDS = 30.0


class SearchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    from_time: datetime | None = None
    to_time: datetime | None = None
    sender: str | None = Field(default=None, max_length=320)
    sender_domain: str | None = Field(default=None, max_length=255)
    recipient: str | None = Field(default=None, max_length=320)
    subject_contains: str | None = Field(default=None, max_length=200)
    body_contains: str | None = Field(default=None, max_length=200)
    has_attachment: bool | None = None
    attachment_suffix: str | None = Field(default=None, max_length=32)
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=10000)

    def to_query(self) -> SearchQuery:
        return SearchQuery(**self.model_dump())


class NaturalLanguageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=2000)
    execute: bool = False


class SOPRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_limit: int = Field(default=100, ge=1, le=200)
    analyze: bool = False
    max_model_calls: int | None = Field(default=None, ge=0)


class _RequestGuard:
    """Authenticate and bound all /v1 requests before framework body parsing."""

    def __init__(self, app: Any, max_message_bytes: int, api_token: str):
        self.app = app
        self.max_message_bytes = max_message_bytes
        self.api_token = api_token
        self.slots = asyncio.Semaphore(8)

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or not scope.get("path", "").startswith(("/v1/", "/api/v1/", "/api/v2/")):
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        tokens = [value for key, value in scope.get("headers", []) if key.lower() == b"x-mailsec-token"]
        if not self.api_token:
            _LOG.warning("request_denied category=auth_unconfigured")
            await self._reject(send, 503, b"API authentication is not configured")
            return
        if len(tokens) != 1 or not hmac.compare_digest(tokens[0], self.api_token.encode()):
            _LOG.warning("request_denied category=auth_invalid")
            await self._reject(send, 401, b"invalid API token")
            return
        upload = scope["path"].endswith("/upload")
        raw = scope["path"] in {"/v1/mail/raw", "/api/v2/mails"}
        limit = self.max_message_bytes + (64 * 1024 if upload else 0) if (upload or raw) else 64 * 1024
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            declared = 0
        if declared > limit:
            _LOG.warning("request_denied category=body_limit")
            await self._reject(send, 413, b"request body exceeds configured limit")
            return
        if (upload or raw) and self.slots.locked():
            await self._reject(send, 429, b"too many concurrent uploads")
            return
        if upload or raw:
            await self.slots.acquire()
        try:
            # Read only up to the cap before handing control to multipart/JSON parsing.
            # Raising inside receive() is caught by Starlette as generic 400.
            body = bytearray()
            deadline = time.monotonic() + _BODY_READ_TIMEOUT_SECONDS
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    _LOG.warning("request_denied category=body_timeout")
                    await self._reject(send, 408, b"request body timed out")
                    return
                try:
                    message = await asyncio.wait_for(receive(), timeout=remaining)
                except TimeoutError:
                    _LOG.warning("request_denied category=body_timeout")
                    await self._reject(send, 408, b"request body timed out")
                    return
                if message["type"] != "http.request":
                    return
                body.extend(message.get("body", b""))
                if len(body) > limit:
                    _LOG.warning("request_denied category=body_limit")
                    await self._reject(send, 413, b"request body exceeds configured limit")
                    return
                if not message.get("more_body", False):
                    break
            replayed = False

            async def replay() -> dict:
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return {"type": "http.disconnect"}

            async def private_send(message: dict) -> None:
                if message["type"] == "http.response.start":
                    message = {**message, "headers": [*message.get("headers", []),
                               (b"cache-control", b"no-store"),
                               (b"x-content-type-options", b"nosniff")]}
                await send(message)

            await self.app(scope, replay, private_send)
        finally:
            if upload or raw:
                self.slots.release()

    @staticmethod
    async def _reject(send: Any, code: int, body: bytes) -> None:
        await send({"type": "http.response.start", "status": code,
                    "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                                (b"cache-control", b"no-store")]})
        await send({"type": "http.response.body", "body": body})


def public_mail(record: MailRecord) -> dict[str, Any]:
    """Serialize searchable metadata without leaking local evidence paths."""
    value = asdict(record)
    value.pop("raw_path", None)
    return value


def mail_summary(record: MailRecord) -> dict[str, Any]:
    """Search lists never return full bodies, headers, or local evidence paths."""
    return {
        "mail_id": record.mail_id,
        "sender": record.sender,
        "sender_domain": record.sender_domain,
        "subject": record.subject,
        "sent_at": record.sent_at,
        "ingested_at": record.ingested_at,
        "attachment_count": len(record.attachments),
        "parse_status": record.parse_status,
        "body_preview": record.body_text[:200],
    }


def _as_json(value: Any) -> dict[str, Any]:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, dict):
        return value
    raise TypeError("analysis result is not serializable")


def create_app(
    settings: Settings | None = None,
    *,
    spool: Any | None = None,
    repository: Any | None = None,
    event_repository: Any | None = None,
    event_spool: Any | None = None,
) -> FastAPI:
    from .spool import DurableSpool, MessageTooLargeError, SpoolFullError
    from .storage import ClickHouseRepository

    settings = settings or Settings.from_env()
    spool = spool or DurableSpool(settings)
    repository = repository or ClickHouseRepository(settings)
    from .event_spool import EventSpool
    from .event_storage import EventRepository

    event_spool = event_spool or EventSpool(settings)
    event_repository = event_repository or EventRepository(repository)
    app = FastAPI(title="MailSec Smart Search", version="0.1.0")
    app.add_middleware(_RequestGuard, max_message_bytes=settings.max_message_bytes,
                       api_token=settings.api_token)
    app.state.settings = settings
    app.state.spool = spool
    app.state.repository = repository
    app.state.event_spool = event_spool
    app.state.event_repository = event_repository
    expensive_slots = asyncio.Semaphore(2)
    query_slots = asyncio.Semaphore(16)
    model_calls: deque[float] = deque()
    budget_lock = asyncio.Lock()

    @asynccontextmanager
    async def bounded_query():
        if query_slots.locked():
            raise HTTPException(status_code=429, detail="too many concurrent queries")
        await query_slots.acquire()
        try:
            yield
        finally:
            query_slots.release()

    @asynccontextmanager
    async def expensive_operation(calls: int = 0):
        if expensive_slots.locked():
            raise HTTPException(status_code=429, detail="too many concurrent analyses")
        await expensive_slots.acquire()
        try:
            if calls:
                async with budget_lock:
                    now = time.monotonic()
                    while model_calls and now - model_calls[0] >= 60:
                        model_calls.popleft()
                    if len(model_calls) + calls > settings.max_llm_calls_per_run:
                        raise HTTPException(status_code=429, detail="model call budget exhausted")
                    model_calls.extend([now] * calls)
            yield
        finally:
            expensive_slots.release()

    def require_auth(request: Request) -> None:
        if not settings.api_token:
            raise HTTPException(status_code=503, detail="API authentication is not configured")
        if not hmac.compare_digest(
            request.headers.get("x-mailsec-token", ""), settings.api_token
        ):
            raise HTTPException(status_code=401, detail="invalid API token")

    async def enqueue(raw: bytes, source: str) -> dict[str, Any]:
        if not raw:
            raise HTTPException(status_code=400, detail="empty EML")
        try:
            receipt = await asyncio.to_thread(spool.enqueue, raw, source)
        except SpoolFullError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except MessageTooLargeError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return asdict(receipt)

    @app.get("/health/live")
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    def ready() -> dict[str, str]:
        if not repository.ping():
            raise HTTPException(status_code=503, detail="ClickHouse unavailable")
        return {"status": "ok"}

    @app.post("/v1/mail/raw", status_code=202, dependencies=[Depends(require_auth)])
    async def ingest_raw(request: Request) -> dict[str, Any]:
        if request.headers.get("content-type", "").split(";")[0].strip().lower() not in {
            "message/rfc822", "application/octet-stream"
        }:
            raise HTTPException(status_code=415, detail="use message/rfc822")
        chunks: list[bytes] = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > settings.max_message_bytes:
                raise HTTPException(status_code=413, detail="EML exceeds configured byte limit")
            chunks.append(chunk)
        return await enqueue(b"".join(chunks), "http_raw")

    @app.post("/v1/mail/upload", status_code=202, dependencies=[Depends(require_auth)])
    async def ingest_upload(file: UploadFile = File(...)) -> dict[str, Any]:
        if file.content_type not in {
            "message/rfc822", "application/octet-stream", "text/plain"
        }:
            raise HTTPException(status_code=415, detail="upload an EML file")
        chunks: list[bytes] = []
        size = 0
        while chunk := await file.read(64 * 1024):
            size += len(chunk)
            if size > settings.max_message_bytes:
                raise HTTPException(status_code=413, detail="EML exceeds configured byte limit")
            chunks.append(chunk)
        await file.close()
        return await enqueue(b"".join(chunks), "http_upload")

    @app.get("/v1/jobs/{job_id}", dependencies=[Depends(require_auth)])
    def job_status(job_id: str) -> dict[str, Any]:
        try:
            job = spool.get_job(job_id)
        except (FileNotFoundError, ValueError):
            raise HTTPException(status_code=404, detail="job not found")
        except OSError as exc:
            raise HTTPException(status_code=503, detail="job lookup unavailable") from exc
        value = asdict(job)
        value.pop("raw_path", None)
        return value

    @app.post("/v1/search", dependencies=[Depends(require_auth)])
    async def search(spec: SearchRequest) -> dict[str, Any]:
        try:
            async with bounded_query():
                rows = await asyncio.to_thread(repository.search_summaries, spec.to_query())
        except HTTPException:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="search unavailable") from exc
        return {"items": rows, "count": len(rows),
                "offset": spec.offset, "limit": spec.limit,
                "may_have_more": len(rows) == spec.limit}

    @app.post("/v1/stats", dependencies=[Depends(require_auth)])
    async def stats(spec: SearchRequest) -> dict[str, Any]:
        try:
            async with bounded_query():
                return await asyncio.to_thread(repository.stats, spec.to_query())
        except HTTPException:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="statistics unavailable") from exc

    @app.get("/v1/mail/{mail_id}", dependencies=[Depends(require_auth)])
    async def get_mail(mail_id: str) -> dict[str, Any]:
        try:
            async with bounded_query():
                record = await asyncio.to_thread(repository.get_mail, mail_id)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail="mail lookup unavailable") from exc
        if record is None:
            raise HTTPException(status_code=404, detail="mail not found")
        return public_mail(record)

    @app.get("/v1/mail/{mail_id}/analyses", dependencies=[Depends(require_auth)])
    async def get_analyses(mail_id: str) -> dict[str, Any]:
        try:
            async with bounded_query():
                return {"items": await asyncio.to_thread(repository.get_analyses, mail_id)}
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail="analysis lookup unavailable") from exc

    @app.post("/v1/mail/{mail_id}/analysis", dependencies=[Depends(require_auth)])
    async def analyze(mail_id: str) -> dict[str, Any]:
        from .analysis import analyze_mail
        from .evidence import read_evidence

        async with expensive_operation(1 if settings.llm_api_key else 0):
            try:
                record = await asyncio.to_thread(repository.get_mail, mail_id)
                if record is None:
                    raise HTTPException(status_code=404, detail="mail not found")
                try:
                    raw = await asyncio.to_thread(read_evidence, record, settings)
                except (OSError, ValueError) as exc:
                    raise HTTPException(status_code=503, detail="raw evidence unavailable") from exc
                result = await asyncio.to_thread(analyze_mail, record, raw, settings)
                value = _as_json(result)
                await asyncio.to_thread(repository.save_analysis, mail_id, value)
                return value
            except HTTPException:
                raise
            except Exception as exc:
                raise HTTPException(status_code=503, detail="analysis unavailable") from exc

    @app.post("/v1/nl/query", dependencies=[Depends(require_auth)])
    async def natural_query(request: NaturalLanguageRequest) -> dict[str, Any]:
        from .event_api import _bind_filters, _mask_query
        from .llm import request_json
        from .redaction import redact_text

        request_hash = hashlib.sha256(request.text.encode("utf-8")).hexdigest()

        def audit(tool: str, executed: bool, status: str, category: str = "none") -> None:
            level = logging.INFO if status == "ok" else logging.WARNING
            _LOG.log(level, "nl_tool input_sha256=%s tool=%s executed=%s status=%s category=%s",
                     request_hash, tool, str(executed).lower(), status, category)

        try:
            masked, bindings = _mask_query(request.text)
        except ValueError as exc:
            audit("unknown", False, "failed", "sensitive_input")
            raise HTTPException(status_code=422, detail="invalid natural-language query placeholder") from exc
        if redact_text(masked, limit=4000) != masked:
            audit("unknown", False, "failed", "sensitive_input")
            raise HTTPException(status_code=422,
                                detail="natural-language query contains sensitive fields; use structured /v1/search locally")

        system_prompt = (
            "Return ONLY a JSON object with keys tool and filters. "
            f"Current time is {datetime.now(ZoneInfo('Asia/Shanghai')).isoformat()}, timezone=Asia/Shanghai. "
            "Resolve relative dates in that timezone; last week is the previous Monday 00:00 "
            "through this Monday 00:00 minus 1 millisecond (inclusive bounds). "
            "tool must be search or stats. filters may contain only from_time, to_time, "
            "sender, sender_domain, recipient, subject_contains, body_contains, "
            "has_attachment, attachment_suffix, limit, offset. "
            "Use timezone-aware timestamps and do not omit any user constraints. "
            "MAILSEC_EMAIL_n, MAILSEC_URL_n, MAILSEC_IP_n, MAILSEC_HASH_n, "
            "MAILSEC_NUMBER_n are local private-value placeholders; copy them exactly "
            "into the matching filter without guessing the underlying values. "
            "If the query cannot be represented, return an unsupported tool. "
            "Never return SQL, code, table names, or other tools."
        )
        try:
            async with expensive_operation(1):
                plan = await asyncio.to_thread(request_json, system_prompt, masked, settings)
            if not isinstance(plan, dict) or set(plan) != {"tool", "filters"} or plan.get("tool") not in {"search", "stats"}:
                raise ValueError("unsupported or extra model query fields")
            filters = _bind_filters(plan["filters"], bindings)
            spec = SearchRequest.model_validate(filters)
            if ((spec.from_time is not None and spec.from_time.tzinfo is None)
                    or (spec.to_time is not None and spec.to_time.tzinfo is None)
                    or (spec.from_time is not None and spec.to_time is not None
                        and spec.from_time > spec.to_time)):
                raise ValueError("invalid query time range")
        except HTTPException:
            audit("unknown", False, "failed", "rate_limited")
            raise
        except (ValueError, TypeError) as exc:
            audit("unknown", False, "failed", "invalid_plan")
            raise HTTPException(status_code=422, detail="invalid or unsupported model query; use structured search") from exc
        except Exception as exc:
            audit("unknown", False, "failed", "model_unavailable")
            raise HTTPException(status_code=503, detail="model query unavailable") from exc
        safe_plan = {"tool": plan["tool"], "filters": spec.model_dump(mode="json")}
        if not request.execute:
            audit(plan["tool"], False, "ok")
            return {"plan": safe_plan, "executed": False}
        try:
            async with bounded_query():
                if plan["tool"] == "stats":
                    result = await asyncio.to_thread(repository.stats, spec.to_query())
                else:
                    rows = await asyncio.to_thread(repository.search_summaries, spec.to_query())
                    result = {"items": rows, "count": len(rows),
                              "offset": spec.offset, "limit": spec.limit,
                              "may_have_more": len(rows) == spec.limit}
        except HTTPException:
            audit(plan["tool"], False, "failed", "query_rate_limited")
            raise
        except Exception as exc:
            audit(plan["tool"], True, "failed", "query_unavailable")
            raise HTTPException(status_code=503, detail="planned query unavailable") from exc
        audit(plan["tool"], True, "ok")
        return {"plan": safe_plan, "executed": True, "result": result}

    @app.get("/v1/sop", dependencies=[Depends(require_auth)])
    def list_sop() -> dict[str, Any]:
        from .sop import PRESETS
        return {"presets": PRESETS}

    @app.post("/v1/sop/{preset}", dependencies=[Depends(require_auth)])
    async def execute_sop(preset: str, spec: SOPRequest) -> dict[str, Any]:
        from .sop import PRESETS, candidate_query, matches, run_sop

        started_at = time.monotonic()
        if preset not in PRESETS:
            raise HTTPException(status_code=404, detail="unknown SOP preset")
        budget = spec.max_model_calls if spec.max_model_calls is not None else settings.max_llm_calls_per_run
        if budget > settings.max_llm_calls_per_run:
            raise HTTPException(status_code=422, detail="model call budget exceeds configured maximum")
        try:
            async with bounded_query():
                rows = await asyncio.to_thread(repository.search_candidates, candidate_query(preset, spec.candidate_limit))
            matched = sum(matches(preset, row) for row in rows)
            # Reserve only the work this bounded window can actually trigger.
            calls = min(matched, 10, budget) if spec.analyze and settings.llm_api_key and settings.llm_external_authorized else 0
            async with expensive_operation(calls):
                return await asyncio.to_thread(
                    run_sop, preset, repository, settings, candidate_limit=spec.candidate_limit,
                    analyze=spec.analyze, max_model_calls=budget if spec.analyze else 0,
                    rows=rows, started_at=started_at,
                )
        except HTTPException:
            raise
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="SOP unavailable") from exc

    from .event_api import event_router

    app.include_router(event_router(settings, event_spool, event_repository,
                                    require_auth, bounded_query, expensive_operation, repository))
    static = Path(__file__).with_name("static")
    app.mount("/assets", StaticFiles(directory=static), name="assets")

    @app.get("/", include_in_schema=False)
    def console() -> FileResponse:
        return FileResponse(static / "index.html", headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        })

    return app


app = create_app()
