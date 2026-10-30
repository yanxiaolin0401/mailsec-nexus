"""Bounded ClickHouse persistence and read-only search for parsed mail."""

from __future__ import annotations

import json
import re
import threading
import time
from collections import deque
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator
from uuid import uuid4

from .config import Settings
from .domain import AttachmentInfo, MailRecord, SearchQuery


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_MAIL_COLUMNS = (
    "mail_id", "raw_sha256", "raw_path", "source", "ingested_at", "sent_at",
    "header_message_id", "sender", "sender_domain", "recipients", "subject",
    "body_text", "headers_json", "attachments_json", "attachment_count",
    "attachment_suffixes", "urls", "claimed_spf", "parse_status",
    "parse_errors", "truncated", "parser_version",
)
_ANALYSIS_COLUMNS = ("event_id", "mail_id", "created_at", "analysis_json")
# Some historical Date headers produced pre-1900 DateTime64 values.  The
# clickhouse-connect 1.10 C decoder cannot decode them reliably; keep the
# stored value intact and mask only the result projection sent to the client.
_SAFE_SENT_AT = (
    "if(toUnixTimestamp64Milli(sent_at) >= -2208988800000 "
    "AND toUnixTimestamp64Milli(sent_at) < 10413792000000, sent_at, NULL) AS sent_at"
)
_MAIL_SELECT = ", ".join(_SAFE_SENT_AT if column == "sent_at" else column for column in _MAIL_COLUMNS)
_SUMMARY_SELECT = (
    "mail_id, substringUTF8(sender, 1, 320) AS sender, "
    "substringUTF8(sender_domain, 1, 255) AS sender_domain, "
    "substringUTF8(subject, 1, 512) AS subject, "
    f"{_SAFE_SENT_AT}, ingested_at, attachment_count, parse_status, "
    "substringUTF8(body_text, 1, 200) AS body_preview"
)
_CANDIDATE_SELECT = (
    "mail_id, raw_sha256, raw_path, source, ingested_at, "
    f"{_SAFE_SENT_AT}, "
    "substringUTF8(sender, 1, 320) AS sender, "
    "substringUTF8(sender_domain, 1, 255) AS sender_domain, "
    "substringUTF8(subject, 1, 300) AS subject, "
    "substringUTF8(body_text, 1, 1000) AS body_text, attachments_json, "
    "substringUTF8(claimed_spf, 1, 2048) AS claimed_spf, parse_status"
)
_QUERY_SETTINGS = {
    "max_execution_time": 5,
    "max_memory_usage": 512 * 1024 * 1024,
    "max_rows_to_read": 10_000_000,
    # Small host: four concurrent body scans must not each materialize 64k
    # wide rows across multiple FINAL threads.
    "max_threads": 1,
    "max_final_threads": 1,
    "max_block_size": 4096,
    "do_not_merge_across_partitions_select_final": 1,
}
_BODY_SCAN_WAIT_SECONDS = 5.0


def _suffix(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _mail_row(record: MailRecord) -> tuple[Any, ...]:
    return (
        record.mail_id, record.raw_sha256, record.raw_path, record.source,
        _utc(record.ingested_at), _utc(record.sent_at) if record.sent_at else None,
        record.header_message_id, record.sender, record.sender_domain,
        list(record.recipients), record.subject, record.body_text,
        json.dumps(record.headers, ensure_ascii=False),
        json.dumps([{
            "name": a.name, "content_type": a.content_type, "size": a.size,
            "sha256": a.sha256,
        } for a in record.attachments], ensure_ascii=False),
        len(record.attachments), [_suffix(a.name) for a in record.attachments],
        list(record.urls), record.claimed_spf, record.parse_status,
        list(record.parse_errors), record.truncated, record.parser_version,
    )


def _as_mail(values: dict[str, Any]) -> MailRecord:
    return MailRecord(
        mail_id=values["mail_id"], raw_sha256=values["raw_sha256"],
        raw_path=values["raw_path"], source=values["source"],
        ingested_at=values["ingested_at"], sent_at=values["sent_at"],
        header_message_id=values["header_message_id"], sender=values["sender"],
        sender_domain=values["sender_domain"], recipients=list(values["recipients"]),
        subject=values["subject"], body_text=values["body_text"],
        headers=[tuple(item) for item in json.loads(values["headers_json"])],
        attachments=[AttachmentInfo(**item) for item in json.loads(values["attachments_json"])],
        urls=list(values["urls"]), claimed_spf=values["claimed_spf"],
        parse_status=values["parse_status"], parse_errors=list(values["parse_errors"]),
        truncated=values["truncated"], parser_version=values["parser_version"],
    )


def _as_candidate(values: dict[str, Any]) -> MailRecord:
    """SOP match fields only; full evidence is fetched singly before analysis."""
    return MailRecord(
        mail_id=values["mail_id"], raw_sha256=values["raw_sha256"],
        raw_path=values["raw_path"], source=values["source"],
        ingested_at=values["ingested_at"], sent_at=values["sent_at"],
        sender=values["sender"], sender_domain=values["sender_domain"],
        subject=values["subject"], body_text=values["body_text"],
        attachments=[AttachmentInfo(**item) for item in json.loads(values["attachments_json"])],
        claimed_spf=values["claimed_spf"], parse_status=values["parse_status"],
    )


class ClickHouseRepository:
    """Only fixed SQL templates and typed bound values reach ClickHouse."""

    def __init__(self, settings: Settings, client: Any | None = None) -> None:
        if not _IDENTIFIER.fullmatch(settings.clickhouse_database):
            raise ValueError("invalid ClickHouse database identifier")
        self.database = settings.clickhouse_database
        self._settings = settings
        self._client = client
        self._connect_lock = threading.Lock()
        self._body_condition = threading.Condition()
        self._body_waiters: deque[object] = deque()
        self._body_active = False

    @property
    def client(self) -> Any:
        if self._client is None:
            with self._connect_lock:
                if self._client is None:
                    self._client = self._connect(self._settings)
        return self._client

    @staticmethod
    def _connect(settings: Settings, *, send_receive_timeout: int = 10) -> Any:
        import clickhouse_connect

        # Connect to default first: the application database may not yet exist.
        return clickhouse_connect.get_client(
            host=settings.clickhouse_host, port=settings.clickhouse_port,
            secure=settings.clickhouse_secure or settings.clickhouse_port == 8443,
            username=settings.clickhouse_user, password=settings.clickhouse_password,
            database="default", connect_timeout=5, send_receive_timeout=send_receive_timeout,
            autogenerate_session_id=False,
        )

    def ensure_schema(self) -> None:
        self.client.command(f"CREATE DATABASE IF NOT EXISTS `{self.database}`")
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        for statement in schema.split(";"):
            # SQL comments are part of a statement and accepted by ClickHouse.
            statement = statement.strip()
            if statement:
                self.client.command(statement.replace("{database}", f"`{self.database}`"))

    def ping(self) -> bool:
        try:
            result = self.client.query("SELECT 1", parameters={}, settings=_QUERY_SETTINGS)
            return bool(result.result_rows and result.result_rows[0][0] == 1)
        except Exception:
            return False

    def insert_batch(self, records: Iterable[MailRecord]) -> int:
        rows = [_mail_row(record) for record in records]
        if not rows:
            return 0
        self.client.insert(f"{self.database}.mail_records", rows, column_names=list(_MAIL_COLUMNS))
        return len(rows)

    def get_mail(self, mail_id: str) -> MailRecord | None:
        result = self.client.query(
            f"SELECT {_MAIL_SELECT} FROM `{self.database}`.mail_records FINAL "
            "WHERE mail_id = {mail_id:String} LIMIT 1",
            parameters={"mail_id": mail_id}, settings=_QUERY_SETTINGS,
        )
        return _as_mail(dict(zip(result.column_names, result.result_rows[0]))) if result.result_rows else None

    @contextmanager
    def _body_scan_slot(self) -> Iterator[None]:
        """FIFO admission prevents a busy worker from starving queued scans."""
        token = object()
        deadline = time.monotonic() + _BODY_SCAN_WAIT_SECONDS
        with self._body_condition:
            self._body_waiters.append(token)
            try:
                while self._body_active or self._body_waiters[0] is not token:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("body scan admission timed out")
                    self._body_condition.wait(remaining)
            except BaseException:
                if token in self._body_waiters:
                    self._body_waiters.remove(token)
                    self._body_condition.notify_all()
                raise
            self._body_waiters.popleft()
            self._body_active = True
        try:
            yield
        finally:
            with self._body_condition:
                self._body_active = False
                self._body_condition.notify_all()

    def _query_read(self, sql: str, parameters: dict[str, Any], query: SearchQuery) -> Any:
        """Admit only one body scan per repository on memory-constrained hosts."""
        if query.body_contains is None:
            return self.client.query(sql, parameters=parameters, settings=_QUERY_SETTINGS)
        with self._body_scan_slot():
            return self.client.query(sql, parameters=parameters, settings=_QUERY_SETTINGS)

    @staticmethod
    def _filters(query: SearchQuery) -> tuple[str, dict[str, Any]]:
        conditions: list[str] = []
        params: dict[str, Any] = {}
        for attr, clause, type_name in (
            ("from_time", "sent_at >=", "DateTime64(3)"),
            ("to_time", "sent_at <=", "DateTime64(3)"),
            ("sender", "sender =", "String"),
            ("sender_domain", "sender_domain =", "String"),
        ):
            value = getattr(query, attr)
            if value is not None:
                conditions.append(f"{clause} {{{attr}:{type_name}}}")
                params[attr] = _utc(value) if isinstance(value, datetime) else value
        if query.recipient is not None:
            conditions.append("has(recipients, {recipient:String})")
            params["recipient"] = query.recipient
        for attr, column in (("subject_contains", "subject"), ("body_contains", "body_text")):
            value = getattr(query, attr)
            if value is not None:
                conditions.append(f"positionCaseInsensitiveUTF8({column}, {{{attr}:String}}) > 0")
                params[attr] = value
        if query.has_attachment is not None:
            conditions.append("attachment_count > 0" if query.has_attachment else "attachment_count = 0")
        if query.attachment_suffix is not None:
            conditions.append("has(attachment_suffixes, {attachment_suffix:String})")
            params["attachment_suffix"] = query.attachment_suffix.lower().lstrip(".")
        return (" WHERE " + " AND ".join(conditions)) if conditions else "", params

    def search(self, query: SearchQuery) -> list[MailRecord]:
        if not 1 <= query.limit <= 200 or not 0 <= query.offset <= 10_000:
            raise ValueError("limit must be 1..200 and offset 0..10000")
        where, params = self._filters(query)
        params.update(limit=query.limit, offset=query.offset)
        result = self._query_read(
            f"SELECT {_MAIL_SELECT} FROM `{self.database}`.mail_records FINAL"
            f"{where} ORDER BY ingested_at DESC, mail_id DESC "
            "LIMIT {limit:UInt16} OFFSET {offset:UInt16}",
            params, query,
        )
        return [_as_mail(dict(zip(result.column_names, row))) for row in result.result_rows]

    def search_summaries(self, query: SearchQuery) -> list[dict[str, Any]]:
        """Return bounded list metadata without transferring bodies or raw headers."""
        if not 1 <= query.limit <= 200 or not 0 <= query.offset <= 10_000:
            raise ValueError("limit must be 1..200 and offset 0..10000")
        where, params = self._filters(query)
        params.update(limit=query.limit, offset=query.offset)
        result = self._query_read(
            f"SELECT {_SUMMARY_SELECT} FROM `{self.database}`.mail_records FINAL"
            f"{where} ORDER BY ingested_at DESC, mail_id DESC "
            "LIMIT {limit:UInt16} OFFSET {offset:UInt16}",
            params, query,
        )
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def search_candidates(self, query: SearchQuery) -> list[MailRecord]:
        """SOP-only bounded match projection; no headers or entire mail body."""
        if not 1 <= query.limit <= 200 or not 0 <= query.offset <= 10_000:
            raise ValueError("limit must be 1..200 and offset 0..10000")
        where, params = self._filters(query)
        params.update(limit=query.limit, offset=query.offset)
        result = self._query_read(
            f"SELECT {_CANDIDATE_SELECT} FROM `{self.database}`.mail_records FINAL"
            f"{where} ORDER BY ingested_at DESC, mail_id DESC "
            "LIMIT {limit:UInt16} OFFSET {offset:UInt16}",
            params, query,
        )
        return [_as_candidate(dict(zip(result.column_names, row))) for row in result.result_rows]

    def stats(self, query: SearchQuery) -> dict[str, int]:
        where, params = self._filters(query)
        result = self._query_read(
            f"SELECT count() AS total, countIf(attachment_count > 0) AS with_attachment, "
            f"countIf(parse_status != 'ok') AS parse_failed "
            f"FROM `{self.database}`.mail_records FINAL{where}",
            params, query,
        )
        return dict(zip(result.column_names, result.result_rows[0]))

    def save_analysis(self, mail_id: str, analysis: dict[str, Any]) -> str:
        if not mail_id:
            raise ValueError("mail_id is required")
        event_id = str(uuid4())
        self.client.insert(
            f"{self.database}.analysis_events",
            [(event_id, mail_id, datetime.now(timezone.utc), json.dumps(analysis, ensure_ascii=False))],
            column_names=list(_ANALYSIS_COLUMNS),
        )
        return event_id

    def get_analyses(self, mail_id: str) -> list[dict[str, Any]]:
        result = self.client.query(
            f"SELECT {', '.join(_ANALYSIS_COLUMNS)} FROM `{self.database}`.analysis_events "
            "WHERE mail_id = {mail_id:String} ORDER BY created_at DESC, event_id DESC LIMIT 100",
            parameters={"mail_id": mail_id}, settings=_QUERY_SETTINGS,
        )
        return [
            {"event_id": str(row[0]), "mail_id": row[1], "created_at": row[2],
             "analysis": json.loads(row[3])}
            for row in result.result_rows
        ]
