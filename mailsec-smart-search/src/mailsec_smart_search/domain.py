"""Stable internal contracts shared by ingestion, storage, and analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


SCHEMA_VERSION = "1"


@dataclass(frozen=True, slots=True)
class AttachmentInfo:
    name: str
    content_type: str
    size: int
    sha256: str


@dataclass(slots=True)
class MailRecord:
    mail_id: str
    raw_sha256: str
    raw_path: str
    source: str
    ingested_at: datetime
    sent_at: datetime | None = None
    header_message_id: str = ""
    sender: str = ""
    sender_domain: str = ""
    recipients: list[str] = field(default_factory=list)
    subject: str = ""
    body_text: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    claimed_spf: str = ""
    parse_status: str = "ok"
    parse_errors: list[str] = field(default_factory=list)
    truncated: bool = False
    parser_version: str = "0.2"


@dataclass(frozen=True, slots=True)
class SearchQuery:
    from_time: datetime | None = None
    to_time: datetime | None = None
    sender: str | None = None
    sender_domain: str | None = None
    recipient: str | None = None
    subject_contains: str | None = None
    body_contains: str | None = None
    has_attachment: bool | None = None
    attachment_suffix: str | None = None
    limit: int = 50
    offset: int = 0


@dataclass(frozen=True, slots=True)
class JobReceipt:
    job_id: str
    mail_id: str
    raw_sha256: str
    status: str
