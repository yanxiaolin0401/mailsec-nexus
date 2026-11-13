"""Strict flat Canonical Ingestion API v2 normalization.

Upstream headers, IPs and security metadata are claims, never verified verdicts.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from urllib.parse import urlsplit

from .events import _MD5, _URL, _address

_HEADER_LINE = 998
_HEADER_LINES = 512
_HEADER_CHARS = 65_536
_RECEIVED_HOPS = 64
_BODY_CHARS = 200_000
_ATTACHMENTS = 100
_URLS = 1_000
_RECIPIENTS = 10_000
_TRUNCATION_TAGS = frozenset({
    "header_line_too_long", "header_block_truncated", "headers_truncated",
    "received_hops_truncated", "body_truncated", "body_html_truncated",
    "attachments_truncated", "urls_truncated", "security_meta_truncated",
})
_UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z")
_KNOWN_TYPES = {
    "eventId": str, "sourceSystemId": str, "sourceEventId": str,
    "tenantId": str, "mailbox": str, "eventTime": str, "from": str,
    "to": list, "cc": list, "replyTo": str, "subject": str,
    "bodyText": str, "bodyHtml": str, "rawHeaders": str,
    "senderIp": str, "senderHost": str, "attachments": list,
    "urls": list, "securityMeta": dict,
}


def _text(payload: dict, key: str, *, default: str | None = None, limit: int = 8192) -> str:
    value = payload.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid or missing {key}")
    if len(value) > limit:
        raise ValueError(f"{key} exceeds {limit} characters")
    return value.strip()


def _mailbox_list(payload: dict, key: str, *, required: bool) -> list[str]:
    values = payload.get(key, [] if not required else None)
    if not isinstance(values, list) or (required and not values):
        raise ValueError(f"invalid or missing {key}")
    output = []
    for value in values:
        if not isinstance(value, str) or not value.strip() or _address(value) != value.strip().lower():
            raise ValueError(f"invalid {key} address")
        output.append(value.strip().lower())
    return list(dict.fromkeys(output))


def _headers(raw: str, tags: list[str]) -> str:
    if raw == "-":
        return raw
    # Bound line-object creation even for a 16 MiB newline-heavy header attack.
    lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n", _HEADER_LINES)
    if len(lines) > _HEADER_LINES:
        tags.append("header_block_truncated")
    lines = lines[:_HEADER_LINES]
    kept = []
    hops = 0
    skip_folded = False
    for line in lines:
        if len(line) > _HEADER_LINE:
            line = line[:_HEADER_LINE]
            tags.append("header_line_too_long")
        if line[:1] not in (" ", "\t"):
            skip_folded = False
            if line.casefold().startswith("received:"):
                hops += 1
                if hops > _RECEIVED_HOPS:
                    skip_folded = True
                    tags.append("received_hops_truncated")
                    continue
        if not skip_folded:
            kept.append(line)
    result = "\n".join(kept)
    if len(result) > _HEADER_CHARS:
        result = result[:_HEADER_CHARS]
        tags.append("headers_truncated")
    return result or "-"


def _attachments(values: list, tags: list[str]) -> list[dict[str, str]]:
    if len(values) > _ATTACHMENTS:
        tags.append("attachments_truncated")
    output = []
    for item in values[:_ATTACHMENTS]:
        if not isinstance(item, dict):
            raise ValueError("invalid attachments item")
        filename = item.get("filename")
        md5 = item.get("md5")
        size = item.get("size")
        if not isinstance(filename, str) or not filename.strip() or len(filename) > 512:
            raise ValueError("invalid attachment filename")
        if not isinstance(md5, str) or _MD5.fullmatch(md5) is None:
            raise ValueError("invalid attachment md5")
        if type(size) is not int or not 0 <= size <= 2**63 - 1:
            raise ValueError("invalid attachment size")
        output.append({"filename": filename.strip(), "md5": md5.lower(), "size": str(size)})
    return output


def _urls(values: list, body: str, tags: list[str]) -> list[str]:
    if not all(isinstance(item, str) for item in values):
        raise ValueError("invalid urls item")
    candidates = [*values, *_URL.findall(body)]
    output: list[str] = []
    seen = set()
    for value in candidates:
        candidate = value.strip().rstrip(".,;)]}")
        if len(candidate) > 2048:
            tags.append("invalid_url")
            continue
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            tags.append("invalid_url")
            continue
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            tags.append("invalid_url")
            continue
        if candidate not in seen:
            if len(output) == _URLS:
                tags.append("urls_truncated")
                break
            seen.add(candidate)
            output.append(candidate)
    return output


def _header_date(headers: str, fallback: datetime, tags: list[str]) -> datetime:
    if headers == "-":
        return fallback
    for line in headers.splitlines():
        if line.casefold().startswith("date:"):
            try:
                date = parsedate_to_datetime(line.partition(":")[2].strip())
                if date.tzinfo is None:
                    raise ValueError("timezone missing")
                date = date.astimezone(timezone.utc)
                if 1900 <= date.year <= 2299:
                    return date
            except (TypeError, ValueError, IndexError, OverflowError):
                pass
            tags.append("invalid_mail_date")
            return fallback
    return fallback


def normalize_canonical(payload: dict, *, ingress_ip: str, now: datetime | None) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("event payload must be an object")
    if "mail" in payload or "data" in payload:
        raise ValueError("canonical event must be flat")
    for key, expected in _KNOWN_TYPES.items():
        if key in payload and not isinstance(payload[key], expected):
            raise ValueError(f"invalid {key} type")
    tags: list[str] = []
    source_system = _text(payload, "sourceSystemId", limit=256)
    source_event = _text(payload, "sourceEventId", limit=256)
    if source_system == "-" or source_event == "-":
        raise ValueError("source IDs must not be placeholders")
    if "eventId" in payload:
        event_id = _text(payload, "eventId", limit=36)
        try:
            parsed_id = uuid.UUID(event_id)
        except ValueError as exc:
            raise ValueError("eventId must be a UUID") from exc
        if str(parsed_id) != event_id.lower():
            raise ValueError("eventId must be a canonical UUID")
        event_id = str(parsed_id)
    else:
        pair = json.dumps([source_system, source_event], ensure_ascii=False, separators=(",", ":"))
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, pair))
    event_time_raw = _text(payload, "eventTime", limit=35)
    if _UTC_TIME.fullmatch(event_time_raw) is None:
        raise ValueError("eventTime must be ISO-8601 UTC")
    try:
        event_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid eventTime") from exc
    if not 1900 <= event_time.year <= 2299:
        raise ValueError("eventTime outside supported range")
    if event_time.microsecond % 1000:
        event_time = event_time.replace(microsecond=event_time.microsecond // 1000 * 1000)
        tags.append("event_time_precision_truncated")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    current = current.astimezone(timezone.utc)
    if not 1970 <= current.year <= 2299:
        raise ValueError("now is outside supported storage time range")
    sender_raw = _text(payload, "from", limit=320)
    sender = _address(sender_raw)
    if (not sender or len(getaddresses([sender_raw])) != 1
            or (sender_raw.lower() != sender and "<" not in sender_raw)):
        raise ValueError("invalid from address")
    if len(payload.get("to", [])) + len(payload.get("cc", [])) > _RECIPIENTS:
        raise ValueError("too many recipients")
    recipients = _mailbox_list(payload, "to", required=True)
    cc = _mailbox_list(payload, "cc", required=False)
    subject = _text(payload, "subject")
    tenant = _text(payload, "tenantId", default="tenant_default", limit=256)
    mailbox = _text(payload, "mailbox", default="INBOX", limit=128)
    reply_to = _text(payload, "replyTo", default="-", limit=320)
    sender_host = _text(payload, "senderHost", default="-", limit=8192)
    raw_headers = _text(payload, "rawHeaders", limit=16 * 1024 * 1024)
    headers = _headers(raw_headers, tags)
    body_raw = _text(payload, "bodyText", default="-", limit=16 * 1024 * 1024)
    if len(body_raw) > _BODY_CHARS:
        body_raw = body_raw[:_BODY_CHARS]
        tags.append("body_truncated")
    body_html = _text(payload, "bodyHtml", default="-", limit=16 * 1024 * 1024)
    if len(body_html) > _BODY_CHARS:
        body_html = body_html[:_BODY_CHARS]
        tags.append("body_html_truncated")
    sender_ip = _text(payload, "senderIp", default="unknown", limit=128)
    if sender_ip != "unknown":
        try:
            sender_ip = str(ipaddress.ip_address(sender_ip))
        except ValueError as exc:
            raise ValueError("invalid senderIp") from exc
        tags.append("sender_ip_declared_upstream")
    try:
        ingress = str(ipaddress.ip_address(ingress_ip))
    except ValueError:
        ingress = "unknown"
    attachments = _attachments(payload.get("attachments", []), tags)
    urls = _urls(payload.get("urls", []), body_raw, tags)
    metadata = payload.get("securityMeta", {})
    security_meta_json = json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(security_meta_json) > 65_536:
        security_meta_json = json.dumps({
            "security_meta_omitted": True,
            "original_sha256": hashlib.sha256(security_meta_json.encode()).hexdigest(),
            "original_bytes": len(security_meta_json.encode()),
        }, sort_keys=True, separators=(",", ":"))
        tags.append("security_meta_truncated")
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    raw_bytes = raw.encode()
    payload_hash = hashlib.sha256(raw_bytes).hexdigest()
    declared_hash = metadata.get("mailHash")
    if declared_hash is not None and (not isinstance(declared_hash, str) or _MD5.fullmatch(declared_hash) is None):
        tags.append("invalid_mail_hash")
    mail_hash = declared_hash.lower() if isinstance(declared_hash, str) and _MD5.fullmatch(declared_hash) else hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()
    mail_date = _header_date(headers, event_time, tags)
    if len(raw_bytes) > 1024 * 1024 or _TRUNCATION_TAGS.intersection(tags):
        raw = json.dumps({
            "audit_payload_omitted": True,
            "original_payload_sha256": payload_hash,
            "original_bytes": len(raw_bytes),
            "sourceSystemId": source_system, "sourceEventId": source_event,
            "eventId": event_id,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        tags.append("raw_json_omitted")
    return {
        "event_id": event_id, "event_time": event_time.isoformat(), "ingested_at": current.isoformat(),
        "source_type": "MAIL_OFFLINE_HTTP", "source_system_id": source_system,
        "source_event_id": source_event, "trace_id": uuid.uuid4().hex,
        "payload_hash": payload_hash, "mail_hash": mail_hash,
        "sender_account": sender, "receiver_accounts": list(dict.fromkeys([*recipients, *cc])), "subject": subject,
        "sender_ip": sender_ip, "ingress_ip": ingress,
        "sender_country": "-", "sender_isp": "-", "risk_verdict": "unknown", "risk_level": "unknown",
        "risk_score": 0, "feature_tags": [], "data_quality_tags": list(dict.fromkeys(tags)),
        "sender_host": sender_host, "suspicious_string": "-", "malicious_sender_ip": "-",
        "tenant_email_addr_url": "-", "external_urls": urls,
        "external_attachments": attachments, "mail_headers": headers,
        "mail_date": mail_date.isoformat(), "reply_to": reply_to,
        "src_email_address": sender, "to_email_address": recipients[0],
        "raw_json": raw, "text_content": body_raw,
        "tenant_id": tenant, "mailbox": mailbox, "cc_accounts": cc,
        "body_html": body_html, "security_meta_json": security_meta_json,
    }
