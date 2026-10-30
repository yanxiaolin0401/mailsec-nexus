"""Normalize the bounded HTTP mail-event JSON contract into storage columns.

Mail headers and source IPs are *claims* supplied upstream, not authenticated facts.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit

from .parser import _decode_header

MAX_TEXT = 200_000
MAX_FIELD = 8_192
MAX_HEADERS = 2_000
MAX_HEADER_TOTAL = 128 * 1024
MAX_ITEMS = 1_000
_URL = re.compile(r"https?://[^\s<>\"',;\[\](){}，。；！？、（）【】\x00-\x1f]+", re.I)
_MD5 = re.compile(r"[0-9a-fA-F]{32}\Z")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_HTML_MARKUP = re.compile(
    r"<\s*/?\s*(?:html|head|body|div|span|p|br|a|img|table|tr|td|th|ul|ol|li|"
    r"h[1-6]|blockquote|pre|strong|em|b|i|font|center|hr|small|big|sup|sub|"
    r"form|input|svg|style|script|meta|title|section|article)"
    r"(?=[\s/>])|<!\s*(?:--|doctype)", re.I
)
_MAIL_FIELDS = {
    "from", "senderaccount", "senderhost", "accountnick", "replyto", "toaccount",
    "tonick", "allreceiveraccount", "subject", "ip", "clientip", "textcontent",
    "mailheaderlist", "urls", "attachinfos_md5", "attachinfos_filename", "attachinfos",
}


class _BodyText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.urls: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self.hidden += 1
        if not self.hidden:
            for name, value in attrs:
                if name in {"href", "src"} and value:
                    self.urls.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)


def _field(obj: dict, key: str):
    """Case-insensitive alias lookup, restricted to the selected envelope."""
    return next((v for k, v in obj.items() if isinstance(k, str) and k.casefold() == key.casefold()), None)


def _string(value: object, limit: int = MAX_FIELD) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()[:limit]


def _address(value: object) -> str:
    parsed = getaddresses([_string(value)])
    for _, addr in parsed:
        if re.fullmatch(r"[^\s<>@,;]+@[^\s<>@,;]+", addr):
            return addr.lower()[:320]
    return ""


def _addresses(value: object) -> list[str]:
    if isinstance(value, list):
        inputs = [_string(item) for item in value[:MAX_ITEMS]]
    else:
        inputs = [_string(value)]
    return list(dict.fromkeys(
        addr.lower()[:320] for _, addr in getaddresses(inputs)
        if re.fullmatch(r"[^\s<>@,;]+@[^\s<>@,;]+", addr)
    ))[:MAX_ITEMS]


def _time(value: object) -> datetime | None:
    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
    if parsed.tzinfo is None:
        return None
    parsed = parsed.astimezone(timezone.utc)
    if not 1970 <= parsed.year <= 2299:
        return None
    return parsed


def _public_ip(value: object) -> str:
    try:
        addr = ipaddress.ip_address(_string(value, 128))
        return str(addr) if addr.is_global else ""
    except ValueError:
        return ""


def _headers(value: object, tags: list[str]) -> tuple[str, list[tuple[str, str]]]:
    if value in (None, "", "-"):
        return "-", []
    if isinstance(value, str):
        if len(value) > MAX_HEADER_TOTAL:
            tags.append("headers_truncated")
        value = value[:MAX_HEADER_TOTAL]
        if value.lstrip().startswith("["):
            try:
                value = json.loads(value)
            except ValueError:
                tags.append("invalid_headers_json")
    if isinstance(value, dict):
        value = [value]
    if isinstance(value, list):
        items = value[:MAX_HEADERS]
        if len(value) > MAX_HEADERS:
            tags.append("headers_truncated")
    elif isinstance(value, str):
        lines = value.splitlines()
        items = []
        for line in lines:
            if line[:1] in {" ", "\t"} and items:
                items[-1] += " " + line.strip()
            else:
                items.append(line)
            if len(items) > MAX_HEADERS:
                tags.append("headers_truncated")
                break
        items = items[:MAX_HEADERS]
    else:
        tags.append("invalid_headers")
        return "-", []
    pairs: list[tuple[str, str]] = []
    for item in items:
        if isinstance(item, dict):
            name = _string(_field(item, "name"), 128)
            content = _string(_field(item, "value"))
        elif isinstance(item, str) and ":" in item:
            name, content = item.split(":", 1)
            name, content = name.strip()[:128], content.strip()[:MAX_FIELD]
        else:
            tags.append("invalid_header_item")
            continue
        if name and re.fullmatch(r"[A-Za-z0-9-]+", name):
            pairs.append((name, content))
        else:
            tags.append("invalid_header_item")
    rendered = "\n".join(f"{name}: {content}" for name, content in pairs)
    if len(rendered) > MAX_HEADER_TOTAL:
        rendered = rendered[:MAX_HEADER_TOTAL]
        tags.append("headers_truncated")
    return rendered or "-", pairs


def _urls(value: object, body: str, html_urls: list[str], tags: list[str]) -> list[str]:
    if isinstance(value, str) and value.lstrip().startswith("["):
        try:
            value = json.loads(value)
        except ValueError:
            tags.append("invalid_urls_json")
    if isinstance(value, list):
        candidates = value[:MAX_ITEMS]
        if len(value) > MAX_ITEMS:
            tags.append("urls_truncated")
    elif isinstance(value, str):
        candidates = _URL.findall(value[:MAX_TEXT])
    elif value is None:
        candidates = []
    else:
        tags.append("invalid_urls")
        candidates = []
    result = []
    for candidate in [*candidates, *html_urls[:MAX_ITEMS], *_URL.findall(body)[:MAX_ITEMS]]:
        if not isinstance(candidate, str):
            continue
        candidate = candidate.strip()[:2048].rstrip(".,;)]}")
        try:
            parsed = urlsplit(candidate)
        except ValueError:
            tags.append("invalid_url")
            continue
        if parsed.scheme.lower() in {"http", "https"} and parsed.netloc and candidate not in result:
            result.append(candidate)
        if len(result) >= MAX_ITEMS:
            tags.append("urls_truncated")
            break
    return result


def _attachments(mail: dict, tags: list[str]) -> list[dict[str, str]]:
    value = _field(mail, "attachInfos")
    if value is not None and not isinstance(value, list):
        tags.append("invalid_attachments")
        return []
    flat_values = (_field(mail, "attachInfos_filename"), _field(mail, "attachInfos_md5"))
    flat_present = any(bool(value) if isinstance(value, list) else
                       bool(_string(value, MAX_TEXT).strip(" ,-;")) for value in flat_values)
    if isinstance(value, list) and (value or not flat_present):
        candidates = value[:MAX_ITEMS]
        if len(value) > MAX_ITEMS:
            tags.append("attachments_truncated")
    else:
        if isinstance(value, list):
            tags.append("empty_attachments_flat_fallback")
        def split(v: object) -> list[str]:
            if isinstance(v, list):
                return [_string(x, 512) for x in v[:MAX_ITEMS]]
            return [_string(x, 512) for x in re.split(r"[,;]", _string(v, MAX_TEXT)) if _string(x)]
        names = split(_field(mail, "attachInfos_filename"))
        md5s = split(_field(mail, "attachInfos_md5"))
        candidates = [{"filename": names[i] if i < len(names) else "", "md5": md5s[i] if i < len(md5s) else ""}
                      for i in range(min(max(len(names), len(md5s)), MAX_ITEMS))]
        if len(names) != len(md5s) and names and md5s:
            tags.append("attachment_metadata_mismatch")
    result = []
    for item in candidates:
        if not isinstance(item, dict):
            tags.append("invalid_attachment_item")
            continue
        filename = _string(_field(item, "filename") or _field(item, "name"), 512)
        md5 = _string(_field(item, "md5"), 64)
        if md5 and md5 != "-" and not _MD5.fullmatch(md5):
            tags.append("invalid_attachment_md5")
            md5 = ""
        row = {"filename": filename or "-", "md5": md5.lower() if md5 and md5 != "-" else "-"}
        size = _field(item, "size")
        if isinstance(size, str) and re.fullmatch(r"[0-9]{1,19}", size.strip()):
            size = int(size.strip())
        if isinstance(size, int) and not isinstance(size, bool) and 0 <= size <= 2**63 - 1:
            row["size"] = str(size)
        elif size not in (None, "", "-"):
            tags.append("invalid_attachment_size")
        content_type = _string(_field(item, "content_type") or _field(item, "contentType"), 256)
        if content_type and content_type != "-":
            row["content_type"] = content_type
        sha256 = _string(_field(item, "sha256"), 128)
        if sha256 and sha256 != "-":
            if _SHA256.fullmatch(sha256):
                row["sha256"] = sha256.lower()
            else:
                tags.append("invalid_attachment_sha256")
        if row["filename"] != "-" or row["md5"] != "-":
            result.append(row)
    return result


def normalize_event(payload: dict, *, ingress_ip: str = "unknown", now: datetime | None = None) -> dict:
    """Return 33 documented mail_events columns plus searchable ``text_content``.

    The canonical nested envelope separates source metadata from ``mail``; flat and
    ``data`` envelopes are accepted only when unambiguous. Unknown fields remain
    in raw_json for audit, never become searchable columns.
    """
    if not isinstance(payload, dict):
        raise ValueError("event payload must be an object")
    nested = [key for key in ("mail", "data") if key in payload]
    if len(nested) > 1:
        raise ValueError("ambiguous mail/data envelopes")
    if nested:
        mail = payload[nested[0]]
        if not isinstance(mail, dict):
            raise ValueError("mail/data must be an object")
        if any(isinstance(key, str) and key.casefold() in _MAIL_FIELDS for key in payload):
            raise ValueError("ambiguous nested and flat mail fields")
    else:
        mail = payload
    try:
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("payload must be JSON serializable") from exc
    tags: list[str] = []
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    current = current.astimezone(timezone.utc)
    if not 1970 <= current.year <= 2299:
        raise ValueError("now is outside supported storage time range")
    for key in ("sourceSystemId", "sourceEventId"):
        source_value = _field(payload, key)
        if isinstance(source_value, str) and len(source_value.strip()) > 256:
            raise ValueError(f"{key} exceeds 256 characters")
    source_system = _string(_field(payload, "sourceSystemId"), 256)
    source_event = _string(_field(payload, "sourceEventId"), 256)
    if not source_system or source_system == "-":
        tags.append("missing_source_system_id")
    if not source_event or source_event == "-":
        tags.append("missing_source_event_id")
    if source_system and source_system != "-" and source_event and source_event != "-":
        pair = json.dumps([source_system, source_event], ensure_ascii=False, separators=(",", ":"))
        event_id = hashlib.sha256(pair.encode()).hexdigest()
    else:
        event_id = uuid.uuid4().hex
    event_time = _time(_field(payload, "eventTime"))
    if event_time is None:
        event_time = current
        tags.append("event_time_fallback")
        if _field(payload, "eventTime") not in (None, "", "-"):
            tags.append("invalid_event_time")
    header_text, headers = _headers(_field(mail, "mailHeaderList"), tags)
    if header_text == "-":
        tags.append("missing_mail_headers")
    def first_header(name: str) -> str:
        return next((v for k, v in headers if k.casefold() == name), "")
    sender = _address(_field(mail, "senderaccount")) or _address(_field(mail, "from")) or _address(first_header("from"))
    if not sender:
        tags.append("missing_sender_account")
    recipients = []
    for value in (_field(mail, "allReceiverAccount"), _field(mail, "toaccount")):
        recipients.extend(_addresses(value))
    for name, value in headers:
        if name.casefold() in {"to", "cc", "bcc"}:
            recipients.extend(_addresses(value))
    recipients = list(dict.fromkeys(recipients))[:MAX_ITEMS]
    if not recipients:
        tags.append("missing_receiver_accounts")
    subject = _decode_header(_string(_field(mail, "subject")) or first_header("subject"))[:MAX_FIELD] or "-"
    if subject == "-":
        tags.append("missing_subject")
    declared_ip = _field(mail, "ip")
    sender_ip = _public_ip(declared_ip)
    if not sender_ip and declared_ip not in (None, "", "-"):
        tags.append("invalid_sender_ip")
    if not sender_ip:
        for name, value in headers:
            if name.casefold() != "received":
                continue
            for candidate in re.findall(r"\[([0-9a-fA-F:.]+)\]", value):
                sender_ip = _public_ip(candidate)
                if sender_ip:
                    tags.append("sender_ip_from_untrusted_received")
                    break
            if sender_ip:
                break
    if not sender_ip:
        sender_ip = "unknown"
        tags.append("missing_sender_ip")
    raw_body_value = _field(mail, "textContent")
    if isinstance(raw_body_value, str) and len(raw_body_value) > MAX_TEXT:
        tags.append("text_content_truncated")
    body_raw = _string(raw_body_value, MAX_TEXT)
    html_urls: list[str] = []
    if _HTML_MARKUP.search(body_raw):
        parsed = _BodyText()
        parsed.feed(body_raw)
        body = " ".join(parsed.parts)[:MAX_TEXT]
        html_urls = parsed.urls
    else:
        body = body_raw
    if not body:
        tags.append("missing_text_content")
    date_claim = _time(first_header("date"))
    if date_claim is None:
        date_claim = event_time
        tags.append("mail_date_fallback")
        if first_header("date"):
            tags.append("invalid_mail_date")
    reply_to = _address(_field(mail, "replyTo")) or _address(first_header("reply-to")) or "-"
    sender_host = _string(_field(mail, "senderhost")) or "-"
    payload_hash = hashlib.sha256(raw.encode()).hexdigest()
    mail_raw = json.dumps(mail, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    external_urls = _urls(_field(mail, "urls"), body, html_urls, tags)
    external_attachments = _attachments(mail, tags)
    try:
        ingress = str(ipaddress.ip_address(ingress_ip))
    except ValueError:
        ingress = "unknown"
    return {
        "event_id": event_id, "event_time": event_time.isoformat(), "ingested_at": current.isoformat(),
        "source_type": "MAIL_OFFLINE_HTTP", "source_system_id": source_system or "-",
        "source_event_id": source_event or "-", "trace_id": uuid.uuid4().hex,
        "payload_hash": payload_hash, "mail_hash": hashlib.md5(mail_raw.encode(), usedforsecurity=False).hexdigest(),
        "sender_account": sender or "-", "receiver_accounts": recipients, "subject": subject,
        "sender_ip": sender_ip, "ingress_ip": ingress,
        "sender_country": "-", "sender_isp": "-", "risk_verdict": "unknown", "risk_level": "unknown",
        "risk_score": 0, "feature_tags": [], "data_quality_tags": list(dict.fromkeys(tags)),
        "sender_host": sender_host, "suspicious_string": "-", "malicious_sender_ip": "-",
        "tenant_email_addr_url": "-", "external_urls": external_urls,
        "external_attachments": external_attachments, "mail_headers": header_text,
        "mail_date": date_claim.isoformat(), "reply_to": reply_to, "src_email_address": sender or "-",
        "to_email_address": recipients[0] if recipients else "-", "raw_json": raw,
        "text_content": body or "-",
    }
