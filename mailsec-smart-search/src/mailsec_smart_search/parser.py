"""Bounded, untrusted EML parsing; this module never opens attachments."""

from __future__ import annotations

import hashlib
import multiprocessing as mp
import re
import resource
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser

from .domain import AttachmentInfo, MailRecord

MAX_MESSAGE_BYTES = 20 * 1024 * 1024
MAX_PARTS = 256
MAX_DECODED_PART_BYTES = 20 * 1024 * 1024
MAX_BODY_CHARS = 200_000
MAX_HEADERS = 2000
MAX_HEADER_CHARS = 8192
MAX_TOTAL_HEADER_CHARS = 128 * 1024
_URL = re.compile(r"https?://[^\s<>\"'\x00-\x1f]+", re.IGNORECASE)
_MIN_SENT_AT = datetime(1900, 1, 1, tzinfo=timezone.utc)
_MAX_SENT_AT = datetime(2300, 1, 1, tzinfo=timezone.utc)


class ParseLimitError(ValueError):
    """A message exceeds a parser safety limit."""


class ParseTimeoutError(TimeoutError):
    """The isolated parser exceeded its deadline."""


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    try:
        decoded = str(make_header(decode_header(str(value))))
    except (UnicodeError, ValueError, LookupError):
        decoded = str(value)
    # BytesParser raw headers may use surrogateescape for invalid octets.
    # Persist replacement characters; the original octets remain in raw EML.
    return decoded.encode("utf-8", errors="replace").decode("utf-8")


class _HTMLText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.urls: list[str] = []
        self.hidden = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style"}:
            self.hidden += 1
        for key, value in attrs:
            if key in {"href", "src"} and value and value.lower().startswith(("http://", "https://")):
                self.urls.append(value)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            self.parts.append(data)


def parse_eml(
    raw: bytes,
    *,
    mail_id: str,
    raw_sha256: str,
    raw_path: str,
    source: str,
    ingested_at: datetime,
    max_body_chars: int = MAX_BODY_CHARS,
) -> MailRecord:
    """Parse bounded RFC5322/MIME metadata; claimed authentication is not verified."""
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ParseLimitError("EML exceeds parser byte limit")
    if max_body_chars < 0 or max_body_chars > MAX_BODY_CHARS:
        raise ValueError("max_body_chars is outside allowed range")
    record = MailRecord(mail_id, raw_sha256, raw_path, source, ingested_at)
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        record.parse_status = "error"
        record.parse_errors.append(f"message parse failed: {type(exc).__name__}")
        return record
    header_chars = 0
    raw_headers: dict[str, str] = {}
    # raw_items avoids stdlib headerregistry crashes on malformed Message-ID.
    # Preserve the ordered duplicates separately, use only the first field for
    # convenience metadata, and keep the immutable raw EML as evidence.
    for index, (key, value) in enumerate(message.raw_items()):
        if index >= MAX_HEADERS or header_chars >= MAX_TOTAL_HEADER_CHARS:
            record.truncated = True
            record.parse_errors.append("header count or total character limit reached")
            break
        decoded = _decode_header(value)
        safe_value = str(value).encode("utf-8", errors="replace").decode("utf-8")
        if safe_value != str(value):
            record.parse_errors.append("invalid header encoding")
        raw_headers.setdefault(key.lower(), safe_value[:MAX_HEADER_CHARS])
        if len(decoded) > MAX_HEADER_CHARS:
            record.truncated = True
            record.parse_errors.append("header character limit reached")
        record.headers.append((key, decoded[:MAX_HEADER_CHARS]))
        header_chars += len(key) + min(len(decoded), MAX_HEADER_CHARS)
    record.subject = _decode_header(raw_headers.get("subject"))[:MAX_HEADER_CHARS]
    record.header_message_id = raw_headers.get("message-id", "")
    if record.header_message_id and not re.fullmatch(r"\s*<[^<>\s]+@[^<>\s]+>\s*", record.header_message_id):
        record.parse_errors.append("invalid Message-ID header")
    senders = getaddresses([raw_headers.get("from", "")])
    record.sender = senders[0][1] if senders else ""
    record.sender_domain = record.sender.rpartition("@")[2].lower()
    recipient_headers = [raw_headers[key] for key in ("to", "cc", "bcc") if raw_headers.get(key)]
    record.recipients = [address for _, address in getaddresses(recipient_headers) if address]
    record.claimed_spf = raw_headers.get("received-spf", "")[:2048]
    if raw_headers.get("date"):
        try:
            sent_at = parsedate_to_datetime(raw_headers["date"])
            sent_at_utc = (sent_at.replace(tzinfo=timezone.utc) if sent_at.tzinfo is None
                           else sent_at.astimezone(timezone.utc))
            if _MIN_SENT_AT <= sent_at_utc < _MAX_SENT_AT:
                record.sent_at = sent_at
            else:
                record.parse_errors.append("Date header outside supported range")
        except (TypeError, ValueError, IndexError, OverflowError):
            record.parse_errors.append("invalid Date header")
    if message.defects:
        record.parse_errors.extend(type(defect).__name__ for defect in message.defects[:10])

    text_parts: list[str] = []
    html_parts: list[str] = []
    html_urls: list[str] = []
    count = 0
    for part in message.walk():
        count += 1
        if count > MAX_PARTS:
            record.truncated = True
            record.parse_errors.append("MIME part limit reached")
            break
        if part.is_multipart():
            continue
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception as exc:
            record.parse_errors.append(f"part decode failed: {type(exc).__name__}")
            continue
        if len(payload) > MAX_DECODED_PART_BYTES:
            record.truncated = True
            record.parse_errors.append("decoded part byte limit reached")
            continue
        filename = part.get_filename()
        if filename is not None or part.get_content_disposition() == "attachment":
            record.attachments.append(AttachmentInfo(
                name=_decode_header(filename)[:512],
                content_type=part.get_content_type(),
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            ))
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            decoded = payload.decode(charset, errors="replace")
        except LookupError:
            decoded = payload.decode("utf-8", errors="replace")
            record.parse_errors.append("unknown charset")
        safe_decoded = decoded.encode("utf-8", errors="replace").decode("utf-8")
        if safe_decoded != decoded:
            record.parse_errors.append("invalid body encoding")
        decoded = safe_decoded
        if part.get_content_type() == "text/html":
            html = _HTMLText()
            html.feed(decoded[:MAX_BODY_CHARS])
            html_parts.append(" ".join(html.parts))
            html_urls.extend(html.urls)
        else:
            text_parts.append(decoded)
    body = "\n".join(text_parts if text_parts else html_parts)
    if len(body) > max_body_chars:
        record.truncated = True
        record.parse_errors.append("body character limit reached")
    record.body_text = body[:max_body_chars]
    record.urls = list(dict.fromkeys([*_URL.findall(record.body_text), *html_urls]))[:1000]
    if record.parse_errors:
        record.parse_status = "partial"
    return record


def _parse_child(conn: object, raw: bytes, kwargs: dict) -> None:
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    try:
        conn.send((True, parse_eml(raw, **kwargs)))
    except Exception as exc:
        conn.send((False, (type(exc).__name__, str(exc))))
    finally:
        conn.close()


def parse_eml_isolated(raw: bytes, *, timeout_seconds: float = 10.0, **kwargs: object) -> MailRecord:
    """Run parsing in a killable process so hostile input cannot hang a worker."""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ParseLimitError("EML exceeds parser byte limit")
    context = mp.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_parse_child, args=(child, raw, kwargs), daemon=True)
    process.start()
    child.close()
    try:
        if not parent.poll(timeout_seconds):
            process.terminate()
            process.join(1)
            if process.is_alive():
                process.kill()
                process.join()
            raise ParseTimeoutError("EML parse timed out")
        try:
            ok, payload = parent.recv()
        except EOFError as exc:
            raise RuntimeError("isolated EML parser exited without a result") from exc
        if not ok:
            name, message = payload
            if name == "ParseLimitError":
                raise ParseLimitError(message)
            raise RuntimeError(f"isolated EML parser failed: {name}: {message}")
        return payload
    finally:
        parent.close()
        process.join(1)
        if process.is_alive():
            process.kill()
            process.join()
