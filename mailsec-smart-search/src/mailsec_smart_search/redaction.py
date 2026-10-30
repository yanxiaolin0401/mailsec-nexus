"""An explicit allowlist of metadata sent to a third-party model."""

from __future__ import annotations

import re
import unicodedata

from .domain import MailRecord


_ADDRESS = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_PHONE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{8,}\d)(?!\w)")
_LONG_TOKEN = re.compile(r"(?<!\w)[A-Za-z0-9+/=_-]{32,}(?!\w)")
_HTML_TAG = re.compile(r"<[^>]{0,500}>")
REDACTION_VERSION = "2"


def redact_text(value: str, limit: int = 4000) -> str:
    # Best-effort masking is not a guarantee of PII removal. Input must already
    # be authorized for third-party transfer under the operator's data policy.
    value = unicodedata.normalize("NFKC", value)
    value = _HTML_TAG.sub(" ", value)
    value = _URL.sub("[url]", value)
    value = _ADDRESS.sub("[email]", value)
    value = _IPV4.sub("[ip]", value)
    value = _PHONE.sub("[phone]", value)
    value = _LONG_TOKEN.sub("[token]", value)
    value = " ".join(value.split())
    return value[:limit]


def model_payload(record: MailRecord) -> dict[str, object]:
    domain = record.sender_domain.lower().strip()
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", domain) or ".." in domain:
        domain = ""
    return {
        "sender_domain": domain,
        "subject": redact_text(record.subject, 300),
        "body_excerpt": redact_text(record.body_text, 1500),
        "attachment_count": len(record.attachments),
        "url_count": len(record.urls),
        "claimed_spf": redact_text(record.claimed_spf, 50),
    }
