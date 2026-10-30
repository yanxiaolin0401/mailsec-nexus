"""Optional, privacy-bounded model opinion for normalized HTTP mail events.

This is not the EML detection pipeline: the event contains attachment metadata,
not attachment bytes, and its headers/authentication results are upstream claims.
"""

from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timezone

from .config import Settings
from .domain import AttachmentInfo, MailRecord
from .llm import analyze_with_llm


_RISK_LEVEL = {"clean": "low", "suspicious": "medium", "malicious": "high"}
_LIMITATIONS = [
    "model_opinion_only_not_rules_or_antivirus_fusion",
    "attachment_content_unavailable_not_scanned",
    "upstream_headers_and_authentication_claims_unverified",
]


def _text(value: object) -> str:
    return value if isinstance(value, str) and value != "-" else ""


def analyze_event(event: dict, settings: Settings) -> dict:
    """Analyze a normalized event without forwarding raw JSON, headers or PII lists.

    Only fields admitted by ``redaction.model_payload`` reach the model. The
    model's free-form reason is replaced with field references so a provider
    cannot echo private event content back into durable analysis evidence.
    """
    sender = _text(event.get("sender_account"))
    domain = sender.rpartition("@")[2] if "@" in sender else ""
    attachments = event.get("external_attachments")
    urls = event.get("external_urls")
    record = MailRecord(
        mail_id="", raw_sha256="", raw_path="", source="http_event",
        ingested_at=datetime.now(timezone.utc), sender_domain=domain,
        subject=_text(event.get("subject")), body_text=_text(event.get("text_content")),
        # Deliberately use placeholders: no filename, hash or bytes enter model_payload.
        attachments=[AttachmentInfo("", "", 0, "") for _ in attachments]
        if isinstance(attachments, list) else [],
        urls=[""] * len(urls) if isinstance(urls, list) else [],
        # Do not turn unverified Authentication-Results / Received-SPF into facts.
        claimed_spf="",
    )
    result = analyze_with_llm(record, settings)
    refs = list(result.evidence_refs) if result.status == "ok" else []
    if result.status == "ok":
        result = replace(result, reason=("Evidence fields: " + ", ".join(refs)) if refs else "Model opinion only")
    limitations = list(_LIMITATIONS)
    if result.status != "ok":
        limitations.append("model_unavailable_or_invalid_no_risk_verdict")
    return {
        "event_id": event.get("event_id"),
        "status": "ok" if result.status == "ok" else "partial",
        "risk_level": _RISK_LEVEL.get(result.risk or "", "unknown") if result.status == "ok" else "unknown",
        "model": asdict(result),
        "evidence_refs": refs,
        "limitations": limitations,
    }
