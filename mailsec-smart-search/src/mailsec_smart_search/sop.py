"""Three bounded, explicit, non-autonomous email investigation playbooks."""

from __future__ import annotations

import re
import time
import logging
from dataclasses import asdict, replace
from typing import Any

from .config import Settings
from .domain import MailRecord, SearchQuery

PRESETS = {
    "invoice_phishing": "Invoice-related mail for manual phishing review",
    "spf_failure_claim": "Mail claiming SPF fail or softfail (unverified header)",
    "double_extension_attachment": "Attachment names ending in document-plus-executable suffixes",
}
_DOCUMENT_SUFFIXES = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png", "zip"}
_DANGEROUS_SUFFIXES = {"exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "com", "hta", "lnk"}
_INVOICE = re.compile(r"invoice|billing|payment|发票|账单|付款", re.IGNORECASE)
_SPF_FAILURE = re.compile(r"\b(?:softfail|fail)\b", re.IGNORECASE)
_LOG = logging.getLogger(__name__)
_MAX_ANALYSES = 10
_TIME_BUDGET_SECONDS = 30.0


def candidate_query(preset: str, limit: int) -> SearchQuery:
    if preset not in PRESETS:
        raise ValueError("unknown SOP preset")
    if not 1 <= limit <= 200:
        raise ValueError("candidate_limit must be 1..200")
    return SearchQuery(has_attachment=True if preset == "double_extension_attachment" else None,
                       limit=limit)


def matches(preset: str, record: MailRecord) -> bool:
    if preset == "invoice_phishing":
        return bool(_INVOICE.search(record.subject) or _INVOICE.search(record.body_text[:1000]))
    if preset == "spf_failure_claim":
        # Received-SPF is a sender-supplied claim, never a verified SPF result.
        return bool(_SPF_FAILURE.search(record.claimed_spf))
    if preset == "double_extension_attachment":
        for item in record.attachments:
            suffixes = item.name.lower().rsplit("/", 1)[-1].split(".")
            if len(suffixes) >= 3 and suffixes[-2] in _DOCUMENT_SUFFIXES and suffixes[-1] in _DANGEROUS_SUFFIXES:
                return True
        return False
    raise ValueError("unknown SOP preset")


def run_sop(
    preset: str,
    repository: Any,
    settings: Settings,
    *,
    candidate_limit: int = 100,
    analyze: bool = False,
    max_model_calls: int = 0,
    rows: list[MailRecord] | None = None,
    started_at: float | None = None,
) -> dict[str, Any]:
    """Search a bounded recent window; analysis is opt-in and persisted per mail."""
    query = candidate_query(preset, candidate_limit)
    if max_model_calls < 0 or max_model_calls > settings.max_llm_calls_per_run:
        raise ValueError("model call budget exceeds configured maximum")
    if rows is None:
        rows = repository.search_candidates(query)
    deadline = (started_at if started_at is not None else time.monotonic()) + _TIME_BUDGET_SECONDS
    candidates = [row for row in rows if matches(preset, row)]
    items: list[dict[str, Any]] = []
    failures = 0
    analyses = 0
    model_calls = 0
    incomplete_reasons: set[str] = set()
    from .analysis import analyze_mail
    from .evidence import read_evidence

    for record in candidates:
        item: dict[str, Any] = {"mail_id": record.mail_id, "subject": record.subject,
                                "sender": record.sender, "analysis_status": "not_requested"}
        if analyze:
            if analyses >= _MAX_ANALYSES:
                item["analysis_status"] = "analysis_limit"
                incomplete_reasons.add("analysis_limit")
                failures += 1
            elif time.monotonic() >= deadline:
                item["analysis_status"] = "time_budget_exhausted"
                incomplete_reasons.add("time_budget_exhausted")
                failures += 1
            else:
                analyses += 1
                use_model = (bool(settings.llm_api_key) and settings.llm_external_authorized
                             and model_calls < max_model_calls)
                if use_model:
                    model_calls += 1
                remaining = max(0.1, deadline - time.monotonic())
                effective = replace(
                    settings,
                    llm_api_key=settings.llm_api_key if use_model else "",
                    parse_timeout_seconds=min(settings.parse_timeout_seconds, remaining / 3),
                    llm_timeout_seconds=min(settings.llm_timeout_seconds, remaining / 3),
                )
                try:
                    full_record = repository.get_mail(record.mail_id)
                    if full_record is None:
                        raise LookupError("SOP candidate no longer exists")
                    raw = read_evidence(full_record, settings)
                    result = asdict(analyze_mail(full_record, raw, effective))
                    # An unavailable scanner/model is not equivalent to a clean verdict.
                    item["analysis_status"] = (
                        "complete" if all(result[engine]["status"] == "ok"
                                          for engine in ("rspamd", "clamav", "model")) else "partial"
                    )
                    item["analysis"] = result
                    if time.monotonic() >= deadline:
                        item["analysis_status"] = "time_budget_exhausted"
                        incomplete_reasons.add("time_budget_exhausted")
                    else:
                        repository.save_analysis(record.mail_id, {"sop": preset, **result})
                    if item["analysis_status"] != "complete":
                        failures += 1
                except Exception as exc:
                    _LOG.warning("sop_analysis_failed category=%s", type(exc).__name__)
                    item["analysis_status"] = "failed"
                    item["error"] = "analysis or persistence unavailable"
                    failures += 1
        items.append(item)
    if len(rows) >= candidate_limit:
        incomplete_reasons.add("candidate_window_truncated")
    return {
        "preset": preset,
        "scan_scope": "bounded_recent_window",
        "window_count": len(rows),
        "candidate_count": len(candidates),
        "window_may_be_truncated": len(rows) >= candidate_limit,
        "analysis_attempted": analyses,
        "analysis_limit": _MAX_ANALYSES,
        "time_budget_seconds": _TIME_BUDGET_SECONDS,
        "model_calls_attempted": model_calls,
        "model_call_budget": max_model_calls if analyze else 0,
        "incomplete": bool(failures or incomplete_reasons),
        "incomplete_reasons": sorted(incomplete_reasons),
        "status": "partial" if failures or incomplete_reasons else "complete",
        "failure_count": failures,
        "items": items,
    }
