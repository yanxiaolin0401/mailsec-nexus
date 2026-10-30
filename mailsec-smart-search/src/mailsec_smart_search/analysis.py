"""Transparent fusion of independent scanner and model verdicts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

from .config import Settings
from .detection import DetectionResult, scan_clamd, scan_rspamd
from .domain import MailRecord
from .llm import ModelResult, analyze_with_llm


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    risk: Literal["clean", "suspicious", "malicious"] | None
    review_required: bool
    reasons: tuple[str, ...]
    rspamd: DetectionResult
    clamav: DetectionResult
    model: ModelResult


def fuse_results(rspamd: DetectionResult, clamav: DetectionResult, model: ModelResult) -> AnalysisResult:
    valid = [result for result in (rspamd, clamav, model) if result.status == "ok" and result.risk is not None]
    risks = {result.risk for result in valid}
    reasons: list[str] = []
    signature = clamav.status == "ok" and clamav.risk == "malicious" and bool(clamav.signals)
    if signature:
        risk = "malicious"
        reasons.append("malware signature detected")
    elif "malicious" in risks:
        risk = "suspicious"
        reasons.append("non-signature malicious indication requires review")
    elif "suspicious" in risks:
        risk = "suspicious"
    elif len(valid) == 3 and risks == {"clean"}:
        risk = "clean"
    else:
        risk = None
    failures = [result.engine if isinstance(result, DetectionResult) else "model" for result in (rspamd, clamav, model) if result.status != "ok"]
    if failures:
        reasons.append("unavailable or invalid: " + ", ".join(failures))
    conflict = "clean" in risks and ("malicious" in risks or "suspicious" in risks)
    if conflict:
        reasons.append("independent verdicts conflict")
    review = bool(conflict or failures or risk is None or risk == "suspicious")
    return AnalysisResult(risk, review, tuple(reasons), rspamd, clamav, model)


def analyze_mail(record: MailRecord, raw_eml: bytes, settings: Settings) -> AnalysisResult:
    """Scan raw EML locally, then send only allowlisted fields to configured model."""
    rspamd = scan_rspamd(raw_eml, settings)
    clamav = scan_clamd(raw_eml, settings)
    model = analyze_with_llm(record, settings)
    result = fuse_results(rspamd, clamav, model)
    if record.parse_status != "ok" or record.truncated:
        return replace(result, risk=None if result.risk == "clean" else result.risk,
                       review_required=True,
                       reasons=(*result.reasons, "parsed evidence incomplete; raw evidence retained"))
    return result
