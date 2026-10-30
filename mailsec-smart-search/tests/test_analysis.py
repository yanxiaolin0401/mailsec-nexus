from dataclasses import asdict

from mailsec_smart_search.analysis import fuse_results
from mailsec_smart_search.detection import DetectionResult
from mailsec_smart_search.llm import ModelResult


def test_signature_forces_malicious_and_conflict_review():
    result = fuse_results(DetectionResult("rspamd", "ok", "clean"),
                          DetectionResult("clamav", "ok", "malicious", signals=("Eicar-Test-Signature",)),
                          ModelResult("openai", "ok", "clean"))
    assert result.risk == "malicious" and result.review_required
    assert asdict(result)["clamav"]["signals"] == ("Eicar-Test-Signature",)


def test_unavailable_never_becomes_clean():
    result = fuse_results(DetectionResult("rspamd", "unavailable"),
                          DetectionResult("clamav", "timeout"),
                          ModelResult("unconfigured", "unavailable"))
    assert result.risk is None and result.review_required


def test_model_only_malicious_is_not_automatic_malicious():
    result = fuse_results(DetectionResult("rspamd", "unavailable"),
                          DetectionResult("clamav", "invalid", error="size limit"),
                          ModelResult("openai", "ok", "malicious"))
    assert result.risk == "suspicious" and result.review_required


def test_all_independent_clean_needed_for_clean():
    result = fuse_results(DetectionResult("rspamd", "ok", "clean"),
                          DetectionResult("clamav", "ok", "clean"),
                          ModelResult("unconfigured", "unavailable"))
    assert result.risk is None and result.review_required


def test_incomplete_parsed_evidence_requires_review(monkeypatch):
    from datetime import datetime, timezone
    from mailsec_smart_search import analysis
    from mailsec_smart_search.config import Settings
    from mailsec_smart_search.domain import MailRecord
    from mailsec_smart_search.detection import DetectionResult
    from mailsec_smart_search.llm import ModelResult
    monkeypatch.setattr(analysis, 'scan_rspamd', lambda *a: DetectionResult('rspamd', 'ok', 'clean'))
    monkeypatch.setattr(analysis, 'scan_clamd', lambda *a: DetectionResult('clamav', 'ok', 'clean'))
    monkeypatch.setattr(analysis, 'analyze_with_llm', lambda *a: ModelResult('test', 'ok', 'clean'))
    record = MailRecord('id','hash','path','test',datetime.now(timezone.utc), truncated=True)
    result = analysis.analyze_mail(record,b'raw',Settings())
    assert result.risk is None and result.review_required
    assert 'incomplete' in result.reasons[-1]
