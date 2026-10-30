from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import time

from fastapi.testclient import TestClient

from mailsec_smart_search.api import create_app
from mailsec_smart_search.config import Settings
from mailsec_smart_search.domain import AttachmentInfo, MailRecord
from mailsec_smart_search.sop import candidate_query, matches, run_sop


class FakeRepository:
    database = "mailsec"

    def __init__(self, records):
        self.records = records
        self.saved = []
        self.hydrated = []

    def search_candidates(self, query):
        return self.records[:query.limit]

    def get_mail(self, mail_id):
        self.hydrated.append(mail_id)
        return next((row for row in self.records if row.mail_id == mail_id), None)

    def save_analysis(self, mail_id, analysis):
        self.saved.append((mail_id, analysis))
        return "event"


def record(name, tmp_path, *, subject="", spf="", attachment=""):
    path = tmp_path / f"{name}.eml"
    raw = b"Subject: test\r\n\r\nbody"
    path.write_bytes(raw)
    attachments = [AttachmentInfo(attachment, "application/octet-stream", 1, "hash")] if attachment else []
    return MailRecord(name, hashlib.sha256(raw).hexdigest(), str(path), "test", datetime.now(timezone.utc),
                      subject=subject, claimed_spf=spf, attachments=attachments)


def test_three_presets_match_bounded_window(tmp_path):
    invoice = record("invoice", tmp_path, subject="Invoice payment required")
    spf = record("spf", tmp_path, spf="fail (domain example.org)")
    double = record("double", tmp_path, attachment="report.pdf.exe")
    assert matches("invoice_phishing", invoice)
    assert matches("spf_failure_claim", spf)
    assert matches("double_extension_attachment", double)
    assert not matches("double_extension_attachment", invoice)
    assert candidate_query("double_extension_attachment", 200).has_attachment
    repo = FakeRepository([invoice, spf, double])
    result = run_sop("invoice_phishing", repo, Settings(), candidate_limit=3)
    assert result["window_count"] == 3
    assert result["candidate_count"] == 1
    assert result["window_may_be_truncated"] is True
    assert result["model_calls_attempted"] == 0 and not repo.saved


def test_api_preview_unknown_budget_and_partial_analysis(tmp_path, monkeypatch):
    invoice = record("invoice", tmp_path, subject="Invoice")
    repo = FakeRepository([invoice])
    settings = replace(Settings(), data_dir=tmp_path, api_token="secret")
    client = TestClient(create_app(settings, repository=repo))
    headers = {"x-mailsec-token": "secret"}
    assert client.get("/v1/sop", headers=headers).status_code == 200
    assert client.post("/v1/sop/unknown", json={}, headers=headers).status_code == 404
    assert client.post("/v1/sop/invoice_phishing", json={"candidate_limit": 201}, headers=headers).status_code == 422
    assert client.post("/v1/sop/invoice_phishing", json={"max_model_calls": 11}, headers=headers).status_code == 422
    preview = client.post("/v1/sop/invoice_phishing", json={}, headers=headers)
    assert preview.status_code == 200 and preview.json()["items"][0]["analysis_status"] == "not_requested"
    assert not repo.saved

    def unavailable(*args):
        from mailsec_smart_search.analysis import AnalysisResult
        from mailsec_smart_search.detection import DetectionResult
        from mailsec_smart_search.llm import ModelResult
        return AnalysisResult(None, True, ("unavailable",),
                              DetectionResult("rspamd", "unavailable"),
                              DetectionResult("clamav", "unavailable"),
                              ModelResult("unconfigured", "unavailable"))

    monkeypatch.setattr("mailsec_smart_search.analysis.analyze_mail", unavailable)
    analyzed = client.post("/v1/sop/invoice_phishing", json={"analyze": True, "max_model_calls": 1}, headers=headers)
    assert analyzed.status_code == 200
    assert analyzed.json()["status"] == "partial"
    assert analyzed.json()["items"][0]["analysis_status"] == "partial"
    assert len(repo.saved) == 1
    assert repo.hydrated == ["invoice"]


def test_local_scans_independent_of_model_budget_and_limited_to_ten(tmp_path, monkeypatch):
    rows = [record(f"r{i}", tmp_path, subject="Invoice") for i in range(12)]
    repo = FakeRepository(rows)
    settings = replace(Settings(), data_dir=tmp_path)
    seen = []

    def fake_analysis(mail, raw, effective):
        from mailsec_smart_search.analysis import AnalysisResult
        from mailsec_smart_search.detection import DetectionResult
        from mailsec_smart_search.llm import ModelResult
        seen.append((mail.mail_id, effective.llm_api_key))
        return AnalysisResult(None, True, ("model unavailable",),
                              DetectionResult("rspamd", "ok", "clean"),
                              DetectionResult("clamav", "ok", "clean"),
                              ModelResult("unconfigured", "unavailable"))

    monkeypatch.setattr("mailsec_smart_search.analysis.analyze_mail", fake_analysis)
    result = run_sop("invoice_phishing", repo, settings, rows=rows, candidate_limit=20,
                     analyze=True, max_model_calls=0)
    assert len(seen) == len(repo.saved) == result["analysis_attempted"] == 10
    assert result["model_calls_attempted"] == 0
    assert result["incomplete"] and "analysis_limit" in result["incomplete_reasons"]
    assert [item["analysis_status"] for item in result["items"][10:]] == ["analysis_limit"] * 2
    assert len(repo.hydrated) == 10


def test_sop_time_budget_reports_incomplete_without_scanning(tmp_path, monkeypatch):
    row = record("invoice", tmp_path, subject="Invoice")
    repo = FakeRepository([row])
    monkeypatch.setattr("mailsec_smart_search.analysis.analyze_mail", lambda *args: 1 / 0)
    result = run_sop("invoice_phishing", repo, replace(Settings(), data_dir=tmp_path),
                     rows=[row], candidate_limit=10, analyze=True,
                     started_at=time.monotonic() - 31)
    assert result["analysis_attempted"] == 0
    assert result["items"][0]["analysis_status"] == "time_budget_exhausted"
    assert result["incomplete"] and "time_budget_exhausted" in result["incomplete_reasons"]
