from dataclasses import replace
from datetime import datetime, timezone
import asyncio
import hashlib
import logging

from fastapi.testclient import TestClient

from mailsec_smart_search.api import _RequestGuard, create_app
from mailsec_smart_search.config import Settings
from mailsec_smart_search.domain import MailRecord
from mailsec_smart_search.spool import DurableSpool


class FakeRepository:
    database = "mailsec"

    def __init__(self, record=None):
        self.record = record
        self.queries = []
        self.fail = False
        self.saved = []

    def ping(self):
        return True

    def search(self, query):
        self.queries.append(query)
        return [self.record] if self.record else []

    def search_candidates(self, query):
        self.queries.append(query)
        return [self.record] if self.record else []

    def search_summaries(self, query):
        self.queries.append(query)
        if not self.record:
            return []
        from mailsec_smart_search.api import mail_summary
        return [mail_summary(self.record)]

    def stats(self, query):
        self.queries.append(query)
        return {"total": 1}

    def get_mail(self, mail_id):
        if self.fail:
            raise RuntimeError("storage offline")
        return self.record if self.record and self.record.mail_id == mail_id else None

    def get_analyses(self, mail_id):
        if self.fail:
            raise RuntimeError("storage offline")
        return self.saved

    def save_analysis(self, mail_id, value):
        self.saved.append(value)
        return "event"


def make_client(tmp_path, *, max_bytes=1024, token="secret", record=None):
    settings = replace(Settings(), data_dir=tmp_path, max_message_bytes=max_bytes,
                       api_token=token)
    repo = FakeRepository(record)
    return TestClient(create_app(settings, spool=DurableSpool(settings), repository=repo)), repo


def test_raw_upload_auth_dedup_job_and_limits(tmp_path):
    client, _ = make_client(tmp_path, max_bytes=100)
    headers = {"x-mailsec-token": "secret"}
    raw = b"Subject: hi\r\n\r\nhello"
    assert client.post("/v1/mail/raw", content=raw, headers={"content-type": "message/rfc822"}).status_code == 401
    first = client.post("/v1/mail/raw", content=raw, headers={**headers, "content-type": "message/rfc822"})
    assert first.status_code == 202
    second = client.post("/v1/mail/upload", files={"file": ("a.eml", raw, "message/rfc822")}, headers=headers)
    assert second.status_code == 202
    assert first.json()["mail_id"] == second.json()["mail_id"]
    job_id = first.json()["job_id"]
    job = client.get(f"/v1/jobs/{job_id}", headers=headers)
    assert job.status_code == 200 and "raw_path" not in job.json()
    assert client.get("/v1/jobs/unknown", headers=headers).status_code == 404
    assert client.post("/v1/mail/raw", content=b"x" * 101,
                       headers={**headers, "content-type": "message/rfc822"}).status_code == 413
    assert client.post("/v1/mail/raw", content=iter([b"x" * 60, b"x" * 41]),
                       headers={**headers, "content-type": "message/rfc822",
                                "transfer-encoding": "chunked"}).status_code == 413
    assert client.post("/v1/mail/upload", files={"file": ("a.eml", b"x" * 101, "message/rfc822")},
                       headers=headers).status_code == 413
    assert client.post("/v1/mail/upload", content=b"x" * (100 + 65537),
                       headers={**headers, "content-type": "multipart/form-data; boundary=x"}).status_code == 413


def test_search_validation_and_model_unavailability_do_not_break_search(tmp_path):
    record = MailRecord("id", "hash", "/tmp/none", "test", datetime.now(timezone.utc),
                        subject="Invoice", body_text="x" * 500, headers=[("X-Secret", "private")])
    client, repo = make_client(tmp_path, record=record)
    headers = {"x-mailsec-token": "secret"}
    invalid = client.post("/v1/search", json={"sql": "DROP TABLE mail"}, headers=headers)
    assert invalid.status_code == 422 and not repo.queries
    okay = client.post("/v1/search", json={"subject_contains": "Invoice"}, headers=headers)
    assert okay.status_code == 200 and okay.json()["count"] == 1
    assert "raw_path" not in okay.json()["items"][0]
    assert "headers" not in okay.json()["items"][0]
    assert "body_text" not in okay.json()["items"][0]
    assert len(okay.json()["items"][0]["body_preview"]) == 200
    assert okay.json()["may_have_more"] is False
    detail = client.get("/v1/mail/id", headers=headers)
    assert detail.status_code == 200 and len(detail.json()["body_text"]) == 500
    model = client.post("/v1/nl/query", json={"text": "show invoices"}, headers=headers)
    assert model.status_code == 503
    assert client.post("/v1/search", json={}, headers=headers).status_code == 200


def test_get_detail_errors_and_model_extra_fields(tmp_path, monkeypatch):
    record = MailRecord("id", "hash", "/tmp/none", "test", datetime.now(timezone.utc))
    client, repo = make_client(tmp_path, record=record)
    headers = {"x-mailsec-token": "secret"}
    assert client.get("/v1/mail/missing", headers=headers).status_code == 404
    repo.fail = True
    assert client.get("/v1/mail/id", headers=headers).status_code == 503
    assert client.get("/v1/mail/id/analyses", headers=headers).status_code == 503
    repo.fail = False
    monkeypatch.setattr("mailsec_smart_search.llm.request_json",
                        lambda *args: {"tool": "search", "filters": {}, "sql": "SELECT *"})
    response = client.post("/v1/nl/query", json={"text": "anything", "execute": False}, headers=headers)
    assert response.status_code == 422


def test_outer_guard_authenticates_before_parsing_and_bounds_all_json(tmp_path):
    client, repo = make_client(tmp_path, max_bytes=100)
    malformed = b"{" + b"x" * 70000
    assert client.post("/v1/search", content=malformed, headers={"content-type": "application/json"}).status_code == 401
    assert client.post("/v1/search", content=malformed,
                       headers={"content-type": "application/json", "x-mailsec-token": "secret"}).status_code == 413
    assert client.post("/v1/search", content=iter([b"x" * 40000, b"x" * 30000]),
                       headers={"content-type": "application/json", "x-mailsec-token": "secret",
                                "transfer-encoding": "chunked"}).status_code == 413
    assert not repo.queries
    no_auth_client, _ = make_client(tmp_path / "noauth", token="")
    assert no_auth_client.post("/v1/search", json={}).status_code == 503


def test_nl_sensitive_text_rejected_without_model_call(tmp_path, monkeypatch):
    client, repo = make_client(tmp_path)
    calls = []
    monkeypatch.setattr("mailsec_smart_search.llm.request_json", lambda *args: calls.append(args))
    response = client.post("/v1/nl/query", json={"text": "find +1 (415) 555-0101 messages"},
                           headers={"x-mailsec-token": "secret"})
    assert response.status_code == 422
    assert "structured" in response.json()["detail"]
    assert not calls and not repo.queries


def test_legacy_nl_masks_private_email_and_previews_before_execution(tmp_path, monkeypatch):
    client, repo = make_client(tmp_path)
    seen = []

    def model(system, text, settings):
        seen.append((system, text))
        return {"tool": "search", "filters": {"sender": "MAILSEC_EMAIL_0"}}

    monkeypatch.setattr("mailsec_smart_search.llm.request_json", model)
    payload = {"text": "find mail from alice@example.org"}
    preview = client.post("/v1/nl/query", json=payload,
                          headers={"x-mailsec-token": "secret"})
    assert preview.status_code == 200, preview.text
    assert preview.json()["executed"] is False and not repo.queries
    assert preview.json()["plan"]["filters"]["sender"] == "alice@example.org"
    assert all("alice@example.org" not in text for _, text in seen)
    assert "timezone=Asia/Shanghai" in seen[0][0]
    assert "minus 1 millisecond" in seen[0][0]
    executed = client.post("/v1/nl/query", json={**payload, "execute": True},
                           headers={"x-mailsec-token": "secret"})
    assert executed.status_code == 200, executed.text
    assert executed.json()["executed"] is True
    assert repo.queries[-1].sender == "alice@example.org"


def test_legacy_nl_rejects_omitted_private_filters_and_invalid_time(tmp_path, monkeypatch):
    client, repo = make_client(tmp_path)
    headers = {"x-mailsec-token": "secret"}
    for text, plan in [
        ("from alice@example.org", {"tool": "search", "filters": {}}),
        ("from alice@example.org", {"tool": "search", "filters": {"sender": "MAILSEC_EMAIL_99"}}),
        ("last week", {"tool": "search", "filters": {"from_time": "2026-10-01"}}),
        ("last week", {"tool": "search", "filters": {"from_time": "2026-10-10T00:00:00Z", "to_time": "2026-10-01T00:00:00Z"}}),
    ]:
        monkeypatch.setattr("mailsec_smart_search.llm.request_json", lambda *args, plan=plan: plan)
        response = client.post("/v1/nl/query", json={"text": text, "execute": True}, headers=headers)
        assert response.status_code == 422, response.text
    assert not repo.queries


def test_nl_tool_audit_records_hash_not_plaintext(tmp_path, monkeypatch, caplog):
    client, _ = make_client(tmp_path)
    monkeypatch.setattr("mailsec_smart_search.llm.request_json",
                        lambda *args: {"tool": "stats", "filters": {}})
    caplog.set_level(logging.INFO, logger="mailsec_smart_search.api")
    prompt = "count messages safely"
    response = client.post("/v1/nl/query", json={"text": prompt, "execute": True},
                           headers={"x-mailsec-token": "secret"})
    assert response.status_code == 200
    audit = [record.message for record in caplog.records if record.message.startswith("nl_tool")]
    assert len(audit) == 1
    assert hashlib.sha256(prompt.encode()).hexdigest() in audit[0]
    assert "tool=stats executed=true status=ok" in audit[0]
    assert prompt not in audit[0]


def test_request_guard_times_out_slow_body_without_leaking_slot(monkeypatch):
    monkeypatch.setattr("mailsec_smart_search.api._BODY_READ_TIMEOUT_SECONDS", 0.01)
    reached_app = []
    sent = []

    async def app(*args):
        reached_app.append(True)

    async def slow_receive():
        await asyncio.sleep(0.1)
        return {"type": "http.request", "body": b"", "more_body": False}

    guard = _RequestGuard(app, max_message_bytes=100, api_token="secret")
    scope = {"type": "http", "path": "/v1/mail/raw",
             "headers": [(b"x-mailsec-token", b"secret")]}
    asyncio.run(guard(scope, slow_receive, lambda event: _append(sent, event)))
    assert sent[0]["status"] == 408
    assert not reached_app
    assert guard.slots._value == 8


async def _append(items, event):
    items.append(event)
