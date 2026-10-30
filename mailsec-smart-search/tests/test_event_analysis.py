import json

import pytest

from mailsec_smart_search.config import Settings
from mailsec_smart_search.event_analysis import analyze_event


def _settings(**overrides):
    values = dict(llm_provider="openai", llm_base_url="https://example.test/v1",
                  llm_model="test", llm_api_key="secret", llm_external_authorized=True)
    values.update(overrides)
    return Settings(**values)


def _event():
    return {
        "event_id": "event-1", "sender_account": "sender@example.org",
        "receiver_accounts": ["private-recipient@example.net"],
        "subject": "Urgent private-recipient@example.net",
        "text_content": "Visit https://private.example/path private-recipient@example.net",
        "external_attachments": [{"filename": "secret-finances.pdf", "md5": "a" * 32}],
        "external_urls": ["https://private.example/path"],
        "mail_headers": "Authentication-Results: mx; spf=pass\nX-Secret: header-private-value",
        "raw_json": '{"secret":"raw-private-value"}',
    }


@pytest.mark.parametrize("verdict,level", [("clean", "low"), ("suspicious", "medium"), ("malicious", "high")])
def test_success_mapping_and_private_payload(monkeypatch, verdict, level):
    captured = []

    def fake_request(system, user, settings, *, client=None):
        captured.append(json.loads(user))
        return {"risk": verdict, "reason": "raw-private-value secret-finances.pdf header-private-value",
                "evidence_refs": ["subject", "attachment_count"]}

    monkeypatch.setattr("mailsec_smart_search.llm.request_json", fake_request)
    result = analyze_event(_event(), _settings())
    assert result["event_id"] == "event-1"
    assert result["status"] == "ok" and result["risk_level"] == level
    assert result["model"]["risk"] == verdict
    assert result["evidence_refs"] == ["subject", "attachment_count"]
    assert captured[0]["sender_domain"] == "example.org"
    assert captured[0]["attachment_count"] == captured[0]["url_count"] == 1
    assert captured[0]["claimed_spf"] == ""
    assert not any(token in json.dumps(captured[0]) + json.dumps(result) for token in
                   ("raw-private-value", "header-private-value", "private-recipient@example.net",
                    "secret-finances.pdf", "https://private.example/path", "spf=pass"))
    assert "attachment_content_unavailable_not_scanned" in result["limitations"]


def test_missing_key_or_authorization_is_partial_unknown():
    for settings in (_settings(llm_api_key=""), _settings(llm_external_authorized=False)):
        result = analyze_event(_event(), settings)
        assert result["status"] == "partial" and result["risk_level"] == "unknown"
        assert result["model"]["status"] == "unavailable"
        assert result["evidence_refs"] == []


def test_header_authentication_claim_not_promoted(monkeypatch):
    seen = []

    def fake_request(system, user, settings, *, client=None):
        seen.append(json.loads(user))
        return {"risk": "clean", "reason": "SPF passed"}

    monkeypatch.setattr("mailsec_smart_search.llm.request_json", fake_request)
    result = analyze_event(_event(), _settings())
    assert seen[0]["claimed_spf"] == ""
    assert result["status"] == "ok"
    assert "upstream_headers_and_authentication_claims_unverified" in result["limitations"]
