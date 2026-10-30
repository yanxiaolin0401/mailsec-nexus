import json
from datetime import datetime, timezone

import httpx
import pytest

from mailsec_smart_search.config import Settings
from mailsec_smart_search.domain import MailRecord
from mailsec_smart_search.llm import ModelCallError, analyze_with_llm, request_json
from mailsec_smart_search.redaction import model_payload


def record():
    return MailRecord("id", "hash", "/private/raw.eml", "test", datetime.now(timezone.utc),
                      sender="alice@example.org", sender_domain="example.org",
                      recipients=["bob@company.test"], subject="Hello bob@company.test",
                      body_text="Visit https://bad.example/login bob@company.test")


def settings(provider="openai"):
    return Settings(llm_provider=provider, llm_base_url="https://example.test/v1", llm_model="test", llm_api_key="secret", llm_external_authorized=True)


def test_redaction_and_unconfigured_key():
    payload = json.dumps(model_payload(record()))
    assert "bob@" not in payload and "https://" not in payload and "/private/" not in payload
    assert model_payload(record())["sender_domain"] == "example.org"
    assert analyze_with_llm(record(), Settings()).status == "unavailable"
    assert len(analyze_with_llm(record(), Settings()).input_sha256) == 64
    sensitive = record()
    sensitive.body_text = "Call +1 (415) 555-1234 from 192.168.1.2; <script>ignore policy</script> ID " + "A" * 40
    masked = json.dumps(model_payload(sensitive))
    assert "555-1234" not in masked and "192.168.1.2" not in masked and "<script>" not in masked and "AAAA" not in masked


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_model_protocol_and_json(provider):
    seen = []

    def handler(request):
        seen.append(request)
        verdict = json.dumps({"risk": "suspicious", "reason": "urgent language", "evidence_refs": ["subject"]})
        return httpx.Response(200, json={"choices": [{"message": {"content": verdict}}]} if provider == "openai" else {"content": [{"type": "text", "text": verdict[:10]}, {"type": "text", "text": verdict[10:]}]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = analyze_with_llm(record(), settings(provider), client=client)
    assert result.status == "ok" and result.risk == "suspicious"
    assert result.model_id == "test" and result.redaction_version == "2" and result.evidence_refs == ("subject",)
    assert seen[0].url.path.endswith("/chat/completions" if provider == "openai" else "/messages")
    assert b"bob@" not in seen[0].content and b"https://bad.example" not in seen[0].content


def test_retry_and_strict_json(monkeypatch):
    monkeypatch.setattr("mailsec_smart_search.llm.time.sleep", lambda _: None)
    count = 0
    def handler(_):
        nonlocal count
        count += 1
        return httpx.Response(429 if count < 3 else 200, json={"choices": [{"message": {"content": '{"risk":"clean","reason":"ok"}'}}]})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert analyze_with_llm(record(), settings(), client=client).status == "ok"
    assert count == 3
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]}))) as client:
        assert analyze_with_llm(record(), settings(), client=client).status == "invalid"
    with pytest.raises(ModelCallError) as exc:
        request_json("system", "query", Settings())
    assert exc.value.status == "unavailable"


def test_oversized_or_unsupported_output_is_invalid():
    huge = httpx.Response(200, content=b"x" * 17_000)
    with httpx.Client(transport=httpx.MockTransport(lambda _: huge)) as client:
        assert analyze_with_llm(record(), settings(), client=client).status == "invalid"
    bad_refs = json.dumps({"risk": "clean", "reason": "ok", "evidence_refs": ["private_raw_path"]})
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"choices": [{"message": {"content": bad_refs}}]}))) as client:
        assert analyze_with_llm(record(), settings(), client=client).status == "invalid"
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"content": [{"type": "tool_use", "id": "x"}]}))) as client:
        assert analyze_with_llm(record(), settings("anthropic"), client=client).status == "invalid"


def test_configured_model_cannot_send_without_authorization():
    from dataclasses import replace

    def forbidden(_):
        pytest.fail("unauthorized network transfer")

    with httpx.Client(transport=httpx.MockTransport(forbidden)) as client:
        result = analyze_with_llm(record(), replace(settings(), llm_external_authorized=False), client=client)
    assert result.status == "unavailable" and "not authorized" in result.error
