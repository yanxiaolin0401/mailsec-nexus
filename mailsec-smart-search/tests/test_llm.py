import json
from datetime import UTC, datetime

import httpx
import pytest

from mailsec_smart_search.config import Settings
from mailsec_smart_search.domain import MailRecord
from mailsec_smart_search.llm import ModelCallError, analyze_with_llm, request_json
from mailsec_smart_search.redaction import model_payload


def record():
    return MailRecord("id", "hash", "/private/raw.eml", "test", datetime.now(UTC),
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


def test_deepseek_bounded_json_mode_and_private_usage_log(caplog):
    from dataclasses import replace

    seen = []

    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={
            "choices": [{"finish_reason": "stop", "message": {"content": '{"ok":true}'}}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16,
                      "private": "do-not-log", "input_tokens": "not-a-count"},
        })

    configured = replace(settings(), llm_base_url="https://api.deepseek.com",
                         llm_model="deepseek-flash", llm_max_output_tokens=512)
    with (caplog.at_level("INFO", logger="mailsec_smart_search.llm"),
          httpx.Client(transport=httpx.MockTransport(handler)) as client):
        assert request_json("JSON only", "private query", configured, client=client) == {"ok": True}
    assert seen[0]["thinking"] == {"type": "disabled"}
    assert seen[0]["response_format"] == {"type": "json_object"}
    assert seen[0]["max_tokens"] == 512
    assert '"total_tokens": 16' in caplog.text
    assert not any(value in caplog.text for value in ("do-not-log", "private query", "secret", "not-a-count"))


def test_deepseek_options_not_sent_to_other_providers():
    def handler(request):
        body = json.loads(request.content)
        assert "thinking" not in body and "response_format" not in body
        assert body["max_tokens"] == 1024
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        assert request_json("system", "query", settings(), client=client) == {}


@pytest.mark.parametrize("provider,response", [
    ("openai", {"choices": [{"finish_reason": "length", "message": {"content": "{}"}}]}),
    ("anthropic", {"stop_reason": "max_tokens", "content": [{"type": "text", "text": "{}"}]}),
    ("openai", []),
])
def test_incomplete_or_nonobject_response_rejected(provider, response):
    with (httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response))) as client,
          pytest.raises(ModelCallError) as exc):
        request_json("system", "query", settings(provider), client=client)
    assert exc.value.status == "invalid"


def test_output_token_config_bounds_and_env(monkeypatch):
    for value in (0, 63, 4097):
        with pytest.raises(ValueError, match="token limit"):
            Settings(llm_max_output_tokens=value)
    monkeypatch.setenv("MAILSEC_LLM_MAX_OUTPUT_TOKENS", "512")
    assert Settings.from_env().llm_max_output_tokens == 512
