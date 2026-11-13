"""Canonical v2 contracts; fixtures are inspected without printing message content."""

import hashlib
import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mailsec_smart_search.events import normalize_event

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)
DATASET = Path(__file__).parents[1] / "docs" / "统一输入流交付包" / "mail_offline_dataset_1000.jsonl"


def sample() -> dict:
    return {
        "sourceSystemId": "MAIL_OFFLINE", "sourceEventId": "source-1",
        "eventTime": "2026-11-01T23:55:25Z", "from": "sender@example.test",
        "to": ["recipient@example.test"], "subject": "-", "rawHeaders": "-",
    }


def test_flat_v2_identity_claims_defaults_and_audit():
    payload = sample()
    payload.update({"eventId": "d0c41219-3950-4e1b-8f2c-e0a850a82d2f",
                    "tenantId": "tenant_demo", "mailbox": "SPAM",
                    "cc": ["copy@example.test"], "senderIp": "10.0.0.2",
                    "bodyText": "searchable", "bodyHtml": "<p>html</p>",
                    "securityMeta": {"mailHash": "a" * 32, "riskVerdict": "pass"},
                    "senderaccount": "ignored@example.test", "textContent": "legacy ignored",
                    "unknownExtension": {"field": "audit only"}})
    row = normalize_event(payload, now=NOW, canonical=True, ingress_ip="192.0.2.5")
    assert len(row) == 39
    assert row["event_id"] == payload["eventId"]
    assert row["sender_account"] == payload["from"]
    assert row["receiver_accounts"] == [*payload["to"], *payload["cc"]]
    assert row["tenant_id"] == "tenant_demo" and row["mailbox"] == "SPAM"
    assert row["cc_accounts"] == payload["cc"] and row["body_html"] == payload["bodyHtml"]
    assert row["text_content"] == "searchable"
    assert row["sender_ip"] == "10.0.0.2"
    assert "sender_ip_declared_upstream" in row["data_quality_tags"]
    assert row["risk_level"] == "unknown" and row["risk_verdict"] == "unknown"
    assert row["mail_hash"] == "a" * 32
    assert json.loads(row["security_meta_json"]) == payload["securityMeta"]
    assert json.loads(row["raw_json"]) == payload
    assert row["payload_hash"] == hashlib.sha256(row["raw_json"].encode()).hexdigest()
    assert "ignored@example.test" not in str({k: v for k, v in row.items() if k != "raw_json"})


def test_v2_auto_detection_and_stable_generated_uuid5():
    payload = sample()
    first = normalize_event(payload, now=NOW)
    second = normalize_event(payload, now=NOW, canonical=True)
    assert first["event_id"] == second["event_id"]
    assert uuid.UUID(first["event_id"]).version == 5
    assert first["tenant_id"] == "tenant_default"
    assert first["mailbox"] == "INBOX" and first["cc_accounts"] == []
    assert first["body_html"] == "-" and first["security_meta_json"] == "{}"
    assert first["sender_ip"] == "unknown"
    assert normalize_event({**payload, "sourceEventId": "source-2"}, now=NOW)["event_id"] != first["event_id"]


def test_v2_accepts_iso8601_utc_microseconds_and_marks_actual_precision_loss():
    payload = {**sample(), "eventTime": "2026-11-01T23:55:25.123456+00:00"}
    row = normalize_event(payload, now=NOW)
    assert row["event_time"] == "2026-11-01T23:55:25.123000+00:00"
    assert "event_time_precision_truncated" in row["data_quality_tags"]
    assert json.loads(row["raw_json"])["eventTime"] == payload["eventTime"]
    assert row["payload_hash"] == hashlib.sha256(row["raw_json"].encode()).hexdigest()
    exact = normalize_event({**sample(), "eventTime": "2026-11-01T23:55:25.123000Z"}, now=NOW)
    assert exact["event_time"] == row["event_time"]
    assert "event_time_precision_truncated" not in exact["data_quality_tags"]


@pytest.mark.parametrize("key,bad", [
    ("sourceSystemId", None), ("sourceEventId", ""),
    ("eventId", "not-a-uuid"), ("eventTime", "2026-11-01T23:55:25+08:00"),
    ("eventTime", "0102-01-01T00:00:00Z"), ("from", "-"),
    ("to", []), ("to", "recipient@example.test"),
    ("to", ["bad"]), ("subject", ""), ("rawHeaders", None),
    ("cc", "[]"), ("bodyText", None), ("bodyHtml", None),
    ("senderIp", "not-an-ip"), ("attachments", None),
    ("urls", [123]), ("securityMeta", None),
])
def test_v2_rejects_invalid_known_fields(key, bad):
    with pytest.raises(ValueError):
        normalize_event({**sample(), key: bad}, now=NOW, canonical=True)


def test_v2_requires_core_fields_and_ignores_unknown_extensions():
    for key in ("sourceSystemId", "sourceEventId", "eventTime", "from", "to", "subject", "rawHeaders"):
        payload = sample()
        del payload[key]
        with pytest.raises(ValueError):
            normalize_event(payload, now=NOW, canonical=True)
    row = normalize_event({**sample(), "arbitraryFutureObject": {"raw": None}}, now=NOW)
    assert "arbitraryFutureObject" in row["raw_json"]
    assert all("arbitraryFutureObject" not in str(v) for k, v in row.items() if k != "raw_json")


def test_v2_rejects_multiple_senders_and_bounds_recipient_count_without_truncation():
    with pytest.raises(ValueError, match="invalid from address"):
        normalize_event({**sample(), "from": "A <a@example.test>, B <b@example.test>"}, now=NOW)
    recipients = [f"user{n}@example.test" for n in range(1832)]
    row = normalize_event({**sample(), "to": recipients}, now=NOW)
    assert len(row["receiver_accounts"]) == 1832
    with pytest.raises(ValueError, match="too many recipients"):
        normalize_event({**sample(), "to": recipients + [f"user{n}@example.test" for n in range(1832, 10001)]}, now=NOW)


def test_v2_enforces_header_body_attachment_and_unique_url_caps():
    payload = sample()
    payload["rawHeaders"] = "\n".join(["Received: hop"] * 66 + ["X-Large: " + "x" * 1000] + ["X-Other: v"] * 450)
    payload["bodyText"] = "x" * 200001
    payload["attachments"] = [{"filename": "f", "md5": "a" * 32, "size": 0}] * 101
    payload["urls"] = [f"https://example.test/{n}" for n in range(1001)]
    row = normalize_event(payload, now=NOW, canonical=True)
    assert len(row["mail_headers"]) <= 65536
    assert all(len(line) <= 998 for line in row["mail_headers"].splitlines())
    assert row["mail_headers"].count("Received:") == 64
    assert len(row["text_content"]) == 200000
    assert len(row["external_attachments"]) == 100
    assert len(row["external_urls"]) == len(set(row["external_urls"])) == 1000
    assert {"header_line_too_long", "header_block_truncated", "received_hops_truncated",
            "body_truncated", "attachments_truncated", "urls_truncated"} <= set(row["data_quality_tags"])
    large_headers = "\n".join(["X-Large: " + "x" * 500] * 512)
    large = normalize_event({**sample(), "rawHeaders": large_headers}, now=NOW, canonical=True)
    assert len(large["mail_headers"]) == 65536
    assert "headers_truncated" in large["data_quality_tags"]
    duplicates = normalize_event({**sample(), "urls": ["https://example.test/one"] * 1001 +
                                  ["https://example.test/two"]}, now=NOW, canonical=True)
    assert duplicates["external_urls"] == ["https://example.test/one", "https://example.test/two"]
    assert "urls_truncated" not in duplicates["data_quality_tags"]
    audit = json.loads(row["raw_json"])
    assert audit["audit_payload_omitted"] is True
    assert audit["original_payload_sha256"] == row["payload_hash"]
    assert "raw_json_omitted" in row["data_quality_tags"]


def test_large_or_truncated_payload_uses_explicit_audit_manifest_not_partial_json():
    payload = {**sample(), "bodyText": "x" * (15 * 1024 * 1024)}
    row = normalize_event(payload, now=NOW)
    full = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    audit = json.loads(row["raw_json"])
    assert len(row["text_content"]) == 200000
    assert audit["audit_payload_omitted"] is True
    assert audit["original_bytes"] == len(full.encode())
    assert audit["original_payload_sha256"] == row["payload_hash"] == hashlib.sha256(full.encode()).hexdigest()
    assert "bodyText" not in audit
    assert {"body_truncated", "raw_json_omitted"} <= set(row["data_quality_tags"])
    assert len(json.dumps(row, ensure_ascii=False).encode()) < 16 * 1024 * 1024
    large_extension = {**sample(), "unrelatedLargeField": "x" * (1024 * 1024)}
    extended = normalize_event(large_extension, now=NOW)
    assert json.loads(extended["raw_json"])["audit_payload_omitted"] is True
    assert "raw_json_omitted" in extended["data_quality_tags"]


def test_large_security_metadata_uses_hashed_manifest_and_unknown_risk():
    metadata = {"claim": "x" * 65536, "riskVerdict": "pass", "mailHash": "a" * 32}
    row = normalize_event({**sample(), "securityMeta": metadata}, now=NOW)
    manifest = json.loads(row["security_meta_json"])
    full = json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    assert manifest["security_meta_omitted"] is True
    assert manifest["original_sha256"] == hashlib.sha256(full.encode()).hexdigest()
    assert manifest["original_bytes"] == len(full.encode())
    assert row["risk_verdict"] == "unknown" and row["risk_level"] == "unknown"
    assert row["mail_hash"] == "a" * 32
    assert {"security_meta_truncated", "raw_json_omitted"} <= set(row["data_quality_tags"])


def test_full_delivery_dataset_explicitly_reports_contract_mismatches_without_fallback():
    counts = Counter()
    with DATASET.open(encoding="utf-8") as stream:
        for line in stream:
            payload = json.loads(line)
            try:
                row = normalize_event(payload, now=NOW, canonical=True)
            except ValueError as exc:
                counts[str(exc)] += 1
            else:
                counts["accepted"] += 1
                assert row["event_id"] == payload["eventId"]
                assert row["risk_level"] == "unknown"
    assert sum(counts.values()) == 1000
    assert counts == {"accepted": 358, "eventId must be a UUID": 621,
                      "invalid from address": 20, "invalid or missing to": 1}
