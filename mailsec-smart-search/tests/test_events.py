import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mailsec_smart_search.events import normalize_event

FIXTURE = Path(__file__).parent / "fixtures" / "nested-mail.json"
NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


def test_nested_documented_columns_and_cleaning():
    payload = json.loads(FIXTURE.read_text())
    row = normalize_event(payload, now=NOW, ingress_ip="192.0.2.2")
    assert len(row) == 34  # documented 33 columns + searchable body extension
    assert len(row["event_id"]) == 64
    assert row["event_time"] == "2026-10-14T01:00:00+00:00"
    assert row["mail_date"] == row["event_time"]
    assert row["ingested_at"] == NOW.isoformat()
    assert row["sender_account"] == "sender@example.org"
    assert row["receiver_accounts"] == ["primary@example.net", "secondary@example.net"]
    assert row["subject"] == "安全通知"
    assert row["sender_ip"] == "8.8.8.8"
    assert row["ingress_ip"] == "192.0.2.2"
    assert row["risk_verdict"] == "unknown"
    assert row["risk_level"] == "unknown"
    assert "hidden" not in row["text_content"] and "bad()" not in row["text_content"]
    assert row["external_urls"] == ["https://example.org/verify"]
    assert row["external_attachments"] == [{"filename": "memo.pdf", "md5": "e10adc3949ba59abbe56e057f20f883e"}]
    assert row["mail_headers"].count("Received:") == 2
    assert "unknownExtension" in row["raw_json"]
    assert all("shouldNotBeSearchable" not in str(v) for k, v in row.items() if k != "raw_json")


def test_canonical_source_identity_and_payload_hash():
    p = json.loads(FIXTURE.read_text())
    first = normalize_event(p, now=NOW)
    assert first["event_id"] == normalize_event(p, now=NOW)["event_id"]
    assert first["payload_hash"] == hashlib.sha256(first["raw_json"].encode()).hexdigest()
    p["sourceEventId"] += "-2"
    assert normalize_event(p, now=NOW)["event_id"] != first["event_id"]
    del p["sourceEventId"]
    a, b = normalize_event(p, now=NOW), normalize_event(p, now=NOW)
    assert a["event_id"] != b["event_id"]
    assert "missing_source_event_id" in a["data_quality_tags"]


def test_flat_data_and_ambiguous_envelopes():
    flat = {"sourceSystemId": "a", "sourceEventId": "b", "senderaccount": "x@y.test"}
    assert normalize_event(flat, now=NOW)["sender_account"] == "x@y.test"
    assert normalize_event({"sourceSystemId": "a", "sourceEventId": "b", "data": {"senderaccount": "x@y.test"}}, now=NOW)["sender_account"] == "x@y.test"
    for payload in ({"mail": []}, {"data": "x"}, {"mail": {}, "data": {}}, {"mail": {}, "subject": "x"}):
        with pytest.raises(ValueError):
            normalize_event(payload, now=NOW)


def test_fallback_header_variants_ip_and_metadata_quality():
    p = {"mail": {"from": "Alias <a@example.org>", "clientip": "8.8.8.8", "ip": "10.0.0.2",
                  "mailHeaderList": json.dumps([{"name": "Received", "value": "from host ([1.1.1.1])"},
                                                {"name": "To", "value": "A <a@example.net>"},
                                                {"name": "To", "value": "B <b@example.net>"},
                                                {"name": "Date", "value": "bad date"}]),
                  "attachInfos_md5": "not-a-md5; e10adc3949ba59abbe56e057f20f883e",
                  "attachInfos_filename": "a.txt;b.txt",
                  "urls": "ftp://no.example/path https://ok.example/path"}}
    row = normalize_event(p, now=NOW)
    assert row["sender_ip"] == "1.1.1.1"
    assert "sender_ip_from_untrusted_received" in row["data_quality_tags"]
    assert row["receiver_accounts"] == ["a@example.net", "b@example.net"]
    assert row["external_urls"] == ["https://ok.example/path"]
    assert row["external_attachments"] == [{"filename": "a.txt", "md5": "-"},
                                            {"filename": "b.txt", "md5": "e10adc3949ba59abbe56e057f20f883e"}]
    assert "invalid_attachment_md5" in row["data_quality_tags"]
    assert "mail_date_fallback" in row["data_quality_tags"]
    assert row["mail_date"] == row["event_time"]


def test_no_client_ip_as_sender_ip():
    row = normalize_event({"mail": {"clientip": "8.8.8.8", "mailHeaderList": "Received: from bad ([10.0.0.1])"}}, now=NOW)
    assert row["sender_ip"] == "unknown"
    assert "missing_sender_ip" in row["data_quality_tags"]


def test_source_ids_do_not_silently_collide_after_truncation():
    base = {"sourceSystemId": "tenant", "sourceEventId": "x" * 256, "mail": {}}
    assert len(normalize_event(base, now=NOW)["event_id"]) == 64
    for key in ("sourceSystemId", "sourceEventId"):
        overlong = {**base, key: "x" * 257}
        with pytest.raises(ValueError, match="exceeds 256"):
            normalize_event(overlong, now=NOW)


def test_out_of_range_dates_fall_back_without_poisoning_storage():
    for date in ("0001-01-01T00:00:00Z", "2300-01-01T00:00:00Z",
                 "9999-12-31T23:59:59Z"):
        row = normalize_event({"eventTime": date, "mail": {"mailHeaderList": ["Date: " + date]}}, now=NOW)
        assert row["event_time"] == NOW.isoformat()
        assert row["mail_date"] == NOW.isoformat()
        assert "invalid_event_time" in row["data_quality_tags"]
        assert "invalid_mail_date" in row["data_quality_tags"]
    assert normalize_event({"eventTime": "2299-12-31T23:59:59Z"}, now=NOW)["event_time"].startswith("2299")
    with pytest.raises(ValueError, match="supported storage time range"):
        normalize_event({}, now=datetime(2300, 1, 1, tzinfo=timezone.utc))


def test_plain_text_angle_address_survives_html_detection():
    text = "Contact <alice@example.com> for details"
    row = normalize_event({"mail": {"textContent": text}}, now=NOW)
    assert row["text_content"] == text
    assert normalize_event({"mail": {"textContent": "<div>Hello <b>world</b></div>"}}, now=NOW)["text_content"].split() == ["Hello", "world"]


def test_attachment_metadata_string_size_sha256_and_flat_fallback():
    sha256 = "A" * 64
    row = normalize_event({"mail": {"attachInfos": [{"filename": "report.pdf", "md5": "a" * 32,
                                                 "size": "123", "contentType": "application/pdf", "sha256": sha256}]}}, now=NOW)
    assert row["external_attachments"] == [{"filename": "report.pdf", "md5": "a" * 32,
                                             "size": "123", "content_type": "application/pdf",
                                             "sha256": sha256.lower()}]
    fallback = normalize_event({"mail": {"attachInfos": [], "attachInfos_filename": "file.txt",
                                          "attachInfos_md5": "b" * 32}}, now=NOW)
    assert fallback["external_attachments"] == [{"filename": "file.txt", "md5": "b" * 32}]
    assert "empty_attachments_flat_fallback" in fallback["data_quality_tags"]
    invalid = normalize_event({"mail": {"attachInfos": [{"filename": "bad", "size": "-1",
                                                     "sha256": "invalid"}]}}, now=NOW)
    assert invalid["external_attachments"] == [{"filename": "bad", "md5": "-"}]
    assert "invalid_attachment_size" in invalid["data_quality_tags"]
    assert "invalid_attachment_sha256" in invalid["data_quality_tags"]


def test_dirty_metadata_uses_valid_header_candidate_and_peer_ip():
    value = normalize_event({'mail': {'subject': '  ', 'replyTo': 123,
                            'mailHeaderList': ['Subject: Header title', 'Reply-To: reply@example.org']}}, ingress_ip='testclient')
    assert value['subject'] == 'Header title'
    assert value['reply_to'] == 'reply@example.org'
    assert value['ingress_ip'] == 'unknown'
