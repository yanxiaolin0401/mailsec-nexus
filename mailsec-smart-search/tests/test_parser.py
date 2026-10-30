from datetime import datetime, timezone
from email.message import EmailMessage
import hashlib

import pytest

from mailsec_smart_search.parser import ParseLimitError, parse_eml, parse_eml_isolated


def parse(raw, **kwargs):
    return parse_eml(raw, mail_id="id", raw_sha256=hashlib.sha256(raw).hexdigest(),
                     raw_path="/tmp/id.eml", source="test",
                     ingested_at=datetime.now(timezone.utc), **kwargs)


def test_duplicate_headers_order_and_claimed_spf():
    raw = (b"Received: one\r\nReceived: two\r\nReceived-SPF: pass\r\n"
           b"From: Alice <alice@example.org>\r\nTo: Bob <bob@example.com>\r\n"
           b"Subject: Test\r\n\r\nVisit https://example.com/path")
    record = parse(raw)
    assert record.headers[:2] == [("Received", "one"), ("Received", "two")]
    assert record.sender == "alice@example.org"
    assert record.recipients == ["bob@example.com"]
    assert record.claimed_spf == "pass"
    assert record.urls == ["https://example.com/path"]


def test_mime_attachment_hash_and_html_fallback():
    message = EmailMessage()
    message["Subject"] = "Résumé"
    message.set_content("Hello")
    message.add_alternative('<a href="https://safe.example/a">Link</a>', subtype="html")
    message.add_attachment(b"sample", maintype="application", subtype="octet-stream", filename="x.bin")
    record = parse(message.as_bytes())
    assert record.subject == "Résumé"
    assert record.body_text.strip() == "Hello"
    assert record.attachments[0].sha256 == hashlib.sha256(b"sample").hexdigest()
    assert record.attachments[0].size == 6
    assert record.urls == ["https://safe.example/a"]


def test_malformed_and_limits():
    record = parse(b"invalid header\r\n\r\nbody")
    assert record.parse_status in {"partial", "ok"}
    assert parse(b"Subject: x\r\n\r\nabcdef", max_body_chars=3).truncated
    with pytest.raises(ParseLimitError):
        parse(b"x" * (20 * 1024 * 1024 + 1))


def test_isolated_parse():
    raw = b"Subject: isolated\r\n\r\nbody"
    record = parse_eml_isolated(raw, mail_id="id", raw_sha256=hashlib.sha256(raw).hexdigest(),
                                raw_path="x", source="test", ingested_at=datetime.now(timezone.utc),
                                timeout_seconds=5)
    assert record.subject == "isolated"


def test_long_headers_are_bounded_and_reported():
    from mailsec_smart_search.parser import MAX_HEADER_CHARS, MAX_TOTAL_HEADER_CHARS
    raw = b'Subject: ' + b'A' * 20000 + b'\r\n' + (b'X-Pad: ' + b'B' * 8192 + b'\r\n') * 30 + b'\r\nbody'
    record = parse(raw)
    assert record.truncated and record.parse_status == 'partial'
    assert len(record.subject) == MAX_HEADER_CHARS
    assert sum(len(k) + len(v) for k, v in record.headers) < MAX_TOTAL_HEADER_CHARS + MAX_HEADER_CHARS + 100


def test_malformed_message_id_does_not_crash_headerregistry():
    record = parse(b"Message-ID: <>\r\nFrom: \r\nSubject: malformed test\r\n\r\nhello")
    assert record.header_message_id == "<>"
    assert record.subject == "malformed test"
    assert record.parse_status == "partial"
    assert "invalid Message-ID header" in record.parse_errors


def test_invalid_header_octets_are_safe_to_persist():
    import json
    from dataclasses import asdict
    record = parse(b"Subject: bad \xa9 encoding\r\nX-Other: \xff\r\nFrom: \xa9@example.org\r\n\r\nbody")
    json.dumps(asdict(record), ensure_ascii=False, default=str).encode("utf-8")
    assert "invalid header encoding" in record.parse_errors
    assert record.parse_status == "partial"


@pytest.mark.parametrize("date,valid", [
    ("01 Jan 0102 00:00:00 +0000", False),
    ("31 Dec 1899 23:59:59 +0000", False),
    ("01 Jan 1900 00:00:00 +0000", True),
    ("31 Dec 2299 23:59:59 +0000", True),
    ("01 Jan 2300 00:00:00 +0000", False),
    ("01 Jan 1900 00:00:00 +0100", False),
])
def test_date_header_outside_portable_datetime64_range_is_preserved_but_not_indexed(date, valid):
    mail = parse(f"Date: {date}\r\nSubject: dated\r\n\r\nbody".encode())
    assert (mail.sent_at is not None) is valid
    assert mail.headers[0] == ("Date", date)
    if not valid:
        assert mail.parse_status == "partial"
        assert "Date header outside supported range" in mail.parse_errors
