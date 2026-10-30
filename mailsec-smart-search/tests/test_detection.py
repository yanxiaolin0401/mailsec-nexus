import socket
from dataclasses import asdict

import httpx

from mailsec_smart_search.config import Settings
from mailsec_smart_search.detection import scan_clamd, scan_rspamd


def test_rspamd_checkv2_and_failure_states():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"score": 8, "action": "reject", "symbols": {"PHISHING": {}}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = scan_rspamd(b"From: a@example.test\n\nhello", Settings(), client=client)
    assert result.status == "ok" and result.risk == "malicious"
    assert seen[0].url.path == "/checkv2"
    assert b"hello" in seen[0].content
    assert asdict(result)["signals"] == ("PHISHING",)
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, text="oops"))) as client:
        assert scan_rspamd(b"x", Settings(), client=client).status == "invalid"
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(503))) as client:
        assert scan_rspamd(b"x", Settings(), client=client).status == "unavailable"


def test_rspamd_compose_name_is_fixed_not_arbitrary_url():
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"score": 0, "action": "no action"}))) as client:
        assert scan_rspamd(b"x", Settings(rspamd_url="http://rspamd:11333"), client=client).risk == "clean"
        for url in ("http://other:11333", "http://rspamd:8123", "http://rspamd:11333/other", "http://user:pass@rspamd:11333"):
            assert scan_rspamd(b"x", Settings(rspamd_url=url), client=client).status == "invalid"
        assert scan_rspamd(b"x", Settings(rspamd_url="http://[broken"), client=client).status == "invalid"


class FakeSocket:
    def __init__(self, reply):
        self.sent = bytearray()
        self.reply = reply

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def settimeout(self, _):
        pass

    def sendall(self, data):
        self.sent.extend(data)

    def recv(self, _):
        reply, self.reply = self.reply, b""
        return reply


def test_clamd_instream_eicar_signature():
    fake = FakeSocket(b"stream: Eicar-Test-Signature FOUND\0")
    result = scan_clamd(b"EICAR", Settings(), socket_factory=lambda *_: fake)
    assert result.status == "ok" and result.risk == "malicious"
    assert result.signals == ("Eicar-Test-Signature",)
    assert fake.sent == b"zINSTREAM\0\x00\x00\x00\x05EICAR\x00\x00\x00\x00"
    assert scan_clamd(b"x", Settings(), socket_factory=lambda *_: FakeSocket(b"stream: OK\0")).risk == "clean"


def test_clamd_failure_not_clean():
    def offline(*_):
        raise ConnectionRefusedError()

    assert scan_clamd(b"x", Settings(), socket_factory=offline).status == "unavailable"
    def timed_out(*_):
        raise socket.timeout()

    assert scan_clamd(b"x", Settings(), socket_factory=timed_out).status == "timeout"
    assert scan_clamd(b"x", Settings(), socket_factory=lambda *_: FakeSocket(b"error\0")).status == "invalid"
    assert scan_clamd(b"x", Settings(), socket_factory=lambda *_: FakeSocket(b"stream: INSTREAM size limit exceeded. ERROR\0")).risk is None
    assert scan_clamd(b"x", Settings(), socket_factory=lambda *_: FakeSocket(b"stream: Heuristics.Limits.Exceeded FOUND\0")).risk is None
    assert scan_clamd(b"x", Settings(clamd_host="clamav", clamd_port=3310), socket_factory=lambda *_: FakeSocket(b"stream: OK\0")).risk == "clean"
    assert scan_clamd(b"x", Settings(clamd_host="other"), socket_factory=lambda *_: FakeSocket(b"stream: OK\0")).status == "invalid"


def test_heuristic_or_incomplete_scan_is_not_malware_signature():
    for name in ('Heuristics.Encrypted.Zip', 'Heuristics.Broken.Executable'):
        reply = f'stream: {name} FOUND\0'.encode()
        result = scan_clamd(b'x', Settings(), socket_factory=lambda *_: FakeSocket(reply))
        assert result.status == 'invalid' and result.risk is None
    result = scan_clamd(b'x', Settings(), socket_factory=lambda *_: FakeSocket(b'stream: Heuristics.OLE2.ContainsMacros FOUND\0'))
    assert result.status == 'ok' and result.risk == 'suspicious'
