"""Optional, local-only scanning adapters. Scanner failures are never clean verdicts."""

from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

import httpx

from .config import Settings


Status = Literal["ok", "unavailable", "timeout", "invalid"]
Risk = Literal["clean", "suspicious", "malicious"]


@dataclass(frozen=True, slots=True)
class DetectionResult:
    engine: str
    status: Status
    risk: Risk | None = None
    score: float | None = None
    signals: tuple[str, ...] = ()
    error: str = ""


def scan_rspamd(raw_eml: bytes, settings: Settings, *, client: httpx.Client | None = None) -> DetectionResult:
    """Submit RFC 5322 bytes to local Rspamd /checkv2."""
    try:
        parsed = urlparse(settings.rspamd_url)
    except ValueError:
        return DetectionResult("rspamd", "invalid", error="invalid Rspamd URL")
    allowed_hosts = {"localhost", "127.0.0.1", "::1", "rspamd"}
    try:
        port = parsed.port
    except ValueError:
        return DetectionResult("rspamd", "invalid", error="invalid Rspamd port")
    if (parsed.scheme != "http" or parsed.hostname not in allowed_hosts
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in {"", "/"} or (parsed.hostname == "rspamd" and port != 11333)):
        return DetectionResult("rspamd", "invalid", error="Rspamd endpoint must be loopback or fixed Compose service")
    url = settings.rspamd_url.rstrip("/") + "/checkv2"
    try:
        if client is None:
            with httpx.Client(timeout=settings.parse_timeout_seconds, trust_env=False) as local_client:
                response = local_client.post(url, content=raw_eml, headers={"Content-Type": "message/rfc822"})
        else:
            response = client.post(url, content=raw_eml, headers={"Content-Type": "message/rfc822"})
    except httpx.TimeoutException:
        return DetectionResult("rspamd", "timeout", error="scanner timed out")
    except httpx.RequestError:
        return DetectionResult("rspamd", "unavailable", error="scanner unavailable")
    if response.status_code != 200:
        return DetectionResult("rspamd", "unavailable", error=f"scanner HTTP {response.status_code}")
    try:
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("score"), (int, float)) or isinstance(data["score"], bool):
            raise ValueError("missing score")
        action = data.get("action")
        if not isinstance(action, str):
            raise ValueError("missing action")
        symbols = data.get("symbols", {})
        if not isinstance(symbols, dict):
            raise ValueError("invalid symbols")
        score = float(data["score"])
        if not -10000 <= score <= 10000:
            raise ValueError("out-of-range score")
        if action in {"reject", "discard"}:
            risk: Risk = "malicious"
        elif action in {"add header", "rewrite subject", "greylist", "soft reject"}:
            risk = "suspicious"
        elif action == "no action":
            risk = "clean"
        else:
            raise ValueError("unknown action")
        return DetectionResult("rspamd", "ok", risk, score, tuple(sorted(str(k) for k in symbols)))
    except (ValueError, TypeError, json.JSONDecodeError):
        return DetectionResult("rspamd", "invalid", error="malformed scanner response")


def scan_clamd(raw_eml: bytes, settings: Settings, *, socket_factory=socket.create_connection) -> DetectionResult:
    """ClamAV INSTREAM framing: zINSTREAM, length-prefixed chunks, zero terminator."""
    if settings.clamd_host not in {"localhost", "127.0.0.1", "::1", "clamav"} or (settings.clamd_host == "clamav" and settings.clamd_port != 3310):
        return DetectionResult("clamav", "invalid", error="ClamAV endpoint must be loopback or fixed Compose service")
    try:
        with socket_factory((settings.clamd_host, settings.clamd_port), settings.parse_timeout_seconds) as connection:
            connection.settimeout(settings.parse_timeout_seconds)
            connection.sendall(b"zINSTREAM\0")
            for offset in range(0, len(raw_eml), 65536):
                chunk = raw_eml[offset:offset + 65536]
                connection.sendall(struct.pack("!I", len(chunk)) + chunk)
            connection.sendall(b"\0\0\0\0")
            reply = bytearray()
            while len(reply) < 4096:
                part = connection.recv(4096 - len(reply))
                if not part:
                    break
                reply.extend(part)
                if b"\0" in part or b"\n" in part:
                    break
    except (socket.timeout, TimeoutError):
        return DetectionResult("clamav", "timeout", error="scanner timed out")
    except OSError:
        return DetectionResult("clamav", "unavailable", error="scanner unavailable")
    line = bytes(reply).split(b"\0", 1)[0].split(b"\n", 1)[0].decode("utf-8", "replace")
    if line == "stream: OK":
        return DetectionResult("clamav", "ok", "clean")
    if line.startswith("stream: ") and line.endswith(" FOUND"):
        signature = line[len("stream: "):-len(" FOUND")]
        if signature:
            if signature.startswith("Heuristics.Limits.Exceeded"):
                return DetectionResult("clamav", "invalid", error="scanner limit reached; scan incomplete")
            if signature.startswith(("Heuristics.Encrypted", "Heuristics.Broken")):
                return DetectionResult("clamav", "invalid", error="encrypted or broken content; scan incomplete")
            if signature.startswith("Heuristics."):
                return DetectionResult("clamav", "ok", "suspicious", signals=(signature,))
            return DetectionResult("clamav", "ok", "malicious", signals=(signature,))
    if line.startswith("stream: ") and line.endswith(" ERROR"):
        return DetectionResult("clamav", "invalid", error="scanner reported incomplete scan or limit")
    return DetectionResult("clamav", "invalid", error="malformed scanner response")
