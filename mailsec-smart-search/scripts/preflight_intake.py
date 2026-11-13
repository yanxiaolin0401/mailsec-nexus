#!/usr/bin/env python3
"""Read-only canonical JSONL preflight with opt-in UUID-only repair.

No message content or identifiers are emitted to stdout or the report.  Full
payload JSONL is written only when explicit non-overwriting paths are supplied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from mailsec_smart_search.events import normalize_event

ROOT = Path(__file__).resolve().parents[1]
_LOGS = ROOT / "logs"


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_category(error: ValueError) -> str:
    # Normalizer errors are defined in code; never leak input-derived text.
    message = str(error)
    if re.fullmatch(r"(?:invalid or missing|invalid|missing) [A-Za-z][A-Za-z0-9]*", message):
        return message
    if message == "eventId must be a UUID":
        return message
    if message == "eventId must be a canonical UUID":
        return message
    if message.startswith("invalid ") or message.startswith("eventTime ") or message.startswith("source IDs "):
        return re.sub(r"[^A-Za-z0-9 _-]", "", message)[:100]
    return "contract_violation"


def _repair_id(payload: dict) -> dict | None:
    if "eventId" not in payload:
        return None
    value = payload["eventId"]
    if isinstance(value, str):
        try:
            if str(uuid.UUID(value)) == value.lower():
                return None
        except ValueError:
            pass
    if "originalEventId" in payload:
        return None
    repaired = dict(payload)
    original = repaired.pop("eventId")
    try:
        generated = normalize_event(repaired, canonical=True)["event_id"]
    except ValueError:
        return None
    repaired["eventId"] = generated
    repaired["originalEventId"] = original
    return repaired


def _validate_destinations(source: Path, output: Path | None, rejects: Path | None,
                           report: Path | None) -> None:
    paths = [path for path in (output, rejects, report) if path is not None]
    resolved = [path.resolve() for path in (source, *paths)]
    if len(set(resolved)) != len(resolved):
        raise ValueError("input/output paths must differ")
    for path in paths:
        if path.exists() or path.is_symlink():
            raise ValueError("output path already exists")
        if not path.parent.is_dir():
            raise ValueError("output parent directory does not exist")
    if report is not None and not report.resolve().is_relative_to(_LOGS.resolve()):
        raise ValueError("report must be within repository logs directory")


def _create_private(path: Path) -> TextIO:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", newline="")


def preflight(source: Path, *, repair_ids: bool = False, output: Path | None = None,
              rejects: Path | None = None, report: Path | None = None) -> dict:
    _validate_destinations(source, output, rejects, report)
    before = _hash_file(source)
    counts: Counter[str] = Counter()
    issues: list[dict[str, object]] = []
    repaired_count = 0
    with ExitStack() as stack:
        valid_stream = stack.enter_context(_create_private(output)) if output else None
        rejected_stream = stack.enter_context(_create_private(rejects)) if rejects else None
        with source.open(encoding="utf-8", newline="") as stream:
            for line_number, line in enumerate(stream, 1):
                try:
                    payload = json.loads(line)
                except (ValueError, TypeError):
                    category = "invalid_json"
                    accepted = False
                else:
                    if not isinstance(payload, dict):
                        category = "invalid_envelope"
                        accepted = False
                    else:
                        candidate = _repair_id(payload) if repair_ids else None
                        if candidate is None:
                            candidate = payload
                        try:
                            normalize_event(candidate, canonical=True)
                        except ValueError as exc:
                            category = _safe_category(exc)
                            accepted = False
                        else:
                            accepted = True
                            if candidate is not payload:
                                repaired_count += 1
                                line = json.dumps(candidate, ensure_ascii=False, separators=(",", ":")) + "\n"
                if accepted:
                    counts["accepted"] += 1
                    if valid_stream:
                        valid_stream.write(line)
                else:
                    counts[category] += 1
                    issues.append({"line": line_number, "category": category})
                    if rejected_stream:
                        rejected_stream.write(line)
    after = _hash_file(source)
    result = {
        "status": "invalid" if issues else "valid",
        "mode": "uuid_repair_opt_in" if repair_ids else "strict_original",
        "original_contract_passed": not repair_ids and not issues,
        "input_sha256_before": before, "input_sha256_after": after,
        "input_unchanged": before == after,
        "total": sum(counts.values()), "accepted": counts["accepted"],
        "rejected": len(issues), "repaired_event_ids": repaired_count,
        "categories": {key: value for key, value in sorted(counts.items()) if key != "accepted"},
        "issues": issues,
        "note": "UUID repair creates a derivative; it does not make the original input contract-compliant" if repair_ids else "Original input validated without mutation",
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    if report is not None:
        with _create_private(report) as stream:
            json.dump(result, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preflight canonical JSONL without exposing message content")
    parser.add_argument("input", type=Path)
    parser.add_argument("--repair-ids", action="store_true", help="explicitly derive UUID5 for invalid eventId only")
    parser.add_argument("--output", type=Path, help="new 0600 JSONL file for accepted payloads")
    parser.add_argument("--rejects", type=Path, help="new 0600 JSONL file for rejected payloads")
    parser.add_argument("--report", type=Path, help="new 0600 JSON report under repository logs/")
    args = parser.parse_args(argv)
    try:
        result = preflight(args.input, repair_ids=args.repair_ids, output=args.output,
                           rejects=args.rejects, report=args.report)
    except (OSError, ValueError, UnicodeError) as exc:
        print(json.dumps({"status": "error", "category": type(exc).__name__}, ensure_ascii=False), file=sys.stderr)
        return 2
    # Deliberately omit SHA and line-level details from console output.
    print(json.dumps({key: result[key] for key in ("status", "mode", "total", "accepted", "rejected",
                                                  "repaired_event_ids", "categories", "input_unchanged")},
                     ensure_ascii=False, sort_keys=True))
    return 1 if result["rejected"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
