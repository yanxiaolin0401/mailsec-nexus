#!/usr/bin/env python3
"""Reproducible, local-only scanner baseline on labeled public EML samples.

Spam and phishing are separate positive labels. They are NOT malware labels;
ClamAV's signature result is reported against the same samples only as context.
No message contents, addresses or scanner symbols are written to reports.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import statistics
import time
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Callable

from mailsec_smart_search.config import Settings
from mailsec_smart_search.detection import DetectionResult, scan_clamd, scan_rspamd

ROOT = Path(__file__).resolve().parents[1]
MAX_SAMPLE_BYTES = 20 * 1024 * 1024


def _safe_path(data_dir: Path, source: str, relative: str) -> Path:
    name = PurePosixPath(relative)
    if not relative or name.is_absolute() or ".." in name.parts or "\\" in relative:
        raise ValueError("unsafe manifest path")
    base = (data_dir / "raw" / source).resolve()
    path = base.joinpath(*name.parts)
    if not path.resolve().is_relative_to(base) or path.is_symlink():
        raise ValueError("manifest path escapes source")
    return path


def iter_manifest(data_dir: Path):
    """Yield whitelisted labels only; Enron and metadata records are excluded."""
    for index in sorted((data_dir / "manifests").glob("*.files.jsonl")):
        source = index.name.removesuffix(".files.jsonl")
        if not (source.startswith("spamassassin-") or source.startswith("nazario-")):
            continue
        with index.open(encoding="utf-8") as stream:
            for line in stream:
                row = json.loads(line)
                label = row.get("label")
                source_label_valid = (source.startswith("spamassassin-") and label in {"ham", "spam"}) or (
                    source.startswith("nazario-") and label == "phishing")
                if row.get("is_message") is True and source_label_valid:
                    digest = row.get("sha256")
                    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                        raise ValueError("invalid manifest digest")
                    yield source, label, digest, _safe_path(data_dir, source, row["path"]), row["bytes"]


def _schema(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS results (
        digest TEXT PRIMARY KEY, source TEXT NOT NULL, label TEXT NOT NULL,
        rspamd_status TEXT NOT NULL, rspamd_risk TEXT, rspamd_latency_ms REAL NOT NULL,
        clamav_status TEXT NOT NULL, clamav_risk TEXT, clamav_latency_ms REAL NOT NULL
    )""")
    db.commit()


def _scan(raw: bytes, settings: Settings,
          rspamd: Callable[[bytes, Settings], DetectionResult],
          clamav: Callable[[bytes, Settings], DetectionResult]):
    results = []
    for engine, scanner in (("rspamd", rspamd), ("clamav", clamav)):
        start = time.perf_counter()
        try:
            result = scanner(raw, settings)
            if result.engine != engine or result.status not in {"ok", "unavailable", "timeout", "invalid"}:
                raise ValueError("invalid scanner result")
            status, risk = result.status, result.risk if result.status == "ok" else None
        except Exception:
            status, risk = "scanner_error", None
        results.extend((status, risk, round((time.perf_counter() - start) * 1000, 3)))
    return tuple(results)


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int((len(ordered) - 1) * fraction))], 3)


def _metrics(rows: list[tuple], engine: str) -> dict:
    offset = 3 if engine == "rspamd" else 6
    stats = {"samples": len(rows), "tp": 0, "fp": 0, "fn": 0, "tn": 0,
             "unknown": 0, "available": 0, "status_counts": {}}
    latencies = []
    for row in rows:
        label, status, risk, latency = row[2], row[offset], row[offset + 1], row[offset + 2]
        stats["status_counts"][status] = stats["status_counts"].get(status, 0) + 1
        latencies.append(latency)
        if status != "ok" or risk not in {"clean", "suspicious", "malicious"}:
            stats["unknown"] += 1
            continue
        stats["available"] += 1
        positive = label != "ham"
        flagged = risk in {"suspicious", "malicious"}
        stats["tp" if positive and flagged else
              "fn" if positive else "fp" if flagged else "tn"] += 1
    stats["availability_rate"] = round(stats["available"] / len(rows), 4) if rows else 0.0
    stats["latency_ms"] = {
        "mean": round(statistics.mean(latencies), 3) if latencies else 0.0,
        "p50": _percentile(latencies, 0.5), "p95": _percentile(latencies, 0.95),
        "max": round(max(latencies), 3) if latencies else 0.0,
    }
    return stats


def _report(db: sqlite3.Connection, limit: int, processed: int, duplicate_count: int) -> tuple[dict, list[dict]]:
    rows = db.execute("SELECT digest, source, label, rspamd_status, rspamd_risk, rspamd_latency_ms, "
                      "clamav_status, clamav_risk, clamav_latency_ms FROM results ORDER BY digest").fetchall()
    groups: dict[str, list[tuple]] = defaultdict(list)
    for row in rows:
        groups[f"label:{row[2]}"].append(row)
        groups[f"source:{row[1]}"].append(row)
    metrics = {name: {engine: _metrics(items, engine) for engine in ("rspamd", "clamav")}
               for name, items in sorted(groups.items())}
    mistakes = []
    for row in rows:
        statuses = []
        for engine, offset in (("rspamd", 3), ("clamav", 6)):
            status, risk = row[offset], row[offset + 1]
            if status != "ok" or risk not in {"clean", "suspicious", "malicious"}:
                statuses.append(f"{engine}:unknown:{status}")
            elif (risk != "clean") != (row[2] != "ham"):
                statuses.append(f"{engine}:misclassified")
        if statuses:
            mistakes.append({"digest": row[0], "source": row[1], "status": ",".join(statuses)})
    report = {
        "version": 1, "mode": "local_scanners_only", "sample_limit_per_class": limit,
        "new_samples_this_run": processed, "duplicate_digest_records_skipped": duplicate_count,
        "total_unique_samples": len(rows),
        "label_warning": "Spam and phishing evaluated separately as mail-threat labels; neither is a malware ground truth. No LLM is called.",
        "flag_rule": "suspicious or malicious; scanner failure is unknown, never clean",
        "groups": metrics,
    }
    return report, mistakes


def _atomic_json(path: Path, value: object, *, jsonl: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        if jsonl:
            for item in value:
                stream.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")
        else:
            json.dump(value, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
    temporary.replace(path)


def evaluate(*, data_dir: Path, checkpoint: Path, output: Path, limit_per_class: int = 100,
             settings: Settings | None = None,
             rspamd: Callable[[bytes, Settings], DetectionResult] = scan_rspamd,
             clamav: Callable[[bytes, Settings], DetectionResult] = scan_clamd) -> dict:
    if limit_per_class < 1:
        raise ValueError("limit_per_class must be positive")
    settings = settings or Settings.from_env()
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(checkpoint)
    try:
        _schema(db)
        existing = db.execute("SELECT digest, label FROM results").fetchall()
        seen = {digest for digest, _ in existing}
        counts = defaultdict(int)
        for _, label in existing:
            counts[label] += 1
        processed = duplicates = 0
        for source, label, digest, path, expected_size in iter_manifest(data_dir):
            if digest in seen:
                duplicates += 1
                continue
            if counts[label] >= limit_per_class:
                continue
            seen.add(digest)
            counts[label] += 1
            try:
                if not isinstance(expected_size, int) or not 0 <= expected_size <= MAX_SAMPLE_BYTES:
                    raise ValueError("sample size exceeds cap")
                raw = path.read_bytes()
                if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != digest:
                    raise ValueError("manifest integrity mismatch")
                result = _scan(raw, settings, rspamd, clamav)
            except (OSError, ValueError):
                result = ("input_error", None, 0.0, "input_error", None, 0.0)
            db.execute("INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (digest, source, label, *result))
            db.commit()  # Each message is a resume checkpoint.
            processed += 1
        report, mistakes = _report(db, limit_per_class, processed, duplicates)
        _atomic_json(output, report)
        _atomic_json(output.with_suffix(".errors.jsonl"), mistakes, jsonl=True)
        return report
    finally:
        db.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    parser.add_argument("--checkpoint", type=Path, default=ROOT / "var/evaluation/results.sqlite3")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/reports/detection-baseline.json")
    parser.add_argument("--limit-per-class", type=int, default=100)
    args = parser.parse_args()
    report = evaluate(data_dir=args.data_dir, checkpoint=args.checkpoint, output=args.output,
                      limit_per_class=args.limit_per_class)
    print(json.dumps({"total_unique_samples": report["total_unique_samples"],
                      "new_samples_this_run": report["new_samples_this_run"],
                      "output": str(args.output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
