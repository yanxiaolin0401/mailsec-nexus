#!/usr/bin/env python3
"""Repeatable, read-only ClickHouse query benchmark after a large corpus import.

The caller may source .env before invoking this script. It never reads or prints
the .env file, API keys, email bodies, addresses, or query result rows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from mailsec_smart_search.config import Settings
from mailsec_smart_search.domain import SearchQuery
from mailsec_smart_search.storage import ClickHouseRepository


@dataclass(frozen=True)
class BenchmarkFilters:
    sender_domain: str
    subject_term: str
    body_term: str
    attachment_suffix: str
    from_time: datetime
    to_time: datetime


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = (len(ordered) - 1) * fraction
    left = math.floor(index)
    right = math.ceil(index)
    return round(ordered[left] + (ordered[right] - ordered[left]) * (index - left), 3)


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unknown"


def _queries(filters: BenchmarkFilters) -> tuple[tuple[str, SearchQuery, bool], ...]:
    return (
        ("recent", SearchQuery(limit=50), False),
        ("sender_domain", SearchQuery(sender_domain=filters.sender_domain, limit=50), False),
        ("time_subject", SearchQuery(from_time=filters.from_time,
                                     to_time=filters.to_time,
                                     subject_contains=filters.subject_term, limit=50), False),
        ("body", SearchQuery(body_contains=filters.body_term, limit=50), False),
        ("attachment", SearchQuery(has_attachment=True,
                                   attachment_suffix=filters.attachment_suffix, limit=50), False),
        ("statistics", SearchQuery(from_time=filters.from_time,
                                   to_time=filters.to_time), True),
    )


def benchmark(
    repository: Any,
    filters: BenchmarkFilters,
    *,
    iterations: int = 20,
    warmups: int = 2,
    concurrency_levels: tuple[int, ...] = (1, 4),
    min_rows: int = 100_000,
    server_version: str = "unknown",
) -> dict[str, Any]:
    """Measure fixed, bounded repository queries; never serialize result contents."""
    if iterations < 1 or warmups < 0 or not concurrency_levels or any(level < 1 or level > 32 for level in concurrency_levels):
        raise ValueError("iterations, warmups, and concurrency levels are outside allowed ranges")
    if min_rows < 1 or filters.from_time > filters.to_time:
        raise ValueError("invalid minimum row count or time window")
    if not all((filters.sender_domain, filters.subject_term, filters.body_term, filters.attachment_suffix)):
        raise ValueError("benchmark filters must not be empty")
    row_count = int(repository.stats(SearchQuery())["total"])
    if row_count < min_rows:
        raise ValueError(f"dataset below minimum row count ({row_count} < {min_rows})")

    report: dict[str, Any] = {
        "schema_version": 1,
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_rows": row_count,
        "iterations": iterations,
        "warmups": warmups,
        "concurrency_levels": list(concurrency_levels),
        # Fingerprints identify a benchmark workload without leaking mail contents.
        "filter_fingerprints": {
            "sender_domain": _fingerprint(filters.sender_domain),
            "subject_term": _fingerprint(filters.subject_term),
            "body_term": _fingerprint(filters.body_term),
            "attachment_suffix": _fingerprint(filters.attachment_suffix),
            "from_time": _fingerprint(filters.from_time.isoformat()),
            "to_time": _fingerprint(filters.to_time.isoformat()),
        },
        "machine": {
            "os": platform.system(), "os_release": platform.release(),
            "architecture": platform.machine(), "cpu_count": os.cpu_count(),
            "python": platform.python_version(),
            "clickhouse_connect": _package_version("clickhouse-connect"),
            "clickhouse": server_version,
        },
        "results": [],
    }
    for scenario, query, is_stats in _queries(filters):
        operation = repository.stats if is_stats else repository.search_summaries

        def measured() -> tuple[float, str | None]:
            started = time.perf_counter()
            try:
                operation(query)
                error = None
            except Exception as exc:
                error = type(exc).__name__  # Never include exception text or SQL.
            return (time.perf_counter() - started) * 1000, error

        for concurrency in concurrency_levels:
            warmup_errors = sum(measured()[1] is not None for _ in range(warmups))
            with ThreadPoolExecutor(max_workers=concurrency) as pool:
                samples = list(pool.map(lambda _: measured(), range(iterations)))
            successful = [elapsed for elapsed, error in samples if error is None]
            errors = [error for _, error in samples if error is not None]
            report["results"].append({
                "scenario": scenario, "concurrency": concurrency,
                "runs": iterations, "warmups": warmups,
                "warmup_errors": warmup_errors, "errors": len(errors),
                "error_types": sorted(set(errors)),
                "p50_ms": _percentile(successful, 0.5),
                "p95_ms": _percentile(successful, 0.95),
                "max_ms": round(max(successful), 3) if successful else None,
            })
    return report


def write_report(path: Path, report: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".query-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _server_version(repository: ClickHouseRepository) -> str:
    result = repository.client.query("SELECT version()", parameters={},
                                     settings={"max_execution_time": 5})
    return str(result.result_rows[0][0])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("docs/reports/query-benchmark.json"))
    parser.add_argument("--iterations", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--min-rows", type=int, default=100_000)
    parser.add_argument("--sender-domain", default="enron.com")
    parser.add_argument("--subject-term", default="meeting")
    parser.add_argument("--body-term", default="http")
    parser.add_argument("--attachment-suffix", default="pdf")
    parser.add_argument("--from-time", type=datetime.fromisoformat,
                        default=datetime(2000, 1, 1, tzinfo=timezone.utc))
    parser.add_argument("--to-time", type=datetime.fromisoformat,
                        default=datetime(2002, 12, 31, tzinfo=timezone.utc))
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    repository = ClickHouseRepository(settings)
    filters = BenchmarkFilters(args.sender_domain, args.subject_term, args.body_term,
                               args.attachment_suffix, args.from_time, args.to_time)
    report = benchmark(repository, filters, iterations=args.iterations,
                       warmups=args.warmups, min_rows=args.min_rows,
                       server_version=_server_version(repository))
    write_report(args.output, report)
    print(f"Wrote {args.output}; rows={report['dataset_rows']}; "
          f"errors={sum(item['errors'] for item in report['results'])}")
    return 1 if any(item["errors"] or item["warmup_errors"] for item in report["results"]) else 0


if __name__ == "__main__":
    sys.exit(main())
