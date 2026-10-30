"""Reproducible local service, spool worker, and public-corpus import commands."""

from __future__ import annotations

import argparse
import json
import resource
import sys
import tarfile
import time
from pathlib import Path
from typing import Any, Iterator

from .config import Settings
from .event_spool import EventSpool
from .event_storage import EventRepository
from .domain import MailRecord
from .parser import ParseLimitError, ParseTimeoutError, parse_eml, parse_eml_isolated
from .spool import DurableSpool, SpoolJob
from .storage import ClickHouseRepository


def _parse_job(spool: DurableSpool, job: SpoolJob, *, isolated: bool):
    raw = spool.load_raw(job)
    kwargs: dict[str, Any] = dict(
        mail_id=job.mail_id,
        raw_sha256=job.raw_sha256,
        raw_path=job.raw_path,
        source=job.source,
        ingested_at=job.ingested_at,
    )
    if isolated:
        return parse_eml_isolated(raw, timeout_seconds=spool.settings.parse_timeout_seconds, **kwargs)
    return parse_eml(raw, **kwargs)


def process_spool_once(
    spool: DurableSpool,
    repository: ClickHouseRepository,
    *,
    batch_size: int = 100,
    isolated: bool = True,
) -> dict[str, int]:
    """Commit parsed mail before acknowledging jobs; retry DB failures after restart."""
    if not 1 <= batch_size <= 500:
        raise ValueError("batch_size must be 1..500")
    records = []
    accepted: list[SpoolJob] = []
    failed = 0
    batch_bytes = 0
    for job in spool.pending(limit=batch_size):
        spool.mark_processing(job)
        try:
            record = _parse_job(spool, job, isolated=isolated)
        except (ValueError, ParseLimitError, ParseTimeoutError, RuntimeError) as exc:
            spool.mark_failed(job, f"{type(exc).__name__}: {exc}")
            failed += 1
            continue
        records.append(record)
        accepted.append(job)
        batch_bytes += Path(job.raw_path).stat().st_size
        if batch_bytes >= 16 * 1024 * 1024:
            break
    if records:
        try:
            repository.insert_batch(records)
        except Exception as exc:
            for job in accepted:
                spool.mark_failed(job, f"storage unavailable: {type(exc).__name__}", retry=True)
            raise
        for job in accepted:
            spool.mark_done(job)
    return {"inserted": len(accepted), "failed": failed}


def _enron_members(archive: tarfile.TarFile) -> Iterator[tarfile.TarInfo]:
    for member in archive:
        if member.isfile() and member.size and "/" in member.name and not Path(member.name).name.startswith("."):
            yield member


def import_enron(
    archive_path: Path,
    spool: DurableSpool,
    repository: ClickHouseRepository,
    *,
    limit: int = 100_000,
    batch_size: int = 250,
    report_path: Path | None = None,
) -> dict[str, object]:
    """Stream an official Enron tar.gz; never extract archive paths to disk."""
    if not archive_path.is_file():
        raise FileNotFoundError(archive_path)
    if limit < 1 or not 1 <= batch_size <= 500:
        raise ValueError("invalid import limit or batch size")
    started = time.monotonic()
    counts = {"seen": 0, "inserted": 0, "duplicate": 0, "skipped_oversize": 0, "parse_failed": 0}
    batch: list[MailRecord] = []
    jobs: list[SpoolJob] = []

    def flush() -> None:
        if not batch:
            return
        repository.insert_batch(batch)
        for job in jobs:
            spool.mark_done(job)
        counts["inserted"] += len(batch)
        batch.clear()
        jobs.clear()

    with tarfile.open(archive_path, mode="r|gz") as archive:
        for member in _enron_members(archive):
            if counts["seen"] >= limit:
                break
            counts["seen"] += 1
            if member.size > spool.settings.max_message_bytes:
                counts["skipped_oversize"] += 1
                continue
            source = archive.extractfile(member)
            if source is None:
                continue
            raw = source.read(spool.settings.max_message_bytes + 1)
            if len(raw) > spool.settings.max_message_bytes:
                counts["skipped_oversize"] += 1
                continue
            receipt = spool.enqueue(raw, source="enron")
            job = spool.get_job(receipt.job_id)
            if job.status == "done":
                counts["duplicate"] += 1
                continue
            spool.mark_processing(job)
            try:
                record = _parse_job(spool, job, isolated=False)
            except (ValueError, ParseLimitError, RuntimeError) as exc:
                spool.mark_failed(job, f"{type(exc).__name__}: {exc}")
                counts["parse_failed"] += 1
                continue
            batch.append(record)
            jobs.append(job)
            if len(batch) >= batch_size:
                flush()
    flush()
    seconds = time.monotonic() - started
    report: dict[str, object] = {
        **counts,
        "seconds": round(seconds, 3),
        "messages_per_second": round(counts["inserted"] / seconds, 3) if seconds else 0,
        "max_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "archive": str(archive_path),
        "archive_size_bytes": archive_path.stat().st_size,
    }
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mailsec")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="start local HTTP API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    worker = sub.add_parser("worker", help="parse pending HTTP submissions")
    worker.add_argument("--loop", action="store_true")
    worker.add_argument("--batch-size", type=int, default=100)
    bulk = sub.add_parser("import-enron", help="stream official Enron tar.gz into ClickHouse")
    bulk.add_argument("archive", type=Path)
    bulk.add_argument("--limit", type=int, default=100_000)
    bulk.add_argument("--batch-size", type=int, default=250)
    bulk.add_argument("--report", type=Path)
    directory = sub.add_parser("import-directory", help="index verified unpacked corpus without copying raw mail")
    directory.add_argument("directory", type=Path)
    directory.add_argument("--source", default="enron")
    directory.add_argument("--limit", type=int, default=100_000)
    directory.add_argument("--batch-size", type=int, default=250)
    directory.add_argument("--report", type=Path)
    query = sub.add_parser("query", help="authenticated JSON event query")
    query.add_argument("json", nargs="?", default="{}")
    query.add_argument("--url", default="http://127.0.0.1:8080")
    query.add_argument("--legacy-eml", action="store_true", help="search legacy EML records")
    natural = sub.add_parser("ask", help="authorized natural-language search (preview by default)")
    natural.add_argument("text")
    natural.add_argument("--execute", action="store_true")
    natural.add_argument("--url", default="http://127.0.0.1:8080")
    natural.add_argument("--legacy-eml", action="store_true", help="query legacy EML records")
    args = parser.parse_args(argv)
    if args.command == "worker" and not 1 <= args.batch_size <= 500:
        parser.error("worker batch size must be 1..500")
    if args.command == "serve":
        import logging
        import uvicorn

        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
        uvicorn.run("mailsec_smart_search.api:app", host=args.host, port=args.port,
                    workers=1, limit_concurrency=64, timeout_keep_alive=5, access_log=False)
        return 0
    settings = Settings.from_env()
    if args.command in {"query", "ask"}:
        import httpx

        payload = json.loads(args.json) if args.command == "query" else {"text": args.text, "execute": args.execute}
        endpoint = ("/v1/search" if args.command == "query" else "/v1/nl/query") if args.legacy_eml else ("/api/v1/mails" if args.command == "query" else "/api/v1/nl/query")
        with httpx.Client(timeout=30, trust_env=False) as client:
            if args.command == "query" and not args.legacy_eml:
                response = client.get(args.url.rstrip("/") + endpoint, params=payload,
                                      headers={"X-Mailsec-Token": settings.api_token})
            else:
                response = client.post(args.url.rstrip("/") + endpoint, json=payload,
                                       headers={"X-Mailsec-Token": settings.api_token})
        print(response.text)
        return 0 if response.is_success else 1
    spool = DurableSpool(settings)
    repository = ClickHouseRepository(settings)
    if args.command != "worker":
        repository.ensure_schema()
    if args.command == "import-directory":
        from .importer import import_directory

        report = import_directory(args.directory, settings, repository, limit=args.limit,
                                  batch_size=args.batch_size, source=args.source, report_path=args.report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1 if report["failed"] else 0
    if args.command == "worker":
        spool.recover()
        event_spool = EventSpool(settings)
        events = EventRepository(repository)
        eml_schema_ready = False
        event_schema_ready = False
        while True:
            failed = False
            # Independent queues: an EML parse/storage error must not starve JSON events.
            try:
                if not eml_schema_ready:
                    repository.ensure_schema()
                    eml_schema_ready = True
                result = process_spool_once(spool, repository, batch_size=args.batch_size)
                failed = bool(result["failed"])
                if result["inserted"] or result["failed"]:
                    print(json.dumps({"eml": result}), flush=True)
            except Exception as exc:
                failed = True
                print(f"EML worker error: {type(exc).__name__}", file=sys.stderr, flush=True)
            try:
                if not event_schema_ready:
                    events.ensure_schema()
                    event_schema_ready = True
                inserted = event_spool.flush(events, batch_size=args.batch_size)
                counts = event_spool.status_counts()
                failed = failed or bool(counts["retry"])
                if inserted or counts["retry"]:
                    print(json.dumps({"events_inserted": inserted, "queue": counts}), flush=True)
            except Exception as exc:
                failed = True
                print(f"event worker error: {type(exc).__name__}", file=sys.stderr, flush=True)
            if not args.loop:
                return 1 if failed else 0
            time.sleep(1)
    if args.command == "import-enron":
        report = import_enron(args.archive, spool, repository, limit=args.limit,
                              batch_size=args.batch_size, report_path=args.report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1 if report["parse_failed"] or report["skipped_oversize"] else 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
