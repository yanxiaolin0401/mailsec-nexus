"""Resumable, bounded import of an unpacked public EML corpus."""

from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import os
import resource
import sqlite3
import stat
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .config import Settings
from .domain import MailRecord
from .parser import ParseTimeoutError, parse_eml


def _worker(conn: Any, memory_limit_bytes: int) -> None:
    # Hostile MIME is parsed only in this killable process, not in the importer.
    resource.setrlimit(resource.RLIMIT_AS, (memory_limit_bytes, memory_limit_bytes))
    try:
        while True:
            try:
                task = conn.recv()
            except EOFError:
                return
            if task is None:
                return
            raw, kwargs = task
            try:
                conn.send((True, parse_eml(raw, **kwargs)))
            except Exception as exc:
                conn.send((False, f"{type(exc).__name__}: {str(exc)[:300]}"))
    finally:
        conn.close()


class ReusableParser:
    """Reuse one parser subprocess; kill and restart it after any timeout/crash."""

    def __init__(self, *, timeout_seconds: float, memory_limit_bytes: int = 512 * 1024 * 1024):
        if timeout_seconds <= 0 or memory_limit_bytes < 64 * 1024 * 1024:
            raise ValueError("invalid parser limits")
        self.timeout_seconds = timeout_seconds
        self.memory_limit_bytes = memory_limit_bytes
        self._process: Any = None
        self._conn: Any = None

    @property
    def pid(self) -> int | None:
        return self._process.pid if self._process is not None and self._process.is_alive() else None

    def _start(self) -> None:
        if self.pid is not None:
            return
        self.close()
        parent, child = mp.get_context("spawn").Pipe(duplex=True)
        process = mp.get_context("spawn").Process(
            target=_worker, args=(child, self.memory_limit_bytes), daemon=True,
        )
        process.start()
        child.close()
        self._conn = parent
        self._process = process

    def parse(self, raw: bytes, **kwargs: Any) -> MailRecord:
        self._start()
        try:
            self._conn.send((raw, kwargs))
            if not self._conn.poll(self.timeout_seconds):
                raise ParseTimeoutError("EML parse timed out")
            ok, result = self._conn.recv()
            if not ok:
                raise RuntimeError(f"isolated EML parser failed: {result}")
            return result
        except (ParseTimeoutError, EOFError, BrokenPipeError, OSError):
            self.close()
            raise

    def close(self) -> None:
        if self._process is not None:
            if self._process.is_alive():
                self._process.terminate()
                self._process.join(1)
                if self._process.is_alive():
                    self._process.kill()
                    self._process.join()
            else:
                self._process.join()
            self._process = None
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> ReusableParser:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _files(root: Path) -> Iterator[Path]:
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories
                                if not (Path(current) / name).is_symlink())
        for name in sorted(files):
            # Public corpora include helper scripts/readmes alongside messages.
            # These are neither executed nor indexed as mail.
            if name.startswith(".") or name.lower() in {"cmds", "readme", "readme.txt", "license", "license.txt"}:
                continue
            yield Path(current) / name


def _read_file(path: Path, max_bytes: int) -> bytes:
    if path.is_symlink():
        raise ValueError("symbolic link skipped")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("not a regular file")
        if before.st_size > max_bytes:
            raise ValueError("EML exceeds configured byte limit")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(max_bytes + 1)
        after = os.fstat(fd)
        if len(raw) > max_bytes:
            raise ValueError("EML exceeds configured byte limit")
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("EML changed while reading")
        return raw
    finally:
        os.close(fd)


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".import-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def import_directory(
    root: Path,
    settings: Settings,
    repository: Any,
    *,
    limit: int = 100_000,
    batch_size: int = 250,
    report_path: Path | None = None,
    source: str = "enron",
) -> dict[str, Any]:
    """Import stable file order; checkpoint a batch only after ClickHouse accepts it.

    The source tree is the raw evidence store and must remain available and immutable.
    A replay after insert but before checkpoint is harmless because mail_id is a
    content digest and the ClickHouse table uses visible FINAL deduplication.
    """
    root = Path(root).resolve(strict=True)
    if not root.is_dir() or limit < 1 or not 1 <= batch_size <= 10_000:
        raise ValueError("root must be a directory, limit positive, batch_size 1..10000")
    datasets_root = settings.datasets_dir.resolve(strict=True)
    if not root.is_relative_to(datasets_root):
        raise ValueError("import root must be inside configured datasets directory")
    if not source or len(source) > 100:
        raise ValueError("invalid source")
    checkpoint_dir = settings.data_dir / "imports"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    report: dict[str, Any] = {
        "root": str(root), "source": source, "seen": 0, "inserted": 0,
        "duplicates": 0, "failed": 0, "seconds": 0.0, "rss_mb": 0.0,
        "errors": [],
    }
    batch: list[MailRecord] = []
    batch_bytes = 0
    pending_ids: set[str] = set()
    write_failed = False

    with closing(sqlite3.connect(checkpoint_dir / "checkpoint.sqlite3")) as db, ReusableParser(
        timeout_seconds=settings.parse_timeout_seconds
    ) as parser:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS imported (mail_id TEXT PRIMARY KEY, raw_path TEXT NOT NULL)")

        def flush() -> bool:
            nonlocal batch_bytes
            if not batch:
                return True
            try:
                repository.insert_batch(batch)
                with db:
                    db.executemany(
                        "INSERT OR IGNORE INTO imported (mail_id, raw_path) VALUES (?, ?)",
                        ((record.mail_id, record.raw_path) for record in batch),
                    )
                report["inserted"] += len(batch)
                batch.clear()
                batch_bytes = 0
                pending_ids.clear()
                return True
            except Exception as exc:
                report["failed"] += len(batch)
                report["errors"].append({"path": "<batch>", "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
                return False

        for path in _files(root):
            if report["seen"] >= limit:
                break
            report["seen"] += 1
            if path.is_symlink():
                continue
            try:
                raw = _read_file(path, settings.max_message_bytes)
                if not raw:
                    raise ValueError("empty EML")
                digest = hashlib.sha256(raw).hexdigest()
                if digest in pending_ids or db.execute(
                    "SELECT 1 FROM imported WHERE mail_id = ?", (digest,)
                ).fetchone():
                    report["duplicates"] += 1
                    continue
                record = parser.parse(
                    raw, mail_id=digest, raw_sha256=digest,
                    raw_path="dataset://" + path.relative_to(datasets_root).as_posix(),
                    source=source, ingested_at=datetime.now(timezone.utc),
                )
                batch.append(record)
                batch_bytes += len(raw)
                pending_ids.add(digest)
                if (len(batch) >= batch_size or batch_bytes >= 16 * 1024 * 1024) and not flush():
                    write_failed = True
                    break
            except Exception as exc:
                report["failed"] += 1
                if len(report["errors"]) < 20:
                    report["errors"].append({"path": str(path.relative_to(root)),
                                             "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
        # The limit break is normal; failed batches remain uncheckpointed.
        if batch and not write_failed:
            flush()

    report["seconds"] = round(time.monotonic() - started, 3)
    report["rss_mb"] = round(max(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                                  resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss) / 1024, 2)
    if report_path is not None:
        _write_report(Path(report_path), report)
    return report
