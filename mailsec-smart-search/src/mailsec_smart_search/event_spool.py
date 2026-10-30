"""Durable SQLite queue for normalized JSON events before ClickHouse delivery."""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import re
import shutil
import os
import stat
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator
from uuid import uuid4

from .config import Settings
from .events import normalize_event
from .spool import MessageTooLargeError, SpoolFullError

_MAX_BATCH_BYTES = 16 * 1024 * 1024
_LOG = logging.getLogger(__name__)


class ConflictError(ValueError):
    """Same source identity was submitted with a different payload."""


class EventSpool:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.root = Path(settings.data_dir) / 'events'
        if self.root.is_symlink():
            raise ValueError('event spool directory must not be a symlink')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not stat.S_ISDIR(self.root.lstat().st_mode):
            raise ValueError('event spool path must be a directory')
        self.root.chmod(0o700)
        self.path = self.root / 'queue.sqlite3'
        self.lock_path = self.root / '.flush.lock'
        self._secure_database_file()
        with self._connect() as connection:
            connection.executescript('''
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    source_system_id TEXT NOT NULL,
                    source_event_id TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    accepted_at TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    event_json BLOB,
                    payload_bytes INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    error_type TEXT NOT NULL DEFAULT ''
                );
                CREATE UNIQUE INDEX IF NOT EXISTS jobs_source_pair
                ON jobs(source_system_id, source_event_id)
                WHERE source_system_id != '-' AND source_event_id != '-';
                CREATE INDEX IF NOT EXISTS jobs_ready ON jobs(status, accepted_at);
            ''')

    def _secure_database_file(self) -> None:
        for path, create in ((self.path, True),
                             (Path(f'{self.path}-wal'), False),
                             (Path(f'{self.path}-shm'), False)):
            if not create and not (path.exists() or path.is_symlink()):
                continue
            flags = os.O_RDWR | os.O_NOFOLLOW | (os.O_CREAT if create else 0)
            fd = os.open(path, flags, 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ValueError('event spool database file must be regular')
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self._secure_database_file()
        connection = sqlite3.connect(self.path, timeout=30)
        try:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('PRAGMA synchronous=FULL')
            connection.row_factory = sqlite3.Row
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _flush_lock(self) -> Iterator[None]:
        with self.lock_path.open('a+b') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    @staticmethod
    def _receipt(row: sqlite3.Row) -> dict[str, str]:
        return {
            'eventId': row['event_id'], 'sourceSystemId': row['source_system_id'],
            'sourceEventId': row['source_event_id'], 'traceId': row['trace_id'],
            'status': 'accepted', 'acceptedAt': row['accepted_at'], 'jobId': row['job_id'],
        }

    def enqueue(self, payload: dict[str, Any], ingress_ip: str = 'unknown') -> dict[str, str]:
        if not isinstance(payload, dict):
            raise ValueError('JSON payload must be an object')
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':'),
                         allow_nan=False).encode('utf-8')
        if len(raw) > self.settings.max_message_bytes:
            raise MessageTooLargeError('JSON event exceeds configured byte limit')
        digest = hashlib.sha256(raw).hexdigest()
        now = datetime.now(timezone.utc)
        event = normalize_event(payload, ingress_ip=ingress_ip, now=now)
        event_bytes = json.dumps(event, ensure_ascii=False, separators=(',', ':'),
                                 allow_nan=False).encode('utf-8')
        if len(event_bytes) > _MAX_BATCH_BYTES:
            raise MessageTooLargeError('normalized JSON event exceeds batch byte limit')
        source_system = str(event['source_system_id'])
        source_event = str(event['source_event_id'])
        pair = source_system not in {'', '-'} and source_event not in {'', '-'}
        accepted_at = now.isoformat()
        job_id = uuid4().hex
        with self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            if pair:
                existing = connection.execute(
                    'SELECT * FROM jobs WHERE source_system_id = ? AND source_event_id = ?',
                    (source_system, source_event)).fetchone()
                if existing:
                    if existing['payload_hash'] != digest:
                        raise ConflictError('source event identity already exists with different payload')
                    return self._receipt(existing)
            used = connection.execute("SELECT coalesce(sum(payload_bytes), 0) FROM jobs WHERE status IN ('pending', 'retry')").fetchone()[0]
            if used + len(event_bytes) > self.settings.max_spool_bytes:
                raise SpoolFullError('event spool byte quota exceeded')
            # Receipts must stay available for idempotency after payload delivery.
            # Bound their backing files too rather than silently growing forever.
            disk_used = sum(path.stat().st_size for path in
                            (self.path, Path(str(self.path) + '-wal'), Path(str(self.path) + '-shm'))
                            if path.exists())
            reserve = len(event_bytes) * 3 + 65536
            disk_budget = max(1024 * 1024, self.settings.max_spool_bytes)
            if disk_used + reserve > disk_budget or shutil.disk_usage(self.root).free < max(64 * 1024 * 1024, reserve):
                raise SpoolFullError('event spool backing files or disk free-space limit reached')
            connection.execute('''INSERT INTO jobs
                (job_id, event_id, source_system_id, source_event_id, trace_id,
                 accepted_at, payload_hash, event_json, payload_bytes, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')''',
                (job_id, event['event_id'], source_system, source_event, event['trace_id'],
                 accepted_at, digest, event_bytes, len(event_bytes)))
            row = connection.execute('SELECT * FROM jobs WHERE job_id = ?', (job_id,)).fetchone()
            return self._receipt(row)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute('''SELECT job_id, event_id, source_system_id,
                source_event_id, trace_id, accepted_at, status, attempts, error_type
                FROM jobs WHERE job_id = ?''', (job_id,)).fetchone()
            if not row:
                return None
            return dict(row)

    def status_counts(self) -> dict[str, int]:
        """Return aggregate queue state without inspecting payloads."""
        with self._connect() as connection:
            rows = connection.execute('SELECT status, count(*) FROM jobs GROUP BY status').fetchall()
            counts = {'pending': 0, 'retry': 0, 'done': 0}
            counts.update({row[0]: row[1] for row in rows})
            return counts

    def flush(self, repository: Any, batch_size: int = 250) -> int:
        if not 1 <= batch_size <= 1000:
            raise ValueError('batch_size must be 1..1000')
        with self._flush_lock():
            with self._connect() as connection:
                rows = connection.execute('''SELECT job_id, event_json, payload_bytes
                    FROM jobs WHERE status IN ('pending', 'retry')
                    ORDER BY accepted_at, job_id LIMIT ?''', (batch_size,)).fetchall()
                selected: list[sqlite3.Row] = []
                size = 0
                for row in rows:
                    if size + row['payload_bytes'] > _MAX_BATCH_BYTES:
                        break
                    selected.append(row)
                    size += row['payload_bytes']
                if not selected:
                    return 0
                events = [json.loads(row['event_json']) for row in selected]
                ids = [row['job_id'] for row in selected]
                try:
                    inserted = repository.insert_batch(events)
                    if inserted != len(events):
                        raise RuntimeError('incomplete event batch insert')
                except Exception as exc:
                    # Driver messages can contain query data. Expose only class/code,
                    # never the raw exception or its potentially sensitive traceback.
                    code = re.search(r"(?:code:|Code:)\s*(\d{1,6})", str(exc))
                    _LOG.error("event_batch_retry batch_size=%s error_type=%s database_code=%s",
                               len(ids), type(exc).__name__, code.group(1) if code else "unknown")
                    connection.executemany('''UPDATE jobs SET status = 'retry', attempts = attempts + 1,
                        error_type = ? WHERE job_id = ?''', [(type(exc).__name__, job_id) for job_id in ids])
                    return 0
                connection.executemany('''UPDATE jobs SET status = 'done', event_json = NULL,
                    payload_bytes = 0, error_type = '' WHERE job_id = ?''', [(job_id,) for job_id in ids])
                return len(ids)
