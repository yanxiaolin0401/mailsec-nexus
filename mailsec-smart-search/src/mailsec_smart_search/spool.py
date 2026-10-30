"""Crash-recoverable, local raw-mail spool for HTTP ingestion."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .config import Settings
from .domain import JobReceipt


class SpoolFullError(ValueError):
    """The configured spool byte quota would be exceeded."""


class MessageTooLargeError(ValueError):
    """The raw EML exceeds the configured per-message byte limit."""


@dataclass(frozen=True, slots=True)
class SpoolJob:
    job_id: str
    mail_id: str
    raw_sha256: str
    raw_path: str
    source: str
    status: str
    attempts: int
    ingested_at: datetime
    error: str = ""


class DurableSpool:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.root = Path(settings.data_dir) / "spool"
        self.raw_dir = self.root / "raw"
        self.jobs_dir = self.root / "jobs"
        self.ready_dir = self.root / "ready"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.ready_dir.mkdir(parents=True, exist_ok=True)
        self.usage_path = self.root / ".usage"
        # Reconcile the counter once per process start; enqueue stays O(1).
        with self._locked():
            used = sum(path.stat().st_size for path in self.raw_dir.glob("*.eml"))
            self._atomic_bytes(self.usage_path, str(used).encode())
            self._rebuild_ready()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with (self.root / ".lock").open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    @staticmethod
    def _sync_dir(path: Path) -> None:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _atomic_bytes(self, target: Path, payload: bytes) -> None:
        fd, temp = tempfile.mkstemp(prefix=".tmp-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, target)
            self._sync_dir(target.parent)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)

    def _save(self, job: SpoolJob) -> None:
        data = asdict(job)
        data["ingested_at"] = job.ingested_at.isoformat()
        self._atomic_bytes(self.jobs_dir / f"{job.job_id}.json", json.dumps(data, ensure_ascii=False).encode())
        marker = self.ready_dir / f"{job.job_id}.ready"
        if job.status in {"pending", "retry"}:
            if not marker.exists():
                self._atomic_bytes(marker, b"")
        else:
            marker.unlink(missing_ok=True)

    def _rebuild_ready(self) -> None:
        """Repair the derived marker index once at startup or explicit recovery."""
        for marker in self.ready_dir.glob("*.ready"):
            if not (self.jobs_dir / f"{marker.stem}.json").exists():
                marker.unlink(missing_ok=True)
        for path in self.jobs_dir.glob("*.json"):
            job = self._read(path)
            marker = self.ready_dir / f"{job.job_id}.ready"
            if job.status in {"pending", "retry"}:
                if not marker.exists():
                    self._atomic_bytes(marker, b"")
            else:
                marker.unlink(missing_ok=True)

    def _read(self, path: Path) -> SpoolJob:
        data = json.loads(path.read_text())
        data["ingested_at"] = datetime.fromisoformat(data["ingested_at"])
        return SpoolJob(**data)

    def _path(self, job_id: str) -> Path:
        if len(job_id) != 64 or any(char not in "0123456789abcdef" for char in job_id):
            raise ValueError("invalid job_id")
        return self.jobs_dir / f"{job_id}.json"

    def get(self, job_id: str) -> SpoolJob:
        return self._read(self._path(job_id))

    def get_job(self, job_id: str) -> SpoolJob:
        return self.get(job_id)

    def enqueue(self, raw: bytes, source: str = "http") -> JobReceipt:
        if not raw:
            raise ValueError("empty EML")
        if len(raw) > self.settings.max_message_bytes:
            raise MessageTooLargeError("EML exceeds configured byte limit")
        digest = hashlib.sha256(raw).hexdigest()
        raw_path = self.raw_dir / f"{digest}.eml"
        job_path = self._path(digest)
        with self._locked():
            if job_path.exists() and raw_path.exists():
                job = self._read(job_path)
                return JobReceipt(job.job_id, job.mail_id, job.raw_sha256, job.status)
            if not raw_path.exists():
                used = int(self.usage_path.read_text())
                if used + len(raw) > self.settings.max_spool_bytes:
                    raise SpoolFullError("spool byte quota exceeded")
                self._atomic_bytes(raw_path, raw)
                self._atomic_bytes(self.usage_path, str(used + len(raw)).encode())
            job = SpoolJob(digest, digest, digest, str(raw_path.resolve()), source,
                           "pending", 0, datetime.now(timezone.utc))
            self._save(job)
            return JobReceipt(job.job_id, job.mail_id, job.raw_sha256, job.status)

    def pending(self, limit: int = 100) -> list[SpoolJob]:
        """Return a bounded batch without loading the whole queue."""
        if limit <= 0:
            raise ValueError("limit must be positive")
        jobs: list[SpoolJob] = []
        for marker in self.ready_dir.glob("*.ready"):
            path = self.jobs_dir / f"{marker.stem}.json"
            if not path.exists():
                marker.unlink(missing_ok=True)
                continue
            job = self._read(path)
            if job.status in {"pending", "retry"}:
                jobs.append(job)
                if len(jobs) >= limit:
                    break
            else:
                marker.unlink(missing_ok=True)
        return jobs

    def load_raw(self, job: SpoolJob | str) -> bytes:
        item = self.get(job) if isinstance(job, str) else job
        raw = Path(item.raw_path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != item.raw_sha256:
            raise ValueError("raw EML checksum mismatch")
        return raw

    def _transition(self, job: SpoolJob | str, status: str, error: str = "") -> SpoolJob:
        job_id = job if isinstance(job, str) else job.job_id
        with self._locked():
            current = self.get(job_id)
            next_job = SpoolJob(current.job_id, current.mail_id, current.raw_sha256,
                                current.raw_path, current.source, status,
                                current.attempts + (status == "retry"),
                                current.ingested_at, error[:1000])
            self._save(next_job)
            return next_job

    def mark_processing(self, job: SpoolJob | str) -> SpoolJob:
        return self._transition(job, "processing")

    def mark_done(self, job: SpoolJob | str) -> SpoolJob:
        return self._transition(job, "done")

    def mark_failed(self, job: SpoolJob | str, error: str, *, retry: bool = False) -> SpoolJob:
        return self._transition(job, "retry" if retry else "failed", error)

    def recover(self, limit: int = 100) -> list[SpoolJob]:
        """Requeue interrupted jobs, materialize orphaned raw files, return bounded work."""
        with self._locked():
            self._rebuild_ready()
            for path in self.jobs_dir.glob("*.json"):
                job = self._read(path)
                if job.status == "processing":
                    self._save(SpoolJob(job.job_id, job.mail_id, job.raw_sha256,
                                        job.raw_path, job.source, "retry", job.attempts + 1,
                                        job.ingested_at, "interrupted processing"))
            for raw_path in self.raw_dir.glob("*.eml"):
                digest = raw_path.stem
                if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                    continue
                if not self._path(digest).exists():
                    self._save(SpoolJob(digest, digest, digest, str(raw_path.resolve()),
                                        "recovered", "pending", 0, datetime.now(timezone.utc)))
        return self.pending(limit)
