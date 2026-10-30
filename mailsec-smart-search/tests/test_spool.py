from dataclasses import replace
import hashlib

import pytest

from mailsec_smart_search.config import Settings
from mailsec_smart_search.spool import DurableSpool, SpoolFullError


def test_restart_dedup_recover_and_states(tmp_path):
    settings = replace(Settings(), data_dir=tmp_path, max_spool_bytes=100)
    spool = DurableSpool(settings)
    receipt = spool.enqueue(b"Subject: Hi\r\n\r\nHi")
    assert receipt.status == "pending"
    assert spool.enqueue(b"Subject: Hi\r\n\r\nHi").job_id == receipt.job_id
    assert len(list((tmp_path / "spool" / "raw").glob("*.eml"))) == 1
    restarted = DurableSpool(settings)
    assert restarted.load_raw(receipt.job_id) == b"Subject: Hi\r\n\r\nHi"
    assert restarted.get_job(receipt.job_id).status == "pending"
    restarted.mark_processing(receipt.job_id)
    assert restarted.recover()[0].status == "retry"
    assert restarted.mark_failed(receipt.job_id, "temporary", retry=True).attempts == 2
    assert restarted.mark_done(receipt.job_id).status == "done"
    assert restarted.pending() == []


def test_quota_and_bounded_queue(tmp_path):
    spool = DurableSpool(replace(Settings(), data_dir=tmp_path, max_spool_bytes=4))
    spool.enqueue(b"one")
    with pytest.raises(SpoolFullError):
        spool.enqueue(b"two")
    assert len(spool.pending(limit=1)) == 1
    with pytest.raises(ValueError):
        spool.pending(limit=0)


def test_orphan_raw_recovered_after_interrupted_enqueue(tmp_path):
    settings = replace(Settings(), data_dir=tmp_path)
    spool = DurableSpool(settings)
    raw = b"Subject: orphan\r\n\r\nbody"
    digest = hashlib.sha256(raw).hexdigest()
    (spool.raw_dir / f"{digest}.eml").write_bytes(raw)
    restarted = DurableSpool(settings)
    job = restarted.recover()[0]
    assert job.mail_id == digest
    assert restarted.load_raw(job) == raw
    assert restarted.get_job(digest).source == "recovered"


def test_pending_uses_ready_index_not_done_history(tmp_path, monkeypatch):
    spool = DurableSpool(replace(Settings(), data_dir=tmp_path))
    done = spool.enqueue(b"Subject: done\r\n\r\nbody")
    spool.mark_done(done.job_id)
    ready = spool.enqueue(b"Subject: ready\r\n\r\nbody")
    original = spool._read

    def guarded(path):
        if path.stem == done.job_id:
            raise AssertionError("pending scanned a completed job")
        return original(path)

    monkeypatch.setattr(spool, "_read", guarded)
    assert [job.job_id for job in spool.pending()] == [ready.job_id]
    (spool.ready_dir / f"{ready.job_id}.ready").unlink()
    (spool.ready_dir / f"{done.job_id}.ready").touch()
    restarted = DurableSpool(replace(Settings(), data_dir=tmp_path))
    assert [job.job_id for job in restarted.pending()] == [ready.job_id]
