from types import SimpleNamespace

import pytest

from mailsec_smart_search.event_spool import ConflictError, EventSpool
from mailsec_smart_search.spool import MessageTooLargeError, SpoolFullError


def settings(tmp_path, *, max_message_bytes=1000, max_spool_bytes=1000):
    return SimpleNamespace(data_dir=tmp_path, max_message_bytes=max_message_bytes,
                           max_spool_bytes=max_spool_bytes)


def normalize(payload, ingress_ip='unknown', now=None):
    return {'event_id': 'evt-1', 'source_system_id': payload.get('sourceSystemId', '-'),
            'source_event_id': payload.get('sourceEventId', '-'),
            'trace_id': 'trc-1', 'event_time': '2026-10-14T01:00:00+00:00',
            'ingested_at': '2026-10-14T01:00:00+00:00', 'subject': payload.get('subject', '-')}


class Repository:
    def __init__(self, fail=False):
        self.fail = fail
        self.events = []

    def insert_batch(self, events):
        if self.fail:
            raise RuntimeError('sensitive payload')
        self.events.extend(events)
        return len(events)


def test_replay_conflict_and_durable_flush(tmp_path, monkeypatch):
    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', normalize)
    spool = EventSpool(settings(tmp_path))
    payload = {'sourceSystemId': 'tenant', 'sourceEventId': 'source-1', 'subject': 'hi'}
    receipt = spool.enqueue(payload)
    assert spool.enqueue(payload) == receipt
    with pytest.raises(ConflictError):
        spool.enqueue({**payload, 'subject': 'different'})
    assert spool.get_job(receipt['jobId'])['status'] == 'pending'
    repository = Repository(fail=True)
    assert spool.flush(repository) == 0
    assert 'sensitive' not in str(spool.get_job(receipt['jobId']))
    repository.fail = False
    assert EventSpool(settings(tmp_path)).flush(repository) == 1
    assert repository.events[0]['event_id'] == 'evt-1'
    assert spool.get_job(receipt['jobId'])['status'] == 'done'
    assert spool.flush(repository) == 0


def test_limits_and_no_source_pair(tmp_path, monkeypatch):
    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', normalize)
    spool = EventSpool(settings(tmp_path, max_message_bytes=100, max_spool_bytes=250))
    with pytest.raises(MessageTooLargeError):
        spool.enqueue({'subject': 'a' * 120})
    first = spool.enqueue({'subject': 'first'})
    with pytest.raises(SpoolFullError):
        spool.enqueue({'subject': 'another'})
    assert spool.get_job(first['jobId'])['status'] == 'pending'


def test_real_normalizer_replay_and_no_pair_create_distinct_events(tmp_path):
    spool = EventSpool(settings(tmp_path, max_message_bytes=1000, max_spool_bytes=10000))
    payload = {'sourceSystemId': 'tenant', 'sourceEventId': 'evt-1',
               'mail': {'senderaccount': 'a@example.com', 'toaccount': 'b@example.com'}}
    a = spool.enqueue(payload)
    assert spool.enqueue(payload) == a
    no_pair = {'mail': {'subject': 'hello'}}
    b = spool.enqueue(no_pair)
    c = spool.enqueue(no_pair)
    assert b['eventId'] != c['eventId']
    assert spool.get_job(a['jobId'])['event_id'] == a['eventId']


def test_status_counts_do_not_expose_payload(tmp_path, monkeypatch):
    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', normalize)
    spool = EventSpool(settings(tmp_path))
    spool.enqueue({'subject': 'secret text'})
    assert spool.status_counts() == {'pending': 1, 'retry': 0, 'done': 0}
    repository = Repository(fail=True)
    assert spool.flush(repository) == 0
    assert spool.status_counts() == {'pending': 0, 'retry': 1, 'done': 0}
    repository.fail = False
    assert spool.flush(repository) == 1
    assert spool.status_counts() == {'pending': 0, 'retry': 0, 'done': 1}


def test_spool_files_are_private_and_existing_permissions_are_tightened(tmp_path):
    import stat

    root = tmp_path / 'events'
    root.mkdir(mode=0o755)
    db = root / 'queue.sqlite3'
    db.touch(mode=0o644)
    spool = EventSpool(settings(tmp_path))
    wal = root / 'queue.sqlite3-wal'
    wal.touch(mode=0o644)
    spool._secure_database_file()
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    assert stat.S_IMODE(wal.stat().st_mode) == 0o600
    spool.status_counts()
    assert stat.S_IMODE(db.stat().st_mode) == 0o600


def test_spool_rejects_symlinked_database(tmp_path):
    root = tmp_path / 'events'
    root.mkdir()
    target = tmp_path / 'target'
    target.write_text('do not touch')
    (root / 'queue.sqlite3').symlink_to(target)
    with pytest.raises(OSError):
        EventSpool(settings(tmp_path))
    assert target.read_text() == 'do not touch'


def test_spool_rejects_symlinked_directory(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    (tmp_path / 'events').symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        EventSpool(settings(tmp_path))


def test_failed_insert_is_observable_without_payload_leak(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', normalize)
    spool = EventSpool(settings(tmp_path))
    spool.enqueue({'subject': 'secret text'})
    spool.flush(Repository(fail=True))
    assert 'event_batch_retry' in caplog.text and 'RuntimeError' in caplog.text
    assert 'sensitive payload' not in caplog.text and 'secret text' not in caplog.text


def test_disk_pressure_rejects_new_events_but_preserves_existing_receipts(tmp_path, monkeypatch):
    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', normalize)
    spool = EventSpool(settings(tmp_path, max_spool_bytes=10000))
    payload = {'sourceSystemId': 'tenant', 'sourceEventId': 'one'}
    receipt = spool.enqueue(payload)
    monkeypatch.setattr('mailsec_smart_search.event_spool.shutil.disk_usage', lambda path: SimpleNamespace(free=0))
    assert spool.enqueue(payload) == receipt
    with pytest.raises(SpoolFullError):
        spool.enqueue({'sourceSystemId': 'tenant', 'sourceEventId': 'two'})
    assert spool.get_job(receipt['jobId'])['status'] == 'pending'
