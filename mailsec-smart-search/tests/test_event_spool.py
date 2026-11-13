import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from mailsec_smart_search.event_spool import ConflictError, EventSpool
from mailsec_smart_search.spool import MessageTooLargeError, SpoolFullError


def settings(tmp_path, *, max_message_bytes=1000, max_spool_bytes=1000):
    return SimpleNamespace(data_dir=tmp_path, max_message_bytes=max_message_bytes,
                           max_spool_bytes=max_spool_bytes)


def normalize(payload, ingress_ip='unknown', now=None, canonical=False):
    default_id = ('evt-1' if payload.get('sourceEventId') == 'source-1'
                  else f"evt-{payload['sourceEventId']}" if payload.get('sourceEventId')
                  else uuid4().hex)
    return {'event_id': payload.get('eventId', default_id),
            'source_system_id': payload.get('sourceSystemId', '-'),
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


def test_batch_rejects_invalid_size_and_rolls_back_late_validation(tmp_path, monkeypatch):
    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', normalize)
    spool = EventSpool(settings(tmp_path, max_spool_bytes=10000))
    with pytest.raises(ValueError):
        spool.enqueue_many([])
    with pytest.raises(ValueError):
        spool.enqueue_many([{}] * 1001)
    with pytest.raises(ValueError):
        spool.enqueue_many([{'sourceEventId': 'one'}, None])
    assert spool.status_counts()['pending'] == 0


def test_batch_conflict_and_quota_failures_are_atomic(tmp_path, monkeypatch):
    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', normalize)
    spool = EventSpool(settings(tmp_path, max_spool_bytes=10000))
    spool.enqueue({'sourceSystemId': 'tenant', 'sourceEventId': 'existing'})
    with pytest.raises(ConflictError):
        spool.enqueue_many([
            {'sourceSystemId': 'tenant', 'sourceEventId': 'new'},
            {'sourceSystemId': 'tenant', 'sourceEventId': 'existing', 'subject': 'changed'},
        ])
    assert spool.status_counts()['pending'] == 1
    assert spool.list_jobs()['total'] == 1

    tiny = EventSpool(settings(tmp_path / 'tiny', max_spool_bytes=300))
    with pytest.raises(SpoolFullError):
        tiny.enqueue_many([{'sourceEventId': 'one'}, {'sourceEventId': 'two'}])
    assert tiny.status_counts()['pending'] == 0


def test_batch_replay_and_global_event_id_uniqueness(tmp_path, monkeypatch):
    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', normalize)
    spool = EventSpool(settings(tmp_path, max_spool_bytes=10000))
    one = {'sourceSystemId': 'tenant', 'sourceEventId': 'one', 'eventId': 'shared-id'}
    receipts = spool.enqueue_many([one, one])
    assert receipts[0] == receipts[1]
    assert spool.enqueue_many([one]) == [receipts[0]]
    with pytest.raises(ConflictError):
        spool.enqueue_many([
            {'sourceSystemId': 'tenant', 'sourceEventId': 'fresh', 'eventId': 'fresh-id'},
            {'sourceSystemId': 'tenant', 'sourceEventId': 'other', 'eventId': 'shared-id'},
        ])
    assert spool.status_counts()['pending'] == 1
    with spool._connect() as connection:
        indexes = connection.execute("PRAGMA index_list('jobs')").fetchall()
    assert 'jobs_event_id' in [row['name'] for row in indexes]


def test_old_pair_receipt_survives_uuid_upgrade(tmp_path, monkeypatch):
    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', normalize)
    spool = EventSpool(settings(tmp_path, max_spool_bytes=10000))
    payload = {'sourceSystemId': 'tenant', 'sourceEventId': 'one'}
    receipt = spool.enqueue(payload)
    with spool._connect() as connection:
        connection.execute('UPDATE jobs SET event_id = ? WHERE job_id = ?',
                           ('historical-digest-id', receipt['jobId']))
    reopened = EventSpool(settings(tmp_path, max_spool_bytes=10000))
    replay = reopened.enqueue(payload)
    assert replay == {**receipt, 'eventId': 'historical-digest-id'}
    assert reopened.status_counts()['pending'] == 1


def test_summary_and_job_listing_exclude_private_data(tmp_path, monkeypatch):
    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', normalize)
    spool = EventSpool(settings(tmp_path, max_spool_bytes=10000))
    spool.enqueue({'sourceEventId': 'one', 'subject': 'private body'})
    spool.enqueue({'sourceEventId': 'two'})
    summary = spool.summary()
    assert summary['counts'] == {'pending': 2, 'retry': 0, 'done': 0}
    assert 0 < summary['pending_bytes'] <= summary['queue_quota_bytes']
    assert summary['disk_bytes'] > 0 and summary['oldest_pending_at']
    page = spool.list_jobs(status='pending', limit=1, offset=1)
    assert page['total'] == 2 and len(page['items']) == 1
    assert not {'event_json', 'payload_hash', 'payload_bytes', 'raw_path'} & set(page['items'][0])
    assert 'private body' not in str(page) and 'private body' not in str(summary)
    with pytest.raises(ValueError):
        spool.list_jobs(status='bogus')
    with pytest.raises(ValueError):
        spool.list_jobs(limit=201)


def test_canonical_flag_is_forwarded_for_single_and_batch(tmp_path, monkeypatch):
    seen = []

    def recorder(payload, ingress_ip='unknown', now=None, canonical=False):
        seen.append((canonical, ingress_ip))
        return normalize(payload, ingress_ip=ingress_ip, now=now, canonical=canonical)

    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', recorder)
    spool = EventSpool(settings(tmp_path, max_spool_bytes=10000))
    spool.enqueue({'sourceEventId': 'one'}, ingress_ip='127.0.0.1', canonical=True)
    spool.enqueue_many([{'sourceEventId': 'two'}], ingress_ip='127.0.0.2', canonical=True)
    spool.enqueue({'sourceEventId': 'three'})
    assert seen == [(True, '127.0.0.1'), (True, '127.0.0.2'), (False, 'unknown')]


def test_real_canonical_batch_preserves_uuid_and_rolls_back_invalid(tmp_path):
    spool = EventSpool(settings(tmp_path, max_message_bytes=16000, max_spool_bytes=100000))
    payload = {
        'eventId': 'd0c41219-3950-4e1b-8f2c-e0a850a82d2f',
        'sourceSystemId': 'MAIL_DEMO_EXCEL', 'sourceEventId': 'demo-row-1',
        'eventTime': '2026-05-18T17:01:38Z', 'from': 'sender@example.org',
        'to': ['recipient@example.org'], 'subject': 'demo',
        'rawHeaders': 'From: sender@example.org\r\nTo: recipient@example.org',
    }
    receipts = spool.enqueue_many([payload, payload], canonical=True)
    assert receipts[0] == receipts[1]
    assert receipts[0]['eventId'] == payload['eventId']
    assert spool.status_counts()['pending'] == 1
    second = {**payload, 'eventId': '4ca92e6b-ba6f-4bd2-9bb9-e8186ccc0128',
              'sourceEventId': 'demo-row-2'}
    with pytest.raises(ValueError):
        spool.enqueue_many([second, {**payload, 'sourceEventId': 'missing-recipient', 'to': []}],
                           canonical=True)
    assert spool.status_counts()['pending'] == 1


def test_enqueue_batch_larger_than_worker_chunk_flushes_in_parts(tmp_path, monkeypatch):
    monkeypatch.setattr('mailsec_smart_search.event_spool.normalize_event', normalize)
    one = {'sourceEventId': 'one', 'subject': 'a'}
    two = {'sourceEventId': 'two', 'subject': 'b'}
    row_bytes = len(json.dumps(normalize(one), ensure_ascii=False,
                               separators=(',', ':'), allow_nan=False).encode('utf-8'))
    monkeypatch.setattr('mailsec_smart_search.event_spool._MAX_BATCH_BYTES', row_bytes + 1)
    spool = EventSpool(settings(tmp_path, max_spool_bytes=10000))
    receipts = spool.enqueue_many([one, two])
    assert len(receipts) == 2 and spool.status_counts()['pending'] == 2
    repository = Repository()
    assert spool.flush(repository) == 1
    assert spool.status_counts()['pending'] == 1
    assert spool.flush(repository) == 1
    assert spool.status_counts()['done'] == 2
    with pytest.raises(MessageTooLargeError):
        spool.enqueue({'sourceEventId': 'three', 'subject': 'x' * 20})
    assert spool.status_counts()['done'] == 2
