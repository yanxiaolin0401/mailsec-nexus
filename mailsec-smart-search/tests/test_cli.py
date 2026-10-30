from dataclasses import replace

from mailsec_smart_search import cli, importer
from mailsec_smart_search.config import Settings


class Repo:
    database = "mailsec"

    def ensure_schema(self):
        pass


def test_directory_import_failure_is_nonzero(tmp_path, monkeypatch):
    monkeypatch.setattr(Settings, 'from_env', lambda: replace(Settings(), data_dir=tmp_path))
    monkeypatch.setattr(cli, 'ClickHouseRepository', lambda settings: Repo())
    monkeypatch.setattr(importer, 'import_directory', lambda *a, **k: {'failed': 1})
    assert cli.main(['import-directory', str(tmp_path)]) == 1
    monkeypatch.setattr(importer, 'import_directory', lambda *a, **k: {'failed': 0})
    assert cli.main(['import-directory', str(tmp_path)]) == 0


def test_worker_storage_failure_is_nonzero(tmp_path, monkeypatch):
    monkeypatch.setattr(Settings, 'from_env', lambda: replace(Settings(), data_dir=tmp_path))
    monkeypatch.setattr(cli, 'ClickHouseRepository', lambda settings: Repo())

    def fail(*a, **k):
        raise RuntimeError('offline')

    monkeypatch.setattr(cli, 'process_spool_once', fail)
    assert cli.main(['worker']) == 1


def test_worker_consumes_json_even_when_legacy_queue_fails(tmp_path, monkeypatch):
    calls = []
    class EventRepo:
        def __init__(self, base):
            pass
        def ensure_schema(self):
            calls.append('schema')
    class EventQueue:
        def __init__(self, settings):
            pass
        def flush(self, repo, batch_size):
            calls.append('flush')
            return 1
        def status_counts(self):
            return {'retry': 0, 'pending': 0, 'done': 1}
    monkeypatch.setattr(Settings, 'from_env', lambda: replace(Settings(), data_dir=tmp_path))
    monkeypatch.setattr(cli, 'ClickHouseRepository', lambda settings: Repo())
    monkeypatch.setattr(cli, 'EventRepository', EventRepo)
    monkeypatch.setattr(cli, 'EventSpool', EventQueue)
    def fail(*args, **kwargs):
        raise RuntimeError('EML failure must not prevent JSON progress')
    monkeypatch.setattr(cli, 'process_spool_once', fail)
    assert cli.main(['worker']) == 1
    assert calls == ['schema', 'flush']


def test_worker_reports_json_storage_retries_nonzero(tmp_path, monkeypatch):
    class EventRepo:
        def __init__(self, base):
            pass
        def ensure_schema(self):
            pass
    class EventQueue:
        def __init__(self, settings):
            pass
        def flush(self, repo, batch_size):
            return 0
        def status_counts(self):
            return {'retry': 1, 'pending': 0, 'done': 0}
    monkeypatch.setattr(Settings, 'from_env', lambda: replace(Settings(), data_dir=tmp_path))
    monkeypatch.setattr(cli, 'ClickHouseRepository', lambda settings: Repo())
    monkeypatch.setattr(cli, 'EventRepository', EventRepo)
    monkeypatch.setattr(cli, 'EventSpool', EventQueue)
    monkeypatch.setattr(cli, 'process_spool_once', lambda *a, **k: {'inserted': 0, 'failed': 0})
    assert cli.main(['worker']) == 1


def test_legacy_schema_failure_cannot_starve_json_worker(tmp_path, monkeypatch):
    calls = []
    class BrokenLegacy(Repo):
        def ensure_schema(self):
            raise RuntimeError('legacy schema unavailable')
    class EventRepo:
        def __init__(self, base):
            pass
        def ensure_schema(self):
            calls.append('event_schema')
    class Queue:
        def __init__(self, settings):
            pass
        def flush(self, repo, batch_size):
            calls.append('event_flush')
            return 1
        def status_counts(self):
            return {'retry': 0, 'pending': 0, 'done': 1}
    monkeypatch.setattr(Settings, 'from_env', lambda: replace(Settings(), data_dir=tmp_path))
    monkeypatch.setattr(cli, 'ClickHouseRepository', lambda settings: BrokenLegacy())
    monkeypatch.setattr(cli, 'EventRepository', EventRepo)
    monkeypatch.setattr(cli, 'EventSpool', Queue)
    assert cli.main(['worker']) == 1
    assert calls == ['event_schema', 'event_flush']
