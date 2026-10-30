from datetime import datetime, timezone
from types import SimpleNamespace

from mailsec_smart_search.event_storage import EventRepository, _COLUMNS


class FakeClient:
    def __init__(self):
        self.commands = []
        self.inserts = []
        self.queries = []

    def command(self, sql):
        self.commands.append(sql)

    def insert(self, table, rows, column_names):
        self.inserts.append((table, rows, column_names))

    def query(self, sql, parameters, settings):
        self.queries.append((sql, parameters, settings))
        if 'count()' in sql:
            return SimpleNamespace(column_names=['total'], result_rows=[(1,)])
        return SimpleNamespace(column_names=['event_id', 'subject'], result_rows=[('evt-1', 'hello')])


def repo():
    client = FakeClient()
    return EventRepository(SimpleNamespace(database='mailsec', client=client)), client


def test_schema_and_insert_do_not_touch_legacy_table():
    repository, client = repo()
    repository.ensure_schema()
    assert any('mail_events' in command for command in client.commands)
    assert not any('mail_records (' in command for command in client.commands)
    item = dict.fromkeys(_COLUMNS, '-')
    item.update({'event_id': 'evt-1', 'event_time': '2026-10-14T01:00:00+00:00',
            'ingested_at': '2026-10-14T01:01:00+00:00',
            'mail_date': '2026-10-14T01:00:00+00:00', 'text_content': 'body'})
    assert repository.insert_batch([item]) == 1
    assert client.inserts[0][0] == 'mailsec.mail_events'
    assert isinstance(client.inserts[0][1][0][client.inserts[0][2].index('event_time')], datetime)
    assert client.inserts[0][1][0][client.inserts[0][2].index('event_time')].tzinfo == timezone.utc


def test_search_is_bounded_parameterized_and_summary_only():
    repository, client = repo()
    response = repository.search({'sender': "x' OR 1=1", 'q': 'secret', 'limit': 2})
    assert response['items'] == [{'event_id': 'evt-1', 'subject': 'hello'}]
    assert response['total'] == 1
    sql, params, settings = client.queries[0]
    assert ' FINAL' in sql and 'raw_json' not in sql and 'text_content' not in sql.split(' FROM')[0]
    assert "x' OR 1=1" not in sql and params['sender'] == "x' OR 1=1"
    assert settings['max_execution_time'] > 0


def test_detail_never_selects_raw_json():
    repository, client = repo()
    assert repository.detail('evt-1')['event_id'] == 'evt-1'
    sql = client.queries[0][0]
    assert 'raw_json' not in sql and 'text_content' in sql


def test_explain_and_stats_reuse_same_safe_filters():
    repository, client = repo()
    plan = repository.explain({'from_time': '2026-10-14T09:00:00+08:00',
                               'attachment_md5': 'abc', 'limit': 3})
    assert plan['parameters']['from_time'].tzinfo == timezone.utc
    assert plan['parameters']['from_time'].hour == 1
    assert 'abc' not in plan['sql']
    assert 'LIMIT {limit:UInt16}' in plan['sql']
    assert repository.stats({'source_system_id': 'tenant'}) == {'total': 1}
    assert client.queries[-1][1] == {'source_system_id': 'tenant'}


def test_repository_construction_does_not_connect():
    class LazyBase:
        database = 'mailsec'

        @property
        def client(self):
            raise AssertionError('unexpected ClickHouse connection')

    repository = EventRepository(LazyBase())
    assert repository.database == 'mailsec'


def test_utc_query_output_includes_timezone_and_aliases_cannot_narrow_filters():
    from mailsec_smart_search.event_storage import _public_row, _EVENT_QUERY_SETTINGS
    value = _public_row(['event_time', 'subject'], (datetime(2026, 10, 21), 'hello'))
    assert value['event_time'] == '2026-10-21T00:00:00+00:00'
    assert _EVENT_QUERY_SETTINGS['prefer_column_name_to_alias'] == 1
