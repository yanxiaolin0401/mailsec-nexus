"""Migration safety regression checks without external database access."""
import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from mailsec_smart_search.config import Settings
from mailsec_smart_search.storage import ClickHouseRepository

spec = importlib.util.spec_from_file_location('migration', Path(__file__).parents[1] / 'scripts/migrate_clickhouse.py')
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


def test_env_values_not_executed_and_password_not_in_repr(tmp_path):
    env = tmp_path / '.env'
    env.write_text('CLICKHOUSE_HOST=example.clickhouse.cloud\nCLICKHOUSE_PORT=8443\n'
                   'CLICKHOUSE_PASSWORD="$(touch NEVER)"\n')
    settings = migration.load_settings(env)
    assert settings.clickhouse_password == '$(touch NEVER)'
    assert 'NEVER' not in repr(settings)
    assert settings.clickhouse_secure


def test_cloud_tls_explicit():
    with patch('clickhouse_connect.get_client') as client:
        ClickHouseRepository._connect(Settings(clickhouse_host='example.clickhouse.cloud'))
        assert client.call_args.kwargs['secure'] is True


def test_canonical_digest_datetime_array_and_map():
    row1 = ('id', datetime(2026, 10, 30), ['a'], {'b': '2', 'a': '1'})
    row2 = ['id', datetime(2026, 10, 30, tzinfo=UTC), ('a',), {'a': '1', 'b': '2'}]
    assert migration.digest(row1) == migration.digest(row2)


def test_existing_rows_skip_but_conflicts_and_duplicates_abort():
    rows = [('a', 'mail 1'), ('b', 'mail 2')]
    assert migration.missing_rows(rows, [rows[0]], 0) == [rows[1]]
    assert migration.missing_rows(rows, rows, 0) == []
    for existing in [[('a', 'different')], [rows[0], rows[0]], [('c', 'unrequested')]]:
        with pytest.raises(ValueError):
            migration.missing_rows(rows, existing, 0)


def repos():
    return [SimpleNamespace(database='mailsec', client=Mock()) for _ in range(2)]


def test_migration_verifies_full_columns_and_rerun_inserts_nothing():
    rows = [('a', 'body'), ('b', 'body2')]
    columns = [('mail_id', 'String'), ('body_text', 'String')]
    snapshot = {'rows': 2, 'unique_ids': 2, 'xor64': 0, 'sum128': 1}
    for existing in [[], rows]:
        source, target = repos()
        source.client.query.side_effect = [SimpleNamespace(result_rows=rows)] + [SimpleNamespace(result_rows=[])] * 16
        target.client.query.side_effect = [SimpleNamespace(result_rows=existing), SimpleNamespace(result_rows=rows)]
        with patch.object(migration, 'schema', return_value=columns), patch.object(
            migration, 'snapshot', side_effect=[snapshot, {**snapshot, 'rows': len(existing)}, snapshot, snapshot]
        ):
            result = migration.migrate_table(source, target, 'mail_records', 500, lambda _: None)
        assert result['verified_rows'] == 2
        assert result['inserted'] == 2 - len(existing)
        assert target.client.insert.call_count == (not existing)
        if not existing:
            settings = target.client.insert.call_args.kwargs['settings']
            assert settings['async_insert'] == 0
            assert settings['insert_deduplication_token'].startswith('mailsec-migrate-')
        assert ' FINAL' in source.client.query.call_args_list[0].args[0]
        assert '> {cursor:String}' in source.client.query.call_args_list[1].args[0]


def test_content_mismatch_after_insert_fails():
    source, target = repos()
    source.client.query.return_value = SimpleNamespace(result_rows=[('a', 'body')])
    target.client.query.side_effect = [SimpleNamespace(result_rows=[]), SimpleNamespace(result_rows=[('a', 'bad')])]
    with patch.object(migration, 'schema', return_value=[('mail_id', 'String'), ('body_text', 'String')]), patch.object(
        migration, 'snapshot', return_value={'rows': 1}
    ), pytest.raises(ValueError, match='SHA-256'):
        migration.migrate_table(source, target, 'mail_records', 10, lambda _: None)


def test_source_change_detected():
    source, target = repos()
    source.client.query.return_value = SimpleNamespace(result_rows=[])
    with patch.object(migration, 'schema', return_value=[('mail_id', 'String')]), patch.object(
        migration, 'snapshot', side_effect=[{'rows': 0}, {'rows': 0}, {'rows': 1}]
    ), pytest.raises(ValueError, match='source changed'):
        migration.migrate_table(source, target, 'mail_records', 10, lambda _: None)


def test_unsafe_targets_rejected_before_connection(tmp_path):
    with pytest.raises(ValueError, match='must differ'):
        migration.run(Settings(), Settings(), report_path=tmp_path / 'r.json')
    with pytest.raises(ValueError, match='TLS'):
        migration.run(Settings(), Settings(clickhouse_host='remote'), report_path=tmp_path / 'r.json')


def test_layout_accepts_cloud_conversion_but_rejects_wrong_version_and_partition():
    repo = repos()[0]
    correct = ('SharedReplacingMergeTree', "SharedReplacingMergeTree('/tables/{uuid}', '{replica}', ingested_at) PARTITION BY cityHash64(event_id) % 16 ORDER BY event_id", 'event_id', 'cityHash64(event_id) % 16')
    repo.client.query.return_value = SimpleNamespace(result_rows=[correct])
    migration.validate_layout(repo, 'mail_events')
    for wrong in [(correct[0], correct[1].replace(', ingested_at', ''), *correct[2:]),
                  (*correct[:3], 'toYYYYMM(event_time)'),
                  (correct[0], correct[1], 'event_time, event_id', correct[3])]:
        repo.client.query.return_value = SimpleNamespace(result_rows=[wrong])
        with pytest.raises(ValueError, match='incompatible'):
            migration.validate_layout(repo, 'mail_events')


def test_snapshot_is_partition_bounded_and_counts_all_rows():
    repo = repos()[0]
    repo.client.query.side_effect = [SimpleNamespace(result_rows=[(2, 2, 1, 2, 'b')]), SimpleNamespace(result_rows=[(0, 0, 0, 0, '')])] * 16 + [SimpleNamespace(result_rows=[(32, 32)])]
    result = migration.snapshot(repo, 'mail_records', ['mail_id'])
    assert result['rows'] == 32
    assert repo.client.query.call_count == 33
    for index, call in enumerate(repo.client.query.call_args_list[:32]):
        assert f'cityHash64(mail_id) % 16 = {index // 2}' in call.args[0]
