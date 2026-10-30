"""Non-destructive, resumable local -> Cloud migration of the three application tables.

Default is read-only inventory. --apply creates missing schemas and inserts only
missing IDs; conflicting content fails closed. Run with source writers stopped,
no concurrent migrator, and no target writes to the IDs being migrated. A rerun
rechecks ALL source rows instead of trusting a cursor or deduplication window.
Secrets are read from env files, never shell-executed or included in reports.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from mailsec_smart_search.config import Settings
from mailsec_smart_search.event_storage import EventRepository
from mailsec_smart_search.storage import ClickHouseRepository

TABLES = {'mail_records': 'mail_id', 'mail_events': 'event_id', 'analysis_events': 'event_id'}
READ_SETTINGS = {'max_threads': 1, 'max_block_size': 128, 'preferred_block_size_bytes': 1048576, 'max_execution_time': 120,
                 'max_memory_usage': 512 * 1024 * 1024, 'max_final_threads': 1,
                 'do_not_merge_across_partitions_select_final': 1}


def load_settings(path: Path) -> Settings:
    values = {}
    for line in path.read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or not re.fullmatch(r'[A-Z_][A-Z_0-9]*', key.strip()):
            raise ValueError('invalid env file entry')
        parts = shlex.split(value, comments=True)
        if len(parts) > 1:
            raise ValueError('env values containing spaces must be quoted')
        values[key.strip()] = parts[0] if parts else ''
    return Settings(
        clickhouse_host=values.get('CLICKHOUSE_HOST', '127.0.0.1'),
        clickhouse_port=int(values.get('CLICKHOUSE_PORT', '8123')),
        clickhouse_secure=values.get('CLICKHOUSE_SECURE', '').lower() == 'true',
        clickhouse_user=values.get('CLICKHOUSE_USER', 'mailsec'),
        clickhouse_password=values.get('CLICKHOUSE_PASSWORD', ''),
        clickhouse_database=values.get('CLICKHOUSE_DB', 'mailsec'),
    )


def canonical(value: Any) -> Any:
    if isinstance(value, datetime):
        return (value.replace(tzinfo=UTC) if value.tzinfo is None else
                value.astimezone(UTC)).isoformat(timespec='milliseconds')
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, (tuple, list)):
        return [canonical(item) for item in value]
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in value.items()}
    return value


def digest(row: Any) -> str:
    return hashlib.sha256(json.dumps(canonical(row), ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def qualified(repo: ClickHouseRepository, table: str) -> str:
    if table not in TABLES:
        raise ValueError('unsupported table')
    return f'`{repo.database}`.`{table}`'


def table_from(repo: ClickHouseRepository, table: str) -> str:
    return qualified(repo, table) + (' FINAL' if table != 'analysis_events' else '')


def schema(repo: ClickHouseRepository, table: str) -> list[tuple[str, str]]:
    return [(row[0], row[1]) for row in repo.client.query(
        f'DESCRIBE TABLE {qualified(repo, table)}').result_rows]


def validate_layout(repo: ClickHouseRepository, table: str) -> None:
    row = repo.client.query(
        'SELECT engine, engine_full, sorting_key, partition_key FROM system.tables '
        'WHERE database = {db:String} AND name = {table:String}',
        parameters={'db': repo.database, 'table': table}).result_rows
    if len(row) != 1:
        raise ValueError(f'{table}: missing table')
    engine, engine_full, sorting, partition = row[0]
    base = 'MergeTree' if table == 'analysis_events' else 'ReplacingMergeTree'
    expected_sort = 'mail_id, created_at, event_id' if table == 'analysis_events' else TABLES[table]
    expected_partition = ('toYYYYMM(created_at)' if table == 'analysis_events' else
                          f'cityHash64({TABLES[table]}) % 16')
    if engine not in (base, 'Shared' + base) or sorting != expected_sort or partition != expected_partition:
        raise ValueError(f'{table}: incompatible engine, sorting or partition key')
    match = re.match(r'^\w+\((.*?)\)', engine_full)
    args = [item.strip() for item in match[1].split(',')] if match else []
    if engine.startswith('Shared'):
        args = args[2:]  # Cloud adds its own internal path and replica arguments.
    if args != (['ingested_at'] if table == 'mail_events' else []):
        raise ValueError(f'{table}: incompatible replacing version or engine arguments')


def snapshot(repo: ClickHouseRepository, table: str, columns: list[str], *, cloud=False) -> dict:
    # Used only to detect source changes during the run, not as the content proof.
    cols = ', '.join(f'`{name}`' for name in columns)
    settings = dict(READ_SETTINGS)
    if cloud:
        settings['select_sequential_consistency'] = 1
    total = {'rows': 0, 'unique_ids': 0, 'xor64': 0, 'sum128': 0}
    key_expr = f'toString({TABLES[table]})' if table == 'analysis_events' else TABLES[table]
    for partition in partitions(table):
        cursor = None
        while True:
            where = partition_where(table, partition)
            if cursor is not None:
                where += (' AND ' if where else ' WHERE ') + f'{key_expr} > {{cursor:String}}'
            row = repo.client.query(
                f'SELECT count(), uniqExact({TABLES[table]}), '
                f'groupBitXor(cityHash64(tuple({cols}))), '
                f'sum(toUInt128(cityHash64(tuple({cols})))), max({key_expr}) FROM '
                f'(SELECT {cols} FROM {table_from(repo, table)}{where} '
                f'ORDER BY {key_expr} LIMIT 500)',
                parameters={'cursor': cursor} if cursor is not None else {},
                settings=settings).result_rows[0]
            if not row[0]:
                break
            if row[0] != row[1]:
                raise ValueError(f'{table}: duplicate logical IDs; refusing unsafe migration')
            total['rows'] += row[0]
            total['unique_ids'] += row[1]
            total['xor64'] ^= row[2]
            total['sum128'] += row[3]
            cursor = row[4]
    # A duplicate key straddling a page boundary must not disappear behind `>`.
    count, unique = repo.client.query(
        f'SELECT count(), uniqExact({TABLES[table]}) FROM {table_from(repo, table)}',
        settings=settings).result_rows[0]
    if count != unique or count != total['rows']:
        raise ValueError(f'{table}: duplicate IDs or source changed during snapshot')
    return total


def partitions(table: str) -> list[int | None]:
    return list(range(16)) if table != 'analysis_events' else [None]


def partition_where(table: str, partition: int | None) -> str:
    return f' WHERE cityHash64({TABLES[table]}) % 16 = {partition}' if partition is not None else ''


def index_rows(rows: list | tuple, key_index: int) -> dict[str, str]:
    result = {}
    for row in rows:
        key = str(row[key_index])
        if key in result:
            raise ValueError('duplicate ID in migration batch')
        result[key] = digest(row)
    return result


def missing_rows(rows: list | tuple, existing: list | tuple, key_index: int) -> list:
    expected = index_rows(rows, key_index)
    actual = index_rows(existing, key_index)
    if any(key not in expected or expected[key] != value for key, value in actual.items()):
        raise ValueError('target content conflicts with source; nothing overwritten')
    return [row for row in rows if str(row[key_index]) not in actual]


def migrate_table(source: ClickHouseRepository, target: ClickHouseRepository,
                  table: str, batch_size: int, progress) -> dict:
    source_schema = schema(source, table)
    if source_schema != schema(target, table):
        raise ValueError(f'{table}: source and target column schemas differ')
    columns = [name for name, _ in source_schema]
    cols = ', '.join(f'`{name}`' for name in columns)
    key = TABLES[table]
    key_index = columns.index(key)
    key_expr = f'toString(`{key}`)' if table == 'analysis_events' else f'`{key}`'
    before = snapshot(source, table, columns)
    target_before = snapshot(target, table, columns, cloud=True)
    copied = skipped = verified = 0
    content_hash = hashlib.sha256()
    target_settings = {**READ_SETTINGS, 'select_sequential_consistency': 1}
    for partition in partitions(table):
        cursor = None
        while True:
            where = partition_where(table, partition)
            if cursor is not None:
                where += (' AND ' if where else ' WHERE ') + f'{key_expr} > {{cursor:String}}'
            rows = source.client.query(
                f'SELECT {cols} FROM {table_from(source, table)}{where} '
                f'ORDER BY {key_expr} LIMIT {{batch:UInt32}}',
                parameters={'cursor': cursor or '', 'batch': batch_size},
                query_formats={'DateTime64': 'int'},
                settings=READ_SETTINGS).result_rows
            if not rows:
                break
            ids = [str(row[key_index]) for row in rows]
            def read_target(batch_ids):
                return target.client.query(
                    f'SELECT {cols} FROM {table_from(target, table)} '
                    f'WHERE {key_expr} IN {{ids:Array(String)}}',
                    parameters={'ids': batch_ids}, query_formats={'DateTime64': 'int'},
                    settings=target_settings).result_rows
            existing = read_target(ids)
            pending = missing_rows(rows, existing, key_index)
            if pending:
                token = 'mailsec-migrate-' + digest([table, columns, pending])
                target.client.insert(qualified(target, table), pending, column_names=columns,
                                     settings={'async_insert': 0, 'insert_deduplicate': 1,
                                               'insert_deduplication_token': token})
                existing = read_target(ids)
            if index_rows(rows, key_index) != index_rows(existing, key_index):
                raise ValueError(f'{table}: full-column SHA-256 readback failed')
            copied += len(pending)
            skipped += len(rows) - len(pending)
            verified += len(rows)
            for row in rows:
                content_hash.update(bytes.fromhex(digest(row)))
            cursor = ids[-1]
            # No addresses, bodies, hosts, or credentials in the progress report.
            progress({'table': table, 'verified': verified, 'inserted': copied, 'skipped': skipped})
    after = snapshot(source, table, columns)
    if before != after or verified != before['rows']:
        raise ValueError(f'{table}: source changed during migration; stop writers and rerun')
    target_after = snapshot(target, table, columns, cloud=True)
    if target_after['rows'] != target_before['rows'] + copied:
        raise ValueError(f'{table}: target count changed concurrently; rerun validation')
    return {'source': before, 'target_before': target_before, 'target_after': target_after,
            'inserted': copied, 'skipped_identical': skipped, 'verified_rows': verified,
            'full_column_sha256': content_hash.hexdigest(), 'source_unchanged': True}


def run(source_settings: Settings, target_settings: Settings, *, apply=False,
        batch_size=500, report_path: Path) -> dict:
    if not 1 <= batch_size <= 2000:
        raise ValueError('batch size must be 1..2000')
    source_id = (source_settings.clickhouse_host.lower().rstrip('.'),
                 source_settings.clickhouse_port, source_settings.clickhouse_database)
    target_id = (target_settings.clickhouse_host.lower().rstrip('.'),
                 target_settings.clickhouse_port, target_settings.clickhouse_database)
    if source_id == target_id:
        raise ValueError('source and target must differ')
    if not (target_settings.clickhouse_secure or target_settings.clickhouse_port == 8443):
        raise ValueError('target TLS is required')
    source = ClickHouseRepository(source_settings)
    target = ClickHouseRepository(target_settings)
    report = {'at': datetime.now(UTC).isoformat(), 'mode': 'apply' if apply else 'inventory',
              'status': 'running', 'tables': {}, 'source_preserved': True,
              'raw_eml_uploaded': False, 'external_model_calls': 0}
    def persist():
        report_path.parent.mkdir(parents=True, exist_ok=True)
        temp = report_path.with_suffix(report_path.suffix + '.tmp')
        temp.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
        temp.replace(report_path)
    def progress(value):
        report['progress'] = value
        persist()
        print(json.dumps(value), flush=True)
    try:
        # Bulk transfer needs a longer socket deadline than latency-bounded API reads.
        source._client = source._connect(source_settings, send_receive_timeout=180)
        target._client = target._connect(target_settings, send_receive_timeout=180)
        # Refuse unknown source application tables rather than silently omitting data.
        tables = source.client.query('SELECT name FROM system.tables WHERE database = {db:String}',
                                     parameters={'db': source.database}).result_rows
        if {row[0] for row in tables} != set(TABLES):
            raise ValueError('source tables differ from the supported application schema')
        if apply:
            target.ensure_schema()
            EventRepository(target).ensure_schema()
        for table in TABLES:
            validate_layout(source, table)
            validate_layout(target, table)
        for table in TABLES:
            if apply:
                report['tables'][table] = migrate_table(source, target, table, batch_size, progress)
            else:
                columns = [name for name, _ in schema(source, table)]
                report['tables'][table] = {'source': snapshot(source, table, columns),
                                          'target': snapshot(target, table, columns, cloud=True)}
            persist()
        report['status'] = 'verified' if apply else 'inventoried'
    except Exception as exc:
        report['status'] = 'failed'
        report['error_type'] = type(exc).__name__  # Driver errors can contain row data/hosts.
        raise
    finally:
        persist()
        for repo in (source, target):
            if repo._client is not None:
                repo.client.close()
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-env', type=Path, default=Path('.env'))
    parser.add_argument('--target-env', type=Path, default=Path('.env.cloud'))
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--batch-size', type=int, default=500)
    parser.add_argument('--report', type=Path, default=Path('var/migration/report.json'))
    args = parser.parse_args()
    try:
        result = run(load_settings(args.source_env), load_settings(args.target_env), apply=args.apply,
                     batch_size=args.batch_size, report_path=args.report)
    except Exception as exc:  # noqa: BLE001 -- sanitize driver errors at CLI boundary
        # Do not echo driver exception text: it may contain mail contents or endpoint details.
        raise SystemExit(f'Migration failed ({type(exc).__name__}); source retained. '
                         f'See {args.report}. Resolve the cause, then rerun; existing rows are verified.') from None
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
