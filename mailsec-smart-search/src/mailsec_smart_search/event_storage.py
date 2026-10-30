"""Independent, bounded ClickHouse storage for normalized JSON mail events."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .storage import _QUERY_SETTINGS

_EVENT_QUERY_SETTINGS = {**_QUERY_SETTINGS, 'prefer_column_name_to_alias': 1}
_COLUMNS = (
    'event_id', 'event_time', 'ingested_at', 'source_type', 'source_system_id',
    'source_event_id', 'trace_id', 'payload_hash', 'mail_hash', 'sender_account',
    'receiver_accounts', 'subject', 'sender_ip', 'ingress_ip', 'sender_country',
    'sender_isp', 'risk_verdict', 'risk_level', 'risk_score', 'feature_tags',
    'data_quality_tags', 'sender_host', 'suspicious_string', 'malicious_sender_ip',
    'tenant_email_addr_url', 'external_urls', 'external_attachments', 'mail_headers',
    'mail_date', 'reply_to', 'src_email_address', 'to_email_address', 'raw_json',
    'text_content',
)
_TIME_COLUMNS = frozenset({'event_time', 'ingested_at', 'mail_date'})
_SUMMARY_COLUMNS = (
    'event_id', 'event_time', 'ingested_at', 'source_system_id', 'source_event_id',
    'trace_id', 'sender_account', 'receiver_accounts', 'subject', 'sender_ip',
    'ingress_ip', 'sender_country', 'sender_isp', 'risk_verdict', 'risk_level',
    'risk_score', 'feature_tags', 'data_quality_tags',
)
_DETAIL_COLUMNS = tuple(column for column in _COLUMNS if column != 'raw_json')
_SUMMARY_SELECT = ', '.join(
    'substringUTF8(subject, 1, 512) AS subject' if column == 'subject' else
    'arraySlice(receiver_accounts, 1, 20) AS receiver_accounts' if column == 'receiver_accounts' else
    column for column in _SUMMARY_COLUMNS
) + ', length(receiver_accounts) AS receiver_count'
_ALLOWED = frozenset({
    'from_time', 'to_time', 'sender', 'sender_domain', 'recipient', 'account',
    'subject_contains', 'body_contains', 'q', 'sender_ip', 'attachment_md5',
    'url', 'risk_level', 'risk_verdict', 'source_system_id', 'has_attachment',
    'attachment_suffix', 'attachment_name_contains', 'limit', 'offset',
})
_IDENTIFIER = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
_MAX_OFFSET = 10_000


def _utc(value: datetime | str) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError('timestamp must include timezone')
    return value.astimezone(timezone.utc)


def _public_row(columns: list[str], row: tuple) -> dict[str, Any]:
    values = dict(zip(columns, row))
    for column in _TIME_COLUMNS:
        value = values.get(column)
        if isinstance(value, datetime):
            # clickhouse-connect may return naive datetimes for an explicitly UTC column.
            values[column] = (value.replace(tzinfo=timezone.utc) if value.tzinfo is None
                              else value.astimezone(timezone.utc)).isoformat()
    return values


class EventRepository:
    """Fixed SQL templates; values are bound through clickhouse-connect parameters."""

    def __init__(self, base_repository: Any):
        if not _IDENTIFIER.fullmatch(base_repository.database):
            raise ValueError('invalid ClickHouse database identifier')
        self.database = base_repository.database
        self._base_repository = base_repository
        self.table = f'`{self.database}`.mail_events'

    @property
    def client(self) -> Any:
        return self._base_repository.client

    def ensure_schema(self) -> None:
        self.client.command(f'CREATE DATABASE IF NOT EXISTS `{self.database}`')
        schema = Path(__file__).with_name('event_schema.sql').read_text(encoding='utf-8')
        for statement in schema.split(';'):
            if statement.strip():
                self.client.command(statement.strip().replace('{database}', f'`{self.database}`'))

    def insert_batch(self, events: list[dict[str, Any]]) -> int:
        if not events:
            return 0
        rows = []
        for event in events:
            rows.append(tuple(_utc(event[column]) if column in _TIME_COLUMNS else event[column]
                              for column in _COLUMNS))
        self.client.insert(f'{self.database}.mail_events', rows, column_names=list(_COLUMNS))
        return len(rows)

    @staticmethod
    def _where(filters: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        unknown = set(filters) - _ALLOWED
        if unknown:
            raise ValueError(f'unsupported filters: {sorted(unknown)}')
        clauses: list[str] = []
        params: dict[str, Any] = {}
        direct = {
            'sender': 'sender_account', 'sender_ip': 'sender_ip',
            'risk_level': 'risk_level', 'risk_verdict': 'risk_verdict',
            'source_system_id': 'source_system_id',
        }
        for key, column in direct.items():
            if filters.get(key) is not None:
                clauses.append(f'{column} = {{{key}:String}}')
                params[key] = str(filters[key])
        for key, operator in (('from_time', '>='), ('to_time', '<=')):
            if filters.get(key) is not None:
                clauses.append(f'event_time {operator} {{{key}:DateTime64(3)}}')
                params[key] = _utc(filters[key])
        if filters.get('sender_domain') is not None:
            clauses.append('endsWith(lowerUTF8(sender_account), concat(\'@\', lowerUTF8({sender_domain:String})))')
            params['sender_domain'] = str(filters['sender_domain']).lstrip('@')
        if filters.get('recipient') is not None:
            clauses.append('has(receiver_accounts, {recipient:String})')
            params['recipient'] = str(filters['recipient'])
        if filters.get('account') is not None:
            clauses.append('(sender_account = {account:String} OR has(receiver_accounts, {account:String}))')
            params['account'] = str(filters['account'])
        for key, column in (('subject_contains', 'subject'), ('body_contains', 'text_content')):
            if filters.get(key) is not None:
                clauses.append(f'positionCaseInsensitiveUTF8({column}, {{{key}:String}}) > 0')
                params[key] = str(filters[key])
        if filters.get('q') is not None:
            clauses.append('(positionCaseInsensitiveUTF8(subject, {q:String}) > 0 OR '
                           'positionCaseInsensitiveUTF8(text_content, {q:String}) > 0)')
            params['q'] = str(filters['q'])
        if filters.get('url') is not None:
            clauses.append('has(external_urls, {url:String})')
            params['url'] = str(filters['url'])
        if filters.get('attachment_md5') is not None:
            clauses.append("arrayExists(x -> x['md5'] = {attachment_md5:String}, external_attachments)")
            params['attachment_md5'] = str(filters['attachment_md5'])
        if filters.get('has_attachment') is not None:
            if type(filters['has_attachment']) is not bool:
                raise ValueError('has_attachment must be bool')
            clauses.append('notEmpty(external_attachments)' if filters['has_attachment'] else 'empty(external_attachments)')
        if filters.get('attachment_suffix') is not None:
            clauses.append("arrayExists(x -> endsWith(lowerUTF8(x['filename']), concat('.', lowerUTF8({attachment_suffix:String}))), external_attachments)")
            params['attachment_suffix'] = str(filters['attachment_suffix']).lstrip('.')
        if filters.get('attachment_name_contains') is not None:
            clauses.append("arrayExists(x -> positionCaseInsensitiveUTF8(x['filename'], {attachment_name_contains:String}) > 0, external_attachments)")
            params['attachment_name_contains'] = str(filters['attachment_name_contains'])
        return (' WHERE ' + ' AND '.join(clauses)) if clauses else '', params

    def explain(self, filters: dict[str, Any], *, stats: bool = False) -> dict[str, Any]:
        limit = filters.get('limit', 50)
        offset = filters.get('offset', 0)
        if type(limit) is not int or not 1 <= limit <= 200 or type(offset) is not int or not 0 <= offset <= _MAX_OFFSET:
            raise ValueError('limit must be 1..200 and offset 0..10000')
        where, params = self._where(filters)
        if stats:
            return {'sql': f'SELECT count() AS total FROM {self.table} FINAL{where}',
                    'parameters': params}
        params.update(limit=limit, offset=offset)
        sql = (f"SELECT {_SUMMARY_SELECT} FROM {self.table} FINAL{where} "
               'ORDER BY event_time DESC, event_id DESC '
               'LIMIT {limit:UInt16} OFFSET {offset:UInt16}')
        return {'sql': sql, 'parameters': params}

    def search(self, filters: dict[str, Any]) -> dict[str, Any]:
        plan = self.explain(filters)
        result = self.client.query(plan['sql'], parameters=plan['parameters'], settings=_EVENT_QUERY_SETTINGS)
        items = [_public_row(result.column_names, row) for row in result.result_rows]
        where, params = self._where(filters)
        count = self.client.query(f'SELECT count() AS total FROM {self.table} FINAL{where}',
                                  parameters=params, settings=_EVENT_QUERY_SETTINGS)
        total = int(count.result_rows[0][0])
        return {'items': items, 'total': total, 'limit': plan['parameters']['limit'],
                'offset': plan['parameters']['offset'],
                'may_have_more': total > plan['parameters']['offset'] + len(items)}

    def stats(self, filters: dict[str, Any]) -> dict[str, int]:
        plan = self.explain(filters, stats=True)
        result = self.client.query(plan['sql'], parameters=plan['parameters'], settings=_EVENT_QUERY_SETTINGS)
        return {'total': int(result.result_rows[0][0])}

    def detail(self, event_id: str) -> dict[str, Any] | None:
        if not event_id:
            raise ValueError('event_id is required')
        result = self.client.query(
            f"SELECT {', '.join(_DETAIL_COLUMNS)} FROM {self.table} FINAL "
            'WHERE event_id = {event_id:String} LIMIT 1',
            parameters={'event_id': event_id}, settings=_EVENT_QUERY_SETTINGS)
        return _public_row(result.column_names, result.result_rows[0]) if result.result_rows else None
