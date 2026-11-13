"""Opt-in, bounded live-model acceptance through the local mail-search API.

Reports contain only case identifiers, query structure, counts, timings and status.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import httpx

CASES = (
    ('subject', '查询主题包含发票的邮件，最多返回5封，不要限定时间', 'search', {'subject_contains': '发票', 'limit': 5}),
    ('attachment', '查询附件名称包含发票的邮件，最多返回5封，不要限定时间', 'search', {'attachment_name_contains': '发票', 'limit': 5}),
    ('stats', '统计所有邮件的总数，不要限定时间', 'stats', {}),
)
DEFAULTS = {'limit': 50, 'offset': 0}


def _local_url(url: str) -> bool:
    parsed = urlparse(url)
    return (parsed.scheme == 'http' and parsed.hostname in {'127.0.0.1', 'localhost', '::1'}
            and parsed.username is None and parsed.password is None and parsed.path in {'', '/'}
            and not parsed.query and not parsed.fragment)


def _report_path(path: str) -> Path:
    target = Path(path).resolve()
    logs = Path('logs').resolve()
    if target == logs or logs not in target.parents:
        raise ValueError('report must be a file beneath logs/')
    return target


def _check_plan(plan: object, tool: str, expected: dict) -> dict:
    if not isinstance(plan, dict) or plan.get('tool') != tool:
        raise ValueError('wrong tool')
    filters = plan.get('filters')
    if not isinstance(filters, dict):
        raise TypeError('missing filters')
    for key, value in expected.items():
        if filters.get(key) != value:
            raise ValueError(f'missing or incorrect filter: {key}')
    if {key: value for key, value in filters.items() if key not in expected and key not in DEFAULTS}:
        raise ValueError('unexpected extra filter')
    if any(filters.get(key, value) != value for key, value in DEFAULTS.items() if key not in expected):
        raise ValueError('unexpected pagination')
    return filters


def run(client: httpx.Client, *, analysis: bool = False) -> dict:
    """Make at most three planning calls and one optional analysis call."""
    results: list[dict] = []
    first_event: str | None = None
    for case_id, question, tool, expected in CASES:
        item: dict = {'case': case_id, 'passed': False}
        results.append(item)
        start = time.monotonic()
        try:
            preview = client.post('/api/v1/nl/query', json={'text': question, 'execute': False})
            item['preview_http'] = preview.status_code
            preview.raise_for_status()
            payload = preview.json()
            if not isinstance(payload, dict):
                raise TypeError('preview response must be an object')
            if payload.get('executed') is not False:
                raise ValueError('preview executed query')
            filters = _check_plan(payload.get('plan'), tool, expected)
            # Execute the exact approved filter set without a second model call.
            path = '/api/v1/stats' if tool == 'stats' else '/api/v1/mails'
            response = client.get(path, params=filters)
            item['query_http'] = response.status_code
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise TypeError('query response must be an object')
            if not isinstance(data.get('total'), int) or data['total'] < 0:
                raise ValueError('invalid total')
            item['total'] = data['total']
            if tool == 'search':
                rows = data.get('items')
                if not isinstance(rows, list) or len(rows) > 5 or any(not isinstance(row, dict) for row in rows):
                    raise ValueError('invalid bounded result')
                if first_event is None and rows and isinstance(rows[0].get('event_id'), str):
                    first_event = rows[0]['event_id']
            item['passed'] = True
        except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
            item['error_type'] = type(exc).__name__
            if isinstance(exc, ValueError) and str(exc).startswith('missing or incorrect filter: '):
                item['mismatched_field'] = str(exc).rsplit(': ', 1)[1]
        item['elapsed_ms'] = round((time.monotonic() - start) * 1000, 2)
    if analysis:
        item = {'case': 'analysis', 'passed': False}
        results.append(item)
        if first_event:
            start = time.monotonic()
            try:
                response = client.post('/api/v1/mails/' + first_event + '/analysis')
                item['analysis_http'] = response.status_code
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise TypeError('analysis response must be an object')
                item['status'] = payload.get('status')
                item['risk_level'] = payload.get('risk_level')
                item['evidence_refs'] = payload.get('evidence_refs')
                item['passed'] = item['status'] == 'ok' and item['risk_level'] in {'low', 'medium', 'high'}
            except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
                item['error_type'] = type(exc).__name__
            item['elapsed_ms'] = round((time.monotonic() - start) * 1000, 2)
        else:
            item['error_type'] = 'NoSearchResult'
    return {'checked_at': datetime.now(UTC).isoformat(), 'passed': all(x['passed'] for x in results), 'cases': results}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-model-calls', action='store_true', help='explicitly allow billable model calls')
    parser.add_argument('--analysis', action='store_true', help='also analyze one returned mail event')
    parser.add_argument('--base-url', default='http://127.0.0.1:8080')
    parser.add_argument('--socket', help='Internal Unix socket; bypasses TCP')
    parser.add_argument('--report', default='logs/smart-search-live.json')
    args = parser.parse_args(argv)
    if not args.allow_model_calls:
        parser.error('live model calls require --allow-model-calls')
    if not _local_url(args.base_url):
        parser.error('base URL must be loopback HTTP with no path or credentials')
    token = os.getenv('MAILSEC_API_TOKEN', '')
    if not token:
        parser.error('MAILSEC_API_TOKEN is required')
    try:
        report_path = _report_path(args.report)
    except ValueError as exc:
        parser.error(str(exc))
    transport = httpx.HTTPTransport(uds=args.socket) if args.socket else None
    with httpx.Client(base_url=args.base_url, headers={'X-Mailsec-Token': token}, transport=transport,
                      timeout=35, trust_env=False) as client:
        result = run(client, analysis=args.analysis)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'passed': result['passed'], 'report': str(report_path),
                      'cases': [{'case': x['case'], 'passed': x['passed']} for x in result['cases']]}, ensure_ascii=False))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
