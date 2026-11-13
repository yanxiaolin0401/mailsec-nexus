"""Opt-in local HTTP intake acceptance, followed by queue and ClickHouse verification.

Reads credentials only from environment. Logs aggregate counts, never messages.
Input records are not modified. Requires --apply because it writes mail events.
Use preflight_intake.py to validate or explicitly derive repaired data first.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import httpx

from mailsec_smart_search.config import Settings
from mailsec_smart_search.events import normalize_event
from mailsec_smart_search.storage import ClickHouseRepository


def verify(path: Path, url: str, batch_size: int = 1) -> dict:
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    expected = {}
    valid = []
    rejected = 0
    for payload in records:
        try:
            event = normalize_event(payload, canonical=True)
        except ValueError:
            valid.append(False)
            rejected += 1
        else:
            expected[event['event_id']] = event
            valid.append(True)
    if not 1 <= batch_size <= 1000 or (batch_size > 1 and rejected):
        raise ValueError('Batch verification requires 1..1000 and fully valid input')
    admin = {'X-Mailsec-Token': os.environ['MAILSEC_API_TOKEN']}
    intake = {'X-Intake-Key': os.environ['MAILSEC_INTAKE_KEY']}
    codes: Counter[int] = Counter()
    receipts = set()
    start = time.monotonic()
    with httpx.Client(base_url=url, timeout=30, trust_env=False) as client:
        assert client.get('/api/v1/storage', headers=intake).status_code == 401
        before = client.get('/api/v1/storage', headers=admin)
        before.raise_for_status()
        if batch_size == 1:
            for number, (payload, should_accept) in enumerate(zip(records, valid), 1):
                response = client.post('/api/v2/mails', json=payload, headers=intake)
                codes[response.status_code] += 1
                assert response.status_code == (202 if should_accept else 422), f'Unexpected status at line {number}: {response.status_code}'
                if should_accept:
                    receipts.add(response.json()['jobId'])
                if number % 100 == 0:
                    print(json.dumps({'processed': number, 'http_codes': dict(codes)}), flush=True)
        else:
            for offset in range(0, len(records), batch_size):
                batch = records[offset:offset + batch_size]
                response = client.post('/api/v2/mails', json=batch, headers=intake)
                codes[response.status_code] += 1
                assert response.status_code == 202, f'Batch status: {response.status_code}'
                values = response.json()
                assert isinstance(values, list) and len(values) == len(batch)
                receipts.update(value['jobId'] for value in values)
                print(json.dumps({'processed': min(offset + batch_size, len(records)),
                                  'http_codes': dict(codes)}), flush=True)
        deadline = time.monotonic() + 180
        while True:
            done = set()
            offset = 0
            while True:
                page = client.get('/api/v2/jobs', headers=admin, params={'status': 'done', 'limit': 200, 'offset': offset})
                page.raise_for_status()
                value = page.json()
                done.update(item['job_id'] for item in value['items'])
                if offset + 200 >= value['total']:
                    break
                offset += 200
                if offset > 10000:
                    raise RuntimeError('Job listing exceeds acceptance verification bound')
            if receipts <= done:
                break
            if time.monotonic() > deadline:
                raise RuntimeError('Accepted jobs did not reach done before deadline')
            time.sleep(1)
        after = client.get('/api/v1/storage', headers=admin)
        after.raise_for_status()
        # Existing EML/analysis are not changed by canonical input.
        before_tables = {x['name']: x['logical_rows'] for x in before.json()['database']['tables']}
        after_tables = {x['name']: x['logical_rows'] for x in after.json()['database']['tables']}
        for table in ('mail_records', 'analysis_events'):
            assert before_tables[table] == after_tables[table]
    repo = ClickHouseRepository(Settings.from_env())
    ids = list(expected)
    checked = 0
    columns = ['event_id', 'payload_hash', 'sender_account', 'receiver_accounts', 'cc_accounts',
               'tenant_id', 'mailbox', 'risk_verdict', 'risk_level', 'external_attachments',
               'external_urls', 'mail_headers', 'text_content', 'body_html', 'security_meta_json']
    for offset in range(0, len(ids), 100):
        result = repo.client.query(
            f"SELECT {', '.join(columns)} FROM `{repo.database}`.mail_events FINAL "
            'WHERE event_id IN {ids:Array(String)}', parameters={'ids': ids[offset:offset + 100]},
            settings={'select_sequential_consistency': 1, 'max_execution_time': 15, 'max_threads': 1})
        assert len(result.result_rows) == len(ids[offset:offset + 100])
        for row in result.result_rows:
            stored = dict(zip(result.column_names, row))
            event = expected[stored['event_id']]
            assert all(stored[column] == event[column] for column in columns), 'Stored normalized fields differ'
            checked += 1
    repo.client.close()
    return {'at': datetime.now(UTC).isoformat(), 'input_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'input_records': len(records), 'batch_size': batch_size, 'expected_rejected': rejected, 'http_codes': dict(codes),
            'unique_jobs_done': len(receipts), 'cloud_rows_verified': checked,
            'before_tables': before_tables, 'after_tables': after_tables,
            'elapsed_seconds': round(time.monotonic() - start, 2),
            'intake_key_read_access_denied': True, 'external_model_calls': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('--url', default='http://127.0.0.1:8080')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--batch-size', type=int, default=1)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if not args.apply:
        parser.error('--apply is required to submit records')
    if not args.report.resolve().is_relative_to(Path('logs').resolve()):
        parser.error('report must be under workspace logs/')
    if args.report.exists():
        parser.error('report already exists')
    result = verify(args.input, args.url, args.batch_size)
    args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
