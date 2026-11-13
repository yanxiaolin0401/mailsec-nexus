"""Canonical intake credentials, status codes, batch atomicity and admin visibility."""
from dataclasses import replace
from uuid import uuid4

from fastapi.testclient import TestClient

from mailsec_smart_search.api import create_app
from mailsec_smart_search.config import Settings
from test_event_api import Base, Events

ADMIN = {'X-Mailsec-Token': 'admin-secret'}
INTAKE = {'X-Intake-Key': 'intake-secret'}


class Repository(Events):
    def overview(self):
        return {'tables': [{'name': 'mail_events', 'logical_rows': 1, 'physical_bytes': None}]}


def client_at(tmp_path, **overrides):
    settings = replace(Settings(), data_dir=tmp_path, api_token='admin-secret',
                       intake_key='intake-secret', **overrides)
    return TestClient(create_app(settings, repository=Base(), event_repository=Repository()))


def sample(source='one'):
    return {'eventId': str(uuid4()), 'sourceSystemId': 'TEST', 'sourceEventId': source,
            'eventTime': '2026-11-01T23:55:25Z', 'from': 'sender@example.test',
            'to': ['recipient@example.test'], 'subject': 'private subject', 'rawHeaders': '-'}


def test_intake_key_is_write_only_and_cannot_downgrade(tmp_path):
    client = client_at(tmp_path)
    payload = sample()
    response = client.post('/api/v2/mails', json=payload, headers=INTAKE)
    assert response.status_code == 202
    assert response.json()['eventId'] == payload['eventId']
    assert client.post('/api/v2/mails', json=payload, headers=INTAKE).json() == response.json()
    for path in ['/api/v1/mails', '/api/v1/storage', '/api/v2/queue', '/api/v2/jobs',
                 '/api/v2/jobs/' + response.json()['jobId']]:
        assert client.get(path, headers=INTAKE).status_code == 401
    assert client.post('/api/v2/mails', json=payload,
                       headers={**ADMIN, 'X-Intake-Key': 'wrong'}).status_code == 401
    assert client.post('/api/v2/mails', json=payload,
                       headers=[('X-Intake-Key', 'intake-secret')] * 2).status_code == 401
    assert client.get('/api/v2/jobs/' + response.json()['jobId'], headers=ADMIN).status_code == 200


def test_intake_strict_but_legacy_admin_ingest_remains(tmp_path):
    client = client_at(tmp_path)
    old = {'sourceSystemId': 'old', 'sourceEventId': 'legacy', 'mail': {'subject': 'old'}}
    assert client.post('/api/v2/mails', json=old, headers=INTAKE).status_code == 422
    assert client.post('/api/v2/mails', json=old, headers=ADMIN).status_code == 202
    # Canonical-looking invalid input is never accepted through the legacy path.
    assert client.post('/api/v2/mails', json={**sample(), 'to': []}, headers=ADMIN).status_code == 422


def test_canonical_http_error_semantics(tmp_path):
    client = client_at(tmp_path)
    json_headers = {**INTAKE, 'Content-Type': 'application/json; charset=utf-8'}
    for bad in [b'{', b'\xff', b'{"eventId":']:
        response = client.post('/api/v2/mails', content=bad, headers=json_headers)
        assert response.status_code == 400 and response.json() == {'detail': 'Invalid JSON body'}
    assert client.post('/api/v2/mails', content='{}', headers=INTAKE).status_code == 415
    assert client.post('/api/v2/mails', content='{"to":[],"to":[]}', headers=json_headers).status_code == 422
    assert client.post('/api/v2/mails', content='{"value":NaN}', headers=json_headers).status_code == 422
    assert client.post('/api/v2/mails', json=[sample(), None], headers=INTAKE).status_code == 422
    assert client.post('/api/v2/mails', json=[], headers=INTAKE).status_code == 422
    assert client.post('/api/v2/mails', content='{}', headers={**json_headers,
                       'Content-Length': str(16 * 1024 * 1024 + 1)}).status_code == 413
    assert client.get('/api/v2/queue', headers=ADMIN).json()['counts']['pending'] == 0


def test_batch_atomic_accept_and_conflict_with_safe_management(tmp_path):
    client = client_at(tmp_path)
    first, second = sample('one'), sample('two')
    response = client.post('/api/v2/mails', json=[first, second], headers=INTAKE)
    assert response.status_code == 202
    assert [x['eventId'] for x in response.json()] == [first['eventId'], second['eventId']]
    third = sample('three')
    assert client.post('/api/v2/mails', json=[third, {**second, 'subject': 'changed'}],
                       headers=INTAKE).status_code == 409
    assert client.post('/api/v2/mails', json=[third, {**second, 'to': []}],
                       headers=INTAKE).status_code == 422
    jobs = client.get('/api/v2/jobs?status=pending&limit=1', headers=ADMIN)
    assert jobs.status_code == 200 and jobs.json()['total'] == 2
    assert len(jobs.json()['items']) == 1
    assert 'private subject' not in jobs.text and 'payload_hash' not in jobs.text
    assert client.get('/api/v2/jobs?status=invalid', headers=ADMIN).status_code == 422
    assert client.get('/api/v2/jobs?limit=1&limit=2', headers=ADMIN).status_code == 422
    assert client.get('/api/v2/jobs?limit=201', headers=ADMIN).status_code == 422
    overview = client.get('/api/v1/storage', headers=ADMIN)
    assert overview.status_code == 200
    assert overview.json()['queue']['counts']['pending'] == 2
    assert overview.json()['database']['tables'][0]['logical_rows'] == 1


def test_new_event_filters_are_typed_and_alias_bound(tmp_path):
    client = client_at(tmp_path)
    response = client.get('/api/v1/mails', params={'tenantId': 'one', 'mailbox': 'INBOX',
                        'eventId': 'abc', 'sourceEventId': 'upstream',
                        'subject_or_attachment_contains': 'invoice'}, headers=ADMIN)
    assert response.status_code == 200
    assert client.get('/api/v1/mails?tenant_id=', headers=ADMIN).status_code == 422


def test_queue_full_is_503_and_acceptance_is_not_database_confirmation(tmp_path):
    client = client_at(tmp_path, max_spool_bytes=1)
    response = client.post('/api/v2/mails', json=sample(), headers=INTAKE)
    assert response.status_code == 503
    assert response.json() == {'detail': 'Ingest queue full or storage unavailable'}
    assert client.get('/api/v2/queue', headers=ADMIN).json()['counts']['pending'] == 0


def test_openapi_documents_canonical_single_and_batch_input(tmp_path):
    client = client_at(tmp_path)
    endpoint = client.get('/openapi.json').json()['paths']['/api/v2/mails']['post']
    schema = endpoint['requestBody']['content']['application/json']['schema']
    assert schema['oneOf'][0]['properties']['rawHeaders']['type'] == 'string'
    assert schema['oneOf'][1]['maxItems'] == 1000
    assert any(p['name'] == 'X-Intake-Key' for p in endpoint['parameters'])


def test_legacy_envelope_ignores_new_extension_names_without_downgrade(tmp_path):
    client = client_at(tmp_path)
    payload = {'sourceSystemId': 'old', 'sourceEventId': 'extensions',
               'mail': {'subject': 'legacy'}, 'tenantId': 'future-extension', 'securityMeta': {}}
    assert client.post('/api/v2/mails', json=payload, headers=ADMIN).status_code == 202
    assert client.post('/api/v2/mails', json=payload, headers=INTAKE).status_code == 422
