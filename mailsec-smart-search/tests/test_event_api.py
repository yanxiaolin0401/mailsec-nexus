from dataclasses import replace

from fastapi.testclient import TestClient

from mailsec_smart_search.api import create_app
from mailsec_smart_search.config import Settings


class Events:
    def __init__(self):
        self.queries = []

    def search(self, filters):
        self.queries.append(filters)
        return {'items': [], 'total': 0, 'limit': filters.get('limit', 50), 'offset': filters.get('offset', 0)}

    def stats(self, filters):
        self.queries.append(filters)
        return {'total': 0}

    def detail(self, event_id):
        return None

    def explain(self, filters):
        return {'sql': 'SELECT event_id FROM mail_events WHERE sender_account = {sender:String}',
                'parameters': filters}


class Base:
    def ping(self):
        return True


def client_at(tmp_path, **kwargs):
    settings = replace(Settings(), data_dir=tmp_path, api_token='secret', **kwargs)
    events = Events()
    app = create_app(settings, repository=Base(), event_repository=events)
    return TestClient(app), events


AUTH = {'X-Mailsec-Token': 'secret'}


def test_json_ingress_security_receipt_idempotency_and_conflict(tmp_path):
    client, _ = client_at(tmp_path)
    payload = {'sourceSystemId': 'one', 'sourceEventId': 'evt-1', 'mail': {'subject': 'hello'}}
    assert client.post('/api/v2/mails', json=payload).status_code == 401
    result = client.post('/api/v2/mails', json=payload, headers=AUTH)
    assert result.status_code == 202
    assert result.json()['status'] == 'accepted'
    replay = client.post('/api/v2/mails', json=payload, headers=AUTH)
    assert replay.json() == result.json()
    payload['mail']['subject'] = 'changed'
    assert client.post('/api/v2/mails', json=payload, headers=AUTH).status_code == 409
    job = client.get('/api/v2/jobs/' + result.json()['jobId'], headers=AUTH)
    assert job.status_code == 200
    assert 'raw_json' not in job.text and 'hello' not in job.text


def test_invalid_bodies_types_and_limits(tmp_path):
    client, _ = client_at(tmp_path, max_message_bytes=128)
    assert client.post('/api/v2/mails', content='{}', headers=AUTH).status_code == 415
    for payload in [[], None, {'mail': []}, {'mail': {}, 'data': {}}]:
        assert client.post('/api/v2/mails', content=__import__('json').dumps(payload),
                           headers={**AUTH, 'Content-Type': 'application/json'}).status_code == 422
    assert client.post('/api/v2/mails', content=b'x' * 129,
                       headers={**AUTH, 'Content-Type': 'application/json'}).status_code == 413
    assert client.get('/api/v1/mails').status_code == 401
    assert client.get('/api/v1/mails?unknown=ignored', headers=AUTH).status_code == 422
    assert client.get('/api/v1/mails?limit=201', headers=AUTH).status_code == 422
    assert client.get('/api/v1/mails?startTime=2026-10-01', headers=AUTH).status_code == 422
    assert client.get('/api/v1/mails?startTime=2026-10-03T00:00:00Z&endTime=2026-10-01T00:00:00Z', headers=AUTH).status_code == 422


def test_query_aliases_and_missing_detail(tmp_path):
    client, repo = client_at(tmp_path)
    result = client.get('/api/v1/mails?senderIp=8.8.8.8&attachmentMd5=' + 'a' * 32, headers=AUTH)
    assert result.status_code == 200
    assert repo.queries[-1]['sender_ip'] == '8.8.8.8'
    assert repo.queries[-1]['attachment_md5'] == 'a' * 32
    assert client.get('/api/v1/mails/not-found', headers=AUTH).status_code == 404


def test_nl_preview_execution_anchor_and_private_bindings(tmp_path, monkeypatch):
    client, repo = client_at(tmp_path)
    captured = []

    def model(system, text, settings):
        captured.append((system, text))
        assert 'alice@example.org' not in text and '8.8.8.8' not in text
        return {'tool': 'search', 'filters': {'sender': 'MAILSEC_EMAIL_0', 'sender_ip': 'MAILSEC_IP_1'}}

    monkeypatch.setattr('mailsec_smart_search.llm.request_json', model)
    text = '查询 alice@example.org 从 8.8.8.8 发来的邮件'
    response = client.post('/api/v1/nl/query', json={'text': text}, headers=AUTH)
    assert response.status_code == 200, response.text
    assert response.json()['executed'] is False and not repo.queries
    assert response.json()['plan']['filters']['sender'] == 'alice@example.org'
    assert 'Asia/Shanghai' in captured[0][0] and 'current_time' in captured[0][0]
    response = client.post('/api/v1/nl/query', json={'text': text, 'execute': True}, headers=AUTH)
    assert response.status_code == 200 and response.json()['executed'] is True
    assert repo.queries[-1]['sender'] == 'alice@example.org'


def test_invalid_model_output_never_reaches_storage(tmp_path, monkeypatch):
    client, repo = client_at(tmp_path)
    for plan in [ {'tool': 'sql', 'filters': {}}, {'tool': 'search', 'filters': {'sql': 'DROP TABLE x'}},
                  {'tool': 'search', 'filters': {'sender': 'MAILSEC_EMAIL_99'}},
                  {'tool': 'search', 'filters': {'from_time': '2026-10-01'}},
                  {'tool': 'search', 'filters': {}, 'sql': 'SELECT 1'} ]:
        monkeypatch.setattr('mailsec_smart_search.llm.request_json', lambda *args: plan)
        result = client.post('/api/v1/nl/query', json={'text': '查邮件', 'execute': True}, headers=AUTH)
        assert result.status_code == 422, result.text
    assert not repo.queries


def test_model_failure_preserves_structured_search_and_ui(tmp_path):
    client, _ = client_at(tmp_path)
    assert client.post('/api/v1/nl/query', json={'text': '查询最近邮件'}, headers=AUTH).status_code == 503
    assert client.get('/api/v1/mails', headers=AUTH).status_code == 200
    page = client.get('/')
    assert page.status_code == 200 and '自然语言' in page.text
    assert 'localStorage' not in client.get('/assets/console.js').text
    assert 'innerHTML' not in client.get('/assets/console.js').text
    assert 'Content-Security-Policy' in page.headers


def test_private_hash_and_long_numbers_are_not_sent_to_model(tmp_path, monkeypatch):
    client, _ = client_at(tmp_path)
    md5 = 'd41d8cd98f00b204e9800998ecf8427e'
    def model(system, text, settings):
        assert md5 not in text and '13800138000' not in text
        return {'tool': 'search', 'filters': {'attachment_md5': 'MAILSEC_HASH_0'}}
    monkeypatch.setattr('mailsec_smart_search.llm.request_json', model)
    response = client.post('/api/v1/nl/query', json={'text': '查附件 ' + md5}, headers=AUTH)
    assert response.status_code == 200
    assert response.json()['plan']['filters']['attachment_md5'] == md5


def test_duplicate_query_aliases_and_tokens_are_rejected(tmp_path):
    client, repo = client_at(tmp_path)
    assert client.get('/api/v1/mails?senderIp=8.8.8.8&sender_ip=1.1.1.1', headers=AUTH).status_code == 422
    assert client.get('/api/v1/mails', headers=[('X-Mailsec-Token', 'secret'), ('X-Mailsec-Token', 'secret')]).status_code == 401
    assert not repo.queries


def test_email_filters_are_normalized_and_attachment_names_supported(tmp_path):
    client, repo = client_at(tmp_path)
    result = client.get('/api/v1/mails', headers=AUTH, params={'sender': 'Alice@Example.Org', 'recipient': 'FINANCE@example.org',
                       'account': 'Bob@Example.Org', 'attachment_name_contains': '发票'})
    assert result.status_code == 200
    assert repo.queries[-1]['sender'] == 'alice@example.org'
    assert repo.queries[-1]['recipient'] == 'finance@example.org'
    assert repo.queries[-1]['account'] == 'bob@example.org'
    assert repo.queries[-1]['attachment_name_contains'] == '发票'
    assert result.headers['cache-control'] == 'no-store'


def test_event_analysis_persists_unknown_instead_of_clean(tmp_path, monkeypatch):
    client, repo = client_at(tmp_path)
    monkeypatch.setattr(repo, 'detail', lambda key: {'event_id': key, 'subject': 'synthetic'})
    saved = []
    base = client.app.state.repository
    monkeypatch.setattr(base, 'save_analysis', lambda key, value: saved.append((key, value)) or 'analysis-1', raising=False)
    response = client.post('/api/v1/mails/evt-1/analysis', headers=AUTH)
    assert response.status_code == 200, response.text
    assert response.json()['risk_level'] == 'unknown' and response.json()['status'] == 'partial'
    assert response.json()['analysis_id'] == 'analysis-1' and len(saved) == 1


def test_both_protocols_generate_event_query_plans(tmp_path, monkeypatch):
    import json
    import httpx
    from mailsec_smart_search.llm import request_json

    for provider in ['openai', 'anthropic']:
        client, repo = client_at(tmp_path / provider, llm_provider=provider,
                                 llm_base_url='https://provider.example.test/v1', llm_model='synthetic-model',
                                 llm_api_key='synthetic-key', llm_external_authorized=True)
        seen = []
        def handler(request):
            seen.append(request)
            plan = json.dumps({'tool': 'search', 'filters': {'subject_contains': '发票', 'attachment_name_contains': '发票'}})
            return httpx.Response(200, json={'choices': [{'message': {'content': plan}}]} if provider == 'openai'
                                  else {'content': [{'type': 'text', 'text': plan}]})
        with httpx.Client(transport=httpx.MockTransport(handler)) as model_client:
            monkeypatch.setattr('mailsec_smart_search.llm.request_json',
                                lambda system, text, settings: request_json(system, text, settings, client=model_client))
            response = client.post('/api/v1/nl/query', json={'text': '找出带发票附件的发票邮件', 'execute': True}, headers=AUTH)
        assert response.status_code == 200, response.text
        assert repo.queries[-1]['attachment_name_contains'] == '发票'
        assert seen[0].url.path == ('/v1/chat/completions' if provider == 'openai' else '/v1/messages')


def test_url_placeholder_does_not_swallow_following_chinese_conditions():
    from mailsec_smart_search.event_api import _mask_query
    for separator in ['，', '。', '；', ')', '）', ',']:
        masked, bindings = _mask_query('查含 https://example.org/path' + separator + '且主题是发票 的邮件')
        assert '且主题是发票' in masked
        assert bindings == {'MAILSEC_URL_0': 'https://example.org/path'}


def test_structured_statistics_does_not_fetch_email_rows(tmp_path, monkeypatch):
    client, repo = client_at(tmp_path)
    def forbidden(*args):
        raise AssertionError('statistics must not fetch message rows')
    monkeypatch.setattr(repo, 'search', forbidden)
    response = client.get('/api/v1/stats?subject_contains=invoice', headers=AUTH)
    assert response.status_code == 200 and response.json() == {'total': 0}
    assert repo.queries[-1]['subject_contains'] == 'invoice'


def test_model_cannot_drop_private_constraints_or_widen_query(tmp_path, monkeypatch):
    client, repo = client_at(tmp_path)
    monkeypatch.setattr('mailsec_smart_search.llm.request_json', lambda *args: {'tool': 'search', 'filters': {}})
    response = client.post('/api/v1/nl/query', json={'text': '查来自 alice@example.org 的邮件', 'execute': True}, headers=AUTH)
    assert response.status_code == 422 and not repo.queries
    from mailsec_smart_search.event_api import _mask_query
    masked, bindings = _mask_query('联系13800138000的邮件')
    assert '13800138000' not in masked and list(bindings.values()) == ['13800138000']
