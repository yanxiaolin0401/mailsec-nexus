import importlib.util
import json
from pathlib import Path

import httpx
import pytest

spec = importlib.util.spec_from_file_location('smoke_smart_search', Path('scripts/smoke_smart_search.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def test_rejects_unapproved_calls_and_nonlocal_token_destination(monkeypatch):
    monkeypatch.setenv('MAILSEC_API_TOKEN', 'secret')
    with pytest.raises(SystemExit):
        smoke.main([])
    with pytest.raises(SystemExit):
        smoke.main(['--allow-model-calls', '--base-url', 'https://example.test'])
    assert smoke._local_url('http://127.0.0.1:8080')
    assert not smoke._local_url('http://127.0.0.1.evil.test')
    with pytest.raises(ValueError):
        smoke._report_path('docs/report.json')


def test_preview_then_exact_query_without_second_model_call():
    calls = []
    filters = [{'subject_contains': '发票', 'limit': 5, 'offset': 0},
               {'attachment_name_contains': '发票', 'limit': 5, 'offset': 0},
               {'limit': 50, 'offset': 0}]
    def handler(request):
        calls.append(request)
        assert request.headers['X-Mailsec-Token'] == 'secret'
        assert request.url.host == '127.0.0.1'
        n = (len(calls) - 1) // 2
        if request.method == 'POST':
            assert request.url.path == '/api/v1/nl/query'
            assert json.loads(request.content)['execute'] is False
            return httpx.Response(200, json={'executed': False, 'plan': {'tool': smoke.CASES[n][2], 'filters': filters[n]}})
        assert dict(request.url.params) == {k: str(v) for k, v in filters[n].items()}
        return httpx.Response(200, json={'total': 1, 'items': [{'event_id': 'one'}]})
    with httpx.Client(base_url='http://127.0.0.1:8080', headers={'X-Mailsec-Token': 'secret'},
                      transport=httpx.MockTransport(handler)) as client:
        result = smoke.run(client)
    assert result['passed'] and len(calls) == 6
    assert [item['total'] for item in result['cases']] == [1, 1, 1]
    assert all(item['elapsed_ms'] >= 0 for item in result['cases'])
    assert 'one' not in json.dumps(result)


def test_bad_plan_never_executes_or_analyzes():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={'executed': False, 'plan': {'tool': 'search', 'filters': {}}})
    with httpx.Client(base_url='http://127.0.0.1:8080', transport=httpx.MockTransport(handler)) as client:
        result = smoke.run(client, analysis=True)
    assert not result['passed']
    assert len(calls) == 3
    assert all(x.method == 'POST' and x.url.path == '/api/v1/nl/query' for x in calls)
    assert result['cases'][-1]['error_type'] == 'NoSearchResult'


def test_analysis_only_one_item_and_no_mail_contents():
    calls = []
    def handler(request):
        calls.append(request)
        if request.url.path.endswith('/analysis'):
            return httpx.Response(200, json={'status': 'ok', 'risk_level': 'medium',
                                             'evidence_refs': ['subject'], 'reason': 'private text'})
        if request.method == 'POST':
            n = sum(x.url.path == '/api/v1/nl/query' for x in calls) - 1
            return httpx.Response(200, json={'executed': False, 'plan': {'tool': smoke.CASES[n][2],
                'filters': {**smoke.CASES[n][3], 'offset': 0, **({'limit': 50} if n == 2 else {})}}})
        return httpx.Response(200, json={'total': 1, 'items': [{'event_id': 'safe-id', 'subject': 'private text'}]})
    with httpx.Client(base_url='http://127.0.0.1:8080', transport=httpx.MockTransport(handler)) as client:
        result = smoke.run(client, analysis=True)
    assert result['passed'] and len(calls) == 7
    assert calls[-1].url.path == '/api/v1/mails/safe-id/analysis'
    assert 'private text' not in json.dumps(result)


@pytest.mark.parametrize('stage', ['preview', 'query', 'analysis'])
@pytest.mark.parametrize('malformed', [[], None])
def test_nonobject_success_response_is_reported(stage, malformed):
    planned = 0

    def handler(request):
        nonlocal planned
        current = ('analysis' if request.url.path.endswith('/analysis') else
                   'preview' if request.method == 'POST' else 'query')
        if current == stage:
            return httpx.Response(200, content=json.dumps(malformed),
                                  headers={'Content-Type': 'application/json'})
        if current == 'preview':
            case = smoke.CASES[planned]
            planned += 1
            return httpx.Response(200, json={'executed': False,
                'plan': {'tool': case[2], 'filters': case[3]}})
        return httpx.Response(200, json={'total': 1, 'items': [{'event_id': 'safe-id'}]})

    with httpx.Client(base_url='http://127.0.0.1:8080', transport=httpx.MockTransport(handler)) as client:
        result = smoke.run(client, analysis=True)
    assert not result['passed']
    assert any(item.get('error_type') == 'TypeError' for item in result['cases'])
    assert json.loads(json.dumps(result)) == result
