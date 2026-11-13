import json
from dataclasses import replace

from fastapi.testclient import TestClient
from mailsec_smart_search.api import create_app
from mailsec_smart_search.config import Settings
from mailsec_smart_search.llm_config import RuntimeSettings
from test_api import FakeRepository

TOKEN = {'X-Mailsec-Token': 'test-token'}
PAYLOAD = {'provider': 'openai', 'base_url': 'https://api.deepseek.com',
           'model': 'deepseek-flash', 'api_key': 'private-key', 'external_authorized': True}


def test_configuration_persists_is_redacted_and_updates_live(tmp_path, monkeypatch):
    settings = replace(Settings(), data_dir=tmp_path, api_token='test-token')
    app = create_app(settings, repository=FakeRepository())
    with TestClient(app) as client:
        assert client.get('/api/v1/llm/config').status_code == 401
        assert client.put('/api/v1/llm/config', json=PAYLOAD).status_code == 401
        before = client.get('/api/v1/llm/config', headers=TOKEN).json()
        assert before['configured'] is False and before['api_key_set'] is False
        result = client.put('/api/v1/llm/config', json=PAYLOAD, headers=TOKEN)
        assert result.status_code == 200, result.text
        assert result.json() == {'provider': 'openai', 'base_url': 'https://api.deepseek.com',
                                 'model': 'deepseek-flash', 'api_key_set': True,
                                 'external_authorized': True, 'configured': True}
        assert 'private-key' not in result.text
        config_file = tmp_path / 'llm-config.json'
        assert config_file.stat().st_mode & 0o777 == 0o600
        assert json.loads(config_file.read_text())['api_key'] == 'private-key'
        observed = {}

        def fake_request(prompt, text, runtime):
            observed.update(provider=runtime.llm_provider, model=runtime.llm_model, key=runtime.llm_api_key)
            return {'tool': 'search', 'filters': {}}

        monkeypatch.setattr('mailsec_smart_search.llm.request_json', fake_request)
        query = client.post('/v1/nl/query', json={'text': 'find all', 'execute': False}, headers=TOKEN)
        assert query.status_code == 200, query.text
        assert observed == {'provider': 'openai', 'model': 'deepseek-flash', 'key': 'private-key'}
        keep = client.put('/api/v1/llm/config', json={k: v for k, v in PAYLOAD.items() if k != 'api_key'}, headers=TOKEN)
        assert keep.status_code == 200 and keep.json()['api_key_set'] is True
        switched = client.put('/api/v1/llm/config', json={**{k: v for k, v in PAYLOAD.items() if k != 'api_key'},
                                                            'base_url': 'https://api.openai.com/v1'}, headers=TOKEN)
        assert switched.status_code == 200 and switched.json()['api_key_set'] is False
        assert json.loads(config_file.read_text())['api_key'] == ''
        cleared = client.put('/api/v1/llm/config', json={**PAYLOAD, 'api_key': ''}, headers=TOKEN)
        assert cleared.status_code == 200 and cleared.json()['configured'] is False
        for base in ('http://api.deepseek.com', 'https://127.0.0.1/v1', 'https://attacker.test/v1'):
            rejected = client.put('/api/v1/llm/config', json={**PAYLOAD, 'base_url': base}, headers=TOKEN)
            assert rejected.status_code == 422
            assert 'private-key' not in rejected.text
            assert rejected.json() == {'detail': 'invalid model configuration'}
    restarted = RuntimeSettings(settings)
    assert restarted.llm_api_key == '' and restarted.llm_model == 'deepseek-flash'
    assert restarted.public()['api_key_set'] is False


def test_environment_initial_configuration_is_visible_without_key(tmp_path):
    initial = replace(Settings(), data_dir=tmp_path, api_token='test-token',
                      llm_provider='anthropic', llm_base_url='https://api.anthropic.com/v1',
                      llm_model='claude-sonnet-4-5', llm_api_key='private', llm_external_authorized=True)
    app = create_app(initial, repository=FakeRepository())
    with TestClient(app) as client:
        response = client.get('/api/v1/llm/config', headers=TOKEN)
        assert response.status_code == 200
        assert response.json()['configured'] is True and response.json()['api_key_set'] is True
        assert 'private' not in response.text
