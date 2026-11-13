"""The search module serves APIs; platform owns all user-facing pages."""
from pathlib import Path

from fastapi.testclient import TestClient

from mailsec_smart_search import cli
from mailsec_smart_search.api import create_app
from mailsec_smart_search.config import Settings
from test_api import FakeRepository


def test_module_has_no_standalone_frontend_and_preserves_api(tmp_path):
    app = create_app(Settings(data_dir=tmp_path, api_token='test-token'), repository=FakeRepository())
    with TestClient(app) as client:
        for path in ('/', '/assets/console.js', '/assets/style.css', '/assets/index.html'):
            assert client.get(path).status_code == 404
        assert client.get('/health/ready').status_code == 200
        assert client.get('/api/v1/mails').status_code == 401
        assert client.post('/v1/stats', json={}, headers={'X-Mailsec-Token': 'test-token'}).json()['total'] == 1
        assert client.get('/openapi.json').status_code == 200
    assert not (Path(__file__).resolve().parents[1] / 'src/mailsec_smart_search/static').exists()


def test_serve_unix_socket_does_not_bind_a_tcp_port(monkeypatch, tmp_path):
    import uvicorn

    calls = []
    monkeypatch.setattr(uvicorn, 'run', lambda app, **kwargs: calls.append((app, kwargs)))
    path = str(tmp_path / 'search.sock')
    assert cli.main(['serve', '--uds', path]) == 0
    assert calls[0][1]['uds'] == path
    assert 'host' not in calls[0][1] and 'port' not in calls[0][1]
