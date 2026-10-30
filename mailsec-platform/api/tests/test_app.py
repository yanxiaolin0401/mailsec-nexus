import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from platform_api.app import PREFIX, make_app
from platform_api.config import Settings
from platform_api.models import Base, Tenant, User
from platform_api.security import password_hash


@pytest.fixture
def env(tmp_path):
    seen = []

    def responder(request):
        seen.append(request)
        if request.url.path.endswith('/missing'):
            return httpx.Response(404, json={'detail': 'private upstream text'})
        if request.url.path.endswith('/fail'):
            return httpx.Response(500, json={'detail': 'private upstream text'})
        if request.url.path.endswith('/mails'):
            return httpx.Response(200, json={'items': [], 'total': 0, 'limit': 50, 'offset': 0})
        return httpx.Response(200, json={'event_id': request.url.path.rsplit('/', 1)[-1]})

    settings = Settings(database_url=f"sqlite:///{tmp_path/'test.db'}", smart_search_url='https://upstream.test', smart_search_token='secret-upstream', smart_search_tenant_id=1, smart_search_dedicated=True, cookie_secure=False, csrf_secret='test-secret')
    app = make_app(settings, httpx.MockTransport(responder))
    Base.metadata.create_all(app.state.engine)
    with Session(app.state.engine) as db:
        db.add_all([Tenant(id=1, name='Alpha', slug='alpha'), Tenant(id=2, name='Beta', slug='beta')])
        db.add_all([User(username='admin', display_name='Admin', role='admin', password_hash=password_hash('admin-password-123')),
                    User(username='alice', display_name='Alice', role='user', tenant_id=1, password_hash=password_hash('alice-password-123')),
                    User(username='bob', display_name='Bob', role='user', tenant_id=2, password_hash=password_hash('bob-password-123'))])
        db.commit()
    with TestClient(app) as client:
        yield client, seen, app


def login(client, username='alice', password=None, mode='user', tenant_slug='alpha'):
    body = {'username': username, 'password': password or f'{username}-password-123', 'mode': mode}
    if tenant_slug is not None:
        body['tenant_slug'] = tenant_slug
    return client.post(PREFIX + '/auth/login', json=body)


def auth(client, username='alice', mode='user', tenant_slug='alpha'):
    result = login(client, username, mode=mode, tenant_slug=tenant_slug)
    assert result.status_code == 200, result.text
    return {'X-CSRF-Token': result.json()['csrf_token']}


def test_mode_tenant_and_login_limit(env):
    client, _, _ = env
    assert login(client, mode='admin').status_code == 401
    assert client.post(PREFIX + '/auth/login', headers={'Origin': 'https://evil.test'}, json={'username': 'alice', 'password': 'alice-password-123', 'mode': 'user', 'tenant_slug': 'alpha'}).status_code == 403
    assert login(client, username='alice', tenant_slug='beta').status_code == 401
    assert login(client, username='admin', mode='admin', tenant_slug=None).status_code == 200
    for _ in range(5):
        result = login(client, username='nobody')
    assert result.status_code == 401
    assert login(client, username='nobody').status_code == 429


def test_session_csrf_logout_and_password(env):
    client, _, _ = env
    headers = auth(client)
    assert client.get(PREFIX + '/session').status_code == 200
    assert client.get(PREFIX + '/session').headers['Cache-Control'] == 'no-store'
    assert client.post(PREFIX + '/mail/search', json={}).status_code == 403
    assert client.post(PREFIX + '/mail/search', headers=headers, json={}).status_code == 200
    assert client.post(PREFIX + '/session/password', headers=headers, json={'current_password': 'alice-password-123', 'new_password': 'new-long-password-123'}).status_code == 200
    assert client.get(PREFIX + '/session').status_code == 401
    assert login(client, password='alice-password-123').status_code == 401
    headers = {'X-CSRF-Token': login(client, password='new-long-password-123').json()['csrf_token']}
    assert client.post(PREFIX + '/session/logout', headers=headers).status_code == 200
    assert client.get(PREFIX + '/session').status_code == 401


def test_admin_user_management_and_revocation(env):
    client, _, _ = env
    headers = auth(client, 'admin', 'admin', None)
    assert client.post(PREFIX + '/admin/users', headers=headers, json={'username': 'new', 'display_name': 'New', 'password': 'new-password-123', 'role': 'user', 'tenant_id': 1}).status_code == 201
    user = next(u for u in client.get(PREFIX + '/admin/users').json()['items'] if u['username'] == 'new')
    assert client.patch(PREFIX + f"/admin/users/{user['id']}", headers=headers, json={'password': 'changed-password-123'}).status_code == 200
    assert login(client, 'new', password='new-password-123').status_code == 401
    assert login(client, 'new', password='changed-password-123').status_code == 200
    assert client.get(PREFIX + '/session').status_code == 200
    # restore admin cookie, then deactivate target
    headers = auth(client, 'admin', 'admin', None)
    assert client.patch(PREFIX + f"/admin/users/{user['id']}", headers=headers, json={'is_active': False}).status_code == 200
    assert login(client, 'new', password='changed-password-123').status_code == 401
    assert client.patch(PREFIX + '/admin/users/1', headers=headers, json={'is_active': False}).status_code == 400
    assert client.get(PREFIX + '/admin/audit').json()['items']


def test_tenant_search_scope_and_errors(env):
    client, seen, _ = env
    headers = auth(client)
    assert client.post(PREFIX + '/mail/search', headers=headers, json={'tenant_id': 2}).status_code == 403
    assert client.get(PREFIX + '/mail/one', params={'tenant_id': 2}).status_code == 403
    result = client.post(PREFIX + '/mail/search', headers=headers, json={'q': 'hello', 'limit': 20})
    assert result.status_code == 200
    assert seen[-1].headers['X-Mailsec-Token'] == 'secret-upstream'
    assert 'tenant_id' not in seen[-1].url.params
    assert client.get(PREFIX + '/mail/missing').status_code == 404
    bad = client.get(PREFIX + '/mail/fail')
    assert bad.status_code == 503 and 'private upstream' not in bad.text
    headers = auth(client, 'bob', 'user', 'beta')
    assert client.get(PREFIX + '/integration/status').json()['smart_search'] == {'status': 'disabled', 'tenant_id': None}
    assert client.post(PREFIX + '/mail/search', headers=headers, json={}).status_code == 403
    headers = auth(client, 'admin', 'admin', None)
    assert client.post(PREFIX + '/mail/search', headers=headers, json={}).status_code == 422
    assert client.post(PREFIX + '/mail/search', headers=headers, json={'tenant_id': 2}).status_code == 403
    assert client.post(PREFIX + '/mail/search', headers=headers, json={'tenant_id': 1}).status_code == 200


def test_disabled_fail_closed(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path/'test.db'}", smart_search_url='https://upstream.test', smart_search_token='secret', smart_search_tenant_id=1, smart_search_dedicated=False, cookie_secure=False, csrf_secret='test')
    app = make_app(settings)
    Base.metadata.create_all(app.state.engine)
    with Session(app.state.engine) as db:
        db.add(Tenant(id=1, name='Alpha', slug='alpha'))
        db.add(User(username='alice', display_name='Alice', role='user', tenant_id=1, password_hash=password_hash('alice-password-123')))
        db.commit()
    with TestClient(app) as client:
        headers = auth(client)
        assert client.get(PREFIX + '/integration/status').json()['smart_search']['status'] == 'disabled'
        assert client.post(PREFIX + '/mail/search', headers=headers, json={}).status_code == 503
        assert client.get(PREFIX + '/mail/one').status_code == 503


def test_modules_and_user_cannot_manage(env):
    client, _, _ = env
    headers = auth(client)
    assert client.get(PREFIX + '/admin/users').status_code == 403
    assert client.post(PREFIX + '/admin/tenants', headers=headers, json={'name': 'X', 'slug': 'x1'}).status_code == 403
    assert client.get(PREFIX + '/modules').json()['items'][1]['status'] == 'not_implemented'
    assert client.post(PREFIX + '/modules/header-parser/invoke', headers=headers).status_code == 501


def test_admin_tenant_creation_and_audit(env):
    client, _, _ = env
    headers = auth(client, 'admin', 'admin', None)
    result = client.post(PREFIX + '/admin/tenants', headers=headers, json={'name': 'Gamma', 'slug': 'gamma'})
    assert result.status_code == 201
    assert any(t['slug'] == 'gamma' for t in client.get(PREFIX + '/admin/tenants').json()['items'])
    assert any(a['action'] == 'admin.tenant_create' for a in client.get(PREFIX + '/admin/audit').json()['items'])


def test_upstream_network_failure_is_generic(env):
    client, _, app = env

    def fail(request):
        raise httpx.ConnectError('secret internal host', request=request)

    # A fresh app uses a failing injected upstream transport.
    settings = app.state.settings
    broken = make_app(settings, httpx.MockTransport(fail))
    with TestClient(broken) as browser:
        headers = auth(browser)
        result = browser.post(PREFIX + '/mail/search', headers=headers, json={})
        assert result.status_code == 503
        assert 'secret internal host' not in result.text
        assert browser.get(PREFIX + '/integration/status').json()['smart_search']['status'] == 'unavailable'


def test_input_bounds_and_privilege_fields(env):
    client, _, _ = env
    assert login(client, password='x' * 257).status_code == 422
    headers = auth(client)
    assert client.post(PREFIX + '/mail/search', headers=headers, json={'source_system_id': 'beta'}).status_code == 422
    assert client.get(PREFIX + '/mail/bad%23id').status_code == 422
    headers = auth(client, 'admin', 'admin', None)
    assert client.patch(PREFIX + '/admin/users/2', headers=headers, json={'role': 'admin'}).status_code == 422
    assert client.post(PREFIX + '/admin/users', headers=headers, json={'username': 'invalid-admin', 'display_name': 'Invalid', 'password': 'long-password-123', 'role': 'admin', 'tenant_id': 1}).status_code == 422


def test_cli_bootstrap_is_audited(tmp_path, monkeypatch, capsys):
    import sys

    from sqlalchemy import create_engine, select

    from platform_api.cli import main
    from platform_api.models import Audit

    url = f"sqlite:///{tmp_path/'bootstrap.db'}"
    monkeypatch.setenv('DATABASE_URL', url)
    monkeypatch.setenv('BOOTSTRAP_ADMIN_USERNAME', 'bootstrap-admin')
    monkeypatch.setenv('BOOTSTRAP_ADMIN_PASSWORD', 'synthetic-bootstrap-password')
    monkeypatch.setattr(sys, 'argv', ['platform', 'init-db'])
    main()
    monkeypatch.setattr(sys, 'argv', ['platform', 'bootstrap-admin'])
    main()
    engine = create_engine(url)
    with Session(engine) as db:
        assert db.scalar(select(Audit.action)) == 'admin.bootstrap'
    assert 'synthetic-bootstrap-password' not in capsys.readouterr().out
    engine.dispose()
