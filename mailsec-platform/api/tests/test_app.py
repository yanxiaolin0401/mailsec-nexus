import json

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from platform_api.app import PREFIX, make_app
from platform_api.config import Settings
from platform_api.models import Audit, Base, Tenant, User
from platform_api.security import password_hash


@pytest.fixture
def env(tmp_path):
    seen = []

    def responder(request):
        seen.append(request)
        if request.url.path in ('/api/v1/nl/query', '/v1/nl/query'):
            body = json.loads(request.content)
            assert body['execute'] is False
            field = 'q' if request.url.path.startswith('/api/') else 'body_contains'
            return httpx.Response(200, json={'plan': {'tool': 'search', 'filters': {field: 'invoice', 'limit': 2}}, 'executed': False})
        if request.url.path == '/api/v1/llm/config':
            return httpx.Response(200, json={'provider': 'openai', 'base_url': 'https://api.example.test/v1',
                                             'model': 'test-model', 'configured': True, 'external_authorized': False,
                                             'api_key_set': True, 'api_key': 'private-upstream-key'})
        if request.url.path.endswith('/missing'):
            return httpx.Response(404, json={'detail': 'private upstream text'})
        if request.url.path.endswith('/fail'):
            return httpx.Response(500, json={'detail': 'private upstream text'})
        if request.url.path == '/v1/search':
            body = json.loads(request.content)
            return httpx.Response(200, json={'items': [{'mail_id': 'legacy-1', 'subject': 'Historical'}],
                                             'count': 1, 'limit': body['limit'], 'offset': body['offset'],
                                             'may_have_more': False})
        if request.url.path in ('/v1/stats', '/api/v1/stats'):
            return httpx.Response(200, json={'total': 109516} if request.url.path == '/v1/stats' else {'total': 13})
        if request.url.path.endswith('/mails'):
            return httpx.Response(200, json={'items': [], 'total': 0, 'limit': 50, 'offset': 0})
        if request.url.path.startswith('/v1/mail/'):
            return httpx.Response(200, json={'mail_id': request.url.path.rsplit('/', 1)[-1]})
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
    body = {'username': username, 'password': f'{username}-password-123' if password is None else password, 'mode': mode}
    if tenant_slug is not None:
        body['tenant_slug'] = tenant_slug
    return client.post(PREFIX + '/auth/login', json=body)


def auth(client, username='alice', mode='user', tenant_slug='alpha'):
    result = login(client, username, mode=mode, tenant_slug=tenant_slug)
    assert result.status_code == 200, result.text
    return {'X-CSRF-Token': result.json()['csrf_token']}


def registration(username='new-user', tenant_slug='alpha'):
    return {'username': username, 'display_name': 'New analyst',
            'password': 'new-analyst-password-123', 'tenant_slug': tenant_slug}


def test_public_registration_requires_administrator_approval(env):
    client, _, app = env
    result = client.post(PREFIX + '/auth/register', json=registration(username='New-User'))
    assert result.status_code == 201
    assert result.json() == {'message': 'Registration pending administrator approval'}
    assert 'set-cookie' not in result.headers
    with Session(app.state.engine) as db:
        registered = db.query(User).filter_by(username='new-user').one()
        assert registered.role == 'user' and registered.tenant_id == 1 and registered.is_active is False
        assert registered.password_hash != registration()['password']
        record = db.query(Audit).filter_by(action='auth.register', target=str(registered.id)).one()
        assert record.actor_user_id is None and 'password' not in record.detail
        user_id = registered.id
    assert login(client, username='new-user', password=registration()['password']).status_code == 401
    assert client.get(PREFIX + '/session').status_code == 401
    admin_headers = auth(client, 'admin', 'admin', None)
    assert client.patch(PREFIX + f'/admin/users/{user_id}', headers=admin_headers,
                        json={'is_active': True}).status_code == 200
    result = login(client, username='new-user', password=registration()['password'])
    assert result.status_code == 200
    assert result.json()['user']['role'] == 'user'


def test_registration_rejects_unsafe_or_invalid_input(env):
    client, _, app = env
    path = PREFIX + '/auth/register'
    assert client.post(path, json={**registration(), 'role': 'admin'}).status_code == 422
    assert client.post(path, json={**registration(), 'is_active': True}).status_code == 422
    assert client.post(path, json={**registration(), 'tenant_id': 2}).status_code == 422
    assert client.post(path, json=registration(tenant_slug='missing')).status_code == 404
    assert client.post(path, headers={'Origin': 'https://evil.test'}, json=registration()).status_code == 403
    assert client.post(path, headers={'Sec-Fetch-Site': 'cross-site'}, json=registration()).status_code == 403
    assert client.post(path, json=registration(username='alice')).status_code == 409
    with Session(app.state.engine) as db:
        assert db.query(User).filter_by(username='new-user').count() == 0


def test_registration_rate_limit_per_peer_across_usernames(env):
    client, _, app = env
    path = PREFIX + '/auth/register'
    for index in range(5):
        assert client.post(path, json=registration(username=f'new-{index}')).status_code == 201
    assert client.post(path, json=registration(username='new-six')).status_code == 429
    with Session(app.state.engine) as db:
        assert db.query(User).filter_by(username='new-six').count() == 0


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


def test_legacy_search_stats_detail_and_filter_mapping(env):
    client, seen, _ = env
    headers = auth(client)
    query = {'source': 'legacy', 'q': 'invoice', 'sender': 'a@example.org',
             'recipient': 'b@example.org', 'subject': 'urgent', 'limit': 20, 'offset': 40}
    result = client.post(PREFIX + '/mail/search', headers=headers, json=query)
    assert result.status_code == 200
    assert result.json() == {'items': [{'mail_id': 'legacy-1', 'subject': 'Historical'}], 'total': None,
                             'limit': 20, 'offset': 40, 'may_have_more': False}
    request = seen[-1]
    assert request.method == 'POST' and request.url.path == '/v1/search'
    assert json.loads(request.content) == {'body_contains': 'invoice', 'sender': 'a@example.org',
                                           'recipient': 'b@example.org', 'subject_contains': 'urgent',
                                           'limit': 20, 'offset': 40}
    assert request.headers['X-Mailsec-Token'] == 'secret-upstream'
    assert client.post(PREFIX + '/mail/stats', headers=headers, json=query).json()['total'] == 109516
    assert seen[-1].url.path == '/v1/stats' and seen[-1].method == 'POST'
    detail = client.get(PREFIX + '/mail/legacy-1', params={'source': 'legacy'})
    assert detail.status_code == 200 and detail.json()['mail_id'] == 'legacy-1'
    assert seen[-1].url.path == '/v1/mail/legacy-1'
    assert client.post(PREFIX + '/mail/stats', headers=headers, json={'source': 'event'}).json()['total'] == 13
    assert seen[-1].url.path == '/api/v1/stats' and seen[-1].method == 'GET'


def test_legacy_rejects_unsupported_filters_and_preserves_scope(env):
    client, seen, _ = env
    headers = auth(client)
    count = len(seen)
    assert client.post(PREFIX + '/mail/search', headers=headers,
                       json={'source': 'legacy', 'risk_level': 'high'}).status_code == 422
    assert client.post(PREFIX + '/mail/stats', headers=headers,
                       json={'source': 'legacy', 'risk_level': 'high'}).status_code == 422
    assert client.post(PREFIX + '/mail/search', headers=headers, json={'source': 'bogus'}).status_code == 422
    assert client.get(PREFIX + '/mail/legacy-1', params={'source': 'bogus'}).status_code == 422
    assert len(seen) == count
    assert client.post(PREFIX + '/mail/search', headers=headers,
                       json={'source': 'legacy', 'tenant_id': 2}).status_code == 403
    assert client.post(PREFIX + '/mail/stats', headers=headers,
                       json={'source': 'legacy', 'tenant_id': 2}).status_code == 403
    assert client.get(PREFIX + '/mail/legacy-1', params={'source': 'legacy', 'tenant_id': 2}).status_code == 403
    assert len(seen) == count
    result = client.get(PREFIX + '/mail/missing', params={'source': 'legacy'})
    assert result.status_code == 404 and 'private upstream' not in result.text
    result = client.get(PREFIX + '/mail/fail', params={'source': 'legacy'})
    assert result.status_code == 503 and 'private upstream' not in result.text


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
    assert login(client, password='x' * 257).status_code == 401
    headers = auth(client)
    assert client.post(PREFIX + '/mail/search', headers=headers, json={'source': 'legacy', 'source_system_id': 'beta'}).status_code == 422
    assert client.get(PREFIX + '/mail/bad%23id').status_code == 422
    headers = auth(client, 'admin', 'admin', None)
    assert client.patch(PREFIX + '/admin/users/2', headers=headers, json={'role': 'admin'}).status_code == 422
    assert client.post(PREFIX + '/admin/users', headers=headers, json={'username': 'invalid-admin', 'display_name': 'Invalid', 'password': 'long-password-123', 'role': 'admin', 'tenant_id': 1}).status_code == 422


def test_demo_passwords_can_be_empty_across_all_account_flows(env):
    client, _, app = env
    result = client.post(PREFIX + '/auth/register', json={**registration(username='empty-register'), 'password': ''})
    assert result.status_code == 201
    assert login(client, 'empty-register', password='').status_code == 401  # pending approval

    headers = auth(client, 'admin', 'admin', None)
    users = client.get(PREFIX + '/admin/users').json()['items']
    registered = next(user for user in users if user['username'] == 'empty-register')
    assert client.patch(PREFIX + f"/admin/users/{registered['id']}", headers=headers,
                        json={'is_active': True}).status_code == 200
    assert login(client, 'empty-register', password='').status_code == 200
    headers = auth(client, 'admin', 'admin', None)
    result = client.post(PREFIX + '/admin/users', headers=headers,
                         json={'username': 'empty-created', 'display_name': 'Empty Created',
                               'password': '', 'role': 'user', 'tenant_id': 1})
    assert result.status_code == 201
    created_id = result.json()['id']
    assert login(client, 'empty-created', password='').status_code == 200
    headers = auth(client, 'admin', 'admin', None)
    # An omitted or null patch leaves the old password; an explicit empty string changes it.
    assert client.patch(PREFIX + f'/admin/users/{created_id}', headers=headers,
                        json={'display_name': 'Still Empty'}).status_code == 200
    assert client.patch(PREFIX + f'/admin/users/{created_id}', headers=headers,
                        json={'password': None}).status_code == 200
    assert login(client, 'empty-created', password='').status_code == 200
    headers = auth(client, 'admin', 'admin', None)
    assert client.patch(PREFIX + f'/admin/users/{created_id}', headers=headers,
                        json={'password': 'x'}).status_code == 200
    assert login(client, 'empty-created', password='x').status_code == 200
    headers = auth(client, 'admin', 'admin', None)
    assert client.patch(PREFIX + f'/admin/users/{created_id}', headers=headers,
                        json={'password': ''}).status_code == 200
    assert login(client, 'empty-created', password='').status_code == 200
    headers = {'X-CSRF-Token': client.get(PREFIX + '/session').json()['csrf_token']}
    assert client.post(PREFIX + '/session/password', headers=headers,
                       json={'current_password': '', 'new_password': 'z'}).status_code == 200
    assert login(client, 'empty-created', password='z').status_code == 200
    headers = {'X-CSRF-Token': client.get(PREFIX + '/session').json()['csrf_token']}
    assert client.post(PREFIX + '/session/password', headers=headers,
                       json={'current_password': 'z', 'new_password': ''}).status_code == 200
    assert login(client, 'empty-created', password='').status_code == 200
    with Session(app.state.engine) as db:
        created = db.get(User, created_id)
        assert created.password_hash != ''
        assert 'scrypt$' in created.password_hash


def test_demo_password_required_as_field_even_when_empty_is_valid(env):
    client, _, _ = env
    assert client.post(PREFIX + '/auth/register', json={k: v for k, v in registration().items() if k != 'password'}).status_code == 422
    assert client.post(PREFIX + '/auth/login', json={'username': 'alice', 'mode': 'user', 'tenant_slug': 'alpha'}).status_code == 422


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


def test_cli_bootstrap_accepts_explicit_empty_password(tmp_path, monkeypatch):
    import sys

    from sqlalchemy import create_engine, select

    from platform_api.cli import main
    from platform_api.models import Audit
    from platform_api.security import verify_password

    url = f"sqlite:///{tmp_path/'empty-bootstrap.db'}"
    monkeypatch.setenv('DATABASE_URL', url)
    monkeypatch.setenv('BOOTSTRAP_ADMIN_USERNAME', 'empty-admin')
    monkeypatch.setattr(sys, 'argv', ['platform', 'init-db'])
    main()
    monkeypatch.delenv('BOOTSTRAP_ADMIN_PASSWORD', raising=False)
    with pytest.raises(SystemExit):
        monkeypatch.setattr(sys, 'argv', ['platform', 'bootstrap-admin'])
        main()
    monkeypatch.setenv('BOOTSTRAP_ADMIN_PASSWORD', '')
    main()
    engine = create_engine(url)
    with Session(engine) as db:
        user = db.scalar(select(User).where(User.username == 'empty-admin'))
        assert user.role == 'admin' and verify_password('', user.password_hash)
        assert db.scalar(select(Audit.action).where(Audit.action == 'admin.bootstrap'))
    engine.dispose()


def test_natural_plan_signed_execution_and_tenant_scope(env):
    client, seen, _ = env
    headers = auth(client)
    planned = client.post(PREFIX + '/mail/nl/plan', headers=headers, json={'source': 'legacy', 'text': '查找发票'})
    assert planned.status_code == 200, planned.text
    token = planned.json()['plan_token']
    assert planned.json()['executed'] is False
    assert seen[-1].url.path == '/v1/nl/query'
    result = client.post(PREFIX + '/mail/plan/execute', headers=headers,
                         json={'source': 'legacy', 'plan_token': token, 'limit': 2, 'offset': 2})
    assert result.status_code == 200, result.text
    assert result.json()['result']['total'] is None
    assert seen[-1].url.path == '/v1/search'
    assert json.loads(seen[-1].content)['offset'] == 2
    assert client.post(PREFIX + '/mail/plan/execute', headers=headers,
                       json={'source': 'event', 'plan_token': token}).status_code == 403
    assert client.post(PREFIX + '/mail/plan/execute', headers=headers,
                       json={'source': 'legacy', 'plan_token': token[:-1] + 'x'}).status_code == 422
    assert client.post(PREFIX + '/mail/nl/plan', headers=headers,
                       json={'source': 'legacy', 'text': 'x', 'tenant_id': 2}).status_code == 403
    other = auth(client, 'bob', 'user', 'beta')
    assert client.post(PREFIX + '/mail/plan/execute', headers=other,
                       json={'source': 'legacy', 'plan_token': token}).status_code == 403


def test_natural_event_and_model_config_boundaries(env):
    client, seen, _ = env
    headers = auth(client)
    planned = client.post(PREFIX + '/mail/nl/plan', headers=headers,
                          json={'source': 'event', 'text': '查找发票'})
    assert planned.status_code == 200
    executed = client.post(PREFIX + '/mail/plan/execute', headers=headers,
                           json={'source': 'event', 'plan_token': planned.json()['plan_token']})
    assert executed.status_code == 200
    assert seen[-1].url.path == '/api/v1/mails'
    assert 'q=invoice' in str(seen[-1].url)
    config = client.get(PREFIX + '/llm/config')
    assert config.status_code == 200
    assert 'private-upstream-key' not in config.text
    assert client.get(PREFIX + '/llm/providers').json()['items']
    assert client.put(PREFIX + '/admin/llm/config', headers=headers, json={}).status_code == 403
    headers = auth(client, 'admin', 'admin', None)
    updated = client.put(PREFIX + '/admin/llm/config', headers=headers, json={
        'provider': 'openai', 'base_url': 'https://api.example.test/v1', 'model': 'test-model',
        'api_key': 'private-upstream-key', 'external_authorized': False})
    assert updated.status_code == 200
    assert 'private-upstream-key' not in updated.text
    assert seen[-1].url.path == '/api/v1/llm/config'


def test_natural_unavailable_is_generic(env):
    _, _, app = env
    def fail(request):
        return httpx.Response(503, json={'detail': 'secret provider error'})
    broken = make_app(app.state.settings, httpx.MockTransport(fail))
    with TestClient(broken) as client:
        headers = auth(client)
        result = client.post(PREFIX + '/mail/nl/plan', headers=headers, json={'source': 'legacy', 'text': 'test'})
        assert result.status_code == 503
        assert 'secret provider error' not in result.text


def test_advanced_search_filters_are_source_scoped(env):
    client, seen, _ = env
    headers = auth(client)
    good = client.post(PREFIX + '/mail/search', headers=headers, json={
        'source': 'event', 'sender_ip': '203.0.113.1', 'has_attachment': True,
        'from_time': '2026-11-01T00:00:00+08:00'})
    assert good.status_code == 200
    assert seen[-1].url.params['sender_ip'] == '203.0.113.1'
    assert seen[-1].url.params['has_attachment'] == 'true'
    assert client.post(PREFIX + '/mail/search', headers=headers,
                       json={'source': 'legacy', 'sender_ip': '203.0.113.1'}).status_code == 422
    assert client.post(PREFIX + '/mail/search', headers=headers,
                       json={'from_time': '2026-11-01T00:00:00'}).status_code == 422


def test_mail_analysis_scope_and_upstream_paths(env):
    client, seen, app = env
    headers = auth(client)
    event_id = 'd0c41219-3950-4e1b-8f2c-e0a850a82d2f'
    event = PREFIX + '/mail/' + event_id
    assert client.get(event + '/analyses?source=event').status_code == 200
    assert seen[-1].url.path == '/api/v1/mails/' + event_id + '/analyses'
    assert client.post(event + '/analysis?source=event').status_code == 403  # CSRF gate
    assert client.post(event + '/analysis?source=event', headers=headers).status_code == 200
    assert seen[-1].url.path == '/api/v1/mails/' + event_id + '/analysis'
    assert client.get(PREFIX + '/mail/invalid%2Fpath/analyses').status_code in (404, 422)
    assert client.get(PREFIX + '/mail/legacy-1/analyses?source=legacy').status_code == 200
    assert seen[-1].url.path == '/v1/mail/legacy-1/analyses'
    assert client.post(PREFIX + '/mail/legacy-1/analysis?source=legacy', headers=headers).status_code == 200
    assert seen[-1].url.path == '/v1/mail/legacy-1/analysis'
    assert auth(client, 'bob', tenant_slug='beta')
    before = len(seen)
    assert client.get(event + '/analyses?source=event').status_code == 403
    assert len(seen) == before
    with Session(app.state.engine) as db:
        assert db.query(Audit).filter_by(action='mail.analysis').count() == 2


def test_admin_storage_queue_and_bounded_jobs(env):
    client, seen, _ = env
    auth(client)
    assert client.get(PREFIX + '/admin/mail/storage').status_code == 403
    assert client.get(PREFIX + '/admin/mail/queue').status_code == 403
    assert client.get(PREFIX + '/admin/mail/jobs').status_code == 403
    auth(client, 'admin', mode='admin', tenant_slug=None)
    for path, upstream_path in [('/admin/mail/storage', '/api/v1/storage'),
                                ('/admin/mail/queue', '/api/v2/queue'),
                                ('/admin/mail/jobs?status=retry&limit=20', '/api/v2/jobs')]:
        assert client.get(PREFIX + path).status_code == 200
        assert seen[-1].url.path == upstream_path
    assert dict(seen[-1].url.params) == {'status': 'retry', 'limit': '20'}
    before = len(seen)
    assert client.get(PREFIX + '/admin/mail/jobs?limit=1000').status_code == 422
    assert client.get(PREFIX + '/admin/mail/jobs?status=other').status_code == 422
    assert len(seen) == before
