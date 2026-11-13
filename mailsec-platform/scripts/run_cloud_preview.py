"""Local test platform against an existing Cloud-backed smart-search API.

No database migration, mail ingestion, worker or model calls. Only the local test
identity database is created. Run with api/.venv/bin/python; Ctrl-C stops both
child servers. Credentials stay in the ignored, owner-only .local directory.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import select as select_io
import shlex
import signal
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

PLATFORM = Path(__file__).resolve().parents[1]
ROOT = PLATFORM.parent
API = PLATFORM / 'api'
WEB = PLATFORM / 'web'
LOCAL = PLATFORM / '.local'
sys.path.insert(0, str(API))

from platform_api.models import Base, Tenant, User
from platform_api.security import password_hash
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


def read_token(path: Path) -> str:
    """Parse dotenv without executing shell code or exposing database credentials."""
    for line in path.read_text().splitlines():
        key, sep, value = line.partition('=')
        if sep and key.strip() == 'MAILSEC_API_TOKEN':
            parts = shlex.split(value, comments=True)
            if len(parts) == 1 and parts[0]:
                return parts[0]
    raise ValueError('MAILSEC_API_TOKEN missing from search environment file')


def private_json(path: Path, data: dict) -> None:
    # Permissions apply before secret bytes are written, not afterwards.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write('\n')


def initialize() -> tuple[str, dict]:
    LOCAL.mkdir(mode=0o700, exist_ok=True)
    config_path = LOCAL / 'cloud-preview-credentials.json'
    database = LOCAL / 'cloud-preview.db'
    if config_path.exists() != database.exists():
        raise RuntimeError('Incomplete preview state; preserve files and repair before restarting')
    fresh = not config_path.exists()
    config = ({'admin': {'username': 'admin', 'password': secrets.token_urlsafe(18)},
               'user': {'username': 'analyst', 'password': secrets.token_urlsafe(18), 'tenant_slug': 'cloud-test'},
               'csrf_secret': secrets.token_urlsafe(32)} if fresh else json.loads(config_path.read_text()))
    url = f'sqlite:///{database}'
    engine = create_engine(url)
    try:
        if fresh:
            Base.metadata.create_all(engine)
            with Session(engine) as db:
                db.add(Tenant(id=1, name='Cloud 公开语料测试空间', slug='cloud-test'))
                db.add_all([
                    User(username=config['admin']['username'], display_name='测试管理员', role='admin', password_hash=password_hash(config['admin']['password'])),
                    User(username=config['user']['username'], display_name='测试分析员', role='user', tenant_id=1, password_hash=password_hash(config['user']['password'])),
                ])
                db.commit()
            private_json(config_path, config)
        else:
            with Session(engine) as db:
                tenant = db.scalar(select(Tenant).where(Tenant.id == 1))
                if tenant is None or tenant.slug != 'cloud-test':
                    raise RuntimeError('Unexpected preview tenant binding; refusing to start')
    finally:
        engine.dispose()
    return url, config


def wait_ready(url: str, children: list[subprocess.Popen]) -> None:
    with httpx.Client(trust_env=False, timeout=2) as client:
        for _ in range(100):
            if any(child.poll() is not None for child in children):
                raise RuntimeError('Preview process exited; inspect .local/cloud-*.log')
            try:
                if client.get(url).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(.2)
    raise RuntimeError('Preview startup timed out; inspect .local/cloud-*.log')


def process_identity(pid: int) -> dict:
    """Linux process identity; a saved PID alone never authorizes a signal."""
    proc = Path('/proc') / str(pid)
    stat = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    argv = (proc / 'cmdline').read_bytes().split(b'\0')
    cwd = (proc / 'cwd').resolve(strict=True)
    script = Path(argv[1].decode()) if len(argv) > 1 and argv[1] else Path('/')
    script = (cwd / script).resolve()
    if script != Path(__file__).resolve():
        raise RuntimeError('Refusing to signal an unrelated process')
    return {'start_ticks': stat[19], 'script': str(script)}


def stop_preview() -> None:
    state = LOCAL / 'cloud-preview-processes.json'
    if not state.exists():
        print('Platform is not running (no process record).')
        return
    record = json.loads(state.read_text())
    pid = int(record['supervisor'])
    try:
        handle = os.pidfd_open(pid)
    except ProcessLookupError:
        print('Platform supervisor already stopped.')
        return
    try:
        identity = process_identity(pid)
        if record.get('identity') != identity:
            raise RuntimeError('Process identity does not match; refusing to stop')
        signal.pidfd_send_signal(handle, signal.SIGTERM)
        poller = select_io.poll()
        poller.register(handle, select_io.POLLIN)
        if not poller.poll(25000):
            raise RuntimeError('Supervisor did not stop within 25 seconds; inspect logs')
        print('Platform Web/API stopped; smart-search and all data preserved.')
    finally:
        os.close(handle)


def search_preflight(url: str, token: str, uds: str = '') -> bool:
    """Identity UI remains usable when the independent search backend is down."""
    try:
        with httpx.Client(base_url=url, transport=httpx.HTTPTransport(uds=uds) if uds else None,
                          trust_env=False, timeout=5) as client:
            client.get('/health/ready').raise_for_status()
            for path in ['/v1/stats', '/api/v1/stats']:
                response = client.post(path, json={}, headers={'X-Mailsec-Token': token}) if path == '/v1/stats' else client.get(path, headers={'X-Mailsec-Token': token})
                response.raise_for_status()
        return True
    except httpx.HTTPError:
        print('Warning: search dependency unavailable; login/registration remain usable. No fallback mail data.', flush=True)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stop', action='store_true', help='Stop only the recorded, identity-verified platform Web/API processes')
    parser.add_argument('--search-url', default='', help='Explicit HTTP(S) upstream override; default uses private search socket')
    parser.add_argument('--search-env', type=Path, default=ROOT / 'mailsec-smart-search/.env.cloud')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--origin', default='http://127.0.0.1:5173')
    parser.add_argument('--confirm-test-dataset', action='store_true', help='Confirm the upstream contains only data authorized for this test space')
    args = parser.parse_args()
    if args.stop:
        stop_preview()
        return
    if not args.confirm_test_dataset:
        parser.error('--confirm-test-dataset required: never bind mixed enterprise tenants')
    search_socket = '' if args.search_url else str(ROOT / 'mailsec-smart-search/var/platform-ipc/search/search.sock')
    search_url = args.search_url or 'http://smart-search'
    if args.search_url:
        parsed = urlparse(search_url)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password:
            parser.error('search URL must be HTTP(S) without embedded credentials')
        if parsed.scheme == 'http' and parsed.hostname not in ('127.0.0.1', 'localhost', '::1'):
            parser.error('remote search services require HTTPS')
    origin = urlparse(args.origin)
    if origin.scheme != 'http' or not origin.hostname or origin.port != 5173 or origin.path not in ('', '/') or origin.query or origin.fragment or origin.username:
        parser.error('preview origin must be an HTTP origin on port 5173; use production deployment for HTTPS')
    os.umask(0o077)
    for host, port in [(args.host, 5173)]:
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))  # Never stop or reuse an unrelated listener.
    token = read_token(args.search_env)
    search_preflight(search_url, token, search_socket)
    url, config = initialize()
    api_socket = LOCAL / 'platform-api.sock'
    if api_socket.exists() or api_socket.is_symlink():
        raise RuntimeError('Platform API socket already exists; refusing to replace an existing endpoint')
    env = {**os.environ, 'DATABASE_URL': url, 'COOKIE_SECURE': 'false',
           'CSRF_SECRET': config['csrf_secret'], 'PLATFORM_ORIGIN': args.origin.rstrip('/'),
           'SMART_SEARCH_URL': search_url.rstrip('/'), 'SMART_SEARCH_SOCKET': search_socket,
           'SMART_SEARCH_TOKEN': token,
           'SMART_SEARCH_TENANT_ID': '1', 'SMART_SEARCH_DEDICATED': 'true'}
    commands = [
        ('api', [str(API / '.venv/bin/python'), '-m', 'uvicorn', 'platform_api.app:app', '--uds', str(api_socket), '--no-access-log', '--no-proxy-headers'], API),
        ('web', ['node', 'node_modules/vite/bin/vite.js', '--host', args.host, '--port', '5173', '--strictPort'], WEB),
    ]
    children: list[subprocess.Popen] = []

    def terminate(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)
    try:
        for name, command, cwd in commands:
            with (LOCAL / f'cloud-{name}.log').open('a') as log:
                children.append(subprocess.Popen(command, cwd=cwd,
                    env=env if name == 'api' else {**os.environ, 'PLATFORM_API_SOCKET': str(api_socket)},
                    stdout=log, stderr=log))
        # Verify the API through its private socket, without allocating another TCP port.
        with httpx.Client(base_url='http://platform-api', transport=httpx.HTTPTransport(uds=str(api_socket)),
                          timeout=2, trust_env=False) as client:
            for _ in range(100):
                if any(child.poll() is not None for child in children):
                    raise RuntimeError('Preview process exited; inspect .local/cloud-*.log')
                try:
                    if client.get('/openapi.json').status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(.2)
            else:
                raise RuntimeError('Platform API socket startup timed out')
        web_host = '127.0.0.1' if args.host == '0.0.0.0' else args.host
        wait_ready(f'http://{web_host}:5173', children)
        private_json(LOCAL / 'cloud-preview-processes.json', {'supervisor': os.getpid(), 'identity': process_identity(os.getpid()), 'api': children[0].pid, 'web': children[1].pid, 'origin': args.origin})
        print(f'Ready: {args.origin}\nCredentials: {LOCAL / "cloud-preview-credentials.json"}\nCtrl-C stops this preview. HTTP test use only; not production.', flush=True)
        while True:
            if any(child.poll() is not None for child in children):
                raise RuntimeError('Preview process exited; inspect .local/cloud-*.log')
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        if api_socket.exists() and stat.S_ISSOCK(api_socket.lstat().st_mode):
            api_socket.unlink()


if __name__ == '__main__':
    main()
