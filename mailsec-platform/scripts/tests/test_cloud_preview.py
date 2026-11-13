import importlib.util
import json
import socketserver
import sys
import threading
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

SCRIPT = Path(__file__).resolve().parents[1] / 'run_cloud_preview.py'
spec = importlib.util.spec_from_file_location('cloud_preview', SCRIPT)
preview = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = preview
spec.loader.exec_module(preview)


def test_token_parser_does_not_execute_shell(tmp_path):
    env = tmp_path / '.env'
    env.write_text('CLICKHOUSE_PASSWORD=not-returned\nMAILSEC_API_TOKEN="$(echo do-not-execute)" # comment\n')
    assert preview.read_token(env) == '$(echo do-not-execute)'
    env.write_text('MAILSEC_API_TOKEN=\n')
    with pytest.raises(ValueError):
        preview.read_token(env)


def test_credentials_private_and_restart_does_not_reset_password(tmp_path, monkeypatch):
    monkeypatch.setattr(preview, 'LOCAL', tmp_path / 'local')
    url, first = preview.initialize()
    path = preview.LOCAL / 'cloud-preview-credentials.json'
    assert path.stat().st_mode & 0o777 == 0o600
    engine = create_engine(url)
    with Session(engine) as db:
        user = db.scalar(select(preview.User).where(preview.User.username == 'admin'))
        user.password_hash = 'changed-after-first-start'
        db.commit()
    _, second = preview.initialize()
    assert second == first
    with Session(engine) as db:
        assert db.scalar(select(preview.User).where(preview.User.username == 'admin')).password_hash == 'changed-after-first-start'
    engine.dispose()


def test_partial_state_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(preview, 'LOCAL', tmp_path)
    (tmp_path / 'cloud-preview.db').touch()
    with pytest.raises(RuntimeError, match='Incomplete preview state'):
        preview.initialize()


def test_unexpected_tenant_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(preview, 'LOCAL', tmp_path)
    url, _ = preview.initialize()
    engine = create_engine(url)
    with Session(engine) as db:
        db.get(preview.Tenant, 1).slug = 'other'
        db.commit()
    with pytest.raises(RuntimeError, match='Unexpected preview tenant'):
        preview.initialize()
    engine.dispose()


def test_stop_refuses_mismatched_process(tmp_path, monkeypatch):
    monkeypatch.setattr(preview, 'LOCAL', tmp_path)
    preview.private_json(tmp_path / 'cloud-preview-processes.json', {'supervisor': 123, 'identity': {'start_ticks': 'old'}})
    monkeypatch.setattr(preview.os, 'pidfd_open', lambda pid: 99)
    monkeypatch.setattr(preview.os, 'close', lambda fd: None)
    monkeypatch.setattr(preview, 'process_identity', lambda pid: {'start_ticks': 'new'})
    signalled = []
    monkeypatch.setattr(preview.signal, 'pidfd_send_signal', lambda *args: signalled.append(args))
    with pytest.raises(RuntimeError, match='identity does not match'):
        preview.stop_preview()
    assert not signalled


def test_stop_already_stopped(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(preview, 'LOCAL', tmp_path)
    preview.stop_preview()
    assert 'not running' in capsys.readouterr().out


def test_search_failure_does_not_block_identity_ui(monkeypatch, capsys):
    class UnavailableClient:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, path):
            raise preview.httpx.ConnectError('internal-secret-host')

    monkeypatch.setattr(preview.httpx, 'Client', UnavailableClient)
    assert preview.search_preflight('http://127.0.0.1:8080', 'private-token') is False
    output = capsys.readouterr().out
    assert 'login/registration remain usable' in output
    assert 'private-token' not in output and 'internal-secret-host' not in output


def test_search_preflight_uses_private_socket(tmp_path):
    paths = []

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            first = self.rfile.readline().decode()
            paths.append(first.split()[1])
            while self.rfile.readline() not in (b'\r\n', b'\n', b''):
                pass
            body = json.dumps({'total': 0}).encode()
            self.wfile.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
                             + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)

    with socketserver.ThreadingUnixStreamServer(str(tmp_path / 'search.sock'), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            assert preview.search_preflight('http://smart-search', 'test-token', str(tmp_path / 'search.sock'))
        finally:
            server.shutdown()
            thread.join()
    assert paths == ['/health/ready', '/v1/stats', '/api/v1/stats']
