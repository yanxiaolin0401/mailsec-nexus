"""Real-browser smoke with a disposable SQLite control plane (no mail data).

Run with platform api venv Python and Playwright on PYTHONPATH. Requires installed
web node_modules and Chromium. Binds only loopback ports 8090/5173 and cleans up.
Search dependency is intentionally disabled; real ClickHouse is tested separately.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
API = ROOT / 'mailsec-platform/api'
WEB = ROOT / 'mailsec-platform/web'
REPORTS = ROOT / 'mailsec-platform/docs/reports'
sys.path.insert(0, str(API))
from playwright.sync_api import sync_playwright, expect
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from platform_api.models import Base, Tenant, User
from platform_api.security import password_hash


def wait_for(url):
    for _ in range(100):
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(.1)
    raise RuntimeError('Local QA service did not start')


def run():
    for port in [8090, 5173]:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', port))  # Do not reuse or kill unrelated listeners.
    REPORTS.mkdir(parents=True, exist_ok=True)
    processes = []
    errors = []
    checks = []
    with tempfile.TemporaryDirectory(prefix='platform-browser-') as temp:
        password = secrets.token_urlsafe(24)
        changed = secrets.token_urlsafe(24)
        db_url = f'sqlite:///{temp}/platform.db'
        engine = create_engine(db_url)
        Base.metadata.create_all(engine)
        with Session(engine) as db:
            db.add(Tenant(id=1, name='合成测试租户', slug='synthetic'))
            db.add_all([User(username='qa-admin', display_name='测试管理员', role='admin', password_hash=password_hash(password)), User(username='qa-user', display_name='测试分析员', role='user', tenant_id=1, password_hash=password_hash(password))])
            db.commit()
        engine.dispose()
        env = {**os.environ, 'DATABASE_URL': db_url, 'COOKIE_SECURE': 'false', 'CSRF_SECRET': secrets.token_urlsafe(32), 'PLATFORM_ORIGIN': 'http://127.0.0.1:5173', 'SMART_SEARCH_DEDICATED': 'false', 'SMART_SEARCH_URL': '', 'SMART_SEARCH_TOKEN': '', 'SMART_SEARCH_TENANT_ID': ''}
        try:
            processes.append(subprocess.Popen([str(API/'.venv/bin/python'), '-m', 'uvicorn', 'platform_api.app:app', '--host', '127.0.0.1', '--port', '8090', '--no-access-log'], cwd=API, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            processes.append(subprocess.Popen(['node', 'node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', '5173', '--strictPort'], cwd=WEB, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            wait_for('http://127.0.0.1:8090/openapi.json')
            wait_for('http://127.0.0.1:5173')
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(viewport={'width':1440,'height':1000})
                page = context.new_page()
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.goto('http://127.0.0.1:5173')
                expect(page.get_by_role('heading', name='欢迎回来')).to_be_visible()
                page.screenshot(path=str(REPORTS/'login-desktop.png'), full_page=True)
                page.get_by_role('tab', name='管理员登录').click()
                page.get_by_label('账号', exact=True).fill('qa-admin')
                page.get_by_label('密码', exact=True).fill(password)
                page.get_by_role('button', name='安全登录').click()
                expect(page.locator('.topbar-role')).to_have_text('管理员')
                checks.append('real_api_admin_login')
                expect(page.get_by_text('正在获取状态…', exact=True)).to_have_count(0)
                expect(page.get_by_text('3 个模块', exact=True)).to_be_visible()
                page.screenshot(path=str(REPORTS/'overview-desktop.png'), full_page=True)
                page.get_by_role('button', name='账号管理', exact=True).click()
                row = page.get_by_role('row').filter(has_text='qa-user')
                expect(row).to_be_visible()
                row.get_by_role('button', name='编辑 / 重置密码').click()
                page.get_by_label('显示名称', exact=True).fill('修改后的分析员')
                page.get_by_label('新密码（留空则不修改）').fill(changed)
                page.get_by_role('button', name='保存', exact=True).click()
                expect(page.get_by_role('dialog')).to_have_count(0)
                expect(row).to_contain_text('修改后的分析员')
                checks.append('admin_edits_name_and_resets_password')
                page.screenshot(path=str(REPORTS/'users-desktop.png'), full_page=True)
                page.get_by_role('button', name='退出登录', exact=True).click()
                expect(page.get_by_role('heading', name='欢迎回来')).to_be_visible()
                page.get_by_label('账号', exact=True).fill('qa-user')
                page.get_by_label('密码', exact=True).fill(changed)
                page.get_by_label('租户标识', exact=True).fill('synthetic')
                page.get_by_role('button', name='安全登录').click()
                expect(page.locator('.topbar-role')).to_have_text('用户')
                expect(page.get_by_role('button', name='账号管理', exact=True)).to_have_count(0)
                checks.append('user_new_password_login_and_no_admin_navigation')
                page.get_by_role('button', name='智能检索', exact=True).click()
                page.get_by_label('关键词', exact=True).fill('synthetic')
                page.get_by_role('button', name='开始检索').click()
                expect(page.get_by_role('alert')).to_contain_text('Search integration unavailable')
                checks.append('unconfigured_search_shows_real_failure')
                page.get_by_role('button', name='邮件头解析 待接入').click()
                expect(page.get_by_role('heading', name='模块尚未接入')).to_be_visible()
                checks.append('unimplemented_module_is_explicit')
                page.set_viewport_size({'width':375,'height':812})
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'mobile horizontal overflow'
                page.screenshot(path=str(REPORTS/'module-mobile.png'), full_page=True)
                checks.append('mobile_375_no_horizontal_overflow')
                page.get_by_role('button', name='退出登录', exact=True).click()
                expect(page.get_by_role('heading', name='欢迎回来')).to_be_visible()
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth'), 'mobile login horizontal overflow'
                page.screenshot(path=str(REPORTS/'login-mobile.png'), full_page=True)
                checks.append('logout_and_mobile_login')
                assert not errors, 'browser page errors'
                browser.close()
        finally:
            for process in reversed(processes):
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
    result = {'status':'passed','checks':checks,'page_errors':errors,'backend':'real FastAPI with disposable SQLite; search intentionally disabled','screenshots':['login-desktop.png','overview-desktop.png','users-desktop.png','module-mobile.png','login-mobile.png']}
    (REPORTS/'browser-smoke.json').write_text(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps(result, ensure_ascii=False))

if __name__ == '__main__':
    run()
