"""Browser acceptance: register -> admin approval -> login -> deactivate test user.

Creates one uniquely named local QA account and leaves it disabled for audit.
Never writes to ClickHouse. Requires optional Playwright QA installation.
"""
from __future__ import annotations

import argparse
import json
import secrets
from datetime import UTC, datetime
from pathlib import Path

import httpx
from playwright.sync_api import expect, sync_playwright

PLATFORM = Path(__file__).resolve().parents[1]
PREFIX = '/api/platform/v1'


def run(url: str, browser_path: str, password_mode: str = 'short') -> dict:
    credentials = json.loads((PLATFORM / '.local/cloud-preview-credentials.json').read_text())
    username = 'qa-register-' + secrets.token_hex(5)
    password = '' if password_mode == 'empty' else '1'
    errors = []
    checks = []
    with httpx.Client(base_url=url, trust_env=False, timeout=20) as admin:
        login = admin.post(PREFIX + '/auth/login', json={**credentials['admin'], 'mode': 'admin'}, headers={'Origin': url})
        assert login.status_code == 200, f'Admin login HTTP {login.status_code}'
        csrf = {'X-CSRF-Token': login.json()['csrf_token']}
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, executable_path=browser_path, args=['--no-sandbox'])
                page = browser.new_page(viewport={'width': 1440, 'height': 1000})
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.goto(url)
                assert page.request.get(url + '/Dockerfile?import').status == 403
                expect(page.locator('vite-error-overlay')).to_have_count(0)
                checks.append('dockerfile_request_does_not_interrupt_ui')
                page.get_by_role('tab', name='用户注册').click()
                expect(page.get_by_role('heading', name='申请用户账号')).to_be_visible()
                page.set_viewport_size({'width': 375, 'height': 812})
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                assert page.evaluate("document.querySelector('.login-mobile-brand').getBoundingClientRect().bottom <= document.querySelector('.login-card').getBoundingClientRect().top")
                assert page.evaluate("document.querySelector('.login-card').getBoundingClientRect().bottom <= document.querySelector('.login-bottom').getBoundingClientRect().top")
                page.screenshot(path=str(PLATFORM / '.local/registration-mobile.png'), full_page=True, animations='disabled')
                page.set_viewport_size({'width': 1440, 'height': 1000})
                page.get_by_label('账号', exact=True).fill(username)
                page.get_by_label('显示名称', exact=True).fill('注册流程验收账号')
                page.get_by_label('密码', exact=True).fill(password)
                page.get_by_label('确认密码', exact=True).fill(password + '-different')
                page.get_by_label('租户标识', exact=True).fill('cloud-test')
                page.get_by_role('button', name='提交注册申请').click()
                expect(page.get_by_role('alert')).to_contain_text('两次输入的密码不一致')
                page.get_by_label('确认密码', exact=True).fill(password)
                page.get_by_role('button', name='提交注册申请').click()
                expect(page.get_by_role('status')).to_contain_text('等待管理员', timeout=15000)
                checks.append('registration_pending_and_password_confirmation')
                page.get_by_role('tab', name='用户登录').click()
                expect(page.get_by_label('密码', exact=True)).to_have_value('')
                page.get_by_label('密码', exact=True).fill(password)
                page.get_by_role('button', name='安全登录').click()
                expect(page.get_by_role('alert')).to_contain_text('尚未启用')
                checks.append('pending_user_cannot_login')
                page.get_by_role('tab', name='管理员登录').click()
                expect(page.get_by_label('租户标识', exact=True)).to_have_count(0)
                page.get_by_label('账号', exact=True).fill(credentials['admin']['username'])
                page.get_by_label('密码', exact=True).fill(credentials['admin']['password'])
                page.get_by_role('button', name='安全登录').click()
                expect(page.locator('.topbar-role')).to_have_text('管理员')
                page.get_by_role('button', name='账号管理', exact=True).click()
                row = page.get_by_role('row').filter(has_text=username)
                expect(row).to_contain_text('待审核')
                page.once('dialog', lambda dialog: dialog.accept())
                row.get_by_role('button', name='启用', exact=True).click()
                expect(row.get_by_role('button', name='停用', exact=True)).to_be_visible()
                checks.append('administrator_approves_registration')
                page.get_by_role('button', name='退出登录').click()
                page.get_by_label('账号', exact=True).fill(username)
                page.get_by_label('密码', exact=True).fill(password)
                page.get_by_label('租户标识', exact=True).fill('cloud-test')
                page.get_by_role('button', name='安全登录').click()
                expect(page.locator('.topbar-role')).to_have_text('用户')
                expect(page.get_by_role('button', name='账号管理', exact=True)).to_have_count(0)
                page.reload()
                expect(page.locator('.topbar-role')).to_have_text('用户')
                assert page.evaluate('localStorage.length + sessionStorage.length') == 0
                page.get_by_role('button', name='修改密码', exact=True).click()
                page.get_by_label('当前密码', exact=True).fill(password)
                page.get_by_label('新密码', exact=True).fill('')
                page.get_by_role('button', name='确认修改', exact=True).click()
                expect(page.get_by_role('heading', name='欢迎回来')).to_be_visible()
                page.get_by_label('账号', exact=True).fill(username)
                page.get_by_label('租户标识', exact=True).fill('cloud-test')
                page.get_by_role('button', name='安全登录').click()
                expect(page.locator('.topbar-role')).to_have_text('用户')
                checks.append('change_to_empty_password_and_login')
                page.get_by_role('button', name='退出登录').click()
                expect(page.get_by_role('heading', name='欢迎回来')).to_be_visible()
                checks.extend(['approved_user_login_persistent_session_logout', 'mobile_layout_and_no_browser_secret_storage'])
                page.get_by_role('tab', name='管理员登录').click()
                page.get_by_label('账号', exact=True).fill(credentials['admin']['username'])
                page.get_by_label('密码', exact=True).fill(credentials['admin']['password'])
                page.get_by_role('button', name='安全登录').click()
                expect(page.locator('.topbar-role')).to_have_text('管理员')
                page.get_by_role('button', name='账号管理', exact=True).click()
                page.get_by_role('row').filter(has_text=username).get_by_role('button', name='编辑 / 重置密码').click()
                page.get_by_label('将密码设为空', exact=True).check()
                with page.expect_response(lambda response: response.request.method == 'PATCH' and '/admin/users/' in response.url) as reset:
                    page.get_by_role('button', name='保存', exact=True).click()
                assert reset.value.status == 200
                assert reset.value.request.post_data_json['password'] == ''
                expect(page.get_by_role('dialog')).to_have_count(0)
                page.get_by_role('button', name='退出登录').click()
                checks.append('admin_explicit_empty_password_reset')
                browser.close()
        finally:
            users = admin.get(PREFIX + '/admin/users')
            users.raise_for_status()
            for user in users.json()['items']:
                if user['username'] == username:
                    admin.patch(PREFIX + f"/admin/users/{user['id']}", headers=csrf, json={'is_active': False}).raise_for_status()
            admin.post(PREFIX + '/session/logout', headers=csrf).raise_for_status()
    assert not errors
    return {'at': datetime.now(UTC).isoformat(), 'status': 'passed', 'checks': checks, 'javascript_errors': errors, 'password_mode': password_mode, 'qa_account_left_disabled': True, 'cloud_writes': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--browser-path', required=True)
    parser.add_argument('--password-mode', choices=['short', 'empty'], default='short')
    args = parser.parse_args()
    result = run(args.url.rstrip('/'), args.browser_path, args.password_mode)
    (PLATFORM / '.local/registration-acceptance.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
