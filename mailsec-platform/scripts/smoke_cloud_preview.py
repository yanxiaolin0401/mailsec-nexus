"""Read-only mail acceptance against a running platform Cloud preview.

Writes only platform login/audit records and a sanitized local report. Never
imports mail, calls a model, or changes accounts. Optional Playwright browser QA.
"""
from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

PLATFORM = Path(__file__).resolve().parents[1]
PREFIX = '/api/platform/v1'


def run(url: str, credentials: dict, browser_path: str | None) -> dict:
    checks = []
    totals = {}
    with httpx.Client(base_url=url, trust_env=False, timeout=40) as client:
        assert client.get(PREFIX + '/session').status_code == 401
        user = credentials['user']
        response = client.post(PREFIX + '/auth/login', headers={'Origin': url}, json={**user, 'mode': 'user'})
        assert response.status_code == 200, f'login HTTP {response.status_code}'
        headers = {'X-CSRF-Token': response.json()['csrf_token']}
        assert client.get(PREFIX + '/integration/status').json()['smart_search']['status'] == 'ready'
        assert client.get(PREFIX + '/admin/users').status_code == 403
        for source in ('legacy', 'event'):
            filters = {'source': source}
            assert client.post(PREFIX + '/mail/search', json=filters).status_code == 403
            assert client.post(PREFIX + '/mail/stats', json={**filters, 'tenant_id': 2}, headers=headers).status_code == 403
            assert client.get(PREFIX + '/mail/test', params={**filters, 'tenant_id': 2}).status_code == 403
            stats = client.post(PREFIX + '/mail/stats', json=filters, headers=headers)
            stats.raise_for_status()
            totals[source] = stats.json()['total']
            pages = []
            for offset in (0, 2):
                response = client.post(PREFIX + '/mail/search', json={**filters, 'limit': 2, 'offset': offset}, headers=headers)
                response.raise_for_status()
                data = response.json()
                if source == 'legacy':
                    assert data['total'] is None and isinstance(data['may_have_more'], bool)
                items = data['items']
                pages.append({item['mail_id' if source == 'legacy' else 'event_id'] for item in items})
            assert pages[0] and not pages[0] & pages[1]
            mail_id = next(iter(pages[0]))
            response = client.get(PREFIX + '/mail/' + mail_id, params=filters)
            response.raise_for_status()
            assert 'raw_path' not in response.json()
            checks.append(f'{source}_stats_pagination_detail_and_tenant_isolation')
        assert client.post(PREFIX + '/mail/search', json={'source': 'legacy', 'risk_level': 'high'}, headers=headers).status_code == 422
        client.post(PREFIX + '/session/logout', headers=headers).raise_for_status()
        assert client.get(PREFIX + '/session').status_code == 401
        checks.append('session_csrf_logout_and_admin_denial')
    errors = []
    if browser_path:
        from playwright.sync_api import expect, sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, executable_path=browser_path, args=['--no-sandbox', '--disable-dev-shm-usage'])
            page = browser.new_page(viewport={'width': 1440, 'height': 1000})
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(url)
            page.get_by_role('tab', name='管理员登录').click()
            page.get_by_label('账号', exact=True).fill(credentials['admin']['username'])
            page.get_by_label('密码', exact=True).fill(credentials['admin']['password'])
            page.get_by_role('button', name='安全登录').click()
            expect(page.locator('.topbar-role')).to_have_text('管理员')
            page.get_by_role('button', name='账号管理', exact=True).click()
            expect(page.get_by_role('row').filter(has_text='analyst')).to_be_visible()
            page.get_by_role('button', name='退出登录').click()
            expect(page.get_by_role('heading', name='欢迎回来')).to_be_visible()
            page.get_by_label('账号', exact=True).fill(user['username'])
            page.get_by_label('密码', exact=True).fill(user['password'])
            page.get_by_label('租户标识', exact=True).fill(user['tenant_slug'])
            page.get_by_role('button', name='安全登录').click()
            expect(page.locator('.topbar-role')).to_have_text('用户')
            expect(page.get_by_role('button', name='账号管理', exact=True)).to_have_count(0)
            page.get_by_role('button', name='智能检索', exact=True).click()
            expect(page.get_by_label('数据源', exact=True)).to_have_value('legacy')
            expect(page.get_by_label('风险等级（仅事件）')).to_be_disabled()
            page.get_by_role('button', name='开始检索').click()
            expect(page.locator('.results-panel tbody tr')).to_have_count(20, timeout=40000)
            expect(page.get_by_text('本页 20 条 · 总数未计算', exact=True)).to_be_visible()
            first = page.locator('.results-panel tbody tr small').all_text_contents()
            page.get_by_role('button', name='下一页', exact=True).click()
            expect(page.get_by_text('第 2 页', exact=True)).to_be_visible(timeout=40000)
            expect(page.locator('.results-panel tbody tr')).to_have_count(20, timeout=40000)
            second = page.locator('.results-panel tbody tr small').all_text_contents()
            assert not set(first) & set(second)
            page.locator('.results-panel tbody tr').first.click()
            expect(page.locator('.drawer-body')).to_be_visible(timeout=40000)
            page.get_by_role('button', name='关闭详情').click()
            page.get_by_role('button', name='统计匹配数').click()
            expect(page.locator('.search-stats')).to_contain_text(str(totals['legacy']), timeout=40000)
            page.get_by_label('数据源', exact=True).select_option('event')
            expect(page.locator('.results-panel tbody tr')).to_have_count(0)
            expect(page.locator('.search-stats')).to_have_count(0)
            page.get_by_role('button', name='开始检索').click()
            expect(page.locator('.results-panel tbody tr')).to_have_count(min(20, totals['event']), timeout=40000)
            page.locator('.results-panel tbody tr').first.click()
            expect(page.locator('.drawer-body')).to_be_visible(timeout=40000)
            page.get_by_role('button', name='关闭详情').click()
            # Clear mail before screenshots: reports never contain message contents.
            page.get_by_label('数据源', exact=True).select_option('legacy')
            page.set_viewport_size({'width': 375, 'height': 812})
            page.wait_for_function("document.querySelector('.sidebar').getBoundingClientRect().right <= 0")
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert page.evaluate('localStorage.length + sessionStorage.length') == 0
            screenshot = PLATFORM / '.local/cloud-preview-mobile.png'
            page.screenshot(path=str(screenshot), full_page=True, animations='disabled')
            page.get_by_role('button', name='退出登录').click()
            expect(page.get_by_role('heading', name='欢迎回来')).to_be_visible()
            browser.close()
        assert not errors, 'Browser JavaScript error; inspect locally without publishing mail content'
        checks.extend(['browser_admin_user_login', 'browser_legacy_pagination_detail_stats', 'browser_source_switch_event_detail', 'mobile_no_overflow_and_no_browser_storage'])
    return {'at': datetime.now(UTC).isoformat(), 'status': 'passed', 'totals': totals, 'checks': checks, 'javascript_errors': errors, 'cloud_mail_writes': 0, 'external_model_calls': 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:5173')
    parser.add_argument('--credentials', type=Path, default=PLATFORM / '.local/cloud-preview-credentials.json')
    parser.add_argument('--browser-path')
    parser.add_argument('--report', type=Path, default=PLATFORM / 'docs/reports/cloud-preview-acceptance.json')
    args = parser.parse_args()
    result = run(args.url.rstrip('/'), json.loads(args.credentials.read_text()), args.browser_path)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    main()
