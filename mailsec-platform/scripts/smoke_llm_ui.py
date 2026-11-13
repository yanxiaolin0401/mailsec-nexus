"""Platform LLM UI acceptance: live config/catalog reads, mocked model planning.

No external model calls or configuration writes. Browser routes stub planning and
execution only; real structured search is covered by smoke_cloud_preview.py.
"""
from __future__ import annotations

import json
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

PLATFORM = Path(__file__).resolve().parents[1]
URL = 'http://43.133.251.134:5173'


def main():
    credentials = json.loads((PLATFORM / '.local/cloud-preview-credentials.json').read_text())
    errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path='/home/ubuntu/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome', args=['--no-sandbox'])
        page = browser.new_page(viewport={'width': 1440, 'height': 1000})
        page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto(URL)
        page.get_by_role('tab', name='管理员登录').click()
        page.get_by_label('账号', exact=True).fill(credentials['admin']['username'])
        page.get_by_label('密码', exact=True).fill(credentials['admin']['password'])
        page.get_by_role('button', name='安全登录').click()
        expect(page.locator('.topbar-role')).to_have_text('管理员')
        page.get_by_role('button', name='大模型接入', exact=True).click()
        expect(page.get_by_label('服务商', exact=True).locator('option')).to_have_count(5)
        page.get_by_label('服务商', exact=True).select_option('deepseek')
        expect(page.get_by_label('Base URL', exact=True)).to_have_value('https://api.deepseek.com')
        expect(page.get_by_label('模型名', exact=True)).to_have_value('deepseek-flash')
        expect(page.get_by_label('API Key', exact=True)).to_have_value('')
        page.set_viewport_size({'width': 375, 'height': 812})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        page.screenshot(path=str(PLATFORM / '.local/llm-config-mobile.png'), full_page=True, animations='disabled')
        page.set_viewport_size({'width': 1440, 'height': 1000})
        page.get_by_role('button', name='智能检索', exact=True).click()
        page.get_by_label('检索租户').select_option('1')
        calls = []

        def preview(route):
            calls.append(route.request.post_data_json)
            route.fulfill(json={'plan': {'tool': 'search', 'filters': {'subject_contains': 'synthetic', 'limit': 2, 'offset': 0}}, 'executed': False, 'plan_token': 'synthetic-browser-token'})

        def execute(route):
            body = route.request.post_data_json
            calls.append(body)
            offset = body.get('offset', 0)
            route.fulfill(json={'plan': {'tool': 'search'}, 'executed': True, 'result': {'items': [{'mail_id': f'synthetic-{offset}', 'subject': '合成 UI 流程', 'sender': 'qa@example.test'}], 'total': None, 'limit': 2, 'offset': offset, 'may_have_more': offset == 0}})

        page.route('**/api/platform/v1/mail/nl/plan', preview)
        page.route('**/api/platform/v1/mail/plan/execute', execute)
        page.get_by_label('描述要找的邮件或统计条件').fill('查找主题含 synthetic 的邮件，最多2封')
        page.get_by_role('button', name='生成查询计划').click()
        expect(page.get_by_text('查询计划预览', exact=True)).to_be_visible()
        assert len(calls) == 1
        page.get_by_role('button', name='确认并执行').click()
        expect(page.locator('.results-panel tbody tr')).to_have_count(1)
        assert calls[-1]['limit'] == 2 and calls[-1]['plan_token'] == 'synthetic-browser-token'
        page.get_by_role('button', name='下一页', exact=True).click()
        expect(page.get_by_text('第 2 页', exact=True)).to_be_visible()
        expect(page.locator('.results-panel tbody tr small')).to_have_text('synthetic-2')
        assert calls[-1]['offset'] == 2 and len(calls) == 3
        page.get_by_label('数据源', exact=True).select_option('event')
        expect(page.get_by_text('查询计划预览', exact=True)).to_have_count(0)
        expect(page.locator('.results-panel tbody tr')).to_have_count(0)
        page.get_by_role('button', name='退出登录').click()
        browser.close()
    assert not errors
    report = {'status': 'passed', 'live_catalog_config_ui': True, 'mocked_plan_confirm_execute_pagination': True, 'source_switch_clears_state': True, 'mobile_no_overflow': True, 'javascript_errors': errors, 'external_model_calls': 0, 'configuration_writes': 0}
    (PLATFORM / '.local/llm-ui-acceptance.json').write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report))


if __name__ == '__main__':
    main()
