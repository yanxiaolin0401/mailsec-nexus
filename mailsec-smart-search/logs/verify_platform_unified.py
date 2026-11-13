"""Authorized real-browser acceptance of the shared platform; two model calls."""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[2]
PLATFORM = ROOT / 'mailsec-platform'
URL = 'http://43.133.251.134:5173'
PREFIX = '/api/platform/v1'
credentials = json.loads((PLATFORM / '.local/cloud-preview-credentials.json').read_text())
report = {'time': datetime.now(timezone.utc).isoformat(), 'checks': {}, 'model_calls': 0}
step = 'unauthorized_and_roles'
try:
    with httpx.Client(base_url=URL, trust_env=False, timeout=40) as client:
        assert client.get(PREFIX + '/session').status_code == 401
        login = client.post(PREFIX + '/auth/login', headers={'Origin': URL},
                            json={**credentials['user'], 'mode': 'user'})
        assert login.status_code == 200
        for path in ('/admin/mail/storage', '/admin/mail/queue', '/admin/mail/jobs'):
            assert client.get(PREFIX + path).status_code == 403
        assert client.get(PREFIX + '/integration/status').json()['smart_search']['status'] == 'ready'
    report['checks']['role_protection_and_uds_integration'] = True
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True,
            executable_path='/home/ubuntu/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome',
            args=['--no-sandbox'])
        page = browser.new_page(viewport={'width': 1440, 'height': 1000})
        errors = []
        destinations = set()
        page.on('pageerror', lambda error: errors.append(type(error).__name__))
        page.on('request', lambda request: destinations.add(request.url.split('/')[2]) if '://' in request.url else None)
        step = 'admin_login'
        page.goto(URL)
        page.get_by_role('tab', name='管理员登录').click()
        page.get_by_label('账号', exact=True).fill(credentials['admin']['username'])
        page.get_by_label('密码', exact=True).fill(credentials['admin']['password'])
        page.get_by_role('button', name='安全登录').click()
        expect(page.locator('.topbar-role')).to_have_text('管理员', timeout=15000)
        step = 'storage_queue'
        page.get_by_role('button', name='存储与队列', exact=True).click()
        expect(page.get_by_role('heading', name='邮件存储与队列')).to_be_visible()
        expect(page.locator('main')).to_contain_text('992', timeout=40000)
        expect(page.locator('main')).to_contain_text('109516', timeout=40000)
        expect(page.locator('main table tbody tr').first).to_be_visible(timeout=40000)
        report['checks']['admin_storage_queue_jobs_ui'] = True
        step = 'natural_language_plan'
        page.get_by_role('button', name='智能检索', exact=True).click()
        page.get_by_label('数据源', exact=True).select_option('event')
        page.get_by_label('检索租户').select_option('1')
        page.locator('textarea').fill('查询主题包含发票的邮件，最多返回5封，不要限定时间')
        with page.expect_response(lambda r: r.url.endswith(PREFIX + '/mail/nl/plan'), timeout=40000) as pending:
            page.get_by_role('button', name='生成查询计划', exact=True).click()
        planned = pending.value
        assert planned.status == 200
        payload = planned.json()
        assert payload['executed'] is False
        filters = payload['plan']['filters']
        assert filters['subject_contains'] == '发票' and filters['limit'] == 5
        report['model_calls'] += 1
        step = 'signed_plan_execute'
        with page.expect_response(lambda r: r.url.endswith(PREFIX + '/mail/plan/execute'), timeout=40000) as pending:
            page.get_by_role('button', name='确认并执行', exact=True).click()
        executed = pending.value
        assert executed.status == 200
        result = executed.json()['result']
        assert result['total'] == 18 and len(result['items']) == 5
        report['checks']['live_nl_preview_and_signed_execution'] = True
        report['search_matches'] = result['total']
        step = 'detail_and_analysis'
        page.locator('main table tbody tr').first.click()
        expect(page.get_by_role('button', name='研判此邮件', exact=True)).to_be_visible(timeout=20000)
        with page.expect_response(lambda r: '/analysis?' in r.url and r.request.method == 'POST', timeout=40000) as pending:
            page.get_by_role('button', name='研判此邮件', exact=True).click()
        analyzed = pending.value
        assert analyzed.status == 200 and analyzed.json()['status'] == 'ok'
        report['model_calls'] += 1
        expect(page.get_by_role('status')).to_contain_text('本次意见', timeout=20000)
        report['checks']['live_mail_detail_analysis_and_history'] = True
        step = 'mobile_and_secrets'
        page.get_by_role('button', name='关闭详情', exact=True).click()
        page.get_by_role('button', name='大模型接入', exact=True).click()
        expect(page.get_by_label('API Key', exact=True)).to_have_value('')
        page.set_viewport_size({'width': 390, 'height': 844})
        assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
        assert not errors
        assert all(':8080' not in host and ':8090' not in host for host in destinations)
        report['checks']['single_browser_origin_no_key_echo_mobile'] = True
        browser.close()
    report['passed'] = True
except Exception as exc:
    report.update(passed=False, failed_step=step, error_type=type(exc).__name__)
Path(__file__).with_suffix('.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(report, ensure_ascii=False))
sys.exit(0 if report['passed'] else 1)
