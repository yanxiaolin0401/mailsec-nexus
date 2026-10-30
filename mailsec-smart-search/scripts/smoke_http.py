"""Local API integration smoke; submits synthetic mail only, never calls a model."""
import json
import os
import time
import uuid
from pathlib import Path

import httpx


def main():
    token = os.environ['MAILSEC_API_TOKEN']
    subject = 'MailSec local smoke ' + uuid.uuid4().hex[:12]
    raw = (f'From: sender@example.org\r\nTo: receiver@example.org\r\nSubject: {subject}\r\n'
           'Date: Tue, 20 Oct 2026 12:00:00 +0800\r\nMessage-ID: <local-test@example.org>\r\n'
           'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nLocal integration test only.\r\n').encode()
    report = {}
    with httpx.Client(base_url='http://127.0.0.1:8080', timeout=45, trust_env=False) as c:
        report['unauthorized_status'] = c.post('/v1/search', json={}).status_code
        assert report['unauthorized_status'] == 401
        c.headers['X-Mailsec-Token'] = token
        report['ready_status'] = c.get('/health/ready').status_code
        assert report['ready_status'] == 200
        response = c.post('/v1/mail/raw', content=raw, headers={'Content-Type': 'message/rfc822'})
        assert response.status_code == 202, response.text
        receipt = response.json()
        report['raw_status'] = response.status_code
        uploaded = c.post('/v1/mail/upload', files={'file': ('sample.eml', raw, 'message/rfc822')})
        assert uploaded.status_code == 202, uploaded.text
        assert uploaded.json()['mail_id'] == receipt['mail_id']
        report['upload_deduplicated'] = True
        for _ in range(60):
            job = c.get('/v1/jobs/' + receipt['job_id']).json()
            if job['status'] == 'done':
                break
            time.sleep(1)
        assert job['status'] == 'done', job
        report['worker_status'] = job['status']
        result = c.post('/v1/search', json={'subject_contains': subject}).json()
        assert result['count'] == 1, result
        report['search_count'] = result['count']
        detail = c.get('/v1/mail/' + receipt['mail_id'])
        assert detail.status_code == 200 and 'raw_path' not in detail.json()
        # Real local scanners, but NEVER allow a model call in this smoke run.
        if not os.environ.get('MAILSEC_LLM_API_KEY'):
            result = c.post('/v1/mail/' + receipt['mail_id'] + '/analysis')
            assert result.status_code == 200, result.text
            value = result.json()
            assert value['rspamd']['status'] == value['clamav']['status'] == 'ok', value
            assert value['model']['status'] == 'unavailable', value
            report['analysis'] = {k: value[k]['status'] for k in ('rspamd','clamav','model')}
            report['analysis_risk'] = value['risk']
            saved = c.get('/v1/mail/' + receipt['mail_id'] + '/analyses').json()
            assert len(saved['items']) >= 1
            report['analysis_persisted'] = True
        report['sensitive_nl_status'] = c.post('/v1/nl/query', json={'text':'Find alice@example.org'}).status_code
        assert report['sensitive_nl_status'] == 422
        report['oversized_json_status'] = c.post('/v1/search', content=b' '*65537).status_code
        assert report['oversized_json_status'] == 413
        report['sop_status'] = c.post('/v1/sop/invoice_phishing', json={'analyze':False,'candidate_limit':10}).status_code
        assert report['sop_status'] == 200
    path = Path('docs/reports/http-smoke.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
