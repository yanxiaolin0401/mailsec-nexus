"""Explicit opt-in live provider check using synthetic, non-personal input only."""
from dataclasses import asdict
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json

from mailsec_smart_search.config import Settings
from mailsec_smart_search.llm import analyze_with_llm
from mailsec_smart_search.parser import parse_eml


def main():
    settings = Settings.from_env()
    raw = b'From: demo@example.org\r\nTo: demo@example.net\r\nSubject: Synthetic security test\r\n\r\nThis is a fabricated integration test; no real email content.\r\n'
    digest = sha256(raw).hexdigest()
    record = parse_eml(raw, mail_id=digest, raw_sha256=digest, raw_path='', source='synthetic', ingested_at=datetime.now(timezone.utc))
    result = analyze_with_llm(record, settings)
    evidence = {'synthetic_only': True, 'checked_at': datetime.now(timezone.utc).isoformat(), 'result': asdict(result)}
    path = Path('docs/reports/model-live-smoke.json')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(evidence, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'status': result.status, 'provider': result.provider, 'model': result.model_id, 'error': result.error},ensure_ascii=False))
    raise SystemExit(0 if result.status == 'ok' else 1)

if __name__ == '__main__':
    main()
