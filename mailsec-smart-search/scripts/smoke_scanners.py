"""Local scanner transport checks using harmless standard GTUBE/EICAR test strings."""
from dataclasses import asdict
from pathlib import Path
import argparse
import json

from mailsec_smart_search.config import Settings
from mailsec_smart_search.detection import scan_clamd, scan_rspamd


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, default=Path('docs/reports/scanner-smoke.json'))
    args = parser.parse_args()
    raw = (b'From: Local Sender <sender@example.org>\r\nTo: Receiver <receiver@example.net>\r\n'
           b'Date: Tue, 20 Oct 2026 12:00:00 +0800\r\nMessage-ID: <synthetic-smoke@example.org>\r\n'
           b'Subject: Local scanner integration test\r\nMIME-Version: 1.0\r\n'
           b'Content-Type: text/plain; charset=utf-8\r\n\r\nHello, this is a synthetic test.\r\n')
    gtube = raw + b'XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X\r\n'
    eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    settings = Settings.from_env()
    report = {'rspamd_benign': asdict(scan_rspamd(raw, settings)), 'rspamd_gtube': asdict(scan_rspamd(gtube, settings)),
              'clamav_benign': asdict(scan_clamd(raw, settings)), 'clamav_eicar': asdict(scan_clamd(eicar, settings))}
    assert all(result['status'] == 'ok' for result in report.values()), report
    assert report['rspamd_gtube']['risk'] == report['clamav_eicar']['risk'] == 'malicious', report
    assert report['clamav_benign']['risk'] == 'clean', report
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print('4 local scanner checks passed (synthetic test strings only)')

if __name__ == '__main__':
    main()
