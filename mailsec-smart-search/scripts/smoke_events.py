"""Synthetic HTTP JSON -> durable queue -> worker -> ClickHouse acceptance smoke.

Requires a running API + worker and MAILSEC_API_TOKEN; never calls an external model.
Leaves three synthetic events under a unique source_system_id for auditability.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import httpx


def smoke(url: str, token: str) -> dict:
    source = "json-smoke-" + uuid4().hex[:12]
    checks = {}
    ids = []
    job_ids = []
    mail = {
        "senderaccount": "SENDER@example.test",
        "toaccount": "finance@example.test",
        "allReceiverAccount": ["finance@example.test", "reviewer@example.test"],
        "subject": "发票 smoke",
        "textContent": "<p>invoice synthetic</p><script>discard</script>",
        "ip": "8.8.8.8",
        "urls": ["https://example.test/smoke"],
        "attachInfos": [{"filename": "发票.pdf", "md5": "a" * 32, "size": "100"}],
        "mailHeaderList": [
            "Received: from test [8.8.8.8]",
            "X-Test: one",
            "X-Test: two",
        ],
    }
    with httpx.Client(
        base_url=url, headers={"X-Mailsec-Token": token}, timeout=15, trust_env=False
    ) as client:
        assert (
            client.get("/api/v1/mails", headers={"X-Mailsec-Token": ""}).status_code
            == 401
        )
        checks["unauthorized"] = 401
        first = None
        for number, envelope in enumerate(["mail", "data", None]):
            payload = {
                "sourceSystemId": source,
                "sourceEventId": str(number),
                "eventTime": datetime.now(timezone.utc).isoformat(),
            }
            payload.update({envelope: mail} if envelope else mail)
            result = client.post("/api/v2/mails", json=payload)
            assert result.status_code == 202, result.text
            receipt = result.json()
            ids.append(receipt["eventId"])
            job_ids.append(receipt["jobId"])
            if number == 0:
                first = (payload, receipt)
        assert len(set(ids)) == 3
        checks["nested_data_flat"] = [202, 202, 202]
        replay = client.post("/api/v2/mails", json=first[0])
        assert replay.json() == first[1]
        conflict = json.loads(json.dumps(first[0]))
        conflict["mail"]["subject"] = "changed"
        assert client.post("/api/v2/mails", json=conflict).status_code == 409
        checks["idempotency"] = True
        checks["conflict"] = 409
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            states = [
                client.get("/api/v2/jobs/" + job_id).json()["status"]
                for job_id in job_ids
            ]
            if states == ["done"] * 3:
                break
            time.sleep(0.5)
        assert states == ["done"] * 3, states
        checks["worker_jobs"] = states
        filters = {
            "source_system_id": source,
            "sender": "SENDER@example.test",
            "senderIp": "8.8.8.8",
            "attachmentMd5": "a" * 32,
            "attachment_name_contains": "发票",
            "body_contains": "invoice",
            "limit": 2,
        }
        response = client.get("/api/v1/mails", params=filters)
        assert response.status_code == 200, response.text
        result = response.json()
        assert (
            result["total"] == 3
            and len(result["items"]) == 2
            and result["may_have_more"]
        )
        assert "text_content" not in result["items"][0]
        assert (
            client.get("/api/v1/mails", params={**filters, "offset": 2}).json()["total"]
            == 3
        )
        checks["combined_filter_total"] = 3
        checks["pagination"] = True
        stats = client.get("/api/v1/stats", params=filters)
        assert stats.status_code == 200 and stats.json() == {"total": 3}, stats.text
        checks["structured_stats"] = stats.json()
        detail = client.get("/api/v1/mails/" + ids[0]).json()
        assert detail["risk_level"] == "unknown" and "raw_json" not in detail
        assert detail["event_time"].endswith("+00:00")
        checks["utc_output"] = True
        assert (
            detail["text_content"] == "invoice synthetic"
            and len(detail["receiver_accounts"]) == 2
        )
        checks["detail_cleaning_privacy"] = True
        checks["homepage"] = client.get("/").status_code
        assert checks["homepage"] == 200
    return {
        "at": datetime.now(timezone.utc).isoformat(),
        "kind": "synthetic_http_json_real_clickhouse",
        "source_system_id": source,
        "event_ids": ids,
        "checks": checks,
        "external_model_calls": 0,
        "not_a_capacity_benchmark": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument(
        "--report", type=Path, default=Path("docs/reports/json-events-smoke.json")
    )
    args = parser.parse_args()
    token = os.environ.get("MAILSEC_API_TOKEN", "")
    if not token:
        parser.error("MAILSEC_API_TOKEN is required")
    report = smoke(args.url, token)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps(report, ensure_ascii=False))


if __name__ == "__main__":
    main()
