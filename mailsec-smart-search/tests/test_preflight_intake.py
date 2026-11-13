"""Offline intake preflight never mutates the source or exposes payloads by default."""

import hashlib
import json
import stat
from pathlib import Path

from scripts.preflight_intake import main, preflight
from mailsec_smart_search.events import normalize_event

DATASET = Path(__file__).parents[1] / "docs" / "统一输入流交付包" / "mail_offline_dataset_1000.jsonl"


def _sample(event_id: str) -> dict:
    return {"eventId": event_id, "sourceSystemId": "MAIL_OFFLINE", "sourceEventId": "source-1",
            "eventTime": "2026-11-01T23:55:25Z", "from": "sender@example.test",
            "to": ["recipient@example.test"], "subject": "-", "rawHeaders": "-"}


def test_full_dataset_strict_and_opt_in_uuid_repair_counts_without_source_mutation(tmp_path):
    before = hashlib.sha256(DATASET.read_bytes()).hexdigest()
    strict = preflight(DATASET)
    assert strict["total"] == 1000
    assert (strict["accepted"], strict["rejected"], strict["repaired_event_ids"]) == (358, 642, 0)
    assert strict["categories"] == {"eventId must be a UUID": 621,
                                    "invalid from address": 20, "invalid or missing to": 1}
    assert strict["input_unchanged"] and strict["original_contract_passed"] is False
    assert strict["issues"] and all(set(issue) == {"line", "category"} for issue in strict["issues"])
    assert hashlib.sha256(DATASET.read_bytes()).hexdigest() == before
    repaired = preflight(DATASET, repair_ids=True)
    assert (repaired["accepted"], repaired["rejected"], repaired["repaired_event_ids"]) == (979, 21, 621)
    assert repaired["categories"] == {"invalid from address": 20, "invalid or missing to": 1}
    assert repaired["mode"] == "uuid_repair_opt_in"
    assert repaired["original_contract_passed"] is False
    assert hashlib.sha256(DATASET.read_bytes()).hexdigest() == before


def test_explicit_output_repair_preserves_original_id_and_private_file_permissions(tmp_path):
    original = _sample("bad-id")
    source = tmp_path / "input.jsonl"
    source.write_text(json.dumps(original) + "\n")
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    output = tmp_path / "valid.jsonl"
    rejects = tmp_path / "rejects.jsonl"
    result = preflight(source, repair_ids=True, output=output, rejects=rejects)
    assert (result["accepted"], result["rejected"], result["repaired_event_ids"]) == (1, 0, 1)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    written = json.loads(output.read_text())
    assert written["originalEventId"] == "bad-id"
    assert written["eventId"] == normalize_event({k: v for k, v in original.items() if k != "eventId"}, canonical=True)["event_id"]
    assert normalize_event(written, canonical=True)["event_id"] == written["eventId"]
    assert rejects.read_text() == ""
    assert stat.S_IMODE(output.stat().st_mode) == stat.S_IRUSR | stat.S_IWUSR
    assert stat.S_IMODE(rejects.stat().st_mode) == stat.S_IRUSR | stat.S_IWUSR
    # Existing outputs fail closed; never silently replace a derivative file.
    assert main([str(source), "--repair-ids", "--output", str(output)]) == 2
    assert output.read_text() == json.dumps(written, ensure_ascii=False, separators=(",", ":")) + "\n"


def test_invalid_payloads_go_to_explicit_rejects_without_legacy_fallback(tmp_path):
    payload = _sample("bad-id")
    payload["from"] = "-"
    payload["senderaccount"] = "legacy@example.test"
    source = tmp_path / "input.jsonl"
    source.write_text(json.dumps(payload) + "\n")
    output = tmp_path / "valid.jsonl"
    rejects = tmp_path / "rejects.jsonl"
    result = preflight(source, repair_ids=True, output=output, rejects=rejects)
    assert result["accepted"] == 0 and result["rejected"] == 1
    assert json.loads(rejects.read_text()) == payload
    assert output.read_text() == ""
    assert main([str(source)]) == 1
    assert main([str(source), "--output", str(source)]) == 2
    assert main([str(source), "--output", str(output), "--rejects", str(output)]) == 2


def test_report_is_private_and_confined_to_repository_logs(tmp_path):
    source = tmp_path / "input.jsonl"
    source.write_text(json.dumps(_sample("bad-id")) + "\n")
    # A report path outside logs must be rejected before any file is created.
    outside = tmp_path / "report.json"
    assert main([str(source), "--report", str(outside)]) == 2
    assert not outside.exists()
    logs = Path(__file__).parents[1] / "logs"
    logs.mkdir(exist_ok=True)
    report = logs / f"preflight-test-{hashlib.sha256(str(tmp_path).encode()).hexdigest()[:12]}.json"
    try:
        result = preflight(source, report=report)
        saved = json.loads(report.read_text())
        assert saved["categories"] == result["categories"]
        assert saved["issues"] == [{"line": 1, "category": "eventId must be a UUID"}]
        assert stat.S_IMODE(report.stat().st_mode) == stat.S_IRUSR | stat.S_IWUSR
    finally:
        report.unlink(missing_ok=True)
