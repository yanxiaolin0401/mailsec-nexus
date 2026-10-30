import hashlib
import importlib.util
import json
from pathlib import Path

from mailsec_smart_search.detection import DetectionResult

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/evaluate_detectors.py"
_SPEC = importlib.util.spec_from_file_location("evaluate_detectors", _SCRIPT)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
evaluate, iter_manifest = _MODULE.evaluate, _MODULE.iter_manifest


def sample(data: Path, source: str, label: str, name: str, raw: bytes, *, is_message=True):
    base = data / "raw" / source
    base.mkdir(parents=True, exist_ok=True)
    (base / name).write_bytes(raw)
    index = data / "manifests" / f"{source}.files.jsonl"
    index.parent.mkdir(parents=True, exist_ok=True)
    with index.open("a") as stream:
        stream.write(json.dumps({"path": name, "sha256": hashlib.sha256(raw).hexdigest(),
                                 "bytes": len(raw), "label": label,
                                 "is_message": is_message}) + "\n")


def test_manifest_whitelist_and_safe_paths(tmp_path):
    sample(tmp_path, "enron", "ham", "one", b"enron")
    sample(tmp_path, "spamassassin-ham", "ham", "one", b"ham")
    sample(tmp_path, "nazario-2024", "phishing", "one", b"phish")
    sample(tmp_path, "spamassassin-spam", "spam", "metadata", b"meta", is_message=False)
    rows = list(iter_manifest(tmp_path))
    assert {row[1] for row in rows} == {"ham", "phishing"}
    index = tmp_path / "manifests/spamassassin-spam.files.jsonl"
    with index.open("a") as stream:
        stream.write(json.dumps({"path": "../escape", "sha256": "a" * 64, "bytes": 1,
                                 "label": "spam", "is_message": True}) + "\n")
    try:
        list(iter_manifest(tmp_path))
    except ValueError as exc:
        assert "unsafe" in str(exc) or "escapes" in str(exc)
    else:
        assert False, "unsafe manifest path was accepted"


def test_evaluation_metrics_resume_dedup_and_no_pii(tmp_path):
    data = tmp_path / "data"
    sample(data, "spamassassin-easy_ham", "ham", "h1", b"ham-1")
    sample(data, "spamassassin-spam", "spam", "s1", b"spam-1")
    sample(data, "nazario-2024", "phishing", "p1", b"phish-1")
    sample(data, "nazario-2025", "phishing", "p2", b"phish-1")  # Duplicate by SHA.
    calls = []

    def rspamd(raw, settings):
        calls.append(("rspamd", raw))
        risk = "clean" if raw == b"ham-1" else "suspicious"
        return DetectionResult("rspamd", "ok", risk)

    def clamav(raw, settings):
        calls.append(("clamav", raw))
        return DetectionResult("clamav", "unavailable")

    output = tmp_path / "reports/baseline.json"
    checkpoint = tmp_path / "var/evaluation/results.sqlite3"
    report = evaluate(data_dir=data, checkpoint=checkpoint, output=output,
                      limit_per_class=2, rspamd=rspamd, clamav=clamav)
    assert report["total_unique_samples"] == 3
    assert report["groups"]["label:ham"]["rspamd"]["tn"] == 1
    assert report["groups"]["label:spam"]["rspamd"]["tp"] == 1
    assert report["groups"]["label:phishing"]["rspamd"]["tp"] == 1
    assert report["groups"]["label:phishing"]["clamav"]["unknown"] == 1
    assert report["groups"]["label:phishing"]["clamav"]["availability_rate"] == 0
    assert len(calls) == 6
    again = evaluate(data_dir=data, checkpoint=checkpoint, output=output,
                     limit_per_class=2, rspamd=rspamd, clamav=clamav)
    assert again["new_samples_this_run"] == 0 and len(calls) == 6
    errors = [json.loads(line) for line in output.with_suffix(".errors.jsonl").read_text().splitlines()]
    assert errors and all(set(item) == {"digest", "source", "status"} for item in errors)
    assert b"ham-1" not in output.read_bytes()


def test_integrity_error_is_unknown_and_no_scanner_call(tmp_path):
    data = tmp_path / "data"
    sample(data, "spamassassin-spam", "spam", "s1", b"original")
    (data / "raw/spamassassin-spam/s1").write_bytes(b"tampered")
    def forbidden(*args):
        raise AssertionError("scanner must not see invalid sample")
    report = evaluate(data_dir=data, checkpoint=tmp_path / "resume.sqlite3",
                      output=tmp_path / "baseline.json", rspamd=forbidden, clamav=forbidden)
    assert report["groups"]["label:spam"]["rspamd"]["unknown"] == 1
    assert report["groups"]["label:spam"]["clamav"]["unknown"] == 1


def test_false_positive_false_negative_and_class_limit(tmp_path):
    data = tmp_path / "data"
    sample(data, "spamassassin-easy_ham", "ham", "h1", b"ham-one")
    sample(data, "spamassassin-easy_ham", "ham", "h2", b"ham-two")
    sample(data, "spamassassin-spam", "spam", "s1", b"spam-one")
    seen = []

    def rspamd(raw, settings):
        seen.append(raw)
        return DetectionResult("rspamd", "ok", "suspicious" if raw.startswith(b"ham") else "clean")

    def clamav(raw, settings):
        return DetectionResult("clamav", "timeout")

    report = evaluate(data_dir=data, checkpoint=tmp_path / "checkpoint.sqlite3",
                      output=tmp_path / "report.json", limit_per_class=1,
                      rspamd=rspamd, clamav=clamav)
    assert report["total_unique_samples"] == 2
    assert report["groups"]["label:ham"]["rspamd"]["fp"] == 1
    assert report["groups"]["label:spam"]["rspamd"]["fn"] == 1
    assert report["groups"]["label:spam"]["clamav"]["unknown"] == 1
    assert len(seen) == 2
