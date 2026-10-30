from dataclasses import replace
from datetime import datetime, timezone

import pytest

from mailsec_smart_search.config import Settings
from mailsec_smart_search.evidence import read_evidence
from mailsec_smart_search.importer import ReusableParser, import_directory


class MemoryRepository:
    def __init__(self):
        self.records = []
        self.calls = 0
        self.fail_at = None

    def insert_batch(self, records):
        self.calls += 1
        if self.calls == self.fail_at:
            raise RuntimeError("database unavailable")
        self.records.extend(records)
        return len(records)


def test_import_checkpoint_dedup_and_original_paths(tmp_path):
    root = tmp_path / "enron"
    (root / "a").mkdir(parents=True)
    (root / "b").mkdir()
    (root / "a" / "1").write_bytes(b"Subject: first\r\n\r\none")
    (root / "b" / "2").write_bytes(b"Subject: first\r\n\r\none")
    (root / "b" / "3").write_bytes(b"Subject: second\r\n\r\ntwo")
    (root / "b" / "cmds").write_bytes(b"#!/bin/sh\nnot a message\n")
    (root / "b" / "README").write_bytes(b"dataset instructions")
    settings = replace(Settings(), data_dir=tmp_path / "state", datasets_dir=tmp_path)
    repository = MemoryRepository()
    report_path = tmp_path / "report.json"
    result = import_directory(root, settings, repository, batch_size=2, report_path=report_path)
    assert result["seen"] == 3
    assert result["inserted"] == 2
    assert result["duplicates"] == 1
    assert result["failed"] == 0
    assert report_path.exists()
    assert all(record.raw_path.startswith("dataset://enron/") for record in repository.records)
    assert all(read_evidence(record, settings) for record in repository.records)
    assert not (settings.data_dir / "spool").exists()
    again = import_directory(root, settings, repository, batch_size=2)
    assert again["inserted"] == 0
    assert again["duplicates"] == 3
    assert repository.calls == 1


def test_checkpoint_only_after_success_and_resume(tmp_path):
    root = tmp_path / "mail"
    root.mkdir()
    for index in range(3):
        (root / str(index)).write_bytes(f"Subject: {index}\r\n\r\nbody".encode())
    settings = replace(Settings(), data_dir=tmp_path / "state", datasets_dir=tmp_path)
    repository = MemoryRepository()
    repository.fail_at = 2
    failed = import_directory(root, settings, repository, batch_size=2)
    assert failed["inserted"] == 2
    assert failed["failed"] >= 1
    repository.fail_at = None
    resumed = import_directory(root, settings, repository, batch_size=2)
    assert resumed["inserted"] == 1
    assert resumed["duplicates"] == 2


def test_import_limits_and_skips_symlinks(tmp_path):
    root = tmp_path / "mail"
    root.mkdir()
    (root / "1").write_bytes(b"Subject: ok\r\n\r\nok")
    (root / "2").write_bytes(b"x" * 101)
    (root / "3").symlink_to(root / "1")
    settings = replace(Settings(), data_dir=tmp_path / "state", datasets_dir=tmp_path,
                       max_message_bytes=100)
    repository = MemoryRepository()
    result = import_directory(root, settings, repository, limit=3, batch_size=1)
    assert result["inserted"] == 1
    assert result["failed"] == 1
    assert result["seen"] == 3
    assert len(result["errors"]) == 1
    with pytest.raises(ValueError):
        import_directory(root, settings, repository, limit=0)


def test_import_rejects_root_outside_dataset_tree(tmp_path):
    root = tmp_path / "mail"
    root.mkdir()
    datasets = tmp_path / "datasets"
    datasets.mkdir()
    settings = replace(Settings(), data_dir=tmp_path / "state", datasets_dir=datasets)
    with pytest.raises(ValueError, match="inside configured datasets"):
        import_directory(root, settings, MemoryRepository())


def test_parser_process_reused_and_closed(tmp_path):
    with ReusableParser(timeout_seconds=5) as parser:
        one = parser.parse(b"Subject: one\r\n\r\na", mail_id="1", raw_sha256="1",
                           raw_path=str(tmp_path / "1"), source="test",
                           ingested_at=datetime.now(timezone.utc))
        pid = parser.pid
        two = parser.parse(b"Subject: two\r\n\r\nb", mail_id="2", raw_sha256="2",
                           raw_path=str(tmp_path / "2"), source="test",
                           ingested_at=datetime.now(timezone.utc))
        assert one.subject == "one"
        assert two.subject == "two"
        assert parser.pid == pid
    assert parser.pid is None
