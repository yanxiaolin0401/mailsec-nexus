from dataclasses import replace
from datetime import datetime, timezone
import hashlib

import pytest

from mailsec_smart_search.config import Settings
from mailsec_smart_search.domain import MailRecord
from mailsec_smart_search.evidence import read_evidence


def record(raw: bytes, raw_path: str) -> MailRecord:
    digest = hashlib.sha256(raw).hexdigest()
    return MailRecord(digest, digest, raw_path, "test", datetime.now(timezone.utc))


def test_portable_dataset_reference_and_checksum(tmp_path):
    datasets = tmp_path / "datasets"
    path = datasets / "raw" / "enron" / "mail.1"
    path.parent.mkdir(parents=True)
    raw = b"Subject: ok\r\n\r\nbody"
    path.write_bytes(raw)
    settings = replace(Settings(), data_dir=tmp_path / "state", datasets_dir=datasets)
    assert read_evidence(record(raw, "dataset://raw/enron/mail.1"), settings) == raw
    with pytest.raises(ValueError, match="checksum"):
        read_evidence(record(b"different", "dataset://raw/enron/mail.1"), settings)


@pytest.mark.parametrize("ref", ["dataset://../outside", "dataset:///etc/passwd",
                                  "dataset://raw//mail", "dataset://raw/./mail",
                                  "dataset://raw/../../outside", "dataset://raw\\mail"])
def test_dataset_reference_rejects_traversal(tmp_path, ref):
    datasets = tmp_path / "datasets"
    datasets.mkdir()
    settings = replace(Settings(), data_dir=tmp_path / "state", datasets_dir=datasets)
    with pytest.raises(ValueError, match="invalid dataset"):
        read_evidence(record(b"x", ref), settings)


def test_dataset_symlink_escape_and_spool_absolute_compatibility(tmp_path):
    datasets = tmp_path / "datasets"
    datasets.mkdir()
    spool = tmp_path / "state" / "spool"
    spool.mkdir(parents=True)
    outside = tmp_path / "outside.eml"
    outside.write_bytes(b"outside")
    (datasets / "escape").symlink_to(outside)
    settings = replace(Settings(), data_dir=tmp_path / "state", datasets_dir=datasets)
    with pytest.raises(ValueError, match="escapes configured root"):
        read_evidence(record(b"outside", "dataset://escape"), settings)
    spool_file = spool / "mail.eml"
    spool_file.write_bytes(b"spool")
    assert read_evidence(record(b"spool", str(spool_file)), settings) == b"spool"


def test_migrated_absolute_spool_reference_reads_only_local_checksum_copy(tmp_path):
    state = tmp_path / "state"
    datasets = tmp_path / "datasets"
    (state / "spool" / "raw").mkdir(parents=True)
    datasets.mkdir()
    raw = b"Subject: migrated\r\n\r\nbody"
    digest = hashlib.sha256(raw).hexdigest()
    local = state / "spool" / "raw" / f"{digest}.eml"
    local.write_bytes(raw)
    old = tmp_path / "old-host" / "spool" / "raw" / f"{digest}.eml"
    old.parent.mkdir(parents=True)
    old.write_bytes(b"untrusted old-host content")
    settings = replace(Settings(), data_dir=state, datasets_dir=datasets)
    assert read_evidence(record(raw, str(old)), settings) == raw
    assert read_evidence(record(raw, "/data/spool/raw/" + digest + ".eml"), settings) == raw
    local.write_bytes(b"wrong local content")
    with pytest.raises(ValueError, match="checksum"):
        read_evidence(record(raw, str(old)), settings)


def test_migrated_absolute_reference_rejects_bad_digest_symlink_and_oversize(tmp_path):
    state = tmp_path / "state"
    datasets = tmp_path / "datasets"
    spool = state / "spool" / "raw"
    spool.mkdir(parents=True)
    datasets.mkdir()
    settings = replace(Settings(), data_dir=state, datasets_dir=datasets, max_message_bytes=4)
    digest = hashlib.sha256(b"good").hexdigest()
    old = str(tmp_path / "old-host" / "spool" / "raw" / f"{digest}.eml")
    item = record(b"good", old)
    with pytest.raises(ValueError, match="invalid legacy evidence checksum"):
        read_evidence(replace(item, raw_sha256="../etc/passwd"), settings)
    outside = tmp_path / "outside.eml"
    outside.write_bytes(b"good")
    local = spool / f"{item.raw_sha256}.eml"
    local.symlink_to(outside)
    with pytest.raises(ValueError, match="symlink"):
        read_evidence(item, settings)
    local.unlink()
    local.write_bytes(b"oversized")
    with pytest.raises(ValueError, match="oversized"):
        read_evidence(item, settings)


def test_migrated_absolute_reference_rejects_symlinked_spool_directory(tmp_path):
    state = tmp_path / "state"
    datasets = tmp_path / "datasets"
    outside = tmp_path / "outside"
    outside.mkdir()
    state.mkdir()
    datasets.mkdir()
    (state / "spool").symlink_to(outside, target_is_directory=True)
    raw = b"good"
    digest = hashlib.sha256(raw).hexdigest()
    (outside / "raw").mkdir()
    (outside / "raw" / f"{digest}.eml").write_bytes(raw)
    settings = replace(Settings(), data_dir=state, datasets_dir=datasets)
    with pytest.raises(ValueError, match="symlink"):
        read_evidence(record(raw, str(tmp_path / "old-host" / "spool" / "raw" / f"{digest}.eml")), settings)


def test_migrated_absolute_reference_requires_exact_old_spool_shape(tmp_path):
    state = tmp_path / "state"
    datasets = tmp_path / "datasets"
    local_dir = state / "spool" / "raw"
    local_dir.mkdir(parents=True)
    datasets.mkdir()
    raw = b"good"
    digest = hashlib.sha256(raw).hexdigest()
    (local_dir / f"{digest}.eml").write_bytes(raw)
    settings = replace(Settings(), data_dir=state, datasets_dir=datasets)
    for ref in (str(tmp_path / "old-host" / "mail.eml"),
                "/etc/passwd", "/data/spool/raw/wrong.eml",
                str(tmp_path / "old-host" / "spool" / "raw" / ".." / "raw" / f"{digest}.eml")):
        with pytest.raises(ValueError, match="invalid legacy evidence reference"):
            read_evidence(record(raw, ref), settings)


def test_migrated_absolute_reference_rejects_old_path_symlink(tmp_path):
    state = tmp_path / "state"
    datasets = tmp_path / "datasets"
    local_dir = state / "spool" / "raw"
    local_dir.mkdir(parents=True)
    datasets.mkdir()
    raw = b"good"
    digest = hashlib.sha256(raw).hexdigest()
    (local_dir / f"{digest}.eml").write_bytes(raw)
    old_dir = tmp_path / "old-host" / "spool" / "raw"
    old_dir.mkdir(parents=True)
    outside = tmp_path / "outside.eml"
    outside.write_bytes(b"different")
    (old_dir / f"{digest}.eml").symlink_to(outside)
    settings = replace(Settings(), data_dir=state, datasets_dir=datasets)
    with pytest.raises(ValueError, match="symlink"):
        read_evidence(record(raw, str(old_dir / f"{digest}.eml")), settings)
