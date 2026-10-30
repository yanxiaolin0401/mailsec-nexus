"""Dataset tooling regression tests use synthetic bytes only, never public emails."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile

import pytest

SPEC = importlib.util.spec_from_file_location("dataset_tools", Path(__file__).parents[1] / "scripts" / "datasets.py")
datasets = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(datasets)


def archive(tmp_path, entries):
    target = tmp_path / "sample.tar.gz"
    with tarfile.open(target, "w:gz") as output:
        for name, kind in entries:
            member = tarfile.TarInfo(name)
            if kind == "file":
                data = b"From: test@example.invalid\nSubject: fixture\n\nbody\n"
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
            else:
                member.type = kind
                member.linkname = "outside"
                output.addfile(member)
    return target


def test_extract_verifies_and_classifies_messages(tmp_path):
    source = archive(tmp_path, [("maildir/user/inbox/1.", "file"), ("README", "file")])
    index = tmp_path / "index.jsonl"
    result = datasets.extract_tar(source, tmp_path / "out", index, None)
    assert result["files"] == 2
    assert result["messages"] == 1
    assert source.exists()  # Caller deletes only AFTER writing final manifest.
    assert '"label": null' in index.read_text()


@pytest.mark.parametrize("name", ["../escape", "/absolute", "inside/../../escape", "foo\\bar"])
def test_archive_rejects_traversal(tmp_path, name):
    with pytest.raises(ValueError, match="Unsafe archive path"):
        datasets.extract_tar(archive(tmp_path, [(name, "file")]), tmp_path / "out", tmp_path / "index", None)
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE])
def test_archive_rejects_links_and_special_files(tmp_path, kind):
    with pytest.raises(ValueError, match="Unsupported archive entry"):
        datasets.extract_tar(archive(tmp_path, [("entry", kind)]), tmp_path / "out", tmp_path / "index", None)


def test_rejects_duplicate_files(tmp_path):
    source = archive(tmp_path, [("1", "file"), ("1", "file")])
    with pytest.raises(FileExistsError):
        datasets.extract_tar(source, tmp_path / "out", tmp_path / "index", None)


def test_rejects_existing_destination_and_symlink(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "out"
    root.mkdir()
    (root / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        datasets.safe_member_path(root, "linked/mail.eml")
    with pytest.raises(FileExistsError):
        datasets.extract_tar(archive(tmp_path, [("1", "file")]), root, tmp_path / "index", None)


def test_truncated_compression_never_verifies(tmp_path):
    source = archive(tmp_path, [("1", "file")])
    source.write_bytes(source.read_bytes()[:-8])
    with pytest.raises((EOFError, tarfile.ReadError)):
        datasets.extract_tar(source, tmp_path / "out", tmp_path / "index", None)
    assert source.exists()


def test_extracted_size_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(datasets, "MAX_EXTRACTED", 1)
    with pytest.raises(ValueError, match="size budget"):
        datasets.extract_tar(archive(tmp_path, [("1", "file")]), tmp_path / "out", tmp_path / "index", None)


def test_sha256(tmp_path):
    path = tmp_path / "bytes"
    path.write_bytes(b"fixture")
    assert datasets.sha256(path) == hashlib.sha256(b"fixture").hexdigest()


class FakeResponse(io.BytesIO):
    def __init__(self, data=b"", *, status=200, headers=None):
        super().__init__(data)
        self.status = status
        self.headers = headers or {}


def test_download_resumes_prefix_with_verified_ranges(tmp_path, monkeypatch):
    body = b"abcdefghijklmnopqrstuvwxyz"
    target = tmp_path / "corpus.tar.gz"
    target.write_bytes(body[:3])
    calls = []

    def open_url(request, timeout):
        if request.get_method() == "HEAD":
            return FakeResponse(headers={"Content-Length": str(len(body)), "ETag": '"fixture"'})
        value = request.get_header("Range")
        start, end = map(int, value.removeprefix("bytes=").split("-"))
        calls.append((start, end))
        return FakeResponse(body[start:end + 1], status=206, headers={"Content-Range": f"bytes {start}-{end}/{len(body)}"})

    monkeypatch.setattr(datasets, "urlopen", open_url)
    monkeypatch.setattr(datasets, "CHUNK", 5)
    assert datasets.download("https://example.invalid/corpus", target, workers=2) == target
    assert target.read_bytes() == body
    assert min(start for start, _ in calls) == 3
    assert not target.with_name(target.name + ".parts").exists()


def test_download_rejects_server_ignoring_range(tmp_path, monkeypatch):
    def open_url(request, timeout):
        if request.get_method() == "HEAD":
            return FakeResponse(headers={"Content-Length": "10", "ETag": '"fixture"'})
        return FakeResponse(b"0123456789", status=200)

    monkeypatch.setattr(datasets, "urlopen", open_url)
    with pytest.raises(ValueError, match="Invalid ranged response"):
        datasets.download("https://example.invalid/corpus", tmp_path / "download")


def test_download_rejects_changed_remote_object(tmp_path, monkeypatch):
    target = tmp_path / "download"
    parts = tmp_path / "download.parts"
    parts.mkdir()
    datasets.atomic_json(parts / "state.json", {"url": "https://example.invalid/corpus", "size": 10, "identity": '"old"', "seed": 0})
    monkeypatch.setattr(datasets, "urlopen", lambda *a, **kw: FakeResponse(headers={"Content-Length": "10", "ETag": '"new"'}))
    with pytest.raises(ValueError, match="Remote object changed"):
        datasets.download("https://example.invalid/corpus", target)


def test_verify_local_detects_file_tampering(tmp_path, monkeypatch):
    import json
    monkeypatch.setattr(datasets, "ROOT", tmp_path)
    raw = tmp_path / "raw" / "fixture"
    raw.mkdir(parents=True)
    message = raw / "1"
    message.write_bytes(b"original")
    manifests = tmp_path / "manifests"
    manifests.mkdir()
    index = manifests / "fixture.files.jsonl"
    index.write_text(json.dumps({"path": "1", "bytes": 8, "sha256": datasets.sha256(message), "is_message": True}) + "\n")
    datasets.atomic_json(manifests / "fixture.json", {"name": "fixture", "raw_path": "raw/fixture", "index": index.name, "messages": 1, "files": 1})
    datasets.verify_local()
    message.write_bytes(b"modified")
    with pytest.raises(ValueError, match="Local dataset verification failed"):
        datasets.verify_local()


def test_no_messages_never_verifies(tmp_path):
    source = archive(tmp_path, [("README", "file")])
    with pytest.raises(ValueError, match="no recognized email messages"):
        datasets.extract_tar(source, tmp_path / "out", tmp_path / "index", None)
    assert source.exists()


def test_completed_marker_does_not_hide_missing_data(tmp_path, monkeypatch):
    monkeypatch.setattr(datasets, "ROOT", tmp_path)
    manifest = tmp_path / "manifests" / "fixture.json"
    datasets.atomic_json(manifest, {"verified": True, "raw_path": "raw/missing", "index": "missing.jsonl"})
    with pytest.raises(ValueError, match="missing local artifacts"):
        datasets.already_verified(manifest)
