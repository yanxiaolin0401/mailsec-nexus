#!/usr/bin/env python3
"""Fetch first-party email corpora; resumable downloads, bounded concurrency, safe extraction.

Run from any directory: python3 scripts/datasets.py [enron|spamassassin|nazario|all]
Downloaded samples are untrusted; this tool never renders HTML, follows email URLs,
executes attachments, or forwards messages to SMTP/LLM services.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import mailbox
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import time
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1] / "data"
ENRON_URL = "https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz"
SPAM_BASE = "https://spamassassin.apache.org/old/publiccorpus/"
NAZARIO_BASE = "https://monkey.org/~jose/phishing/"
CHUNK = 8 * 1024 * 1024
MAX_EXTRACTED = 12 * 1024**3


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def download(url: str, target: Path, workers: int = 1) -> Path:
    """Resume independently verified HTTP ranges; max three attempts per segment.

    A byte-length check is transport validation, NOT an upstream authenticity hash.
    Locally computed SHA-256 values are recorded after successful extraction.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    with urlopen(Request(url, method="HEAD"), timeout=30) as response:
        size = int(response.headers["Content-Length"])
        identity = response.headers.get("ETag") or response.headers.get("Last-Modified")
    if target.exists() and target.stat().st_size == size:
        return target
    if target.exists() and target.stat().st_size > size:
        raise ValueError(f"Local file larger than remote: {target}")
    parts = target.with_name(target.name + ".parts")
    parts.mkdir(exist_ok=True)
    state = parts / "state.json"
    if state.exists():
        meta = json.loads(state.read_text())
        if (meta["url"], meta["size"], meta["identity"]) != (url, size, identity):
            raise ValueError("Remote object changed; preserve partials for manual inspection")
        seed = meta["seed"]
    else:
        seed = target.stat().st_size if target.exists() else 0
        atomic_json(state, {"url": url, "size": size, "identity": identity, "seed": seed})
    # Recovery also covers interruption between state write and prefix rename.
    if seed and not (parts / "prefix").exists():
        if not target.exists() or target.stat().st_size != seed:
            raise ValueError("Missing original download prefix")
        target.replace(parts / "prefix")
    ranges = [(start, min(start + CHUNK, size)) for start in range(seed, size, CHUNK)]

    def fetch(bounds: tuple[int, int]) -> Path:
        start, end = bounds
        path = parts / f"{start}-{end}"
        for attempt in range(3):
            offset = path.stat().st_size if path.exists() else 0
            if offset == end - start:
                return path
            if offset > end - start:
                raise ValueError(f"Oversized partial: {path}")
            headers = {"Range": f"bytes={start + offset}-{end - 1}", "Accept-Encoding": "identity"}
            if identity:
                headers["If-Range"] = identity
            try:
                with urlopen(Request(url, headers=headers), timeout=45) as response:
                    expected = f"bytes {start + offset}-{end - 1}/{size}"
                    if response.status != 206 or response.headers.get("Content-Range") != expected:
                        raise ValueError(f"Invalid ranged response: {response.status} {response.headers.get('Content-Range')}")
                    remaining = end - start - offset
                    with path.open("ab") as output:
                        while remaining:
                            data = response.read(min(256 * 1024, remaining))
                            if not data:
                                raise OSError("Premature EOF")
                            output.write(data)
                            remaining -= len(data)
                print(f"downloaded {target.name}: range {start}:{end}", flush=True)
                return path
            except (OSError, TimeoutError):
                if attempt == 2:
                    raise
                time.sleep(2 * (attempt + 1))
        raise AssertionError("unreachable")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        completed = list(pool.map(fetch, ranges))
    merged = target.with_name(target.name + ".assembling")
    with merged.open("wb") as out:
        for part in ([parts / "prefix"] if seed else []) + completed:
            with part.open("rb") as source:
                shutil.copyfileobj(source, out, 1024 * 1024)
    if merged.stat().st_size != size:
        raise ValueError("Assembled length mismatch")
    merged.replace(target)
    shutil.rmtree(parts)
    return target


def safe_member_path(destination: Path, name: str) -> Path:
    member = PurePosixPath(name)
    if not name or member.is_absolute() or ".." in member.parts or "\\" in name:
        raise ValueError(f"Unsafe archive path: {name!r}")
    path = destination.joinpath(*member.parts)
    if not path.resolve().is_relative_to(destination.resolve()):
        raise ValueError(f"Archive path escapes destination: {name!r}")
    # Reject existing symlinks even when their destination happens to be inside.
    if destination.is_symlink() or any(p.is_symlink() for p in [path, *path.parents] if p != destination.parent):
        raise ValueError(f"Symlink in destination path: {name!r}")
    return path


def extract_tar(archive: Path, destination: Path, index: Path, label: str | None) -> dict:
    """Only regular files/directories; no links/devices, exclusive files, size budget.

    Every emitted file is read back and compared with its streamed source digest.
    Manifest contains all files; non-message corpus metadata gets is_message=false.
    """
    if destination.exists():
        raise FileExistsError(f"Refusing to overwrite {destination}")
    destination.mkdir(parents=True)
    count = total = messages = 0
    with tarfile.open(archive, "r|*") as tar, index.open("w") as records:
        for member in tar:
            path = safe_member_path(destination, member.name)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise ValueError(f"Unsupported archive entry: {member.name}")
            total += member.size
            if total > MAX_EXTRACTED:
                raise ValueError("Archive exceeds uncompressed size budget")
            path.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise ValueError("Missing archive payload")
            digest = hashlib.sha256()
            length = 0
            with path.open("xb") as out:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
                    length += len(block)
                    out.write(block)
            if length != member.size or sha256(path) != digest.hexdigest():
                raise ValueError(f"Extraction verification failed: {path}")
            is_message = path.name.isdigit() or bool(re.match(r"^\d+\.[0-9a-f]{32}$", path.name)) or ("maildir" in path.parts and path.name.rstrip(".").isdigit())
            count += 1
            messages += is_message
            if count % 25000 == 0:
                print(f"extracting {archive.name}: {count} files verified", flush=True)
            records.write(json.dumps({"path": str(path.relative_to(destination)), "sha256": digest.hexdigest(), "bytes": length, "label": label if is_message else None, "is_message": is_message}) + "\n")
    # Streaming tar can stop at end-of-archive before gzip/bzip trailers. Read the
    # complete compression stream to force CRC/truncation checks before deletion.
    import gzip
    import bz2
    opener = gzip.open if archive.name.endswith(".gz") else bz2.open
    with opener(archive, "rb") as stream:
        while stream.read(1024 * 1024):
            pass
    if not messages:
        raise ValueError("Archive contains no recognized email messages")
    return {"files": count, "messages": messages, "uncompressed_bytes": total}


def already_verified(manifest: Path) -> bool:
    if not manifest.exists():
        return False
    metadata = json.loads(manifest.read_text())
    if not metadata.get("verified"):
        return False
    if not (ROOT / metadata["raw_path"]).is_dir() or not (ROOT / "manifests" / metadata["index"]).is_file():
        raise ValueError(f"Completed dataset is missing local artifacts: {manifest}; inspect before recovery")
    return True


def tar_dataset(name: str, url: str, label: str | None, metadata: dict, workers: int) -> None:
    manifest = ROOT / "manifests" / f"{name}.json"
    if already_verified(manifest):
        print(f"already verified: {name}", flush=True)
        return
    archive = download(url, ROOT / ".downloads" / url.rsplit("/", 1)[-1], workers)
    archive_hash = sha256(archive)
    destination = ROOT / "raw" / name
    temporary = ROOT / "raw" / f".{name}.extracting"
    if temporary.exists():
        if temporary.is_symlink():
            raise ValueError("Unexpected staging symlink")
        shutil.rmtree(temporary)
    index = ROOT / "manifests" / f"{name}.files.jsonl"
    print(f"extracting {archive.name}: downloaded bytes and SHA-256 recorded", flush=True)
    statistics = extract_tar(archive, temporary, index, label)
    if destination.exists():
        raise FileExistsError(destination)
    temporary.rename(destination)
    atomic_json(manifest, {"name": name, "url": url, "archive_sha256": archive_hash, "archive_bytes": archive.stat().st_size, "sha256_provenance": "locally computed; no publisher checksum supplied", "verified": True, "verified_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "raw_path": str(destination.relative_to(ROOT)), "index": index.name, **statistics, **metadata})
    archive.unlink()
    print(f"verified {name}: {statistics}; compressed archive removed", flush=True)


def nazario(year: int) -> None:
    name = f"nazario-{year}"
    manifest = ROOT / "manifests" / f"{name}.json"
    if already_verified(manifest):
        print(f"already verified: {name}", flush=True)
        return
    # Preserve source mbox as well as individual raw EML; it is not a compressed archive.
    url = NAZARIO_BASE + f"phishing-{year}"
    source = download(url, ROOT / "raw" / "nazario-mbox" / f"phishing-{year}.mbox")
    destination = ROOT / "raw" / name
    temporary = ROOT / "raw" / f".{name}.extracting"
    if temporary.exists():
        if temporary.is_symlink():
            raise ValueError("Unexpected staging symlink")
        shutil.rmtree(temporary)
    temporary.mkdir(parents=True)
    box = mailbox.mbox(source, create=False)
    count = 0
    index = ROOT / "manifests" / f"{name}.files.jsonl"
    try:
        with index.open("w") as out:
            for count, key in enumerate(box.iterkeys(), 1):
                data = box.get_bytes(key, from_=False)
                path = temporary / f"{count:06d}.eml"
                path.write_bytes(data)
                digest = hashlib.sha256(data).hexdigest()
                if sha256(path) != digest:
                    raise ValueError("EML verification failed")
                out.write(json.dumps({"path": path.name, "sha256": digest, "bytes": len(data), "label": "phishing", "is_message": True}) + "\n")
    finally:
        box.close()
    if not count:
        raise ValueError("Empty mbox")
    if destination.exists():
        raise FileExistsError(destination)
    temporary.rename(destination)
    atomic_json(manifest, {"name": name, "url": url, "source_sha256": sha256(source), "source_bytes": source.stat().st_size, "messages": count, "verified": True, "verified_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "raw_path": str(destination.relative_to(ROOT)), "index": index.name, "license": "CC-BY-4.0; attribution to Jose Nazario", "license_url": NAZARIO_BASE + "LICENSE.txt", "limitations": "Personal-inbox hand labels may contain errors; phishing only, not benign or malware ground truth; URLs remain untrusted; mbox envelope separators removed in EML export."})
    print(f"verified {name}: {count} messages", flush=True)


def verify_local() -> None:
    """Recheck every extracted file against the recorded local SHA-256 manifest."""
    manifests = sorted((ROOT / "manifests").glob("*.json"))
    if not manifests:
        raise ValueError("No local dataset manifests")
    for manifest in manifests:
        metadata = json.loads(manifest.read_text())
        destination = ROOT / metadata["raw_path"]
        index = ROOT / "manifests" / metadata["index"]
        count = messages = 0
        with index.open() as records:
            for line in records:
                entry = json.loads(line)
                path = safe_member_path(destination, entry["path"])
                if not path.is_file() or path.stat().st_size != entry["bytes"] or sha256(path) != entry["sha256"]:
                    raise ValueError(f"Local dataset verification failed: {path}")
                count += 1
                messages += entry["is_message"]
        if messages != metadata["messages"] or count != metadata.get("files", metadata["messages"]):
            raise ValueError(f"Manifest count mismatch: {manifest}")
        if metadata["name"].startswith("nazario-"):
            year = metadata["name"].split("-")[1]
            source = ROOT / "raw" / "nazario-mbox" / f"phishing-{year}.mbox"
            if sha256(source) != metadata["source_sha256"]:
                raise ValueError(f"Original mbox changed: {source}")
        print(f"reverified {metadata['name']}: {messages} messages, {count} files", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", choices=["enron", "spamassassin", "nazario", "all", "verify"])
    parser.add_argument("--workers", type=int, choices=range(1, 5), default=4)
    parser.add_argument("--nazario-years", nargs="+", type=int, choices=range(2015, 2026), default=list(range(2015, 2026)))
    args = parser.parse_args()
    if args.dataset == "verify":
        verify_local()
        return
    (ROOT / "manifests").mkdir(parents=True, exist_ok=True)
    (ROOT / "raw").mkdir(parents=True, exist_ok=True)
    if args.dataset in ("enron", "all"):
        tar_dataset("enron", ENRON_URL, None, {"version": "2015-05-07", "license": "Research resource; no general open license stated on CMU page; respect personal privacy", "source_page": "https://www.cs.cmu.edu/~enron/", "limitations": "No malware/spam gold labels; not automatically ham. Attachments removed; addresses modified; not original transport/authentication evidence."}, args.workers)
    if args.dataset in ("spamassassin", "all"):
        for corpus, date, label in [("easy_ham", "20030228", "ham"), ("easy_ham_2", "20030228", "ham"), ("hard_ham", "20030228", "ham"), ("spam", "20030228", "spam"), ("spam_2", "20050311", "spam")]:
            tar_dataset(f"spamassassin-{corpus}", SPAM_BASE + f"{date}_{corpus}.tar.bz2", label, {"source_page": SPAM_BASE + "readme.html", "license": "Message copyright remains with original senders; not Apache software license", "limitations": "Historical spam/ham labels, not malware labels; some headers anonymized. Never replay to live mail servers; current DNS/blacklist lookups unsuitable for historical gold evaluation."}, args.workers)
    if args.dataset in ("nazario", "all"):
        for year in args.nazario_years:
            nazario(year)


if __name__ == "__main__":
    main()
