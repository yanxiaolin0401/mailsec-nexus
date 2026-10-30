"""Only checksum-verified evidence inside configured roots may reach scanners."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .config import Settings
from .domain import MailRecord


def read_evidence(record: MailRecord, settings: Settings) -> bytes:
    if record.raw_path.startswith("dataset://"):
        relative = record.raw_path[len("dataset://"):]
        parts = relative.split("/")
        if (not relative or any(part in {"", ".", ".."} for part in parts)
                or "\\" in relative or "\x00" in relative):
            raise ValueError("invalid dataset evidence reference")
        dataset_root = settings.datasets_dir.resolve(strict=True)
        path = dataset_root.joinpath(*parts).resolve(strict=True)
        if not path.is_relative_to(dataset_root):
            raise ValueError("dataset evidence escapes configured root")
    else:
        original = Path(record.raw_path)
        data_root = settings.data_dir.resolve()
        dataset_root = settings.datasets_dir.resolve()
        resolved_original = original.resolve()
        # Migrated rows can retain an absolute spool path from another host.
        # Never open that path: locate only its checksum-named copy in this
        # deployment's spool, and apply the normal root/size/hash checks below.
        if (original.is_absolute() and not resolved_original.is_relative_to(data_root)
                and not resolved_original.is_relative_to(dataset_root)):
            if re.fullmatch(r"[0-9a-f]{64}", record.raw_sha256) is None:
                raise ValueError("invalid legacy evidence checksum")
            if (".." in original.parts or original.parts[-3:] !=
                    ("spool", "raw", f"{record.raw_sha256}.eml")):
                raise ValueError("invalid legacy evidence reference")
            if original.is_symlink() or any(parent.is_symlink() for parent in original.parents):
                raise ValueError("legacy evidence symlink is not allowed")
            spool = data_root / "spool"
            raw_dir = spool / "raw"
            path_ref = raw_dir / f"{record.raw_sha256}.eml"
            if any(part.is_symlink() for part in (spool, raw_dir, path_ref)):
                raise ValueError("legacy evidence symlink is not allowed")
            path = path_ref.resolve(strict=True)
            if not path.is_relative_to(data_root):
                raise ValueError("legacy evidence escapes configured root")
        else:
            path = original.resolve(strict=True)
    roots = (settings.data_dir.resolve(), settings.datasets_dir.resolve())
    if not any(path.is_relative_to(root) for root in roots):
        raise ValueError("evidence path is outside configured data roots")
    if not path.is_file() or path.stat().st_size > settings.max_message_bytes:
        raise ValueError("evidence file is unavailable or oversized")
    with path.open("rb") as stream:
        raw = stream.read(settings.max_message_bytes + 1)
    if len(raw) > settings.max_message_bytes:
        raise ValueError("evidence exceeds configured byte limit")
    if hashlib.sha256(raw).hexdigest() != record.raw_sha256:
        raise ValueError("evidence checksum mismatch")
    return raw
