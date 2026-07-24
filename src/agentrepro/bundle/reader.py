"""Bundle reader — inspect tar archives without full extraction.

Supports .tar (uncompressed), .tar.gz (gzip), and .tar.zst (zstd).
Returns seekable TarFile objects for efficient random access.
"""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path
from typing import Any

from .models import Manifest


class BundleReaderError(Exception):
    """Raised when bundle reading fails."""


def open_tar_read(path: str | Path) -> tarfile.TarFile:
    """Open a tar archive, detecting compression from content.

    Returns a seekable TarFile (mode 'r:') for efficient random access.
    """
    path = Path(path)
    if not path.exists():
        raise BundleReaderError(f"Bundle not found: {path}")

    raw = path.read_bytes()

    # zstd magic
    if raw[:4] == b"\x28\xb5\x2f\xfd":
        try:
            import zstandard
        except ImportError:
            raise BundleReaderError(
                "zstd-compressed bundle requires 'zstandard' package: pip install zstandard"
            )
        decompressed = io.BytesIO()
        dctx = zstandard.ZstdDecompressor()
        with dctx.stream_reader(io.BytesIO(raw)) as reader:
            decompressed.write(reader.read())
        decompressed.seek(0)
        return tarfile.open(fileobj=decompressed, mode="r:")

    # gzip magic
    if raw[:2] == b"\x1f\x8b":
        decompressed = io.BytesIO()
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as gz:
            decompressed.write(gz.read())
        decompressed.seek(0)
        return tarfile.open(fileobj=decompressed, mode="r:")

    # Uncompressed tar
    return tarfile.open(path, mode="r:")


def validate_tar_header_safety(
    members: list[tarfile.TarInfo],
    max_members: int = 100,
) -> list[tuple[str, str]]:
    """Validate tar members against safety invariants per spec §5.1.

    Returns list of (error_code, message) tuples. Empty = safe.
    """
    errors: list[tuple[str, str]] = []

    # Member count limit
    if len(members) > max_members:
        errors.append(("ARCHIVE_TOO_MANY_MEMBERS", f"{len(members)} members, limit {max_members}"))

    seen_paths: set[str] = set()
    for m in members:
        name = m.name

        # Non-regular types
        if m.type != tarfile.REGTYPE:
            errors.append(("ARCHIVE_NON_REGULAR", f"Non-regular member: {name} (type={m.type})"))
            continue

        # Path safety
        if not name:
            errors.append(("ARCHIVE_EMPTY_PATH", "Empty path in archive"))
            continue

        norm = name.replace("\\", "/")  # Normalize backslash
        if ".." in norm.split("/"):
            errors.append(("ARCHIVE_TRAVERSAL", f"Path traversal: {name}"))
            continue

        if name.startswith("/"):
            errors.append(("ARCHIVE_ABSOLUTE_PATH", f"Absolute path: {name}"))
            continue

        # Duplicate check
        if name in seen_paths:
            errors.append(("ARCHIVE_DUPLICATE", f"Duplicate path: {name}"))
        seen_paths.add(name)

        # Name length
        name_bytes = name.encode("utf-8")
        if len(name_bytes) > 240:
            errors.append(("ARCHIVE_LONG_NAME", f"Name > 240 bytes: {name} ({len(name_bytes)})"))

        # Unsafe mode
        if m.mode & 0o7000:  # setuid/setgid/sticky
            errors.append(("ARCHIVE_UNSAFE_MODE", f"Unsafe mode for: {name} ({oct(m.mode)})"))

    return errors


class BundleReader:
    """Read an AgentRepro bundle without full extraction."""

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._tar: tarfile.TarFile | None = None
        self._manifest: Manifest | None = None

    def _ensure_open(self) -> tarfile.TarFile:
        if self._tar is None:
            self._tar = open_tar_read(self._path)
        return self._tar

    def manifest(self) -> Manifest:
        """Read and return the bundle manifest."""
        if self._manifest is not None:
            return self._manifest
        tar = self._ensure_open()
        content = self._read_file_bytes(tar, "manifest.json")
        self._manifest = Manifest.from_json(content.decode("utf-8"))
        return self._manifest

    def list_files(self) -> list[dict[str, Any]]:
        """List all files in the bundle with metadata."""
        tar = self._ensure_open()
        return [
            {"path": m.name, "size": m.size, "mtime": m.mtime, "type": m.type}
            for m in tar.getmembers()
        ]

    def list_members(self) -> list[tarfile.TarInfo]:
        """Get raw tar members for safety verification."""
        tar = self._ensure_open()
        return tar.getmembers()

    def read_file(self, archive_path: str) -> bytes:
        """Read a specific file from the bundle."""
        tar = self._ensure_open()
        return self._read_file_bytes(tar, archive_path)

    def read_json(self, archive_path: str) -> Any:
        """Read and parse a JSON file from the bundle."""
        return json.loads(self.read_file(archive_path).decode("utf-8"))

    def close(self) -> None:
        if self._tar is not None:
            self._tar.close()
            self._tar = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @staticmethod
    def _read_file_bytes(tar: tarfile.TarFile, path: str) -> bytes:
        try:
            member = tar.getmember(path)
        except KeyError:
            raise BundleReaderError(f"File not found in bundle: {path}")
        f = tar.extractfile(member)
        if f is None:
            raise BundleReaderError(f"Could not extract: {path}")
        return f.read()


class InspectReport:
    """Human-readable inspection report from a bundle."""

    def __init__(self, reader: BundleReader):
        self.reader = reader
        self._manifest: Manifest | None = None

    def summary(self) -> dict[str, Any]:
        m = self._manifest or self.reader.manifest()
        return {
            "manifest_version": m.manifest_version,
            "bundle_id": m.bundle_id,
            "generator": f"{m.generator.name} v{m.generator.version}",
            "source_agent": m.source.agent,
            "session_ref_status": m.source.session_ref_status,
            "created_at": m.created_at,
            "file_count": len(m.files),
            "capabilities": m.capabilities.to_dict(),
            "redaction": m.redaction.to_dict(),
            "limits": m.limits.to_dict(),
            "reproduction": m.reproduction.to_dict(),
        }

    def file_table(self) -> list[dict[str, Any]]:
        m = self._manifest or self.reader.manifest()
        return [
            {
                "path": f.path,
                "role": f.role,
                "bytes": f.bytes,
                "sha256": f.sha256[:16] + "...",
            }
            for f in m.files
        ]

    def text_summary(self) -> str:
        """Return a human-readable text summary."""
        s = self.summary()
        lines = [
            f"Bundle:        {s['bundle_id']}",
            f"Format:        v{s['manifest_version']}",
            f"Generator:     {s['generator']}",
            f"Agent:         {s['source_agent']}",
            f"Session ref:   {s['session_ref_status']}",
            f"Created:       {s['created_at']}",
            f"Redaction:     applied={s['redaction']['applied']}, "
            f"replacements={s['redaction']['total_replacements']}",
            f"Limits:        {s['limits']['actual_payload_bytes']} / {s['limits']['max_bundle_bytes']} bytes",
            f"Reproduction:  {s['reproduction']['classification']}",
            f"Files:         {s['file_count']}",
            "",
            "Capabilities:",
        ]
        caps = s["capabilities"]
        for key, val in caps.items():
            lines.append(f"  {key}: {val}")
        lines.append("")
        lines.append("Files:")
        for f in self.file_table():
            lines.append(f"  {f['path']:<40s} {f['role']:<20s} {f['bytes']:>8d}")
        return "\n".join(lines)
