"""Bundle writer — creates tar.zst/tar archives with manifest and checksums.

Layout per spec §5:
- manifest.json and checksums.txt are NOT in manifest.files (no self-reference)
- All other files are in both manifest.files and checksums.txt
- Default compression: zstd (tar.zst); --compression none = tar (uncompressed)
- Atomic write: write to temp, self-verify, then rename
"""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from agentrepro.errors import ArchiveError, IntegrityError
from .models import (
    ROLE_ENUM,
    Manifest,
    ManifestCapabilities,
    ManifestFile,
    ManifestGenerator,
    ManifestLimits,
    ManifestRedaction,
    ManifestReproduction,
    ManifestSource,
)


class BundleWriterError(Exception):
    """Raised when bundle writing fails."""


class BundleWriter:
    """Creates AgentRepro bundle tar archives.

    Usage:
        writer = BundleWriter(output_path)
        writer.add_payload("session.jsonl", content, role="session")
        writer.add_schema(schema_dir)
        writer.write(source_info={...}, ...)
    """

    def __init__(
        self,
        output_path: str | Path,
        compression: Literal["zst", "none"] = "zst",
    ):
        self.output_path = Path(output_path)
        self.compression = compression
        self._payload: dict[str, tuple[bytes, str]] = {}
        """archive_path -> (content_bytes, role) for payload files."""
        self._schema_dir: Path | None = None
        self._finalized = False

    def add_payload(self, archive_path: str, content: str | bytes, role: str = "evidence") -> None:
        """Add a payload file. role must be in the role enum."""
        if self._finalized:
            raise BundleWriterError("Cannot add files after write()")
        if not archive_path:
            raise BundleWriterError("archive_path must not be empty")
        if role not in ROLE_ENUM:
            raise BundleWriterError(f"Invalid role '{role}', must be one of {sorted(ROLE_ENUM)}")
        content_bytes = content.encode("utf-8") if isinstance(content, str) else content
        self._payload[archive_path] = (content_bytes, role)

    def add_schema(self, schema_dir: str | Path) -> None:
        """Point to schemas/ directory — schemas are auto-added from there."""
        self._schema_dir = Path(schema_dir)

    def _sha256(self, content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    def write(
        self,
        *,
        source_info: dict[str, Any] | None = None,
        capabilities: dict[str, Any] | None = None,
        redaction_info: dict[str, Any] | None = None,
        reproduction_info: dict[str, Any] | None = None,
        limits_info: dict[str, Any] | None = None,
        extra_files: list[ManifestFile] | None = None,
    ) -> Path:
        if self._finalized:
            raise BundleWriterError("write() already called")
        self._finalized = True

        # ---- Phase 1: collect all file contents ----
        file_contents: dict[str, bytes] = {}  # archive_path -> bytes
        data_entries: list[ManifestFile] = []

        for arc_path, (content_bytes, role) in self._payload.items():
            file_contents[arc_path] = content_bytes
            data_entries.append(ManifestFile(
                path=arc_path,
                role=role,
                bytes=len(content_bytes),
                sha256=self._sha256(content_bytes),
            ))

        # Add schemas
        schema_files_added: set[str] = set()
        if self._schema_dir and self._schema_dir.is_dir():
            for schema_file in sorted(self._schema_dir.iterdir()):
                if schema_file.suffix == ".json":
                    sbytes = schema_file.read_bytes()
                    arc = f"schemas/{schema_file.name}"
                    file_contents[arc] = sbytes
                    data_entries.append(ManifestFile(
                        path=arc,
                        role="schema",
                        bytes=len(sbytes),
                        sha256=self._sha256(sbytes),
                    ))
                    schema_files_added.add(arc)

        data_entries.sort(key=lambda f: f.path)

        # ---- Phase 2: build checksums.txt ----
        checksum_lines: list[str] = []
        for de in data_entries:
            checksum_lines.append(f"{de.sha256}  {de.path}")
        checksum_text = "\n".join(checksum_lines) + "\n"
        checksum_bytes = checksum_text.encode("utf-8")

        # checksums.txt exists in the bundle but NOT in manifest.files per spec §5.1
        file_contents["checksums.txt"] = checksum_bytes

        # ---- Phase 3: manifest.files = data_entries ONLY ----
        # Per spec §5.1: manifest.json and checksums.txt do NOT enter manifest.files
        all_entries = data_entries
        all_entries.sort(key=lambda f: f.path)

        # ---- Phase 4: capabilities ----
        caps = ManifestCapabilities()
        if capabilities:
            for k, v in capabilities.items():
                if hasattr(caps, k):
                    setattr(caps, k, v)
        else:
            file_set = set(self._payload.keys())
            caps.session_excerpt = "session.jsonl" in file_set
            caps.environment = "environment.json" in file_set
            caps.git_state = "git-state.json" in file_set
            caps.evidence = any(p.startswith("evidence/") for p in file_set)
            caps.incident = "incident.json" in file_set
            caps.prepare_supported = "git-state.json" in file_set

        # ---- Phase 5: metadata ----
        gen = ManifestGenerator()
        src = ManifestSource()
        if source_info:
            src.agent = source_info.get("agent", src.agent)
            src.agent_version = source_info.get("agent_version")
            src.session_ref_status = source_info.get("session_ref_status", "not_provided")
            src.incident_id = source_info.get("incident_id")
            src.incident_producer = source_info.get("incident_producer")

        # ---- Phase 6: redaction info ----
        red = ManifestRedaction()
        if redaction_info:
            for k, v in redaction_info.items():
                if hasattr(red, k):
                    setattr(red, k, v)

        # ---- Phase 7: reproduction ----
        repro = ManifestReproduction()
        if reproduction_info:
            for k, v in reproduction_info.items():
                if hasattr(repro, k):
                    setattr(repro, k, v)

        # ---- Phase 8: limits ----
        lim = ManifestLimits()
        if limits_info:
            for k, v in limits_info.items():
                if hasattr(lim, k):
                    setattr(lim, k, v)

        # Compute actual payload bytes from all payload files
        lim.actual_payload_bytes = sum(len(v) for v in file_contents.values())

        # ---- Phase 9: build manifest.json ----
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        bundle_id = Manifest.generate_bundle_id()

        manifest = Manifest(
            manifest_version="1.0",
            bundle_id=bundle_id,
            generator=gen,
            created_at=now,
            source=src,
            capabilities=caps,
            redaction=red,
            limits=lim,
            reproduction=repro,
            files=all_entries,
        )

        manifest_bytes = manifest.to_json().encode("utf-8")
        file_contents["manifest.json"] = manifest_bytes

        # ---- Phase 10: check total payload size ----
        total_payload = sum(len(v) for v in file_contents.values())
        if total_payload > lim.max_bundle_bytes:
            raise BundleWriterError(
                f"Total payload ({total_payload} bytes) exceeds max_bundle_bytes ({lim.max_bundle_bytes})"
            )

        # ---- Phase 11: atomic write to temp, then rename ----
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        # Use a temp file adjacent to the final path
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self.output_path.parent),
            prefix=f".{self.output_path.name}.",
            suffix=".tmp",
        )
        os.close(fd)
        tmp_path = Path(tmp_path)

        try:
            self._write_tar(tmp_path, file_contents)

            # Self-verify: read back the manifest and validate
            self._self_verify(tmp_path, manifest, all_entries, checksum_text)

            # Atomic rename
            shutil.move(str(tmp_path), str(self.output_path))
        except (ArchiveError, IntegrityError, BundleWriterError):
            # Clean up temp file on failure
            if tmp_path.exists():
                tmp_path.unlink()
            raise

        return self.output_path

    def _write_tar(self, path: Path, file_contents: dict[str, bytes]) -> None:
        """Write the tar archive with safety invariants."""
        if self.compression == "zst":
            try:
                import zstandard
            except ImportError:
                raise BundleWriterError("zstandard package required for zst compression")
            # Write uncompressed tar first, then compress with zstd
            buf = io.BytesIO()
            self._write_tar_entries(buf, file_contents)
            buf.seek(0)
            cctx = zstandard.ZstdCompressor(level=3)
            with open(path, "wb") as f:
                cctx.copy_stream(buf, f)
        else:
            with open(path, "wb") as f:
                self._write_tar_entries(f, file_contents)

    def _write_tar_entries(self, out, file_contents: dict[str, bytes]) -> None:
        """Write tar entries with safety invariants per spec §5.1."""
        with tarfile.open(fileobj=out, mode="w|") as tar:  # streaming — no full in-memory copy
            for arc_path in sorted(file_contents.keys()):
                content = file_contents[arc_path]
                # Tar invariants per spec
                assert len(arc_path.encode("utf-8")) <= 240, f"Tar name too long: {arc_path}"
                assert ".." not in arc_path.split("/"), f"Path traversal: {arc_path}"
                assert not arc_path.startswith("/"), f"Absolute path: {arc_path}"
                assert arc_path, "Empty path"

                info = tarfile.TarInfo(name=arc_path)
                info.size = len(content)
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mode = 0o644
                info.type = tarfile.REGTYPE
                tar.addfile(info, io.BytesIO(content))

    def _self_verify(
        self,
        tmp_path: Path,
        manifest: Manifest,
        all_entries: list[ManifestFile],
        checksum_text: str,
    ) -> None:
        """After writing, verify the bundle is self-consistent."""
        from .reader import open_tar_read

        try:
            tar = open_tar_read(tmp_path)
        except Exception as e:
            raise ArchiveError(f"Self-verify: cannot read bundle: {e}", code="E_SELF_VERIFY_READ")

        try:
            # Verify manifest
            m_bytes = _read_tar_file(tar, "manifest.json")
            m_parsed = Manifest.from_json(m_bytes.decode("utf-8"))

            if m_parsed.bundle_id != manifest.bundle_id:
                raise IntegrityError("Self-verify: bundle_id mismatch", code="E_SELF_VERIFY_BUNDLE_ID")

            # Verify checksums.txt
            cs_bytes = _read_tar_file(tar, "checksums.txt")
            if cs_bytes.decode("utf-8") != checksum_text:
                raise IntegrityError("Self-verify: checksums.txt content mismatch", code="E_SELF_VERIFY_CHECKSUM")

            # Verify each payload file
            for entry in all_entries:
                content = _read_tar_file(tar, entry.path)
                actual_hex = self._sha256(content)
                if actual_hex != entry.sha256:
                    raise IntegrityError(
                        f"Self-verify: checksum mismatch for {entry.path}",
                        code="E_SELF_VERIFY",
                    )
        finally:
            tar.close()


def _read_tar_file(tar, path: str) -> bytes:
    """Read a file from an open tar."""
    try:
        member = tar.getmember(path)
    except KeyError:
        raise IntegrityError(f"Self-verify: {path} not found in archive", code="E_SELF_VERIFY_MISSING")
    f = tar.extractfile(member)
    if f is None:
        raise IntegrityError(f"Self-verify: could not extract {path}", code="E_SELF_VERIFY_EXTRACT")
    return f.read()


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
