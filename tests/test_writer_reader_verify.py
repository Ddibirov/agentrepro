"""Tests for bundle writer, reader, and verifier."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentrepro.bundle.models import Manifest, ManifestFile
from agentrepro.bundle.reader import BundleReader, validate_tar_header_safety
from agentrepro.bundle.verify import BundleVerify
from agentrepro.bundle.writer import BundleWriter


@pytest.fixture
def bundle_path(tmp_path: Path) -> Path:
    return tmp_path / "test-bundle.agentrepro.tar.zst"


def test_write_minimal_bundle(tmp_path):
    """Write a bundle with session data and verify."""
    w = BundleWriter(tmp_path / "minimal.tar.zst")
    w.add_payload("session.jsonl", '{"test":true}', role="session")
    w.add_schema(Path(__file__).resolve().parent.parent / "schemas")
    result = w.write()

    assert result.exists()
    assert result.stat().st_size > 0

    # Read back
    r = BundleReader(result)
    m = r.manifest()
    assert m.manifest_version == "1.0"
    assert m.bundle_id.startswith("bnd_")

    # Check files
    paths = {f.path for f in m.files}
    assert "session.jsonl" in paths
    assert "schemas/bundle-manifest-1.json" in paths
    assert "schemas/agent-incident-1.json" in paths

    # Check checksums.txt not in manifest.files
    assert "checksums.txt" not in paths
    assert "manifest.json" not in paths

    # Verify
    v = BundleVerify()
    res = v.verify(result)
    issues = [i for i in res.issues if i.severity == "error"]
    assert not issues, f"Errors: {[(i.code, i.message) for i in issues]}"


def test_write_uncompressed(tmp_path):
    """Test uncompressed tar output."""
    w = BundleWriter(tmp_path / "test.tar", compression="none")
    w.add_payload("test.txt", "hello", role="evidence")
    result = w.write()
    assert result.exists()

    # Should be readable as plain tar
    r = BundleReader(result)
    m = r.manifest()
    assert m.bundle_id.startswith("bnd_")


def test_verify_bad_checksum(tmp_path):
    """Verify detects checksum tampering."""
    w = BundleWriter(tmp_path / "good.tar", compression="none")  # Use uncompressed for tampering
    w.add_payload("session.jsonl", '{"test":true}', role="session")
    w.add_schema(Path(__file__).resolve().parent.parent / "schemas")
    result = w.write()

    # Read the uncompressed tar, modify one byte in session.jsonl, re-write
    import tarfile, io
    members = {}
    with tarfile.open(result, "r:") as tar:
        for m in tar.getmembers():
            f = tar.extractfile(m)
            content = f.read() if f else b""
            members[m.name] = content

    # Tamper with session.jsonl
    original = members.get("session.jsonl", b"")
    members["session.jsonl"] = original.replace(b"true", b"false")

    # Rewrite tar
    with tarfile.open(result, "w") as tar:
        for name, content in sorted(members.items()):
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(content))

    v = BundleVerify()
    res = v.verify(result)
    assert not res.valid
    codes = [i.code for i in res.issues]
    assert any("CHECKSUM" in c for c in codes), f"Expected checksum error, got: {codes}"


def test_verify_missing_member(tmp_path):
    """Verify detects missing manifest."""
    import tarfile, io
    bad = tmp_path / "bad.tar"
    # Write a tar without manifest.json
    with tarfile.open(bad, "w") as tar:
        info = tarfile.TarInfo(name="trash.txt")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"test"))

    v = BundleVerify()
    res = v.verify(bad)
    assert not res.valid
    codes = [i.code for i in res.issues]
    assert "REQUIRED_MISSING" in codes


def test_tar_header_safety(tmp_path):
    """Reader rejects dangerous tar members."""
    import tarfile, io

    # Test traversal
    bad = tmp_path / "traversal.tar"
    with tarfile.open(bad, "w") as tar:
        info = tarfile.TarInfo(name="../etc/passwd")
        info.size = 5
        tar.addfile(info, io.BytesIO(b"root:"))
        info2 = tarfile.TarInfo(name="good.txt")
        info2.size = 4
        tar.addfile(info2, io.BytesIO(b"test"))

    with BundleReader(bad) as r:
        members = r.list_members()

    errors = validate_tar_header_safety(members)
    assert any("TRAVERSAL" in c for (c, _) in errors)


def test_tar_header_safety_duplicate(tmp_path):
    import tarfile, io
    bad = tmp_path / "dup.tar"
    with tarfile.open(bad, "w") as tar:
        for _ in range(2):
            info = tarfile.TarInfo(name="same.txt")
            info.size = 4
            tar.addfile(info, io.BytesIO(b"test"))

    with BundleReader(bad) as r:
        members = r.list_members()
    errors = validate_tar_header_safety(members)
    assert any("DUPLICATE" in c for (c, _) in errors)


def test_tar_header_safety_absolute(tmp_path):
    import tarfile, io
    bad = tmp_path / "abs.tar"
    with tarfile.open(bad, "w") as tar:
        info = tarfile.TarInfo(name="/etc/passwd")
        info.size = 4
        tar.addfile(info, io.BytesIO(b"root"))

    with BundleReader(bad) as r:
        members = r.list_members()
    errors = validate_tar_header_safety(members)
    assert any("ABSOLUTE" in c for (c, _) in errors)


def test_verify_with_incident(tmp_path, sample_incident_full):
    """Bundle with incident passes verify."""
    w = BundleWriter(tmp_path / "with-incident.tar.zst")
    w.add_payload("session.jsonl", '{"test":true}', role="session")
    w.add_payload("incident.json", json.dumps(sample_incident_full), role="incident")
    w.add_schema(Path(__file__).resolve().parent.parent / "schemas")
    result = w.write()

    v = BundleVerify()
    res = v.verify(result)
    errors = [i for i in res.issues if i.severity == "error"]
    assert not errors, f"Errors: {[(i.code, i.message) for i in errors]}"


def test_verify_strict_reproduce(tmp_path):
    """Strict verify flags missing REPRODUCE.md as error."""
    w = BundleWriter(tmp_path / "no-repro.tar.zst")
    w.add_payload("data.txt", "something", role="evidence")
    w.add_schema(Path(__file__).resolve().parent.parent / "schemas")
    result = w.write()

    v = BundleVerify(strict=True)
    res = v.verify(result)
    codes = [i.code for i in res.issues]
    assert "REQUIRED_MISSING" in codes
