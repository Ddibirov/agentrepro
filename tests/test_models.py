"""Tests for bundle models."""
from __future__ import annotations

from agentrepro.bundle.models import (
    Manifest,
    ManifestFile,
    ManifestSource,
    validate_manifest_structure,
)


def test_manifest_defaults():
    m = Manifest()
    assert m.manifest_version == "1.0"
    assert m.bundle_id == ""
    assert m.source.agent == "unknown"


def test_generate_bundle_id():
    bid = Manifest.generate_bundle_id()
    assert bid.startswith("bnd_")
    assert len(bid) > 20


def test_manifest_round_trip():
    m = Manifest()
    m.bundle_id = Manifest.generate_bundle_id()
    m.created_at = "2026-07-24T12:00:00Z"
    m.source = ManifestSource(agent="claude-code", session_ref_status="resolved")
    m.files = [
        ManifestFile(path="session.jsonl", role="session", media_type="application/x-ndjson", bytes=100, sha256="a" * 64),
    ]
    m.capabilities.session_excerpt = True
    m.redaction.applied = True
    m.redaction.total_replacements = 3
    m.reproduction.classification = "partial"

    d = m.to_dict()
    m2 = Manifest.from_dict(d)
    assert m2.bundle_id == m.bundle_id
    assert m2.source.agent == "claude-code"
    assert m2.files[0].role == "session"
    assert m2.capabilities.session_excerpt is True
    assert m2.redaction.total_replacements == 3
    assert m2.reproduction.classification == "partial"

    # JSON round-trip
    j = m.to_json()
    m3 = Manifest.from_json(j)
    assert m3.bundle_id == m.bundle_id


def test_validate_manifest_ok():
    m = Manifest()
    m.bundle_id = Manifest.generate_bundle_id()
    m.created_at = "2026-07-24T12:00:00Z"
    m.source = ManifestSource(agent="claude-code", session_ref_status="resolved")
    m.files = [
        ManifestFile(path="session.jsonl", role="session", bytes=100, sha256="a" * 64),
        ManifestFile(path="z_file.json", role="schema", bytes=50, sha256="b" * 64),
    ]

    errors = validate_manifest_structure(m)
    assert not errors, f"Expected no errors, got: {errors}"


def test_validate_manifest_missing_required():
    m = Manifest()  # Empty manifest
    errors = validate_manifest_structure(m)
    assert errors
    codes = set()
    for err in errors:
        if "bundle_id" in err:
            codes.add("no_bundle_id")
        if "created_at" in err:
            codes.add("no_created_at")
        if "agent" in err:
            codes.add("no_agent")
    assert "no_bundle_id" in codes
    assert "no_created_at" in codes


def test_validate_manifest_bundle_id_prefix():
    m = Manifest()
    m.bundle_id = "bad_id"
    m.created_at = "2026-07-24T12:00:00Z"
    m.source = ManifestSource(agent="claude-code")
    m.files = [ManifestFile(path="f.json", role="schema", bytes=1, sha256="a" * 64)]
    errors = validate_manifest_structure(m)
    assert any("bundle_id must start with 'bnd_'" in e for e in errors)


def test_validate_manifest_sorted_files():
    m = Manifest()
    m.bundle_id = Manifest.generate_bundle_id()
    m.created_at = "2026-07-24T12:00:00Z"
    m.source = ManifestSource(agent="codex-cli", session_ref_status="unresolved")
    m.files = [
        ManifestFile(path="z.json", role="schema", bytes=1, sha256="a" * 64),
        ManifestFile(path="a.json", role="schema", bytes=1, sha256="a" * 64),
    ]
    errors = validate_manifest_structure(m)
    assert any("files must be sorted" in e for e in errors)


def test_validate_manifest_bad_sha256():
    m = Manifest()
    m.bundle_id = Manifest.generate_bundle_id()
    m.created_at = "2026-07-24T12:00:00Z"
    m.source = ManifestSource(agent="codex-cli")
    m.files = [ManifestFile(path="f.json", role="schema", bytes=1, sha256="short")]
    errors = validate_manifest_structure(m)
    assert any("sha256 must be 64 hex chars" in e for e in errors)


def test_validate_manifest_bad_role():
    m = Manifest()
    m.bundle_id = Manifest.generate_bundle_id()
    m.created_at = "2026-07-24T12:00:00Z"
    m.source = ManifestSource(agent="codex-cli")
    m.files = [ManifestFile(path="f.bin", role="binary", bytes=1, sha256="a" * 64)]
    errors = validate_manifest_structure(m)
    assert any("invalid role" in e for e in errors)


def test_minimal_json_roundtrip():
    m = Manifest()
    m.bundle_id = "bnd_test_id_12345"
    m.created_at = "2026-07-24T12:00:00Z"
    m.source = ManifestSource(agent="none", session_ref_status="not_provided")
    m.files = [ManifestFile(path="REPRODUCE.md", role="reproduce", bytes=42, sha256="c" * 64)]

    j = m.to_json()
    m2 = Manifest.from_json(j)
    assert m2.bundle_id == "bnd_test_id_12345"
    assert m2.source.agent == "none"
