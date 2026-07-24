"""Canonical typed models for AgentRepro bundle manifest v1.0.

Matches the JSON Schema at schemas/bundle-manifest-1.json.
"""

from __future__ import annotations

import dataclasses
import json
import secrets
from typing import Any


@dataclasses.dataclass
class ManifestFile:
    """One entry in manifest.files."""

    path: str
    role: str  # one of the role enum
    media_type: str | None = None
    bytes: int = 0
    sha256: str = ""  # 64 lowercase hex chars

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "path": self.path,
            "role": self.role,
            "bytes": self.bytes,
            "sha256": self.sha256,
        }
        if self.media_type is not None:
            d["media_type"] = self.media_type
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ManifestFile:
        return cls(
            path=d["path"],
            role=d.get("role", "evidence"),
            media_type=d.get("media_type"),
            bytes=d.get("bytes", 0),
            sha256=d.get("sha256", ""),
        )


@dataclasses.dataclass
class ManifestGenerator:
    """Tool that created the bundle."""

    name: str = "agentrepro"
    version: str = "0.1.0"
    build_commit: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "version": self.version}
        # Always include build_commit even if null per spec
        d["build_commit"] = self.build_commit
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ManifestGenerator:
        return cls(
            name=d.get("name", "agentrepro"),
            version=d.get("version", "0.0.0"),
            build_commit=d.get("build_commit"),
        )


@dataclasses.dataclass
class ManifestSource:
    """Information about the originating agent session."""

    agent: str = "unknown"  # one of the agent enum
    agent_version: str | None = None
    session_ref_status: str = "not_provided"  # resolved | unresolved | not_provided
    incident_id: str | None = None
    incident_producer: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"agent": self.agent}
        d["agent_version"] = self.agent_version
        d["session_ref_status"] = self.session_ref_status
        d["incident_id"] = self.incident_id
        d["incident_producer"] = self.incident_producer
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ManifestSource:
        return cls(
            agent=d.get("agent", "unknown"),
            agent_version=d.get("agent_version"),
            session_ref_status=d.get("session_ref_status", "not_provided"),
            incident_id=d.get("incident_id"),
            incident_producer=d.get("incident_producer"),
        )


@dataclasses.dataclass
class ManifestCapabilities:
    """Capability flags indicating what the bundle contains."""

    session_excerpt: bool = False
    environment: bool = False
    git_state: bool = False
    evidence: bool = False
    incident: bool = False
    prepare_supported: bool = False
    exact_llm_replay: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_excerpt": self.session_excerpt,
            "environment": self.environment,
            "git_state": self.git_state,
            "evidence": self.evidence,
            "incident": self.incident,
            "prepare_supported": self.prepare_supported,
            "exact_llm_replay": self.exact_llm_replay,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ManifestCapabilities:
        return cls(
            session_excerpt=d.get("session_excerpt", False),
            environment=d.get("environment", False),
            git_state=d.get("git_state", False),
            evidence=d.get("evidence", False),
            incident=d.get("incident", False),
            prepare_supported=d.get("prepare_supported", False),
            exact_llm_replay=d.get("exact_llm_replay", False),
        )


@dataclasses.dataclass
class ManifestRedaction:
    """Redaction metadata."""

    policy_version: str = "1.0"
    applied: bool = False
    total_replacements: int = 0
    unresolved_high_confidence: int = 0
    hard_deny_overrides: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_version": self.policy_version,
            "applied": self.applied,
            "total_replacements": self.total_replacements,
            "unresolved_high_confidence": self.unresolved_high_confidence,
            "hard_deny_overrides": self.hard_deny_overrides,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ManifestRedaction:
        return cls(
            policy_version=d.get("policy_version", "1.0"),
            applied=d.get("applied", False),
            total_replacements=d.get("total_replacements", 0),
            unresolved_high_confidence=d.get("unresolved_high_confidence", 0),
            hard_deny_overrides=d.get("hard_deny_overrides", 0),
        )


@dataclasses.dataclass
class ManifestLimits:
    """Size and count limits."""

    max_file_bytes: int = 10 * 1024 * 1024  # 10 MiB
    max_bundle_bytes: int = 50 * 1024 * 1024  # 50 MiB
    actual_payload_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_file_bytes": self.max_file_bytes,
            "max_bundle_bytes": self.max_bundle_bytes,
            "actual_payload_bytes": self.actual_payload_bytes,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ManifestLimits:
        return cls(
            max_file_bytes=d.get("max_file_bytes", 10 * 1024 * 1024),
            max_bundle_bytes=d.get("max_bundle_bytes", 50 * 1024 * 1024),
            actual_payload_bytes=d.get("actual_payload_bytes", 0),
        )


@dataclasses.dataclass
class ManifestReproduction:
    """Reproduction classification."""

    classification: str = "inspection_only"  # inspection_only | partial | exact_candidate
    baseline_commit: str | None = None
    reasons_not_exact: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"classification": self.classification}
        d["baseline_commit"] = self.baseline_commit
        d["reasons_not_exact"] = list(self.reasons_not_exact)
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ManifestReproduction:
        return cls(
            classification=d.get("classification", "inspection_only"),
            baseline_commit=d.get("baseline_commit"),
            reasons_not_exact=d.get("reasons_not_exact", []),
        )


@dataclasses.dataclass
class Manifest:
    """Top-level bundle manifest v1.0."""

    manifest_version: str = "1.0"
    bundle_id: str = ""
    generator: ManifestGenerator = dataclasses.field(default_factory=ManifestGenerator)
    created_at: str = ""
    source: ManifestSource = dataclasses.field(default_factory=ManifestSource)
    capabilities: ManifestCapabilities = dataclasses.field(
        default_factory=ManifestCapabilities
    )
    redaction: ManifestRedaction = dataclasses.field(default_factory=ManifestRedaction)
    limits: ManifestLimits = dataclasses.field(default_factory=ManifestLimits)
    reproduction: ManifestReproduction = dataclasses.field(
        default_factory=ManifestReproduction
    )
    files: list[ManifestFile] = dataclasses.field(default_factory=list)

    @staticmethod
    def generate_bundle_id() -> str:
        """Generate a random bundle ID with bnd_ prefix."""
        random_part = secrets.token_urlsafe(16)[:20]
        return f"bnd_{random_part}"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "$schema": "./schemas/bundle-manifest-1.json",
            "manifest_version": self.manifest_version,
            "bundle_id": self.bundle_id,
            "generator": self.generator.to_dict(),
            "created_at": self.created_at,
            "source": self.source.to_dict(),
            "capabilities": self.capabilities.to_dict(),
            "redaction": self.redaction.to_dict(),
            "limits": self.limits.to_dict(),
            "reproduction": self.reproduction.to_dict(),
            "files": [f.to_dict() for f in self.files],
        }
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Manifest:
        return cls(
            manifest_version=d.get("manifest_version", "1.0"),
            bundle_id=d.get("bundle_id", ""),
            generator=ManifestGenerator.from_dict(d.get("generator", {})),
            created_at=d.get("created_at", ""),
            source=ManifestSource.from_dict(d.get("source", {})),
            capabilities=ManifestCapabilities.from_dict(d.get("capabilities", {})),
            redaction=ManifestRedaction.from_dict(d.get("redaction", {})),
            limits=ManifestLimits.from_dict(d.get("limits", {})),
            reproduction=ManifestReproduction.from_dict(d.get("reproduction", {})),
            files=[ManifestFile.from_dict(f) for f in d.get("files", [])],
        )

    @classmethod
    def from_json(cls, text: str) -> Manifest:
        return cls.from_dict(json.loads(text))


# ---- Structural validation helpers ----


ROLE_ENUM = frozenset({
    "schema", "incident", "session", "session_metadata",
    "environment", "git_state", "evidence_index", "evidence",
    "redaction_report", "reproduce",
})

AGENT_ENUM = frozenset({"claude-code", "codex-cli", "opencode", "unknown", "none"})

REPRO_CLASSIFICATION_ENUM = frozenset({"inspection_only", "partial", "exact_candidate"})

SESSION_REF_STATUS_ENUM = frozenset({"resolved", "unresolved", "not_provided"})


def validate_manifest_structure(manifest: Manifest) -> list[str]:
    """Check required fields per the bundle manifest spec.

    Returns a list of error messages (empty = valid).
    """
    errors: list[str] = []

    if not manifest.manifest_version:
        errors.append("manifest_version is required")
    if not manifest.bundle_id:
        errors.append("bundle_id is required")
    elif not manifest.bundle_id.startswith("bnd_"):
        errors.append("bundle_id must start with 'bnd_'")

    if not manifest.generator.name:
        errors.append("generator.name is required")
    if not manifest.generator.version:
        errors.append("generator.version is required")

    if not manifest.created_at:
        errors.append("created_at is required")

    if not manifest.source.agent:
        errors.append("source.agent is required")
    elif manifest.source.agent not in AGENT_ENUM:
        errors.append(f"source.agent must be one of {sorted(AGENT_ENUM)}, got '{manifest.source.agent}'")

    if manifest.source.session_ref_status not in SESSION_REF_STATUS_ENUM:
        errors.append(f"source.session_ref_status must be one of {sorted(SESSION_REF_STATUS_ENUM)}, got '{manifest.source.session_ref_status}'")

    for f in manifest.files:
        if f.role not in ROLE_ENUM:
            errors.append(f"file '{f.path}' has invalid role '{f.role}'")
        if len(f.sha256) != 64:
            errors.append(f"file '{f.path}' sha256 must be 64 hex chars")

    if manifest.reproduction.classification not in REPRO_CLASSIFICATION_ENUM:
        errors.append(f"reproduction.classification must be one of {sorted(REPRO_CLASSIFICATION_ENUM)}, got '{manifest.reproduction.classification}'")

    # Check files are sorted and unique
    paths = [f.path for f in manifest.files]
    if paths != sorted(paths):
        errors.append("files must be sorted by path")
    if len(paths) != len(set(paths)):
        errors.append("files paths must be unique")

    return errors
