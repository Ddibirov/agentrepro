"""Bundle verify — fully offline verification of AgentRepro bundles.

Implements the 10-point verification checklist from spec §10.2.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentrepro.schema.validator import validate_against_schema
from .models import Manifest, ManifestFile, validate_manifest_structure
from .reader import (
    BundleReader,
    validate_tar_header_safety,
)


@dataclass
class VerifyIssue:
    """A single verification issue."""

    code: str
    message: str
    severity: str = "error"  # 'error' or 'warning'


@dataclass
class VerifyResult:
    """Result of a bundle verification."""

    valid: bool
    issues: list[VerifyIssue] = field(default_factory=list)
    manifest: Manifest | None = None

    def add(self, code: str, message: str, severity: str = "error") -> None:
        self.issues.append(VerifyIssue(code=code, message=message, severity=severity))
        if severity == "error":
            self.valid = False

    def summary(self) -> str:
        total = len(self.issues)
        errors = sum(1 for i in self.issues if i.severity == "error")
        warnings = total - errors
        if self.valid:
            return f"VALID — {total} checks passed"
        return f"INVALID — {errors} errors, {warnings} warnings"


class BundleVerify:
    """Offline verifier for AgentRepro bundles.

    Spec §10.2 checklist:
    1. Tar header safety (decompression, traversal, symlink, devices, etc.)
    2. Required members + embedded schemas
    3. Manifest JSON Schema + semantic version
    4. Unique inventory / capability-to-file consistency
    5. Checksums set equality and SHA-256 per payload
    6. incident.json validation (if present)
    7. redaction-report.json invariants + unresolved == 0
    8. Hard-deny path absence
    9. Known-secret residual scan over eligible payloads
    10. No recipe execution or network attempt (guaranteed by offline design)
    """

    def __init__(self, strict: bool = False):
        self._strict = strict
        self._bundle_manifest_schema: dict[str, Any] | None = None
        self._incident_schema: dict[str, Any] | None = None

    def load_schemas(self, bundle_reader: BundleReader) -> None:
        """Load embedded schemas from the bundle."""
        try:
            content = bundle_reader.read_file("schemas/bundle-manifest-1.json")
            self._bundle_manifest_schema = json.loads(content)
        except Exception:
            pass
        try:
            content = bundle_reader.read_file("schemas/agent-incident-1.json")
            self._incident_schema = json.loads(content)
        except Exception:
            pass

    def verify(self, bundle_path: str | Path) -> VerifyResult:
        """Run all verifications on a bundle."""
        result = VerifyResult(valid=True)

        try:
            with BundleReader(bundle_path) as reader:
                self._verify_all(reader, result)
        except Exception as e:
            result.add("ARCHIVE_READ", f"Failed to read archive: {e}")
            return result

        return result

    def _verify_all(self, reader: BundleReader, result: VerifyResult) -> None:
        """All verification steps."""

        # ---- Step 0: Tar header safety (before any extraction) ----
        try:
            members = reader.list_members()
        except Exception as e:
            result.add("ARCHIVE_LIST", f"Cannot list archive members: {e}")
            return

        header_errors = validate_tar_header_safety(members)
        for code, msg in header_errors:
            result.add(code, msg)

        if header_errors:
            return  # Don't proceed if archive is structurally unsafe

        # ---- Load schemas ----
        self.load_schemas(reader)

        # ---- Step 1: Required members ----
        member_paths = {m.name for m in members}
        required = {"manifest.json", "checksums.txt", "REPRODUCE.md",
                     "schemas/bundle-manifest-1.json", "schemas/agent-incident-1.json"}
        for req in required:
            if req not in member_paths:
                sev = "error" if req in ("manifest.json", "checksums.txt") else ("error" if self._strict else "warning")
                result.add("REQUIRED_MISSING", f"Required member missing: {req}", severity=sev)

        if "manifest.json" not in member_paths:
            return  # Cannot continue without manifest

        # ---- Step 2: Read and validate manifest ----
        try:
            manifest = reader.manifest()
            result.manifest = manifest
        except Exception as e:
            result.add("MANIFEST_PARSE", f"manifest.json parse error: {e}")
            return

        result.add("MANIFEST_EXISTS", "manifest.json found and parsed", severity="info")

        # Struct validation
        struct_errors = validate_manifest_structure(manifest)
        for err in struct_errors:
            result.add("MANIFEST_STRUCT", f"manifest.json: {err}")

        # Schema validation
        if self._bundle_manifest_schema:
            valid, schema_errors = validate_against_schema(
                manifest.to_dict(), self._bundle_manifest_schema
            )
            if valid:
                result.add("MANIFEST_SCHEMA", "manifest.json validates against schema", severity="info")
            else:
                for se in schema_errors[:5]:
                    result.add("MANIFEST_SCHEMA", f"manifest.json schema: {se}")

        # ---- Step 3: Checksums ----
        checksums: dict[str, str] = {}
        try:
            cs_content = reader.read_file("checksums.txt").decode("utf-8")
            for line in cs_content.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                parts = line.split("  ", 1)
                if len(parts) != 2:
                    result.add("CHECKSUMS_FORMAT", f"Invalid checksums.txt line: {line}")
                    continue
                digest, path = parts
                checksums[path] = digest.strip()
        except Exception as e:
            result.add("CHECKSUMS_MISSING", f"Cannot read checksums.txt: {e}")

        # ---- Step 4: File inventory match ----
        manifest_paths = {f.path for f in manifest.files}
        # manifest.json and checksums.txt are NOT in manifest.files per spec
        for mpath in sorted(manifest_paths):
            if mpath not in member_paths:
                result.add("FILE_MISSING", f"In manifest but not in archive: {mpath}")

        for mpath in sorted(member_paths):
            if mpath not in ("manifest.json", "checksums.txt"):
                if mpath not in manifest_paths:
                    sev = "warning" if not self._strict else "error"
                    result.add("FILE_UNKNOWN", f"In archive but not in manifest: {mpath}", severity=sev)

        # ---- Step 5: Checksums verification ----
        # manifest.files entries MUST match file content AND checksums.txt
        for mf in manifest.files:
            try:
                content = reader.read_file(mf.path)
                actual_hex = hashlib.sha256(content).hexdigest()
                if actual_hex != mf.sha256:
                    result.add("CHECKSUM_CONTENT", f"Checksum mismatch for {mf.path}")
            except Exception as e:
                result.add("CHECKSUM_READ", f"Cannot read for checksum: {mf.path}: {e}")

        # Cross-check manifest.files vs checksums.txt
        for mf in manifest.files:
            expected = checksums.get(mf.path)
            if expected is None:
                result.add("CHECKSUM_MISSING_ENTRY", f"No checksums.txt entry for: {mf.path}")
            elif expected != mf.sha256:
                result.add("CHECKSUM_MISMATCH", f"checksums.txt mismatch for {mf.path}")

        # Check for entries in checksums.txt not in manifest
        for cs_path in checksums:
            if cs_path not in manifest_paths:
                result.add("CHECKSUM_EXTRA", f"checksums.txt has entry not in manifest: {cs_path}", severity="warning" if not self._strict else "error")

        # ---- Step 6: incident.json validation ----
        if "incident.json" in member_paths and self._incident_schema:
            try:
                incident_data = reader.read_json("incident.json")
                valid, schema_errors = validate_against_schema(
                    incident_data, self._incident_schema
                )
                if valid:
                    result.add("INCIDENT_VALID", "incident.json validates against schema", severity="info")
                else:
                    for se in schema_errors[:5]:
                        result.add("INCIDENT_SCHEMA", f"incident.json: {se}")
            except Exception as e:
                result.add("INCIDENT_PARSE", f"incident.json error: {e}")

        # ---- Step 7: redaction-report.json invariants ----
        REPORT_FILES = {"redaction-report.json", "redaction_report.json"}
        report_found = member_paths & REPORT_FILES
        if report_found:
            report_path = next(iter(report_found))
            try:
                rr = reader.read_json(report_path)
                unresolved = rr.get("high_confidence_unresolved", -1)
                if unresolved == 0:
                    result.add("REDACTION_REPORT", "redaction-report.json: unresolved = 0", severity="info")
                elif unresolved > 0:
                    result.add("REDACTION_UNRESOLVED", f"redaction-report.json: high_confidence_unresolved = {unresolved}")
                else:
                    result.add("REDACTION_REPORT_MISSING_FIELD", "redaction-report.json missing 'high_confidence_unresolved'", severity="warning")
            except Exception as e:
                result.add("REDACTION_PARSE", f"redaction-report.json parse error: {e}")
        elif "redaction-report.json" in manifest_paths:
            result.add("REDACTION_MISSING", "redaction-report.json referenced in manifest but not readable")

        # ---- Step 8: Hard-deny path check (on archive paths) ----
        deny_matches = self._check_hard_deny_archive(list(member_paths))
        if deny_matches:
            for path, reason in deny_matches:
                result.add("HARD_DENY_PATH", f"Hard-deny path in archive: {path} ({reason})")

        # ---- Step 9: Residual secret scan ----
        textual_extensions = {".json", ".jsonl", ".md", ".txt", ".log", ".yaml", ".yml", ".toml"}
        for member in members:
            ext = Path(member.name).suffix.lower()
            if ext in textual_extensions:
                try:
                    content = reader.read_file(member.name)
                    residual = self._residual_secret_scan(content)
                    if residual:
                        result.add("RESIDUAL_SECRET", f"Possible residual secret in {member.name}: {residual[:80]}", severity="warning")
                except Exception:
                    pass

        # ---- Step 10: Offline guarantee ----
        result.add("OFFLINE", "Verification performed entirely offline", severity="info")

    def _check_hard_deny_archive(self, paths: list[str]) -> list[tuple[str, str]]:
        """Check archive paths against hard-deny patterns.

        This is the archive-level check (the policy module handles
        the pre-read check for source paths).
        """
        import re
        deny_patterns = [
            ("SSH directory", re.compile(r"(^|/)\.ssh/")),
            ("AWS credentials", re.compile(r"(^|/)\.aws/")),
            ("Azure credentials", re.compile(r"(^|/)\.azure/")),
            ("GPG directory", re.compile(r"(^|/)\.gnupg/")),
            ("Git credentials", re.compile(r"(^|/)\.git-credentials$")),
            ("Git config", re.compile(r"(^|/)\.gitconfig$")),
            ("Netrc", re.compile(r"(^|/)\.netrc$")),
            ("Env file", re.compile(r"(^|/)\.env$")),
            ("Env var file", re.compile(r"(^|/)\.env\.[^.]+$")),
            ("Private key", re.compile(r"\.pem$|\.key$|\.cert$")),
            ("Credentials file", re.compile(r"(^|/)credentials$")),
            ("Secrets file", re.compile(r"(^|/)secrets\.(yml|yaml)$")),
            ("Vault file", re.compile(r"(^|/)vault\.(yml|yaml)$")),
            ("Shell history", re.compile(r"(^|/)\.(bash|zsh|python)_history$")),
        ]
        result: list[tuple[str, str]] = []
        for p in paths:
            for reason, pattern in deny_patterns:
                if pattern.search(p):
                    result.append((p, reason))
                    break
        return result

    def _residual_secret_scan(self, content: bytes) -> str:
        """Quick scan for known high-confidence secret patterns.

        Returns first match or empty string.
        """
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            return ""

        import re
        high_confidence = [
            re.compile(r'sk-(?:proj-|svc-|)[A-Za-z0-9]{20,}'),
            re.compile(r'sk-ant-(?:api|admin|staff)[0-9A-Za-z_-]{40,}'),
            re.compile(r'(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}'),
            re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}'),
            re.compile(r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP|PRIVATE)\s+KEY-----'),
            re.compile(r'https?://[^\s:@/]+:[^\s:@/]+@[^\s]+'),
        ]
        for pattern in high_confidence:
            match = pattern.search(text)
            if match:
                return match.group(0)[:60]
        return ""
