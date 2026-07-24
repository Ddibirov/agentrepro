"""Incident — import and project agent-incident/1 records.

Matches spec §6: validates version, project known fields, adds import metadata.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentrepro.errors import SchemaError


# Known optional (forward-compatible) field names that ARE copied to projection.
# Unknown optional fields are NOT copied per spec §6.1.
KNOWN_FIELDS = frozenset({
    "$schema", "schema_version", "incident_id", "source", "detector",
    "timestamps", "evidence_refs", "severity", "status",
})

KNOWN_SOURCE_FIELDS = frozenset({"producer", "producer_version", "agent", "agent_version", "session_ref"})
KNOWN_DETECTOR_FIELDS = frozenset({"rule", "threshold", "observed", "details"})
KNOWN_TIMESTAMPS_FIELDS = frozenset({"detected_at", "session_started_at", "session_ended_at"})


def load_and_validate_incident(path: str | Path) -> dict[str, Any]:
    """Load an incident.json file, validate version, return parsed data.

    Raises SchemaError on: invalid file, unsupported major version, bad JSON.
    """
    p = Path(path)
    if not p.exists():
        raise SchemaError(f"Incident file not found: {p}", code="E_INCIDENT_NOT_FOUND")

    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SchemaError(f"Invalid JSON in incident: {e}", code="E_INCIDENT_MALFORMED")

    schema_version = raw.get("schema_version", "0.0")
    major = schema_version.split(".")[0] if "." in schema_version else schema_version

    if major != "1":
        raise SchemaError(
            f"Unsupported incident schema_version '{schema_version}' (only 1.x supported)",
            code="E_SCHEMA_VERSION",
        )

    return raw


def project_incident(raw: dict[str, Any]) -> dict[str, Any]:
    """Project raw incident to sanitised bundle-safe incident record.

    Only known fields are copied. Unknown optional fields are ignored.
    Adds 'import' metadata with counts and resolution status.

    Based on spec §6.2.
    """
    projected: dict[str, Any] = {}

    unknown_count = 0
    for k, v in raw.items():
        if k in KNOWN_FIELDS:
            projected[k] = _project_value(k, v)
        else:
            unknown_count += 1

    # Add import metadata
    projected["import"] = {
        "unknown_optional_fields_ignored": unknown_count,
        "session_ref_resolution": "not_provided",
    }

    return projected


def _project_value(field: str, value: Any) -> Any:
    """Project a single field, preserving structure but only known sub-fields."""
    if field == "source" and isinstance(value, dict):
        return {k: v for k, v in value.items() if k in KNOWN_SOURCE_FIELDS}
    if field == "detector" and isinstance(value, dict):
        return {k: v for k, v in value.items() if k in KNOWN_DETECTOR_FIELDS}
    if field == "timestamps" and isinstance(value, dict):
        return {k: v for k, v in value.items() if k in KNOWN_TIMESTAMPS_FIELDS}
    if field == "evidence_refs" and isinstance(value, list):
        # Evidence refs: keep only safe metadata
        safe: list[dict[str, str]] = []
        for ref in value:
            if isinstance(ref, dict):
                safe.append({
                    "type": ref.get("type", "unknown"),
                    "description": ref.get("description", ""),
                })
        return safe
    return value


class IncidentImporter:
    """Import an external incident record for bundle creation."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.raw: dict[str, Any] = {}
        self.projected: dict[str, Any] = {}
        self.unknown_fields_ignored = 0

    def load(self) -> IncidentImporter:
        """Load and validate the incident file."""
        self.raw = load_and_validate_incident(self.path)
        return self

    def project(self) -> IncidentImporter:
        """Project to sanitized record."""
        self.projected = project_incident(self.raw)
        self.unknown_fields_ignored = self.projected.get("import", {}).get(
            "unknown_optional_fields_ignored", 0
        )
        return self

    def get_agent(self) -> str:
        """Return the agent name from the incident, or 'unknown'."""
        source = self.raw.get("source", {})
        return source.get("agent", "unknown")

    def get_agent_version(self) -> str | None:
        source = self.raw.get("source", {})
        return source.get("agent_version")

    def get_session_ref(self) -> str | None:
        source = self.raw.get("source", {})
        return source.get("session_ref")

    def get_producer(self) -> str | None:
        source = self.raw.get("source", {})
        return source.get("producer")

    def get_incident_id(self) -> str | None:
        return self.raw.get("incident_id")
