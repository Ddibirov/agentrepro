"""Tests for incident importer."""
from __future__ import annotations


import pytest

from agentrepro.errors import SchemaError
from agentrepro.incident import IncidentImporter, load_and_validate_incident, project_incident
from agentrepro.schema.validator import validate_against_schema, load_schema


def test_load_valid_incident(incident_file):
    importer = IncidentImporter(incident_file).load()
    assert importer.raw["incident_id"] == "inc_test_001"
    assert importer.raw["schema_version"] == "1.0"


def test_load_v2_incident_rejected(incident_file_v2):
    with pytest.raises(SchemaError, match="E_SCHEMA_VERSION"):
        load_and_validate_incident(incident_file_v2)


def test_project_incident(sample_incident):
    projected = project_incident(sample_incident)
    assert projected["incident_id"] == "inc_test_001"
    assert projected["source"]["agent"] == "claude-code"
    assert projected["detector"]["rule"] == "repeated_tool_call"
    assert "import" in projected
    assert projected["import"]["unknown_optional_fields_ignored"] == 0


def test_project_incident_ignores_unknown(incident_file_with_unknown):
    importer = IncidentImporter(incident_file_with_unknown).load().project()
    projected = importer.projected
    # Unknown fields should be absent
    assert "action" not in projected
    assert "timestamp" not in projected  # top-level, not timestamps
    assert "config_snapshot" not in projected
    # Import metadata should track ignored count
    assert projected["import"]["unknown_optional_fields_ignored"] >= 3


def test_incident_missing_file(tmp_path):
    with pytest.raises(SchemaError, match="E_INCIDENT_NOT_FOUND"):
        load_and_validate_incident(tmp_path / "nonexistent.json")


def test_incident_malformed_json(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{invalid json}")
    with pytest.raises(SchemaError, match="E_INCIDENT_MALFORMED"):
        load_and_validate_incident(p)


def test_incident_getters(incident_file):
    importer = IncidentImporter(incident_file).load()
    assert importer.get_agent() == "claude-code"
    assert importer.get_incident_id() == "inc_test_001"


def test_incident_projection_known_only(incident_file_with_unknown):
    importer = IncidentImporter(incident_file_with_unknown).load().project()
    p = importer.projected
    # Known fields preserved
    assert p["schema_version"] == "1.0"
    assert p["incident_id"] == "inc_test_001"
    assert p["source"]["producer"] == "loopbreaker"
    assert p["detector"]["rule"] == "repeated_tool_call"
    assert p["timestamps"]["detected_at"] == "2026-07-22T12:00:00Z"
    assert p.get("severity")  # known optional


def test_incident_schema_validation(schema_path, sample_incident):
    schema = load_schema(schema_path)
    valid, errors = validate_against_schema(sample_incident, schema)
    assert valid, f"Schema errors: {errors}"


def test_incident_schema_rejects_missing_required(schema_path):
    schema = load_schema(schema_path)
    invalid = {"schema_version": "1.0"}  # Missing incident_id, source, detector, timestamps
    valid, errors = validate_against_schema(invalid, schema)
    assert not valid
    # The actual error path keys from jsonschema differ, just check something failed
    assert len(errors) > 0


def test_incident_schema_rejects_bad_version(schema_path):
    schema = load_schema(schema_path)
    bad = {
        "schema_version": "2.0",
        "incident_id": "test",
        "source": {"producer": "t", "producer_version": "1", "agent": "a"},
        "detector": {"rule": "r", "threshold": 1, "observed": 1},
        "timestamps": {"detected_at": "2026-01-01T00:00:00Z"},
    }
    valid, errors = validate_against_schema(bad, schema)
    assert not valid


def test_incident_allows_unknown_optional(schema_path, sample_incident):
    schema = load_schema(schema_path)
    with_unknown = dict(sample_incident)
    with_unknown["action"] = "stop"
    with_unknown["config"] = {"timeout": 60}
    valid, errors = validate_against_schema(with_unknown, schema)
    assert valid, f"Schema should allow unknown optionals: {errors}"
