"""JSON Schema validation using jsonschema library."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import ValidationError, validate


def load_schema(path: str | Path) -> dict[str, Any]:
    """Load a JSON Schema from a file path."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate_against_schema(
    data: dict[str, Any],
    schema: dict[str, Any],
) -> tuple[bool, list[str]]:
    """Validate a JSON object against a JSON Schema.

    Returns (is_valid, list_of_error_messages).
    Unknown optional fields are allowed (additionalProperties: true in schema).
    """
    try:
        validate(instance=data, schema=schema)
        return True, []
    except ValidationError as e:
        errors = []
        for err in sorted(
            e.context if hasattr(e, "context") and e.context else [e],
            key=lambda x: str(x.path),
        ):
            errors.append(f"{' → '.join(str(p) for p in err.path)}: {err.message}")
        if not errors:
            errors.append(str(e))
        return False, errors


def validate_instance_against_schema_file(
    data: dict[str, Any],
    schema_path: str | Path,
) -> tuple[bool, list[str]]:
    """Shorthand: load schema from file, validate data against it."""
    schema = load_schema(schema_path)
    return validate_against_schema(data, schema)
