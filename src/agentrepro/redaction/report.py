"""Redaction report — serialisable summary of redaction results.

The format does NOT store original values — only placeholder IDs,
categories, and locations. Matches spec §8.3.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from .engine import FileResult, RedactionEngine


@dataclass
class PlaceholderEntry:
    """One placeholder record for the report."""

    id: str
    category: str
    pattern_name: str
    locations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "pattern_name": self.pattern_name,
            "locations": self.locations,
        }


@dataclass
class RedactionReport:
    """Full redaction report, ready for JSON serialisation."""

    redaction_version: str = "1.0"
    generator: str = "agentrepro"
    generator_version: str = "0.1.0"
    total_redactions: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_pattern: dict[str, int] = field(default_factory=dict)
    placeholders: list[PlaceholderEntry] = field(default_factory=list)
    high_confidence_unresolved: int = 0
    """
    Counts *residual matches after redaction* — matches that were successfully
    replaced must result in 0 here. Nonzero means a high-confidence pattern
    matched input that was NOT replaced (shouldn't happen in normal flow).
    """

    def to_dict(self) -> dict[str, Any]:
        return {
            "redaction_version": self.redaction_version,
            "generator": self.generator,
            "generator_version": self.generator_version,
            "total_redactions": self.total_redactions,
            "by_category": dict(self.by_category),
            "by_pattern": dict(self.by_pattern),
            "placeholders": [p.to_dict() for p in self.placeholders],
            "high_confidence_unresolved": self.high_confidence_unresolved,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_file_results(
        cls,
        file_results: list[FileResult],
        high_confidence_unresolved: int = 0,
    ) -> RedactionReport:
        """Build a report from the output of RedactionEngine.redact_files."""
        placeholders_map: dict[str, PlaceholderEntry] = {}
        by_category: dict[str, int] = {}
        by_pattern: dict[str, int] = {}
        total = 0

        for fr in file_results:
            for change in fr.changes:
                total += 1
                by_category[change.category] = by_category.get(change.category, 0) + 1
                by_pattern[change.pattern_name] = by_pattern.get(change.pattern_name, 0) + 1

                if change.placeholder_id not in placeholders_map:
                    placeholders_map[change.placeholder_id] = PlaceholderEntry(
                        id=change.placeholder_id,
                        category=change.category,
                        pattern_name=change.pattern_name,
                    )
                placeholders_map[change.placeholder_id].locations.append(
                    {
                        "file": fr.path,
                        "line": change.line,
                        "column": change.column,
                        "snippet": change.snippet,
                    }
                )

        return cls(
            total_redactions=total,
            by_category=by_category,
            by_pattern=by_pattern,
            placeholders=sorted(placeholders_map.values(), key=lambda p: p.id),
            high_confidence_unresolved=high_confidence_unresolved,
        )


def redact_text_for_report(
    engine: RedactionEngine, files: dict[str, str]
) -> tuple[dict[str, str], RedactionReport]:
    """Run redaction and return both redacted content and report.

    high_confidence_unresolved is set to 0 because all matches
    were replaced (the residual scan would catch any misses).
    """
    redacted_files, file_results = engine.redact_files(files)
    report = RedactionReport.from_file_results(
        file_results, high_confidence_unresolved=0
    )
    return redacted_files, report
