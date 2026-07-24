"""Redaction engine — orchestrates multiple filters to redact content.

Matches the spec §8: pipeline with field selection, text size caps,
structured JSON/JSONL redaction, stable per-bundle placeholders.

Usage:
    engine = RedactionEngine()
    result = engine.redact_text("My API key is sk-abc123...")
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from .filters import (
    CustomRegexFilter,
    RedactionChange,
    RedactionFilter,
    default_filters,
)
from .patterns import DEFAULT_REGISTRY, PatternRegistry


@dataclass
class RedactionResult:
    """Result of redacting a single text."""

    redacted: str
    changes: list[RedactionChange] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        return len(self.changes)

    def changes_by_category(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for c in self.changes:
            counts[c.category] = counts.get(c.category, 0) + 1
        return counts

    def high_confidence_count(self) -> int:
        """Count changes from high-confidence patterns."""
        from .patterns import DEFAULT_REGISTRY

        high_conf_names: set[str] = set()
        for cat, pdef in DEFAULT_REGISTRY.all_patterns():
            if pdef.confidence == "high":
                high_conf_names.add(pdef.name)

        count = 0
        for c in self.changes:
            if c.pattern_name in high_conf_names:
                count += 1
        return count


@dataclass
class FileResult:
    """Result of redacting a single file."""

    path: str
    redacted: str
    original_size: int
    redacted_size: int
    changes: list[RedactionChange] = field(default_factory=list)
    truncated: bool = False

    @property
    def total_changes(self) -> int:
        return len(self.changes)

    def high_confidence_count(self) -> int:
        """Count changes from high-confidence patterns."""
        from .patterns import DEFAULT_REGISTRY

        high_conf_names: set[str] = set()
        for cat, pdef in DEFAULT_REGISTRY.all_patterns():
            if pdef.confidence == "high":
                high_conf_names.add(pdef.name)

        count = 0
        for c in self.changes:
            if c.pattern_name in high_conf_names:
                count += 1
        return count


class RedactionEngine:
    """Orchestrates the redaction pipeline across multiple filters.

    Filters run in order: high-specificity first.
    """

    def __init__(
        self,
        filters: list[RedactionFilter] | None = None,
        registry: PatternRegistry | None = None,
        skip_categories: set[str] | None = None,
    ):
        self._registry = registry or DEFAULT_REGISTRY
        self._filters = filters or default_filters(self._registry)

        if skip_categories:
            self._filters = [f for f in self._filters if f.category not in skip_categories]

    def add_custom_pattern(self, name: str, pattern_str: str, confidence: str = "high") -> None:
        """Add a custom regex pattern at runtime."""
        import re

        compiled = re.compile(pattern_str)
        for f in self._filters:
            if isinstance(f, CustomRegexFilter):
                f._custom_specs.append((name, compiled, confidence))
                return
        self._filters.append(CustomRegexFilter([(name, compiled, confidence)], self._registry))

    def redact_text(self, text: str) -> RedactionResult:
        """Redact a single string through all filters.

        Filters are applied sequentially. Each filter sees the output
        of the previous one, so later filters never see values already
        replaced by earlier filters.
        """
        if not text:
            return RedactionResult(redacted="")

        all_changes: list[RedactionChange] = []
        current = text

        for filt in self._filters:
            redacted, changes = filt.redact(current)
            # Re-apply changes tracking
            for c in changes:
                all_changes.append(c)
            current = redacted

        all_changes.sort(key=lambda c: (c.line, c.column))
        return RedactionResult(redacted=current, changes=all_changes)

    def redact_file(self, archive_path: str, content: str) -> FileResult:
        """Redact a single file's content."""
        result = self.redact_text(content)
        content_bytes = content.encode("utf-8")
        redacted_bytes = result.redacted.encode("utf-8")

        return FileResult(
            path=archive_path,
            redacted=result.redacted,
            original_size=len(content_bytes),
            redacted_size=len(redacted_bytes),
            changes=result.changes,
        )

    def redact_files(
        self, files: dict[str, str]
    ) -> tuple[dict[str, str], list[FileResult]]:
        """Redact a dict of archive_path -> content.

        Returns (redacted_files, file_results).
        """
        redacted: dict[str, str] = {}
        results: list[FileResult] = []
        for path, content in files.items():
            fr = self.redact_file(path, content)
            redacted[path] = fr.redacted if fr.changes else content
            results.append(fr)
        return redacted, results

    def redact_json_object(
        self, obj: object, archive_path: str = ""
    ) -> tuple[dict[str, str] | list | str | int | float | bool | None, list[RedactionChange]]:
        """Redact all string leaves in a parsed JSON object.

        Returns (redacted_object, changes).
        """
        if isinstance(obj, str):
            result = self.redact_text(obj)
            return result.redacted, result.changes
        elif isinstance(obj, dict):
            changes: list[RedactionChange] = []
            redacted_dict: dict = {}
            for k, v in obj.items():
                redacted_v, sub_changes = self.redact_json_object(v, archive_path)
                for c in sub_changes:
                    c.file = archive_path
                redacted_dict[k] = redacted_v
                changes.extend(sub_changes)
            return redacted_dict, changes
        elif isinstance(obj, list):
            changes = []
            redacted_list: list = []
            for item in obj:
                redacted_item, sub_changes = self.redact_json_object(item, archive_path)
                for c in sub_changes:
                    c.file = archive_path
                redacted_list.append(redacted_item)
                changes.extend(sub_changes)
            return redacted_list, changes
        else:
            return obj, []
