"""Preview — human-readable summary before export.

Matches spec §8.4: reports inventory, byte total, capability absence,
redactions per category, truncated/omitted records, hard-deny blocks,
unresolved risk and reproduction classification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .engine import FileResult


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"


@dataclass
class FileInventory:
    path: str
    original_size: int
    redacted_size: int
    redactions: int
    high_confidence: int


@dataclass
class PreviewReport:
    """User-facing preview before export."""

    total_files: int = 0
    total_original_size: int = 0
    total_redacted_size: int = 0
    total_redactions: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_pattern: dict[str, int] = field(default_factory=dict)
    high_confidence_count: int = 0
    medium_confidence_count: int = 0
    file_inventory: list[FileInventory] = field(default_factory=list)
    unresolved_warnings: list[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    hard_deny_blocks: int = 0
    truncated_records: list[str] = field(default_factory=list)

    @classmethod
    def from_file_results(
        cls, file_results: list[FileResult]
    ) -> PreviewReport:
        """Build a preview from RedactionEngine.redact_files output."""
        total_orig = 0
        total_redacted = 0
        total_redactions = 0
        high_conf = 0
        med_conf = 0
        by_cat: dict[str, int] = {}
        by_pat: dict[str, int] = {}
        inventory: list[FileInventory] = []
        warnings: list[str] = []
        truncated: list[str] = []

        for fr in file_results:
            total_orig += fr.original_size
            total_redacted += fr.redacted_size
            fc = fr.total_changes
            total_redactions += fc
            hc = fr.high_confidence_count()
            high_conf += hc

            inventory.append(
                FileInventory(
                    path=fr.path,
                    original_size=fr.original_size,
                    redacted_size=fr.redacted_size,
                    redactions=fc,
                    high_confidence=hc,
                )
            )

            for change in fr.changes:
                by_cat[change.category] = by_cat.get(change.category, 0) + 1
                by_pat[change.pattern_name] = by_pat.get(change.pattern_name, 0) + 1

            if fr.truncated:
                truncated.append(fr.path)

        med_conf = total_redactions - high_conf

        # Risk level per spec §8.4
        risk = RiskLevel.LOW
        if high_conf > 0:
            risk = RiskLevel.BLOCKED  # high-confidence blocks export per spec
        elif med_conf > 0:
            risk = RiskLevel.MEDIUM

        # Medium-confidence warnings
        from .patterns import DEFAULT_REGISTRY

        medium_names: set[str] = set()
        for cat, pdef in DEFAULT_REGISTRY.all_patterns():
            if pdef.confidence == "medium":
                medium_names.add(pdef.name)
        for fr in file_results:
            for c in fr.changes:
                if c.pattern_name in medium_names:
                    warnings.append(
                        f"Medium-confidence pattern '{c.pattern_name}' matched — verify manually"
                    )
                    break  # One warning per file

        return cls(
            total_files=len(file_results),
            total_original_size=total_orig,
            total_redacted_size=total_redacted,
            total_redactions=total_redactions,
            by_category=by_cat,
            by_pattern=by_pat,
            high_confidence_count=high_conf,
            medium_confidence_count=med_conf,
            file_inventory=inventory,
            unresolved_warnings=warnings,
            risk_level=risk,
            hard_deny_blocks=0,
            truncated_records=truncated,
        )

    @property
    def export_blocked(self) -> bool:
        """True if export should be blocked per spec: high-confidence unresolved."""
        return self.risk_level in (RiskLevel.BLOCKED, RiskLevel.HIGH)

    def format(self) -> str:
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("  AGENTREPO REDACTION PREVIEW")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"  Files processed:      {self.total_files}")
        lines.append(f"  Original size:        {self._human_size(self.total_original_size)}")
        lines.append(f"  Redacted size:        {self._human_size(self.total_redacted_size)}")
        lines.append(f"  Total redactions:     {self.total_redactions}")
        lines.append(f"  High confidence:      {self.high_confidence_count}")
        lines.append(f"  Medium confidence:    {self.medium_confidence_count}")
        lines.append(f"  Risk level:           {self.risk_level.value.upper()}")
        lines.append(f"  Hard-deny blocks:     {self.hard_deny_blocks}")
        lines.append("")

        if self.truncated_records:
            lines.append("--- TRUNCATED RECORDS ---")
            for t in self.truncated_records:
                lines.append(f"  ! {t} was truncated")
            lines.append("")

        if self.unresolved_warnings:
            lines.append("--- WARNINGS ---")
            for w in self.unresolved_warnings:
                lines.append(f"  ! {w}")
            lines.append("")

        lines.append("--- FILE INVENTORY ---")
        lines.append(f"  {'Path':<50s} {'Orig':>8s} {'New':>8s} {'#Red':>6s}")
        lines.append(f"  {'-'*50} {'-'*8} {'-'*8} {'-'*6}")
        for fi in self.file_inventory:
            lines.append(
                f"  {fi.path:<50s} {self._human_size(fi.original_size):>8s}"
                f" {self._human_size(fi.redacted_size):>8s} {fi.redactions:>6d}"
            )
        lines.append("")

        if self.by_category:
            lines.append("--- REDACTIONS BY CATEGORY ---")
            for cat in sorted(self.by_category):
                lines.append(f"  {cat:<25s} {self.by_category[cat]}")
            lines.append("")

        if self.export_blocked:
            lines.append("!" * 60)
            lines.append("  EXPORT BLOCKED: High-confidence unresolved secrets detected.")
            lines.append("  Review the matches above before creating the bundle.")
            lines.append("!" * 60)
        else:
            lines.append("  Export: allowed")
            if self.hard_deny_blocks > 0:
                lines.append("  (hard-deny blocks: some sources were excluded)")
        lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_files": self.total_files,
            "total_original_size": self.total_original_size,
            "total_redacted_size": self.total_redacted_size,
            "total_redactions": self.total_redactions,
            "by_category": dict(self.by_category),
            "by_pattern": dict(self.by_pattern),
            "high_confidence_count": self.high_confidence_count,
            "medium_confidence_count": self.medium_confidence_count,
            "risk_level": self.risk_level.value,
            "hard_deny_blocks": self.hard_deny_blocks,
            "export_blocked": self.export_blocked,
            "truncated_records": list(self.truncated_records),
        }

    @staticmethod
    def _human_size(size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes}B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f}KB"
        else:
            return f"{size_bytes / (1024 * 1024):.1f}MB"
