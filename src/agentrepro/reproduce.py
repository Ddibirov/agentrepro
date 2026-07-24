"""Reproduce — generate REPRODUCE.md from sanitized bundle data.

Matches spec §11: required sections from sanitized data only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def generate_reproduce_md(
    bundle_id: str,
    source_info: dict[str, Any] | None = None,
    capabilities: dict[str, Any] | None = None,
    redaction_info: dict[str, Any] | None = None,
    reproduction_info: dict[str, Any] | None = None,
    file_list: list[dict[str, Any]] | None = None,
    git_commit: str | None = None,
    git_dirty: bool | None = None,
) -> str:
    """Generate REPRODUCE.md from manifest data.

    Uses ONLY sanitized data. No original paths, secrets, or commands.
    """
    source = source_info or {}
    caps = capabilities or {}
    redact = redaction_info or {}
    repro = reproduction_info or {}
    files = file_list or []
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    agent = source.get("agent", "unknown")
    agent_ver = source.get("agent_version", "unknown")
    redact_count = redact.get("total_replacements", 0)
    classification = repro.get("classification", "inspection_only")
    reasons = repro.get("reasons_not_exact", [])

    lines = [
        f"# Reproduction Bundle: {bundle_id}",
        "",
        f"Generated: {created}",
        f"Agent: {agent} v{agent_ver}",
        "",
        "## Incident Summary",
        "",
    ]

    if source.get("incident_id"):
        lines.append(f"Triggered by incident `{source['incident_id']}` from `{source.get('incident_producer', 'unknown')}`.")
    else:
        lines.append("This bundle captures a session excerpt for reproduction purposes.")

    lines += [
        "",
        "## Scope and Limitations",
        "",
        "- **Local evidence only**: All data in this bundle is sourced from a local machine.",
        "- **Unauthenticated provenance**: Embedded checksums verify integrity but not authorship.",
        "- **No deterministic LLM replay**: LLM outputs are non-deterministic; exact reproduction is not guaranteed.",
        "- **Commands are never auto-executed**: This document is for manual review only.",
        "",
        "## Verification",
        "",
        "```",
        f"agentrepro verify {bundle_id}",
        "```",
        "",
        "Integrity: SHA-256 checksums verified against manifest. Commands are never auto-executed.",
        "",
    ]

    # Known baseline
    lines += [
        "## Known Baseline",
        "",
    ]
    if git_commit:
        lines.append(f"- Baseline commit: `{git_commit}`")
        if git_dirty:
            lines.append("- Working tree had uncommitted changes at capture time.")
        lines.append("")
    else:
        lines.append("- No Git baseline commit captured.")
        lines.append("")

    # Capabilities
    lines.append("## Bundle Contents")
    lines.append("")
    for f in files:
        checked = "✓" if f.get("present", True) else "✗"
        lines.append(f"- {checked} {f.get('path', 'unknown')} ({_role_label(f.get('role', ''))})")
    lines.append("")

    # Redaction
    lines.append("## Redaction")
    lines.append("")
    lines.append(f"- Policy version: {redact.get('policy_version', '1.0')}")
    lines.append(f"- Total redactions: {redact_count}")
    lines.append(f"- Unresolved high-confidence: {redact.get('unresolved_high_confidence', 0)}")
    lines.append(f"- Hard-deny overrides: {redact.get('hard_deny_overrides', 0)}")
    lines.append("")

    # Reproduction
    lines.append("## Reproduction Classification")
    lines.append("")
    lines.append(f"Classification: **{classification}**")
    if reasons:
        lines.append("")
        lines.append("Reasons reproduction is not exact:")
        for r in reasons:
            lines.append(f"- {r}")

    lines.append("")
    lines.append("## Observed Sequence")
    lines.append("")
    lines.append("The session transcript in `session.jsonl` records the agent's action sequence.")
    lines.append("Steps are classified as:")
    lines.append("- **Deterministic**: Shell commands, tool invocations with known inputs.")
    lines.append("- **Environment-dependent**: Commands whose output varies by OS/runtime.")
    lines.append("- **Model-nondeterministic**: LLM-generated messages (no exact replay).")
    lines.append("")

    # Evidence
    has_evidence = caps.get("evidence", False)
    if has_evidence:
        lines.append("## Evidence")
        lines.append("")
        lines.append("See `evidence/` directory for referenced evidence files.")
        lines.append("")

    lines.append("## Inventory and Redaction Summary")
    lines.append("")
    lines.append(f"- Number of payload files: {len(files)}")
    lines.append(f"- Redactions applied: {redact_count}")
    lines.append(f"- Reproduction: {classification}")
    lines.append("")

    return "\n".join(lines)


def _role_label(role: str) -> str:
    labels = {
        "session": "Session transcript",
        "session_metadata": "Session metadata",
        "environment": "Environment info",
        "git_state": "Git state",
        "incident": "Incident record",
        "evidence": "Evidence file",
        "evidence_index": "Evidence index",
        "redaction_report": "Redaction report",
        "schema": "JSON Schema",
        "reproduce": "Reproduction instructions",
    }
    return labels.get(role, role)
