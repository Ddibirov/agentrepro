"""Capture — orchestrate bundle creation.

Captures session data, redacts, previews, and writes a bundle.
Matches spec §4: source resolver, collection policy, redaction, preview, bundle write.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapters import get_adapter, NormalizedSession
from .bundle.models import Manifest, ManifestFile, ManifestCapabilities
from .bundle.verify import BundleVerify
from .bundle.writer import BundleWriter
from .errors import SourceError
from .incident import IncidentImporter
from .redaction.engine import RedactionEngine
from .redaction.filters import reset_placeholder_cache
from .redaction.preview import PreviewReport
from .redaction.report import RedactionReport
from .reproduce import generate_reproduce_md

CAPTURE_AGENTS = {"claude", "claude-code", "codex", "codex-cli", "opencode", "opencode-cli"}


# ---------------------------------------------------------------------------
# Public helpers (shared with preview, etc.)
# ---------------------------------------------------------------------------


def _collect_payload(
    *,
    source_selector: str,
    agent: str | None = None,
    incident_path: str | None = None,
    evidence_paths: list[str] | None = None,
) -> tuple[
    dict[str, tuple[bytes, str]],  # payload (archive_path -> (bytes, role))
    list[ManifestFile],            # files_meta
    ManifestCapabilities,          # caps
    dict[str, Any],                # source_info
    IncidentImporter | None,       # incident_importer
    dict[str, Any] | None,         # git_state
    dict[str, Any],                # reproduction_info
]:
    """Collect all payload data for a capture or preview.

    Returns (payload, files_meta, caps, source_info, incident_importer,
             git_state, reproduction_info).
    """
    session_data: NormalizedSession | None = None
    importer: IncidentImporter | None = None
    source_info: dict[str, Any] = {}
    caps = ManifestCapabilities()
    reproduction_info: dict[str, Any] = {}
    if incident_path:
        # Incident-driven capture
        importer = IncidentImporter(incident_path).load().project()

        source_info = {
            "agent": agent or importer.get_agent() or "unknown",
            "agent_version": importer.get_agent_version(),
            "session_ref_status": "unresolved",
            "incident_id": importer.get_incident_id(),
            "incident_producer": importer.get_producer(),
        }

        # Try to resolve session from incident
        session_ref = importer.get_session_ref()
        if session_ref:
            try:
                adp = get_adapter(source_info["agent"])
                descriptor = adp.resolve(session_ref)
                if descriptor:
                    session_data = adp.read_normalized(descriptor)
                    source_info["session_ref_status"] = "resolved"
                    caps.session_excerpt = True
            except Exception:
                pass

        caps.incident = True

    elif source_selector and agent:
        # Agent-driven capture
        agent = agent.lower()
        if agent not in CAPTURE_AGENTS:
            raise SourceError(
                f"Unknown agent: {agent}. Use one of: {sorted(CAPTURE_AGENTS)}",
                code="E_USAGE",
            )

        adp = get_adapter(agent)
        descriptors = adp.discover(source_selector)
        if not descriptors:
            raise SourceError(
                f"No sessions found for '{source_selector}' using {agent}",
                code="E_SOURCE",
            )
        descriptor = descriptors[0]
        session_data = adp.read_normalized(descriptor)
        source_info = {
            "agent": adp.agent_name,
            "agent_version": descriptor.agent_version,
            "session_ref_status": "resolved",
        }
        caps.session_excerpt = True
    else:
        raise SourceError(
            "Either --incident or --agent with --session/--last is required",
            code="E_USAGE",
        )

    # ---- Build payload ----
    payload: dict[str, tuple[bytes, str]] = {}
    files_meta: list[ManifestFile] = []

    # Session JSONL
    if session_data and caps.session_excerpt:
        jsonl_content = session_data.to_jsonl()
        payload["session.jsonl"] = (jsonl_content.encode("utf-8"), "session")
        files_meta.append(ManifestFile(path="session.jsonl", role="session", bytes=len(jsonl_content)))

        # Session metadata
        meta_json = json.dumps({
            "session_id": session_data.metadata.get("session_id", ""),
            "event_count": len(session_data.events),
            "unknown_event_types": session_data.unknown_event_types,
            "source_format": session_data.source_format,
        }, indent=2)
        payload["session-metadata.json"] = (meta_json.encode("utf-8"), "session_metadata")
        files_meta.append(ManifestFile(path="session-metadata.json", role="session_metadata", bytes=len(meta_json)))

    # Incident projection
    if importer:
        inc_json = json.dumps(importer.projected, indent=2, ensure_ascii=False)
        payload["incident.json"] = (inc_json.encode("utf-8"), "incident")
        files_meta.append(ManifestFile(path="incident.json", role="incident", bytes=len(inc_json)))

    # Environment info (minimal, safe)
    env_data = _collect_safe_environment()
    env_json = json.dumps(env_data, indent=2)
    payload["environment.json"] = (env_json.encode("utf-8"), "environment")
    files_meta.append(ManifestFile(path="environment.json", role="environment", bytes=len(env_json)))
    caps.environment = True

    # Git state (if available)
    git_state = _collect_git_state(source_info.get("cwd_hint"))
    if git_state:
        git_json = json.dumps(git_state, indent=2)
        payload["git-state.json"] = (git_json.encode("utf-8"), "git_state")
        files_meta.append(ManifestFile(path="git-state.json", role="git_state", bytes=len(git_json)))
        caps.git_state = True
        reproduction_info["baseline_commit"] = git_state.get("commit")
        if git_state.get("dirty", True):
            reproduction_info["reasons_not_exact"] = ["uncommitted_changes", "llm_output_nondeterministic"]
        else:
            reproduction_info["reasons_not_exact"] = ["llm_output_nondeterministic"]

    # Evidence files
    if evidence_paths:
        caps.evidence = True
        ev_index: list[dict[str, str]] = []
        for i, ev_path in enumerate(evidence_paths[:20]):
            ev_name = f"evidence_{i+1:03d}.txt"
            try:
                content = Path(ev_path).read_text(encoding="utf-8", errors="replace")
                payload[f"evidence/{ev_name}"] = (content.encode("utf-8"), "evidence")
                files_meta.append(ManifestFile(path=f"evidence/{ev_name}", role="evidence", bytes=len(content)))
                ev_index.append({"file": ev_name, "source": str(Path(ev_path).name)})
            except Exception as e:
                print(f"Warning: cannot read evidence {ev_path}: {e}", file=sys.stderr)

        if ev_index:
            idx_json = json.dumps({"files": ev_index}, indent=2)
            payload["evidence/index.json"] = (idx_json.encode("utf-8"), "evidence_index")
            files_meta.append(ManifestFile(path="evidence/index.json", role="evidence_index", bytes=len(idx_json)))

    return payload, files_meta, caps, source_info, importer, git_state, reproduction_info


def _run_redaction(
    payload: dict[str, tuple[bytes, str]],
) -> tuple[
    dict[str, tuple[bytes, str]] | None,  # redacted payload
    dict[str, Any],                        # redaction_info
    list,                                   # file_results
    RedactionReport | None,                # report
]:
    """Run redaction pipeline over payload files.

    Returns (redacted_payload, redaction_info, file_results, report).
    If no text payloads, returns (None, defaults, [], None).
    """
    text_payloads: dict[str, str] = {}
    for arc_path, (content_bytes, role) in payload.items():
        try:
            text_payloads[arc_path] = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            pass

    if not text_payloads:
        return None, {
            "policy_version": "1.0", "applied": False, "total_replacements": 0,
            "unresolved_high_confidence": 0, "hard_deny_overrides": 0,
        }, [], None

    engine = RedactionEngine()
    redacted, file_results = engine.redact_files(text_payloads)

    redacted_payload: dict[str, tuple[bytes, str]] = {}
    for arc_path, content in redacted.items():
        redacted_payload[arc_path] = (content.encode("utf-8"), payload[arc_path][1])

    total_reds = sum(fr.total_changes for fr in file_results)
    redaction_info: dict[str, Any] = {
        "policy_version": "1.0",
        "applied": total_reds > 0,
        "total_replacements": total_reds,
        "unresolved_high_confidence": 0,
        "hard_deny_overrides": 0,
    }

    report = RedactionReport.from_file_results(file_results)
    report_json = report.to_json()
    redacted_payload["redaction-report.json"] = (report_json.encode("utf-8"), "redaction_report")

    return redacted_payload, redaction_info, file_results, report


def _build_preview(file_results) -> PreviewReport:
    """Build a preview report from file_results."""
    preview = PreviewReport.from_file_results(file_results)
    preview.hard_deny_blocks = 0
    return preview


# ---------------------------------------------------------------------------
# Main capture command
# ---------------------------------------------------------------------------


def cmd_capture(
    *,
    source_selector: str,  # "last", session ID, or incident path
    agent: str | None = None,
    output: str | None = None,
    yes: bool = False,
    incident_path: str | None = None,
    evidence_paths: list[str] | None = None,
    format: str = "text",
) -> int:
    """Execute a capture workflow per spec §9.

    Returns exit code.
    """
    reset_placeholder_cache()

    # Resolve source and collect payload
    try:
        payload, files_meta, caps, source_info, incident_importer, git_state, reproduction_info = _collect_payload(
            source_selector=source_selector,
            agent=agent,
            incident_path=incident_path,
            evidence_paths=evidence_paths,
        )
    except SourceError as e:
        if format == "json":
            print(json.dumps({"error": str(e), "code": e.code}))
        else:
            print(str(e), file=sys.stderr)
        return e.exit_code
    except Exception as e:
        msg = f"Error loading source: {e}"
        if format == "json":
            print(json.dumps({"error": msg, "code": "E_SOURCE"}))
        else:
            print(msg, file=sys.stderr)
        return 3

    # ---- Redaction ----
    redacted_payload, redaction_info, file_results, report = _run_redaction(payload)
    if redacted_payload:
        payload.update(redacted_payload)

    # Add redaction-report.json if redaction ran
    if report is not None:
        rr_path = "redaction-report.json"
        files_meta.append(ManifestFile(path=rr_path, role="redaction_report", bytes=len(report.to_json())))

    # ---- Preview ----
    preview = _build_preview(file_results)

    if format == "text":
        print(preview.format())

    # Check export block
    if preview.export_blocked:
        msg = "Export blocked: high-confidence unresolved secrets detected"
        if format == "json":
            print(json.dumps({"error": msg, "code": "E_POLICY"}))
        else:
            print(f"\n! {msg}", file=sys.stderr)
        return 5

    # ---- Confirmation ----
    if not yes and sys.stdout.isatty():
        try:
            response = input("\nCreate bundle? [y/N] ")
            if response.lower() not in ("y", "yes"):
                if format == "json":
                    print(json.dumps({"status": "cancelled"}))
                else:
                    print("Capture cancelled.")
                return 6
        except (EOFError, KeyboardInterrupt):
            print("\nCapture cancelled.")
            return 6
    elif not yes and not sys.stdout.isatty():
        if format == "json":
            print(json.dumps({"error": "Confirmation required (use --yes for non-interactive)", "code": "E_CONFIRMATION"}))
        else:
            print("Confirmation required for non-TTY capture. Use --yes.", file=sys.stderr)
        return 6

    # ---- Write bundle ----
    output_path = output or _default_output_path()
    out = Path(output_path)

    writer = BundleWriter(out, compression="zst")

    for arc_path, (content_bytes, role) in payload.items():
        writer.add_payload(arc_path, content_bytes, role=role)

    writer.add_schema(Path(__file__).resolve().parent.parent.parent / "schemas")

    # ---- Capability for guide ----
    caps.prepare_supported = caps.git_state

    # Reproduction classification
    if not reproduction_info.get("classification"):
        if git_state and not git_state.get("dirty", True) and caps.session_excerpt:
            reproduction_info["classification"] = "partial"
        else:
            reproduction_info["classification"] = "inspection_only"

    # ---- Generate REPRODUCE.md ----
    file_list_meta = [{"path": ft.path, "role": ft.role, "present": True} for ft in files_meta]

    reproduce_md = generate_reproduce_md(
        bundle_id=Manifest.generate_bundle_id(),
        source_info=source_info,
        capabilities=caps.to_dict(),
        redaction_info=redaction_info,
        reproduction_info=reproduction_info,
        file_list=file_list_meta,
        git_commit=git_state.get("commit") if git_state else None,
        git_dirty=git_state.get("dirty") if git_state else None,
    )
    writer.add_payload("REPRODUCE.md", reproduce_md, role="reproduce")

    try:
        result_path = writer.write(
            source_info=source_info,
            capabilities=caps.to_dict(),
            redaction_info=redaction_info,
            reproduction_info=reproduction_info,
            limits_info={},
        )
    except Exception as e:
        msg = f"Bundle write failed: {e}"
        if format == "json":
            print(json.dumps({"error": msg, "code": "E_ARCHIVE"}))
        else:
            print(msg, file=sys.stderr)
        return 7

    # ---- Self-verify ----
    verifier = BundleVerify(strict=False)
    verify_result = verifier.verify(result_path)
    if not verify_result.valid:
        errors = [i for i in verify_result.issues if i.severity == "error"]
        if errors:
            msg = f"Self-verify failed: {verify_result.summary()}"
            if format == "json":
                print(json.dumps({"error": msg, "code": "E_INTEGRITY"}))
            else:
                print(msg, file=sys.stderr)
            # Clean up failed output
            if result_path.exists():
                result_path.unlink()
            return 8

    if format == "json":
        print(json.dumps({
            "status": "ok",
            "bundle": str(result_path),
            "size": result_path.stat().st_size,
            "redactions": redaction_info["total_replacements"],
        }))
    else:
        print(f"\nBundle created: {result_path}")
        print(f"  Size: {result_path.stat().st_size} bytes")
        print(f"  Redactions: {redaction_info['total_replacements']}")
        print("  Verification: PASSED")

    return 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _collect_safe_environment() -> dict[str, Any]:
    """Collect minimal, safe environment info. No env vars, secrets."""
    import platform
    return {
        "os": platform.system().lower(),
        "os_version": platform.release(),
        "machine": platform.machine(),
        "python_version": platform.python_version(),
        "hostname": "<redacted>",
    }


def _collect_git_state(cwd_hint: str | None) -> dict[str, Any] | None:
    """Collect Git state from cwd or CWD. Returns None if not a git repo."""
    import subprocess

    cwd = cwd_hint or os.getcwd()

    try:
        subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            cwd=cwd, capture_output=True, timeout=5,
            check=True,
        )
    except Exception:
        return None

    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd, capture_output=True, timeout=5, text=True,
        ).stdout.strip()
    except Exception:
        commit = None

    dirty = True
    try:
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=cwd, capture_output=True, timeout=5, text=True,
        )
        dirty = bool(status.stdout.strip())
    except Exception:
        pass

    branch = None
    try:
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=cwd, capture_output=True, timeout=5, text=True,
        ).stdout.strip()
    except Exception:
        pass

    result: dict[str, Any] = {}
    if commit:
        result["commit"] = commit
    result["dirty"] = dirty
    if branch:
        result["branch"] = branch

    return result if commit else None


def _default_output_path() -> str:
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y%m%d")
    return f"bug-{date_str}.agentrepro.tar.zst"
