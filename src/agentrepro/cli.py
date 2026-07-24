"""AgentRepro CLI — capture, preview, inspect, verify, prepare, redact test.

Matches spec §9: CLI contract with proper exit codes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from .bundle.reader import BundleReader, InspectReport
from .bundle.verify import BundleVerify
from .errors import AgentReproError
from .redaction.engine import RedactionEngine
from .redaction.report import RedactionReport


def cmd_inspect(args) -> int:
    """Inspect a bundle: show manifest summary without extraction."""
    try:
        with BundleReader(args.bundle) as reader:
            report = InspectReport(reader)
            if args.format == "json":
                print(json.dumps(report.summary(), indent=2, default=str))
                return 0
            print(report.text_summary())
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_verify(args) -> int:
    """Verify a bundle offline per spec §10.2."""
    verifier = BundleVerify(strict=args.strict)
    result = verifier.verify(args.bundle)

    if args.format == "json":
        print(json.dumps({
            "valid": result.valid,
            "issues": [
                {"code": i.code, "message": i.message, "severity": i.severity}
                for i in result.issues
            ],
        }, indent=2))
        return _verify_exit_code(result)

    print(f"Bundle: {Path(args.bundle).name}")
    print(f"Result: {result.summary()}")
    print()

    if result.issues:
        errors = [i for i in result.issues if i.severity == "error"]
        warnings = [i for i in result.issues if i.severity == "warning"]
        infos = [i for i in result.issues if i.severity == "info"]

        if errors:
            print("--- ERRORS ---")
            for e in errors:
                print(f"  [{e.code}] {e.message}")
            print()

        if warnings:
            print("--- WARNINGS ---")
            for w in warnings:
                print(f"  [{w.code}] {w.message}")
            print()

        if infos:
            print("--- INFO ---")
            for i_ in infos:
                print(f"  [{i_.code}] {i_.message}")
            print()

    return _verify_exit_code(result)


def _verify_exit_code(result) -> int:
    """Map verify result to spec-compliant exit code.

    Spec §9: 0=OK, 7=E_ARCHIVE, 8=E_INTEGRITY, 1=unexpected.
    """
    if result.valid:
        return 0

    has_archive = any(
        i.code and i.code.startswith("ARCHIVE_")
        for i in result.issues if i.severity == "error"
    )
    has_integrity = any(
        i.code and i.code.startswith(("CHECKSUM_", "INTEGRITY_", "REQUIRED_MISSING", "HARD_DENY", "RESIDUAL_SECRET", "MANIFEST_"))
        for i in result.issues if i.severity == "error"
    )

    if has_archive:
        return 7  # E_ARCHIVE
    if has_integrity:
        return 8  # E_INTEGRITY
    return 1  # General error


def cmd_redact_test(args) -> int:
    """Test redaction rules against a fixture file."""
    path = Path(args.fixture)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    content = path.read_text(encoding="utf-8", errors="replace")
    engine = RedactionEngine()

    if args.policy:
        try:
            policy_text = Path(args.policy).read_text(encoding="utf-8")
            for line in policy_text.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(" ", 2)
                    if len(parts) >= 2:
                        engine.add_custom_pattern(parts[0], parts[1])
        except Exception as e:
            print(f"Error loading policy: {e}", file=sys.stderr)
            return 1

    result = engine.redact_text(content)

    if args.format == "json":
        file_results = [engine.redact_file(path.name, content)]
        report = RedactionReport.from_file_results(file_results)
        print(report.to_json())
        return 2 if report.high_confidence_unresolved > 0 else 0

    if not result.changes:
        print(f"No secrets found in {path.name}")
        return 0

    print(f"File: {path.name}")
    print(f"  Total redactions: {result.total_changes}")
    print(f"  High confidence:  {result.high_confidence_count()}")
    print()

    if result.changes:
        print("--- REDACTED ITEMS ---")
        last_cat = ""
        for c in result.changes:
            if c.category != last_cat:
                print(f"\n  [{c.category}]")
                last_cat = c.category
            print(f"    {c.placeholder_id} -> {c.snippet[:70]}")

    if result.high_confidence_count() > 0:
        print()
        print("HIGH-CONFIDENCE SECRETS FOUND — export would be blocked.")
        return 2

    return 0


def cmd_preview(args) -> int:
    """Preview redaction results for a capture source.

    Runs the same policy/redaction pipeline as capture but does NOT
    write a bundle. Shows inventory, redaction counts, and risk level.
    Never exposes original values. Matches spec §8.4.
    """
    from .capture import _collect_payload, _run_redaction, _build_preview

    source_selector: str = "last"
    incident_path: str | None = None
    agent: str | None = args.agent

    if args.last:
        source_selector = "last"
    elif args.session:
        source_selector = args.session
    elif args.incident:
        incident_path = args.incident
    else:
        print("Error: one of --last, --session, or --incident is required", file=sys.stderr)
        return 2

    # Collect payload (same code path as capture)
    try:
        payload, files_meta, caps, source_info, incident_importer, git_state, reproduction_info = _collect_payload(
            source_selector=source_selector,
            agent=agent,
            incident_path=incident_path,
            evidence_paths=getattr(args, "evidence", None),
        )
    except Exception as e:
        print(f"Error collecting data: {e}", file=sys.stderr)
        return 3

    # Run redaction
    redacted_payload, redaction_info, file_results, report = _run_redaction(payload)
    if redacted_payload:
        payload = redacted_payload

    # Build preview
    preview = _build_preview(file_results)

    if args.format == "json":
        print(json.dumps(preview.to_dict(), indent=2))
    else:
        print(preview.format())

    if preview.export_blocked:
        return 5  # E_POLICY
    return 0


def cmd_capture_cli(args) -> int:
    """CLI handler for capture command."""
    from .capture import cmd_capture

    # Determine selector
    if args.last:
        selector = "last"
    elif args.session:
        selector = args.session
    elif args.incident:
        selector = args.incident
    else:
        print("Error: one of --last, --session, or --incident is required", file=sys.stderr)
        return 2

    return cmd_capture(
        source_selector=selector,
        agent=args.agent,
        output=args.output,
        yes=args.yes,
        incident_path=args.incident,
        evidence_paths=args.evidence,
        format=args.format,
    )


def cmd_prepare(args) -> int:
    """Prepare a reproduction worktree from a bundle (spec §10.3).

    Requires --repo (local existing repo) and --dir (empty/non-existent target).
    Does NOT modify the current working tree.
    """
    from .prepare import cmd_prepare as _prepare_impl

    return _prepare_impl(
        bundle_path=args.bundle,
        repo_path=args.repo,
        dir_path=args.dir,
        yes=args.yes,
    )


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="AgentRepro — coding agent incident reproduction bundles",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"agentrepro {__import__('agentrepro').__version__}",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # --- capture ---
    cap_p = sub.add_parser("capture", help="Create an incident reproduction bundle")
    cap_sel = cap_p.add_mutually_exclusive_group(required=True)
    cap_sel.add_argument("--last", action="store_true", help="Capture the most recent session")
    cap_sel.add_argument("--session", type=str, help="Capture a specific session by ID")
    cap_sel.add_argument("--incident", type=str, help="Capture from an incident.json file")
    cap_p.add_argument("--agent", type=str, help="Agent type (claude, codex, claude-code, codex-cli)")
    cap_p.add_argument("--output", type=str, help="Output bundle path (default: auto-generated)")
    cap_p.add_argument("--yes", action="store_true", help="Skip preview confirmation")
    cap_p.add_argument("--evidence", type=str, nargs="*", default=[], help="Evidence files to include")
    cap_p.add_argument("--format", type=str, choices=["text", "json"], default="text")

    # --- preview ---
    prev_p = sub.add_parser("preview", help="Preview redaction results without creating bundle")
    prev_sel = prev_p.add_mutually_exclusive_group(required=True)
    prev_sel.add_argument("--last", action="store_true", help="Preview most recent session")
    prev_sel.add_argument("--session", type=str, help="Preview a specific session")
    prev_sel.add_argument("--incident", type=str, help="Preview from an incident file")
    prev_p.add_argument("--agent", type=str, help="Agent type")
    prev_p.add_argument("--evidence", type=str, nargs="*", default=[], help="Evidence files")
    prev_p.add_argument("--format", type=str, choices=["text", "json"], default="text")

    # --- inspect ---
    ins_p = sub.add_parser("inspect", help="Inspect a bundle without extraction")
    ins_p.add_argument("bundle", type=str, help="Path to .agentrepro.tar[.zst] bundle")
    ins_p.add_argument("--format", type=str, choices=["text", "json"], default="text")

    # --- verify ---
    ver_p = sub.add_parser("verify", help="Verify a bundle (offline)")
    ver_p.add_argument("bundle", type=str, help="Path to .agentrepro.tar[.zst] bundle")
    ver_p.add_argument("--strict", action="store_true", help="Promote warnings to errors")
    ver_p.add_argument("--format", type=str, choices=["text", "json"], default="text")

    # --- prepare ---
    prep_p = sub.add_parser("prepare", help="Prepare a reproduction worktree from a bundle")
    prep_p.add_argument("bundle", type=str, help="Path to .agentrepro.tar[.zst] bundle")
    prep_p.add_argument("--repo", type=str, required=True, help="Local Git repository to use as base")
    prep_p.add_argument("--dir", type=str, required=True, help="Target directory for worktree (must be empty/non-existent)")
    prep_p.add_argument("--yes", action="store_true", help="Skip confirmation")

    # --- redact test ---
    redact_p = sub.add_parser("redact", help="Redaction commands")
    redact_sub = redact_p.add_subparsers(dest="redact_command", required=True)

    redact_test_p = redact_sub.add_parser("test", help="Test redaction rules against a fixture file")
    redact_test_p.add_argument("fixture", type=str, help="Path to fixture file to test")
    redact_test_p.add_argument("--policy", type=str, help="Path to custom policy file")
    redact_test_p.add_argument("--format", type=str, choices=["text", "json"], default="text")

    args = parser.parse_args()

    try:
        if args.command == "capture":
            return cmd_capture_cli(args)
        elif args.command == "preview":
            return cmd_preview(args)
        elif args.command == "inspect":
            return cmd_inspect(args)
        elif args.command == "verify":
            return cmd_verify(args)
        elif args.command == "prepare":
            return cmd_prepare(args)
        elif args.command == "redact":
            if args.redact_command == "test":
                return cmd_redact_test(args)
            return 1
        return 1
    except AgentReproError as e:
        print(f"error [{e.code}]: {e.args[0]}", file=sys.stderr)
        return e.exit_code
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
