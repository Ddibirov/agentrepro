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
from .redaction.preview import PreviewReport
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
        return 0 if result.valid else 1

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

    return 0 if result.valid else 1


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

    Delegates capture logic but doesn't write final bundle.
    """
    from .capture import cmd_capture

    # Re-use capture's logic but in preview-only mode
    return cmd_capture(
        source_selector=args.session if args.session else "last",
        agent=args.agent,
        output="/dev/null",  # No output
        yes=True,  # Skip confirmation for preview
        incident_path=args.incident,
        evidence_paths=args.evidence,
        format=args.format,
    )


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
    import subprocess

    repo = Path(args.repo).resolve()
    target = Path(args.dir).resolve()

    # Verify bundle first
    verifier = BundleVerify(strict=True)
    verify_result = verifier.verify(args.bundle)
    if not verify_result.valid:
        print(f"Bundle verification failed. Prepare requires strict verification.", file=sys.stderr)
        for i in verify_result.issues:
            if i.severity == "error":
                print(f"  [{i.code}] {i.message}", file=sys.stderr)
        return 9

    # Validate repo
    if not repo.is_dir():
        print(f"Error: --repo must be an existing directory: {repo}", file=sys.stderr)
        return 9

    if not (repo / ".git").is_dir():
        print(f"Error: --repo is not a Git repository: {repo}", file=sys.stderr)
        return 9

    # Validate target
    if target.exists():
        if any(target.iterdir()):
            print(f"Error: --dir must be empty or non-existent: {target}", file=sys.stderr)
            return 9
    else:
        target.mkdir(parents=True, exist_ok=True)

    # Read git-state from bundle
    try:
        with BundleReader(args.bundle) as reader:
            git_state = reader.read_json("git-state.json")
    except Exception as e:
        print(f"Cannot read git-state from bundle: {e}", file=sys.stderr)
        return 9

    baseline_commit = (git_state or {}).get("commit", "")
    if not baseline_commit:
        print("Warning: bundle has no baseline commit; creating detached worktree at current HEAD.", file=sys.stderr)
        baseline_commit = "HEAD"

    # Record original repo state
    try:
        original_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo, capture_output=True, timeout=10, text=True,
        ).stdout.strip()
    except Exception as e:
        print(f"Cannot determine original HEAD: {e}", file=sys.stderr)
        return 9

    try:
        # Verify baseline commit exists in repo
        subprocess.run(
            ["git", "cat-file", "-e", baseline_commit],
            cwd=repo, capture_output=True, timeout=10,
            check=True,
        )
    except Exception:
        print(f"Baseline commit not found in repo: {baseline_commit}", file=sys.stderr)
        return 9

    try:
        # Create detached worktree (fixed argv, no shell)
        subprocess.run(
            ["git", "worktree", "add", "--detach", str(target), baseline_commit],
            cwd=repo, capture_output=True, timeout=30,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to create worktree: {e.stderr.decode() if e.stderr else e}", file=sys.stderr)
        # Clean up target if created
        if target.exists() and not any(target.iterdir()):
            target.rmdir()
        return 9

    # Verify original repo is unchanged
    try:
        new_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo, capture_output=True, timeout=10, text=True,
        ).stdout.strip()
        if new_head != original_head:
            print(f"ERROR: Original repo HEAD changed! Was {original_head}, now {new_head}", file=sys.stderr)
            return 9
    except Exception:
        pass

    print(f"Worktree created at: {target}")
    print(f"  Baseline commit: {baseline_commit}")
    print()
    print("Suggested commands from REPRODUCE.md (review before executing):")
    print(f"  cd {target}")
    print("  # Review bundle contents and follow REPRODUCE.md instructions")
    print("  # Commands are NOT auto-executed per security policy")

    return 0


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
